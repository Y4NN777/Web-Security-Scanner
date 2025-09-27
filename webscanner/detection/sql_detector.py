# Enhanced SQL injection detection
from .detector_base import DetectorBase
from ..crawling.url_handler import URLHandler
from ..analysis.response_analyzer import ResponseAnalyzer
from typing import List, Dict
import time

class SQLDetector(DetectorBase):
    """Enhanced SQL injection detector with encoding awareness"""
    
    def __init__(self, session, config=None):
        super().__init__(session, config)
        self.url_handler = URLHandler()
        self.response_analyzer = ResponseAnalyzer()
        
        # SQL injection payloads by category
        self.payloads = {
            'error_based': [
                "'",
                '"',
                "' OR '1'='1",
                '" OR "1"="1',
                "' OR 1=1--",
                '" OR 1=1#',
                "') OR ('1'='1"
            ],
            'union_based': [
                "' UNION SELECT NULL--",
                "' UNION SELECT 1,2,3--",
                '" UNION SELECT NULL,NULL--',
                "' UNION ALL SELECT 1,2,3,4,5--"
            ],
            'time_based': [
                "'; WAITFOR DELAY '0:0:5'--",
                "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
                "'; SELECT pg_sleep(5)--",
                "' AND SUBSTR(VERSION(),1,1) = '5' AND SLEEP(5)--"
            ]
        }
        
        # Database error patterns
        self.error_patterns = {
            'mysql': [r'mysql_fetch_array', r'mysql error', r'table.*doesn\'t exist'],
            'postgresql': [r'postgresql query failed', r'pg_query.*expects'],
            'mssql': [r'microsoft odbc sql server', r'unclosed quotation mark'],
            'oracle': [r'ora-\d{5}', r'oracle.*error'],
            'sqlite': [r'sqlite3\.operationalerror', r'no such table']
        }
    
    def detect(self, page_data: Dict) -> List[Dict]:
        """Detect SQL injection vulnerabilities"""
        vulnerabilities = []
        url = page_data['url']
        
        # Test URL parameters
        url_params = page_data.get('url_parameters', {})
        for param_name, param_values in url_params.items():
            vulns = self._test_parameter(url, param_name, 'GET')
            vulnerabilities.extend(vulns)
        
        # Test form parameters
        forms = page_data.get('forms', [])
        for form in forms:
            for input_field in form['inputs']:
                if input_field['name'] and input_field['type'] not in ['submit', 'button']:
                    vulns = self._test_parameter(form['action'], input_field['name'], form['method'])
                    vulnerabilities.extend(vulns)
        
        return vulnerabilities
    
    def _test_parameter(self, url: str, param_name: str, method: str) -> List[Dict]:
        """Test a specific parameter for SQL injection"""
        vulnerabilities = []
        
        try:
            # Get baseline response
            baseline_response = self._get_baseline_response(url, param_name, method)
            
            # Test each payload category
            for payload_type, payloads in self.payloads.items():
                for base_payload in payloads:
                    # Test with different encoding variations
                    payload_variations = self.url_handler.generate_payload_variations(base_payload)
                    
                    for payload_data in payload_variations:
                        payload = payload_data['payload']
                        encoding = payload_data['encoding']
                        
                        result = self._test_single_payload(
                            url, param_name, method, payload, baseline_response, payload_type
                        )
                        
                        if result['vulnerable']:
                            confidence = self._calculate_sql_confidence(result, encoding, payload_type)
                            
                            if confidence >= self.config.get('min_confidence', 0.3):
                                vuln = self.create_vulnerability(
                                    'SQL Injection',
                                    url=url,
                                    parameter=param_name,
                                    method=method,
                                    payload=payload,
                                    original_payload=base_payload,
                                    encoding_type=encoding,
                                    payload_type=payload_type,
                                    evidence=result['evidence'],
                                    confidence=confidence,
                                    severity=self._get_severity(payload_type)
                                )
                                vulnerabilities.append(vuln)
        
        except Exception as e:
            print(f"Error testing SQL injection on {param_name}: {e}")
        
        return vulnerabilities
    
    def _test_single_payload(self, url: str, param_name: str, method: str, 
                           payload: str, baseline_response, payload_type: str) -> Dict:
        """Test a single payload variation"""
        result = {
            'vulnerable': False,
            'evidence': [],
            'indicators': {}
        }
        
        try:
            # Send test request
            if method.upper() == 'GET':
                test_url = self.url_handler.build_test_url(url, param_name, payload)
                test_response = self.session.get(test_url)
            else:
                test_response = self.session.post(url, data={param_name: payload})
            
            # Analyze response
            result['indicators'] = self._analyze_sql_response(
                baseline_response, test_response, payload, payload_type
            )
            
            # Determine vulnerability
            result['vulnerable'] = self._is_sql_vulnerable(result['indicators'])
            
            # Collect evidence
            if result['vulnerable']:
                result['evidence'] = self._collect_sql_evidence(result['indicators'], test_response)
        
        except Exception as e:
            print(f"Error testing payload {payload}: {e}")
        
        return result
    
    def _analyze_sql_response(self, baseline, test_response, payload: str, payload_type: str) -> Dict:
        """Analyze response for SQL injection indicators"""
        indicators = {}
        
        # Check for database errors
        indicators['error_patterns'] = self._check_error_patterns(test_response.text)
        
        # Response comparison
        if baseline:
            indicators['response_changes'] = self.response_analyzer.analyze_difference(
                baseline.text, test_response.text
            )
        
        # Time-based analysis
        if payload_type == 'time_based':
            indicators['time_based'] = test_response.elapsed.total_seconds() > 4.0
        
        # Status code changes
        if baseline:
            indicators['status_change'] = baseline.status_code != test_response.status_code
        
        return indicators
    
    def _check_error_patterns(self, response_text: str) -> List[str]:
        """Check for database error patterns"""
        import re
        found_errors = []
        response_lower = response_text.lower()
        
        for db_type, patterns in self.error_patterns.items():
            for pattern in patterns:
                if re.search(pattern, response_lower, re.IGNORECASE):
                    found_errors.append(f"{db_type}: {pattern}")
        
        return found_errors
    
    def _is_sql_vulnerable(self, indicators: Dict) -> bool:
        """Determine if response indicates SQL injection"""
        return (
            bool(indicators.get('error_patterns')) or
            bool(indicators.get('time_based')) or
            (indicators.get('response_changes', {}).get('significant_change', False) and
             indicators.get('response_changes', {}).get('new_errors', []))
        )
    
    def _calculate_sql_confidence(self, result: Dict, encoding: str, payload_type: str) -> float:
        """Calculate confidence score for SQL injection"""
        indicators = result.get('indicators', {})
        
        confidence_factors = {
            'error_patterns': 0.7 if indicators.get('error_patterns') else 0.0,
            'time_based': 0.6 if indicators.get('time_based') else 0.0,
            'response_changes': 0.4 if indicators.get('response_changes', {}).get('significant_change') else 0.0,
            'encoding_bonus': 0.2 if encoding != 'none' else 0.0,
            'payload_type_bonus': {'error_based': 0.1, 'union_based': 0.2, 'time_based': 0.0}.get(payload_type, 0.0)
        }
        
        return min(sum(confidence_factors.values()), 1.0)
    
    def _get_baseline_response(self, url: str, param_name: str, method: str):
        """Get baseline response for comparison"""
        try:
            if method.upper() == 'GET':
                return self.session.get(url)
            else:
                return self.session.post(url, data={param_name: 'test'})
        except:
            return None
    
    def _get_severity(self, payload_type: str) -> str:
        """Get severity based on payload type"""
        severity_map = {
            'error_based': 'high',
            'union_based': 'critical',
            'time_based': 'medium'
        }
        return severity_map.get(payload_type, 'medium')
    
    def _collect_sql_evidence(self, indicators: Dict, response) -> List[str]:
        """Collect evidence of SQL injection"""
        evidence = []
        
        if indicators.get('error_patterns'):
            evidence.extend([f"Database error: {err}" for err in indicators['error_patterns']])
        
        if indicators.get('time_based'):
            evidence.append(f"Time delay detected: {response.elapsed.total_seconds():.2f}s")
        
        if indicators.get('status_change'):
            evidence.append(f"Status code changed to: {response.status_code}")
        
        return evidence