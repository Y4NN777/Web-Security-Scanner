# detection/xss_detector.py
from .detector_base import DetectorBase
from ..crawling.url_handler import URLHandler
from ..analysis.response_analyzer import ResponseAnalyzer
from typing import List, Dict
import html
from bs4 import BeautifulSoup

class XSSDetector(DetectorBase):
    """Enhanced XSS detector that actually tests for vulnerabilities"""
    
    def __init__(self, session, config=None):
        super().__init__(session, config)
        self.url_handler = URLHandler()
        self.response_analyzer = ResponseAnalyzer()
        
        # XSS payloads by context
        self.payloads = {
            'script_injection': [
                '<script>alert("XSS")</script>',
                '<script>confirm("XSS")</script>',
                '<ScRiPt>alert("XSS")</ScRiPt>'  # Case variation
            ],
            'attribute_injection': [
                '" onmouseover="alert(\'XSS\')"',
                '\' onmouseover=\'alert("XSS")\'',
                '"><img src=x onerror=alert("XSS")>',
                '\'><!img src=x onerror=alert("XSS")>'
            ],
            'html_injection': [
                '<img src=x onerror=alert("XSS")>',
                '<svg onload=alert("XSS")>',
                '<iframe src="javascript:alert(\'XSS\')">',
                '<body onload=alert("XSS")>'
            ]
        }

    def detect(self, page_data: Dict) -> List[Dict]:
        """Test for XSS vulnerabilities by injecting payloads"""
        vulnerabilities = []
        url = page_data['url']
        
        # Test URL parameters
        url_params = page_data.get('url_parameters', {})
        for param_name, param_values in url_params.items():
            vulns = self._test_parameter_for_xss(url, param_name, 'GET')
            vulnerabilities.extend(vulns)
        
        # Test form parameters  
        forms = page_data.get('forms', [])
        for form in forms:
            for input_field in form['inputs']:
                if (input_field['name'] and 
                    input_field['type'] not in ['submit', 'button', 'hidden']):
                    vulns = self._test_parameter_for_xss(
                        form['action'], input_field['name'], form['method']
                    )
                    vulnerabilities.extend(vulns)
        
        return vulnerabilities
    
    def _test_parameter_for_xss(self, url: str, param_name: str, method: str) -> List[Dict]:
        """Test a specific parameter for XSS"""
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
                        
                        result = self._test_single_xss_payload(
                            url, param_name, method, payload, baseline_response, payload_type
                        )
                        
                        if result['vulnerable']:
                            confidence = self._calculate_xss_confidence(result, encoding, payload_type)
                            
                            if confidence >= self.config.get('min_confidence', 0.3):
                                vuln = self.create_vulnerability(
                                    'Cross-Site Scripting (XSS)',
                                    url=url,
                                    parameter=param_name,
                                    method=method,
                                    payload=payload,
                                    original_payload=base_payload,
                                    encoding_type=encoding,
                                    payload_type=payload_type,
                                    evidence=result['evidence'],
                                    confidence=confidence,
                                    severity=self._get_xss_severity(payload_type)
                                )
                                vulnerabilities.append(vuln)
        
        except Exception as e:
            print(f"Error testing XSS on {param_name}: {e}")
        
        return vulnerabilities
    
    def _test_single_xss_payload(self, url: str, param_name: str, method: str,
                                payload: str, baseline_response, payload_type: str) -> Dict:
        """Test a single XSS payload"""
        result = {
            'vulnerable': False,
            'evidence': [],
            'reflection_contexts': []
        }
        
        try:
            # Send test request
            if method.upper() == 'GET':
                test_url = self.url_handler.build_test_url(url, param_name, payload)
                test_response = self.session.get(test_url)
            else:
                test_response = self.session.post(url, data={param_name: payload})
            
            # Check if payload is reflected
            reflection_analysis = self._analyze_payload_reflection(
                test_response.text, payload, payload_type
            )
            
            result['reflection_contexts'] = reflection_analysis['contexts']
            result['vulnerable'] = reflection_analysis['exploitable']
            
            # Collect evidence
            if result['vulnerable']:
                result['evidence'] = self._collect_xss_evidence(reflection_analysis, test_response)
        
        except Exception as e:
            print(f"Error testing XSS payload {payload}: {e}")
        
        return result
    
    def _analyze_payload_reflection(self, response_text: str, payload: str, payload_type: str) -> Dict:
        """Analyze where and how the payload is reflected"""
        analysis = {
            'contexts': [],
            'exploitable': False
        }
        
        try:
            # Check for direct reflection
            if payload in response_text:
                analysis['contexts'].append('direct_reflection')
                analysis['exploitable'] = True
            
            # Check for HTML escaped reflection
            escaped_payload = html.escape(payload)
            if escaped_payload in response_text:
                analysis['contexts'].append('html_escaped')
                # Escaped payloads are usually not exploitable unless in specific contexts
                
            # Parse HTML to check contexts
            soup = BeautifulSoup(response_text, 'html.parser')
            
            # Check if payload appears in dangerous contexts
            contexts_found = self._find_dangerous_contexts(soup, payload)
            analysis['contexts'].extend(contexts_found)
            
            if contexts_found:
                analysis['exploitable'] = True
            
        except Exception as e:
            print(f"Error analyzing XSS reflection: {e}")
        
        return analysis
    
    def _find_dangerous_contexts(self, soup: BeautifulSoup, payload: str) -> List[str]:
        """Find dangerous contexts where payload appears"""
        dangerous_contexts = []
        
        try:
            # Check script tags
            for script in soup.find_all('script'):
                if script.string and payload in script.string:
                    dangerous_contexts.append('script_context')
            
            # Check event handlers
            for tag in soup.find_all():
                for attr_name, attr_value in tag.attrs.items():
                    if (attr_name.startswith('on') and 
                        attr_value and payload in str(attr_value)):
                        dangerous_contexts.append(f'event_handler_{attr_name}')
                    
                    # Check href/src attributes for javascript: protocol
                    if (attr_name in ['href', 'src'] and 
                        attr_value and 'javascript:' in str(attr_value) and payload in str(attr_value)):
                        dangerous_contexts.append(f'javascript_protocol_{attr_name}')
            
            # Check for payload in tag attributes that could break out
            page_text = str(soup)
            if payload in page_text:
                # Simple heuristic: if payload contains < or > and appears unescaped
                if ('<' in payload or '>' in payload) and payload in page_text:
                    dangerous_contexts.append('html_injection')
                
                # Check for attribute injection
                if ('"' in payload or "'" in payload) and payload in page_text:
                    dangerous_contexts.append('attribute_injection')
        
        except Exception as e:
            print(f"Error finding dangerous contexts: {e}")
        
        return dangerous_contexts
    
    def _calculate_xss_confidence(self, result: Dict, encoding: str, payload_type: str) -> float:
        """Calculate confidence score for XSS detection"""
        confidence = 0.0
        
        # Base confidence from reflection
        if result.get('vulnerable'):
            confidence += 0.5
        
        # Context-based confidence
        contexts = result.get('reflection_contexts', [])
        dangerous_contexts = ['script_context', 'html_injection', 'attribute_injection']
        
        for context in contexts:
            if any(dangerous in context for dangerous in dangerous_contexts):
                confidence += 0.3
                break
        
        # Encoding bonus (encoded payloads that work suggest filter bypass)
        if encoding != 'none':
            confidence += 0.2
        
        # Payload type bonus
        type_bonuses = {
            'script_injection': 0.2,
            'attribute_injection': 0.15,
            'html_injection': 0.1
        }
        confidence += type_bonuses.get(payload_type, 0.0)
        
        return min(confidence, 1.0)
    
    def _get_baseline_response(self, url: str, param_name: str, method: str):
        """Get baseline response for comparison"""
        try:
            if method.upper() == 'GET':
                return self.session.get(url)
            else:
                return self.session.post(url, data={param_name: 'test'})
        except:
            return None
    
    def _get_xss_severity(self, payload_type: str) -> str:
        """Get severity based on payload type"""
        severity_map = {
            'script_injection': 'high',
            'attribute_injection': 'medium',
            'html_injection': 'medium'
        }
        return severity_map.get(payload_type, 'medium')
    
    def _collect_xss_evidence(self, reflection_analysis: Dict, response) -> List[str]:
        """Collect evidence of XSS vulnerability"""
        evidence = []
        
        contexts = reflection_analysis.get('contexts', [])
        for context in contexts:
            evidence.append(f"Payload reflected in: {context}")
        
        if reflection_analysis.get('exploitable'):
            evidence.append("Payload appears in exploitable context")
        
        return evidence