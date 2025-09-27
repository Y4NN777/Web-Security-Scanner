# detection/header_detector.py
from .detector_base import DetectorBase
from typing import List, Dict

class SecurityHeadersDetector(DetectorBase):
    """Detect missing and misconfigured security headers"""
    
    def __init__(self, session, config=None):  # Fixed: Accept config parameter
        super().__init__(session, config)
        self.required_headers = {
            'Content-Security-Policy': {
                'description': 'Prevents XSS and injection attacks',
                'severity': 'medium'
            },
            'X-Frame-Options': {
                'description': 'Prevents clickjacking',
                'severity': 'medium'
            },
            'X-Content-Type-Options': {
                'description': 'Prevents MIME sniffing',
                'severity': 'low'
            },
            'Strict-Transport-Security': {
                'description': 'Enforces HTTPS',
                'severity': 'medium'
            },
            'X-XSS-Protection': {
                'description': 'Enables browser XSS filtering',
                'severity': 'low'
            },
            'Referrer-Policy': {
                'description': 'Controls referrer information',
                'severity': 'low'
            }
        }
    
    def detect(self, page_data: Dict) -> List[Dict]:  # Fixed: Use page_data instead of separate parameters
        """Check for missing security headers"""
        vulnerabilities = []
        url = page_data['url']
        
        try:
            # Use the response from page_data instead of making a new request
            response = page_data.get('response')
            if not response:
                # Fallback to making request if response not in page_data
                response = self.session.get(url)
            
            headers = response.headers
            
            for header_name, header_info in self.required_headers.items():
                if header_name not in headers:
                    vuln = self.create_vulnerability(
                        'Missing Security Header',
                        url=url,
                        header_name=header_name,
                        description=header_info['description'],
                        severity=header_info['severity'],
                        confidence=1.0,  # Missing headers are definitive
                        recommendation=self._get_header_recommendation(header_name)
                    )
                    vulnerabilities.append(vuln)
                else:
                    # Check for misconfigured headers
                    header_value = headers[header_name]
                    misconfig_vuln = self._check_header_configuration(
                        url, header_name, header_value, header_info
                    )
                    if misconfig_vuln:
                        vulnerabilities.append(misconfig_vuln)
        
        except Exception as e:
            print(f"Error checking security headers for {url}: {str(e)}")
        
        return vulnerabilities
    
    def _check_header_configuration(self, url: str, header_name: str, 
                                   header_value: str, header_info: Dict) -> Dict:
        """Check if existing header is properly configured"""
        
        # Content Security Policy validation
        if header_name == 'Content-Security-Policy':
            if self._is_csp_weak(header_value):
                return self.create_vulnerability(
                    'Weak Content Security Policy',
                    url=url,
                    header_name=header_name,
                    header_value=header_value,
                    description='CSP contains unsafe directives',
                    severity='medium',
                    confidence=0.8,
                    issues=self._get_csp_issues(header_value)
                )
        
        # X-Frame-Options validation
        elif header_name == 'X-Frame-Options':
            valid_values = ['DENY', 'SAMEORIGIN']
            if header_value.upper() not in valid_values and not header_value.upper().startswith('ALLOW-FROM'):
                return self.create_vulnerability(
                    'Invalid X-Frame-Options',
                    url=url,
                    header_name=header_name,
                    header_value=header_value,
                    description='Invalid X-Frame-Options value',
                    severity='low',
                    confidence=1.0
                )
        
        # HSTS validation
        elif header_name == 'Strict-Transport-Security':
            if 'max-age=' not in header_value.lower():
                return self.create_vulnerability(
                    'Invalid HSTS Configuration',
                    url=url,
                    header_name=header_name,
                    header_value=header_value,
                    description='HSTS missing max-age directive',
                    severity='medium',
                    confidence=1.0
                )
        
        return None
    
    def _is_csp_weak(self, csp_value: str) -> bool:
        """Check if CSP contains weak/unsafe directives"""
        weak_indicators = [
            'unsafe-inline',
            'unsafe-eval', 
            "'unsafe-inline'",
            "'unsafe-eval'",
            '*',  # Wildcard source
            'data:',  # Data URIs (can be problematic)
        ]
        
        csp_lower = csp_value.lower()
        return any(indicator in csp_lower for indicator in weak_indicators)
    
    def _get_csp_issues(self, csp_value: str) -> List[str]:
        """Get list of CSP configuration issues"""
        issues = []
        csp_lower = csp_value.lower()
        
        if 'unsafe-inline' in csp_lower:
            issues.append("Contains 'unsafe-inline' which allows inline scripts/styles")
        
        if 'unsafe-eval' in csp_lower:
            issues.append("Contains 'unsafe-eval' which allows eval() and similar functions")
        
        if '*' in csp_value:
            issues.append("Contains wildcard '*' which allows content from any source")
        
        # Check for missing important directives
        important_directives = ['default-src', 'script-src', 'style-src', 'img-src']
        for directive in important_directives:
            if directive not in csp_lower:
                issues.append(f"Missing '{directive}' directive")
        
        return issues
    
    def _get_header_recommendation(self, header_name: str) -> str:
        """Get implementation recommendation for missing header"""
        recommendations = {
            'Content-Security-Policy': "Add: Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'",
            'X-Frame-Options': "Add: X-Frame-Options: DENY",
            'X-Content-Type-Options': "Add: X-Content-Type-Options: nosniff",
            'Strict-Transport-Security': "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
            'X-XSS-Protection': "Add: X-XSS-Protection: 1; mode=block",
            'Referrer-Policy': "Add: Referrer-Policy: strict-origin-when-cross-origin"
        }
        return recommendations.get(header_name, f"Configure {header_name} header properly")