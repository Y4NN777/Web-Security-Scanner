# Security headers detection
from .detector_base import BaseDetector
from typing import List, Dict

class SecurityHeadersDetector(BaseDetector):
    """Detect missing security headers"""
    
    def __init__(self, session):
        super().__init__(session)
        self.required_headers = {
            'Content-Security-Policy': 'Prevents XSS and injection attacks',
            'X-Frame-Options': 'Prevents clickjacking',
            'X-Content-Type-Options': 'Prevents MIME sniffing',
            'Strict-Transport-Security': 'Enforces HTTPS'
        }
    
    def detect(self, url: str, response_text: str) -> List[Dict]:
        """Check for missing security headers"""
        vulnerabilities = []
        
        try:
            response = self.session.get(url)
            headers = response.headers
            
            for header_name, description in self.required_headers.items():
                if header_name not in headers:
                    vuln = self.create_vulnerability(
                        'Missing Security Header',
                        url=url,
                        header_name=header_name,
                        description=description,
                        severity='low',
                        confidence=1.0  # Missing headers are definitive
                    )
                    vulnerabilities.append(vuln)
        
        except Exception as e:
            print(f"Error checking security headers for {url}: {str(e)}")
        
        return vulnerabilities