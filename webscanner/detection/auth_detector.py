# Authentication issues detection
from .detector_base import BaseDetector
from typing import List, Dict
import re

class AuthDetector(BaseDetector):
    """Detect authentication-related vulnerabilities"""
    
    def __init__(self, session):
        super().__init__(session)
        self.weak_passwords = ['admin', 'password', '123456', 'admin123']
    
    def detect(self, url: str, response_text: str) -> List[Dict]:
        """Detect auth vulnerabilities"""
        vulnerabilities = []
        
        # Check for login forms
        if self._has_login_form(response_text):
            # Test default credentials
            if self._test_default_credentials(url):
                vuln = self.create_vulnerability(
                    'Default Credentials',
                    url=url,
                    severity='high',
                    confidence=0.9
                )
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _has_login_form(self, response_text: str) -> bool:
        """Check if page contains login form"""
        login_patterns = [
            r'<input[^>]*type=["\']password["\']',
            r'<input[^>]*name=["\']username["\']',
            r'<form[^>]*login'
        ]
        
        for pattern in login_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
        return False
    
    def _test_default_credentials(self, url: str) -> bool:
        """Test common default credentials"""
        # This is simplified - real implementation would parse forms properly
        default_creds = [
            {'username': 'admin', 'password': 'admin'},
            {'username': 'admin', 'password': 'password'}
        ]
        
        for creds in default_creds:
            try:
                response = self.session.post(url, data=creds)
                if 'dashboard' in response.text.lower() or 'welcome' in response.text.lower():
                    return True
            except Exception:
                continue
        
        return False