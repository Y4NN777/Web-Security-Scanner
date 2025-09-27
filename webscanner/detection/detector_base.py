# Base class for all detectors
from abc import ABC, abstractmethod
from typing import List, Dict, Any
import requests
from datetime import datetime

class DetectorBase(ABC):
    """Base class for all vulnerability detectors"""
    
    def __init__(self, session: requests.Session, config: Dict = None):
        self.session = session
        self.config = config or {}
        self.name = self.__class__.__name__
        
    @abstractmethod
    def detect(self, page_data: Dict) -> List[Dict]:
        """
        Detect vulnerabilities in a page
        
        Args:
            page_data: Dictionary containing url, response, forms, parameters
            
        Returns:
            List of vulnerability dictionaries
        """
        pass
    
    def create_vulnerability(self, vuln_type: str, **kwargs) -> Dict[str, Any]:
        """Create standardized vulnerability report"""
        return {
            'type': vuln_type,
            'detector': self.name,
            'timestamp': datetime.now().isoformat(),
            'confidence': kwargs.get('confidence', 0.5),
            'severity': kwargs.get('severity', 'medium'),
            **kwargs
        }
    
    def calculate_confidence(self, indicators: Dict[str, Any]) -> float:
        """Calculate confidence score based on detection indicators"""
        confidence = 0.0
        
        # Error-based indicators (highest confidence)
        if indicators.get('error_patterns'):
            confidence += 0.6
        
        # Behavioral indicators
        if indicators.get('response_changes'):
            confidence += 0.3
        
        # Encoding bypass indicators
        if indicators.get('encoding_bypass'):
            confidence += 0.2
        
        # Time-based indicators
        if indicators.get('time_based'):
            confidence += 0.4
        
        return min(confidence, 1.0)