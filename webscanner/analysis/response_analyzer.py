# Response comparison & analysis
import difflib
from typing import Dict, Any, List

class ResponseAnalyzer:
    """Analyzes HTTP responses to detect significant changes"""
    
    def __init__(self):
        self.similarity_threshold = 0.85
        self.length_change_threshold = 0.15
    
    def analyze_difference(self, baseline_text: str, test_text: str) -> Dict[str, Any]:
        """Compare baseline and test responses"""
        if not baseline_text or not test_text:
            return {'significant_change': False}
        
        analysis = {
            'similarity_score': self._calculate_similarity(baseline_text, test_text),
            'length_difference': abs(len(baseline_text) - len(test_text)),
            'length_ratio': abs(len(baseline_text) - len(test_text)) / max(len(baseline_text), 1),
            'new_errors': self._find_new_errors(baseline_text, test_text),
            'content_changes': self._analyze_content_changes(baseline_text, test_text),
            'significant_change': False
        }
        
        # Determine if change is significant
        analysis['significant_change'] = (
            analysis['similarity_score'] < self.similarity_threshold or
            analysis['length_ratio'] > self.length_change_threshold or
            len(analysis['new_errors']) > 0
        )
        
        return analysis
    
    def _calculate_similarity(self, text1: str, text2: str) -> float:
        """Calculate similarity ratio between two text responses"""
        if not text1 and not text2:
            return 1.0
        if not text1 or not text2:
            return 0.0
        
        # Use difflib for similarity calculation
        matcher = difflib.SequenceMatcher(None, text1.lower(), text2.lower())
        return matcher.ratio()
    
    def _find_new_errors(self, baseline: str, test: str) -> List[str]:
        """Find error indicators that appear only in test response"""
        error_keywords = [
            'error', 'exception', 'warning', 'fatal', 'failed',
            'stack trace', 'traceback', 'undefined', 'null pointer',
            'syntax error', 'runtime error', 'access violation'
        ]
        
        baseline_lower = baseline.lower()
        test_lower = test.lower()
        
        new_errors = []
        for keyword in error_keywords:
            if keyword in test_lower and keyword not in baseline_lower:
                new_errors.append(keyword)
        
        return new_errors
    
    def _analyze_content_changes(self, baseline: str, test: str) -> Dict[str, Any]:
        """Analyze specific types of content changes"""
        changes = {
            'html_structure_changed': self._html_structure_changed(baseline, test),
            'status_messages_changed': self._status_messages_changed(baseline, test),
            'script_content_changed': self._script_content_changed(baseline, test)
        }
        
        return changes
    
    def _html_structure_changed(self, baseline: str, test: str) -> bool:
        """Check if HTML structure significantly changed"""
        try:
            from bs4 import BeautifulSoup
            
            baseline_soup = BeautifulSoup(baseline, 'html.parser')
            test_soup = BeautifulSoup(test, 'html.parser')
            
            baseline_tags = [tag.name for tag in baseline_soup.find_all()]
            test_tags = [tag.name for tag in test_soup.find_all()]
            
            # Simple comparison of tag counts
            return abs(len(baseline_tags) - len(test_tags)) > max(len(baseline_tags) * 0.1, 5)
            
        except Exception:
            return False
    
    def _status_messages_changed(self, baseline: str, test: str) -> bool:
        """Check for changes in status/error messages"""
        status_patterns = [
            r'success', r'error', r'warning', r'info', r'alert',
            r'failed', r'completed', r'invalid', r'denied'
        ]
        
        import re
        baseline_lower = baseline.lower()
        test_lower = test.lower()
        
        for pattern in status_patterns:
            baseline_matches = len(re.findall(pattern, baseline_lower))
            test_matches = len(re.findall(pattern, test_lower))
            
            if abs(baseline_matches - test_matches) > 0:
                return True
        
        return False
    
    def _script_content_changed(self, baseline: str, test: str) -> bool:
        """Check if JavaScript content changed"""
        try:
            from bs4 import BeautifulSoup
            
            baseline_soup = BeautifulSoup(baseline, 'html.parser')
            test_soup = BeautifulSoup(test, 'html.parser')
            
            baseline_scripts = [script.get_text() for script in baseline_soup.find_all('script') if script.get_text()]
            test_scripts = [script.get_text() for script in test_soup.find_all('script') if script.get_text()]
            
            return len(baseline_scripts) != len(test_scripts)
            
        except Exception:
            return False
        
