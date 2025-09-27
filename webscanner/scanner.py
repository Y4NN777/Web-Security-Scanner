from .core.scanner_engine import ScannerEngine
from typing import List, Dict

class WebSecurityScanner:
    """Main scanner class - now just a wrapper around ScannerEngine"""
    
    def __init__(self, target_url: str, max_depth: int = 3):
        self.config = {
            'crawling': {
                'max_depth': max_depth,
                'crawl_delay': 0.5,
                'timeout': 10
            },
            'detectors': {
                'sql_injection': {
                    'enabled': True,
                    'min_confidence': 0.3
                },
                'xss': {
                    'enabled': True,
                    'min_confidence': 0.3
                },
                'security_headers': {
                    'enabled': True
                }
            }
        }
        
        self.engine = ScannerEngine(target_url, self.config)
        self.vulnerabilities = []  # For backward compatibility
        self.visited_urls = set()  # For backward compatibility
    
    def scan(self) -> List[Dict]:
        """Execute scan and return vulnerabilities list"""
        results = self.engine.scan()
        
        # For backward compatibility
        self.vulnerabilities = results.vulnerabilities
        self.visited_urls = set(vuln.get('url', '') for vuln in self.vulnerabilities)
        
        return self.vulnerabilities
    
    def export_json(self, filename: str = None) -> str:
        """Export results to JSON"""
        return self.engine.export_results('json', filename)
    
    def export_html(self, filename: str = None) -> str:
        """Export results to HTML"""
        return self.engine.export_results('html', filename)
