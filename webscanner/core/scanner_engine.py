# Main coordinator for scanning operations
import requests
from typing import List, Dict, Any
from ..crawling.web_crawler import WebCrawler
from ..detection.sql_detector import SQLDetector
from ..detection.xss_detector import XSSDetector  # You'll create this
from ..reporting.vulnerability_report import VulnerabilityReport
from ..reporting.console_reporter import ConsoleReporter
import colorama

class ScannerEngine:
    """Main scanning engine that coordinates all modules"""
    
    def __init__(self, target_url: str, config: Dict = None):
        self.target_url = target_url
        self.config = config or {}
        
        # Initialize session
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': self.config.get('user_agent', 'WebSecurityScanner/2.0')
        })
        
        # Initialize modules
        self.crawler = WebCrawler(self.session, self.config.get('crawling', {}))
        self.detectors = self._initialize_detectors()
        self.reporter = ConsoleReporter()
        
        # Results storage
        self.scan_results = VulnerabilityReport()
        
        colorama.init()
    
    def _initialize_detectors(self) -> List:
        """Initialize all vulnerability detectors"""
        detector_config = self.config.get('detectors', {})
        
        detectors = []
        
        # Add SQL injection detector
        if detector_config.get('sql_injection', {}).get('enabled', True):
            sql_config = detector_config.get('sql_injection', {})
            detectors.append(SQLDetector(self.session, sql_config))
        
        # Add other detectors as you create them
        # detectors.append(XSSDetector(self.session, detector_config.get('xss', {})))
        # detectors.append(HeaderDetector(self.session, detector_config.get('headers', {})))
        
        return detectors
    
    def scan(self) -> VulnerabilityReport:
        """Execute complete security scan"""
        print(f"\n{colorama.Fore.BLUE}Starting enhanced security scan of {self.target_url}{colorama.Style.RESET_ALL}\n")
        
        # Phase 1: Crawling
        print(f"{colorama.Fore.YELLOW}Phase 1: Crawling and discovery{colorama.Style.RESET_ALL}")
        pages_found = 0
        
        for page_data in self.crawler.crawl(self.target_url):
            pages_found += 1
            print(f"  Discovered: {page_data['url']}")
            
            # Phase 2: Vulnerability Detection
            self._scan_page(page_data)
        
        print(f"\n{colorama.Fore.YELLOW}Phase 2: Vulnerability detection complete{colorama.Style.RESET_ALL}")
        print(f"  Pages scanned: {pages_found}")
        print(f"  Vulnerabilities found: {len(self.scan_results.vulnerabilities)}")
        
        # Phase 3: Reporting
        print(f"\n{colorama.Fore.GREEN}Scan Complete!{colorama.Style.RESET_ALL}")
        self.reporter.print_summary(self.scan_results)
        
        return self.scan_results
    
    def _scan_page(self, page_data: Dict) -> None:
        """Scan a single page with all detectors"""
        url = page_data['url']
        
        for detector in self.detectors:
            try:
                vulnerabilities = detector.detect(page_data)
                
                for vuln in vulnerabilities:
                    # Add page context to vulnerability
                    vuln['page_data'] = {
                        'forms_count': len(page_data.get('forms', [])),
                        'url_params_count': len(page_data.get('url_parameters', {})),
                        'depth': page_data.get('depth', 0)
                    }
                    
                    self.scan_results.add_vulnerability(vuln)
                    
                    # Real-time reporting
                    self.reporter.print_vulnerability(vuln)
                    
            except Exception as e:
                print(f"  {colorama.Fore.RED}Error with {detector.name} on {url}: {e}{colorama.Style.RESET_ALL}")
    
    def export_results(self, format_type: str = 'json', filename: str = None) -> str:
        """Export scan results in specified format"""
        if format_type == 'json':
            from ..reporting.json_reporter import JSONReporter
            reporter = JSONReporter()
            return reporter.export(self.scan_results, filename)
        
        elif format_type == 'html':
            from ..reporting.html_reporter import HTMLReporter
            reporter = HTMLReporter()
            return reporter.export(self.scan_results, filename)
        
        else:
            raise ValueError(f"Unsupported export format: {format_type}")