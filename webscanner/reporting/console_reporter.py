# Console output for vulnerabilities
import colorama
from typing import Dict, Any
from .vulnerability_report import VulnerabilityReport

class ConsoleReporter:
    """Console output reporter for real-time feedback"""
    
    def __init__(self):
        self.severity_colors = {
            'critical': colorama.Fore.MAGENTA,
            'high': colorama.Fore.RED,
            'medium': colorama.Fore.YELLOW,
            'low': colorama.Fore.CYAN,
            'info': colorama.Fore.BLUE
        }
    
    def print_vulnerability(self, vulnerability: Dict[str, Any]) -> None:
        """Print individual vulnerability as it's found"""
        vuln_type = vulnerability.get('type', 'Unknown')
        severity = vulnerability.get('severity', 'medium').lower()
        confidence = float(vulnerability.get('confidence', 0))
        url = vulnerability.get('url', 'Unknown URL')
        
        color = self.severity_colors.get(severity, colorama.Fore.WHITE)
        
        print(f"\n{color}[{severity.upper()} VULNERABILITY FOUND]{colorama.Style.RESET_ALL}")
        print(f"  Type: {vuln_type}")
        print(f"  URL: {url}")
        print(f"  Confidence: {confidence:.2f}")
        
        # Print additional details
        if vulnerability.get('parameter'):
            print(f"  Parameter: {vulnerability['parameter']}")
        
        if vulnerability.get('payload'):
            payload = vulnerability['payload']
            if len(payload) > 50:
                payload = payload[:50] + "..."
            print(f"  Payload: {payload}")
        
        if vulnerability.get('evidence'):
            print(f"  Evidence: {', '.join(vulnerability['evidence'][:2])}")
    
    def print_summary(self, report: VulnerabilityReport) -> None:
        """Print final scan summary"""
        summary = report.get_summary()
        
        print(f"\n{colorama.Fore.GREEN}{'='*60}{colorama.Style.RESET_ALL}")
        print(f"{colorama.Fore.GREEN}SCAN SUMMARY{colorama.Style.RESET_ALL}")
        print(f"{colorama.Fore.GREEN}{'='*60}{colorama.Style.RESET_ALL}")
        
        # Basic stats
        print(f"\nTarget: {report.target_url}")
        print(f"Total Vulnerabilities: {summary['total_vulnerabilities']}")
        print(f"High Confidence Findings: {summary['high_confidence_count']}")
        
        # Severity breakdown
        if summary['by_severity']:
            print(f"\nSeverity Breakdown:")
            for severity, count in sorted(summary['by_severity'].items(), 
                                        key=lambda x: {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}.get(x[0], 0), 
                                        reverse=True):
                color = self.severity_colors.get(severity, colorama.Fore.WHITE)
                print(f"  {color}{severity.capitalize()}: {count}{colorama.Style.RESET_ALL}")
        
        # Vulnerability type breakdown
        if summary['by_type']:
            print(f"\nVulnerability Types:")
            for vuln_type, count in summary['by_type'].items():
                print(f"  {vuln_type}: {count}")
        
        # Scan metadata
        metadata = summary['scan_metadata']
        if metadata.get('scan_duration'):
            print(f"\nScan Duration: {metadata['scan_duration']:.2f} seconds")
        if metadata.get('pages_scanned'):
            print(f"Pages Scanned: {metadata['pages_scanned']}")
    
    def print_recommendations(self, report: VulnerabilityReport) -> None:
        """Print security recommendations based on findings"""
        critical_high = report.get_vulnerabilities_by_severity('high')
        
        if not critical_high:
            print(f"\n{colorama.Fore.GREEN}✓ No critical or high severity vulnerabilities found!{colorama.Style.RESET_ALL}")
            return
        
        print(f"\n{colorama.Fore.YELLOW}SECURITY RECOMMENDATIONS{colorama.Style.RESET_ALL}")
        print(f"{colorama.Fore.YELLOW}{'='*50}{colorama.Style.RESET_ALL}")
        
        # Group recommendations by vulnerability type
        recommendations = {
            'SQL Injection': [
                "Implement parameterized queries/prepared statements",
                "Add input validation and sanitization",
                "Use an ORM or query builder",
                "Apply principle of least privilege to database accounts"
            ],
            'Cross-Site Scripting (XSS)': [
                "Implement output encoding/escaping",
                "Use Content Security Policy (CSP) headers",
                "Validate and sanitize all user inputs",
                "Use auto-escaping template engines"
            ],
            'Missing Security Header': [
                "Configure security headers in web server/application",
                "Implement Content Security Policy",
                "Add X-Frame-Options, X-Content-Type-Options",
                "Enable HTTPS with HSTS"
            ]
        }
        
        found_types = set(vuln.get('type') for vuln in critical_high)
        
        for vuln_type in found_types:
            if vuln_type in recommendations:
                print(f"\n{colorama.Fore.CYAN}For {vuln_type}:{colorama.Style.RESET_ALL}")
                for i, rec in enumerate(recommendations[vuln_type], 1):
                    print(f"  {i}. {rec}")