import colorama
from typing import Dict, Any
from .vulnerability_report import VulnerabilityReport
import threading

class ConsoleReporter:
    """Thread-safe console output reporter"""
    
    def __init__(self):
        self.severity_colors = {
            'critical': colorama.Fore.MAGENTA,
            'high': colorama.Fore.RED,
            'medium': colorama.Fore.YELLOW,
            'low': colorama.Fore.CYAN,
            'info': colorama.Fore.BLUE
        }
        self.print_lock = threading.Lock()  # Add thread lock
    
    def print_vulnerability(self, vulnerability: Dict[str, Any]) -> None:
        """Thread-safe vulnerability printing"""
        with self.print_lock:  # Ensure only one thread prints at a time
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
            
            if vulnerability.get('header_name'):
                print(f"  Missing Header: {vulnerability['header_name']}")
            
            if vulnerability.get('payload'):
                payload = vulnerability['payload']
                if len(payload) > 50:
                    payload = payload[:50] + "..."
                print(f"  Payload: {payload}")
            
            if vulnerability.get('evidence'):
                print(f"  Evidence: {', '.join(vulnerability['evidence'][:2])}")