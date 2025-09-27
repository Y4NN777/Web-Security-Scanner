# JSON export for vulnerabilities
import json
from datetime import datetime
from typing import Dict, Any
from .vulnerability_report import VulnerabilityReport

class JSONReporter:
    """JSON export functionality"""
    
    def export(self, report: VulnerabilityReport, filename: str = None) -> str:
        """Export scan results to JSON"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"security_scan_{timestamp}.json"
        
        # Prepare export data
        export_data = {
            'scan_metadata': {
                'target_url': report.target_url,
                'scan_start': report.start_time.isoformat() if report.start_time else None,
                'scan_end': report.end_time.isoformat() if report.end_time else None,
                **report.scan_metadata
            },
            'summary': report.get_summary(),
            'vulnerabilities': report.vulnerabilities
        }
        
        # Write to file
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, ensure_ascii=False)
            
            print(f"Results exported to: {filename}")
            return filename
            
        except Exception as e:
            print(f"Error exporting to JSON: {e}")
            return None
