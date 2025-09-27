import sys
import colorama
from .scanner import WebSecurityScanner

def main():
    if len(sys.argv) < 2:
        print("Usage: python -m webscanner <target_url> [--export-json] [--export-html]")
        print("Example: python -m webscanner https://example.com --export-json")
        sys.exit(1)

    target_url = sys.argv[1]
    
    # Parse additional arguments
    export_json = '--export-json' in sys.argv
    export_html = '--export-html' in sys.argv
    
    # Create and run scanner
    scanner = WebSecurityScanner(target_url)
    vulnerabilities = scanner.scan()
    
    # Export results if requested
    if export_json:
        json_file = scanner.export_json()
        print(f"\n{colorama.Fore.GREEN}Results exported to JSON: {json_file}{colorama.Style.RESET_ALL}")
    
    if export_html:
        html_file = scanner.export_html()
        print(f"\n{colorama.Fore.GREEN}Results exported to HTML: {html_file}{colorama.Style.RESET_ALL}")

if __name__ == "__main__":
    main()