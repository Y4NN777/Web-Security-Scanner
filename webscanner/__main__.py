import sys
import colorama
from .scanner import WebSecurityScanner

def main():
    if len(sys.argv) != 2:
        print("Usage: python -m webscanner <target_url>")
        sys.exit(1)

    target_url = sys.argv[1]
    scanner = WebSecurityScanner(target_url)
    vulnerabilities = scanner.scan()

    print(f"\n{colorama.Fore.GREEN}Scan Complete!{colorama.Style.RESET_ALL}")
    print(f"Total URLs scanned: {len(scanner.visited_urls)}")
    print(f"Vulnerabilities found: {len(vulnerabilities)}")

if __name__ == "__main__":
    main()
