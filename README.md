
# Web Security Scanner

A modular Python tool to scan websites for vulnerabilities including SQL Injection, XSS, security headers, authentication issues, and exposed sensitive information.


## Features

- Modular architecture for easy extension
- Configurable crawling depth and delay
- SQL Injection detection (error, union, time-based)
- Cross-Site Scripting (XSS) detection
- Sensitive information exposure detection (emails, credit cards, SSNs, API keys)
- Security headers and authentication issues detection
- HTML, JSON, and console reporting
- Colorful output for easy identification


## Installation

1. Clone the repository:
    ```bash
    git clone https://github.com/Y4NN777/Web-Security-Scanner.git
    cd Web-Security-Scanner
    ```
2. Install dependencies:
    ```bash
    pip install -r requirements.txt
    ```


## Usage

Run the scanner using the module entry point:

```bash
python -m webscanner <target_url> [--max-depth N] [--export-json file] [--export-html file]
```

Example:

```bash
python -m webscanner https://example.com --max-depth 2 --export-json results.json --export-html report.html
```


## Project Structure

```
webscanner/
├── __init__.py
├── __main__.py
├── scanner.py                # Main scanner class
├── core/
│   ├── __init__.py
│   ├── scanner_engine.py     # Main coordinator
│   └── config.py             # Configuration management
├── crawling/
│   ├── __init__.py
│   ├── web_crawler.py        # URL discovery & crawling
│   └── url_handler.py        # URL normalization & encoding
├── detection/
│   ├── __init__.py
│   ├── detector_base.py      # Base class for all detectors
│   ├── sql_detector.py       # Enhanced SQL injection
│   ├── xss_detector.py       # Enhanced XSS detection
│   ├── info_detector.py      # Sensitive information
│   ├── header_detector.py    # Security headers
│   └── auth_detector.py      # Authentication issues
├── analysis/
│   ├── __init__.py
│   ├── response_analyzer.py  # Response comparison & analysis
│   └── payload_generator.py  # Payload creation & encoding
└── reporting/
    ├── __init__.py
    ├── vulnerability_report.py # Vulnerability data structure
    ├── console_reporter.py     # Console output
    ├── json_reporter.py        # JSON export
    └── html_reporter.py        # HTML reports
```


## Notes

- The scanner uses multi-threading for faster checks.
- Output is colorized for better readability.
- For best results, run against test or staging environments.
- Easily extend detection modules by subclassing `DetectorBase`.


## License

MIT
