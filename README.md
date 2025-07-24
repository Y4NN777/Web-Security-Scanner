# Web Security Scanner

A simple Python tool to scan websites for common vulnerabilities such as SQL Injection, XSS, and exposed sensitive information.

## Features

- Crawls a target website up to a configurable depth
- Checks for SQL Injection vulnerabilities
- Checks for Cross-Site Scripting (XSS) vulnerabilities
- Detects exposed sensitive information (emails, phone numbers, SSNs, API keys)
- Colorful output for easy identification

## Installation

1. Clone the repository.
2. Install dependencies:

    ```bash
    pip install -r requirements.txt
    ```

## Usage

Run the scanner using the module entry point:

```bash
python -m webscanner <target_url>
```

Example:

```bash
python -m webscanner https://example.com
```

## Project Structure

- `webscanner/scanner.py`: Contains the `WebSecurityScanner` class and scanning logic.
- `webscanner/__main__.py`: Entry point for running the scanner from the command line.
- `requirements.txt`: Python dependencies.
- `README.md`: Project documentation.

## Notes

- The scanner uses multi-threading for faster checks.
- Output is colorized for better readability.
- For best results, run against test or staging environments.

## License

MIT
