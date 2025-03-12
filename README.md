# WAFspector
Test your Web Application Firewall (WAF) against common web-based attacks to confirm its effectiveness and reliability.

**WAFspector** is an open-source, comprehensive Python-based tool designed to assess Web Application Firewalls (WAFs) against common vulnerabilities (OWASP Top 10 and more). It automatically detects major input fields on a target webpage and tests each field with multiple payloads. The tool generates both detailed and executive reports in HTML and PDF formats, and it displays real-time progress in the CLI.

## Features

- **Automatic Input Detection:** Scans the target URL for forms and input fields (e.g., text, search, textarea) and uses the appropriate HTTP method (GET/POST).
- **Comprehensive Testing:** Uses a set of vulnerability test cases (loaded from a JSON file) with multiple payload variations.
- **Real-time CLI Progress:** Shows each request being tested (URL, parameter, payload).
- **Reporting:** Generates detailed reports (including per-payload results) and an executive report (with charts and summaries).
- **PDF Generation:** Uses WeasyPrint to convert HTML reports to PDF.
- **Docker Support:** Comes with a Dockerfile for containerized execution.

## Installation

### Using a Virtual Environment

1. **Clone the repository:**

   ```bash
   git clone https://github.com/AliAbdollahiii/waf-tester.git
   cd waf-tester
   
2. **Create and activate a virtual environment:**

   ```bash
   python3 -m venv waf-env
   source waf-env/bin/activate
   
3. **Install Python dependencies:**

   ```bash
   pip install -r requirements.txt
   
3. **Run WAFspector:**

   ```bash
   python src/waf_tester.py --url http://example.com/test --comprehensive --executive --report both --output waf_report

### Using a Virtual Environment

1. **Build the Docker image:**

   ```bash
   cd docker
   docker build -t wafspector .

2. **Run the Docker container (replace <target_url> with your target URL):**

   ```bash
   docker run --rm -it wafspector --url <target_url> --comprehensive --executive --report both --output waf_report
   

## Command-line Options

- `--url`: Target URL to test.
- `--param`: (Optional) Override auto-detected input field name.
- `--method`: Default HTTP method if no input is detected (default: GET).
- `--comprehensive`: Enable comprehensive mode (extended payload variations).
- `--executive`: Generate an executive (aggregated) report.
- `--report`: Report format (`html`, `pdf`, or `both`).
- `--output`: Base filename for reports.
- `--concurrency`: Number of concurrent threads (default: 10).
