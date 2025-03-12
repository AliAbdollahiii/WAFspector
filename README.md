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
   git clone https://github.com/yourusername/waf-tester.git
   cd waf-tester

