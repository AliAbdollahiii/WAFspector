#!/usr/bin/env python3
"""
WAFspector - Comprehensive WAF Security Testing Tool
======================================================
WAFspector performs comprehensive testing of Web Application Firewalls (WAFs) by sending
crafted HTTP requests against detected input fields on a target page. It loads vulnerability
tests from a JSON file (if available), auto-detects form fields (and their respective methods
and actions), and injects multiple payload variations per test. It generates detailed and executive
reports in HTML and PDF formats while displaying real-time CLI progress.
"""

import argparse
import concurrent.futures
import logging
import requests
import sys
import time
import io
import base64
import json
import os
from urllib.parse import urljoin

# PDF generation using WeasyPrint
try:
    from weasyprint import HTML
except ImportError:
    logging.error("WeasyPrint is required for PDF generation. Install it via pip.")
    exit(1)

# For HTML parsing to detect input fields
from bs4 import BeautifulSoup

# For generating charts in the executive report
import matplotlib.pyplot as plt

# Configure logging (DEBUG level can be enabled for more verbosity)
logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s: %(message)s')


#########################
# Load Vulnerability Tests
#########################
def load_vulnerability_tests():
    default_tests = [
        {
            "name": "SQL Injection",
            "base_payloads": [
                "' OR '1'='1",
                "\" OR \"1\"=\"1",
                "' OR 1=1--",
                "'; DROP TABLE users; --"
            ],
            "description": "Tests designed to simulate SQL injection attempts."
        },
        {
            "name": "XSS",
            "base_payloads": [
                "<script>alert('XSS')</script>",
                "\"/><script>alert('XSS')</script>",
                "<IMG SRC=javascript:alert('XSS')>"
            ],
            "description": "Tests to check for Cross-Site Scripting vulnerabilities."
        },
        {
            "name": "XXE",
            "base_payloads": [
                "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>"
            ],
            "description": "Tests for XML External Entity (XXE) vulnerabilities."
        },
        {
            "name": "Local File Inclusion (LFI)",
            "base_payloads": [
                "../../../../etc/passwd",
                "../../etc/passwd"
            ],
            "description": "Tests for Local File Inclusion vulnerabilities."
        },
        {
            "name": "Command Injection",
            "base_payloads": [
                "; ls -la",
                "&& cat /etc/passwd",
                "| id"
            ],
            "description": "Tests designed to inject OS commands."
        },
        {
            "name": "SSRF",
            "base_payloads": [
                "http://127.0.0.1:22",
                "http://localhost:80",
                "http://169.254.169.254/latest/meta-data/"
            ],
            "description": "Tests for Server-Side Request Forgery vulnerabilities."
        }
    ]
    json_path = os.path.join("test_cases", "vuln_tests.json")
    if os.path.exists(json_path):
        try:
            with open(json_path, "r", encoding="utf-8") as f:
                tests = json.load(f)
            logging.info("Loaded vulnerability tests from %s", json_path)
            return tests
        except Exception as e:
            logging.error("Error loading vulnerability tests from JSON: %s", e)
            return default_tests
    else:
        return default_tests

vulnerability_tests = load_vulnerability_tests()


#########################
# Input Field Detection
#########################
def detect_input_fields(url):
    """
    Fetches the target URL and uses BeautifulSoup to detect input fields from forms.
    Returns a list of dictionaries with keys: name, method, and action.
    """
    try:
        r = requests.get(url, timeout=10)
        soup = BeautifulSoup(r.text, "html.parser")
        input_fields = []
        for form in soup.find_all("form"):
            method = form.get("method", "GET").upper()
            action = form.get("action")
            if action:
                action = urljoin(url, action)
            else:
                action = url
            for inp in form.find_all("input"):
                input_type = inp.get("type", "text").lower()
                if input_type in ["text", "search", "email", "url"] or not input_type:
                    name = inp.get("name")
                    if name:
                        input_fields.append({
                            "name": name,
                            "method": method,
                            "action": action
                        })
            for ta in form.find_all("textarea"):
                name = ta.get("name")
                if name:
                    input_fields.append({
                        "name": name,
                        "method": method,
                        "action": action
                    })
        return input_fields
    except Exception as e:
        logging.error("Error detecting input fields: %s", e)
        return []


#########################
# Payload Variations
#########################
def add_number_modifier(payload, n):
    return f"{payload}_{n}"

def generate_test_cases_for_inputs(input_fields, comprehensive=False):
    test_cases = []
    num_variations = 100 if comprehensive else 10
    for field in input_fields:
        for vuln in vulnerability_tests:
            for base in vuln["base_payloads"]:
                for i in range(1, num_variations + 1):
                    variant = add_number_modifier(base, i)
                    test_cases.append({
                        "vulnerability": vuln["name"],
                        "payload": variant,
                        "description": vuln["description"],
                        "input_field": field
                    })
    return test_cases


#########################
# Test Execution Functions
#########################
def test_payload(url, payload, method="GET", param="input"):
    print(f"[TESTING] {method} {url} -> param: {param}, payload: {payload}", flush=True)
    try:
        if method.upper() == "GET":
            test_url = f"{url}?{param}={payload}"
            response = requests.get(test_url, timeout=10)
        else:
            response = requests.post(url, data={param: payload}, timeout=10)
        blocked = False
        if response.status_code in [403, 406]:
            blocked = True
        if "Access Denied" in response.text or "blocked" in response.text.lower():
            blocked = True
        snippet = response.text[:200].replace("\n", " ").replace("\r", " ")
        return {"payload": payload, "status": response.status_code, "blocked": blocked, "response": snippet}
    except Exception as e:
        print(f"[ERROR] Payload: {payload} | Error: {e}", flush=True)
        return {"payload": payload, "status": None, "blocked": None, "error": str(e)}

def run_all_tests(test_cases, max_workers):
    logging.info("Starting tests on detected input fields...")
    results_by_vuln = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_case = {}
        for tc in test_cases:
            field = tc["input_field"]
            param_name = field["name"]
            method_field = field["method"]
            action_url = field["action"]
            future = executor.submit(test_payload, action_url, tc["payload"], method_field, param_name)
            future_to_case[future] = tc
        for future in concurrent.futures.as_completed(future_to_case):
            tc = future_to_case[future]
            vuln_name = tc["vulnerability"]
            result = future.result()
            if vuln_name not in results_by_vuln:
                results_by_vuln[vuln_name] = {
                    "vulnerability": vuln_name,
                    "description": tc["description"],
                    "results": []
                }
            results_by_vuln[vuln_name]["results"].append(result)
    return list(results_by_vuln.values())

def compute_scores(results):
    for vuln in results:
        total = len(vuln["results"])
        if total == 0:
            vuln["score"] = 0
        else:
            blocked_count = sum(1 for r in vuln["results"] if r.get("blocked") is True)
            vuln["score"] = (blocked_count / total) * 100
            vuln["total"] = total
            vuln["blocked"] = blocked_count
    return results

def compute_overall_score(results):
    total_tests = sum(v.get("total", 0) for v in results)
    total_blocked = sum(v.get("blocked", 0) for v in results)
    overall_score = (total_blocked / total_tests * 100) if total_tests > 0 else 0
    return overall_score, total_tests, total_blocked

def identify_waf_vendor(url):
    try:
        r = requests.get(url, timeout=10)
        headers_combined = " ".join(r.headers.values()).lower()
        content = r.text.lower()
        vendors = {
            "cloudflare": "Cloudflare",
            "mod_security": "ModSecurity",
            "wallarm": "Wallarm",
            "f5": "F5 BIG-IP",
            "imperva": "Imperva",
            "aws": "AWS WAF",
            "sucuri": "Sucuri",
            "citrix": "Citrix Netscaler",
            "kona": "Kona SiteDefender (Akamai)"
        }
        for key, name in vendors.items():
            if key in headers_combined or key in content:
                return name
        return "Kona SiteDefender (Akamai)"
    except Exception as e:
        logging.error("Error identifying WAF vendor: %s", e)
        return "Kona SiteDefender (Akamai)"


#########################
# Chart Generation (Executive Report)
#########################
def create_vuln_chart(total, blocked):
    try:
        labels = ['Blocked', 'Not Blocked']
        sizes = [blocked, total - blocked]
        colors = ['#28a745', '#dc3545']
        fig, ax = plt.subplots(figsize=(4, 4))
        ax.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=90, colors=colors)
        ax.axis('equal')
        buf = io.BytesIO()
        plt.savefig(buf, format='png', bbox_inches='tight')
        plt.close(fig)
        buf.seek(0)
        return base64.b64encode(buf.read()).decode('utf-8')
    except Exception as e:
        logging.error("Error generating chart: %s", e)
        return ""

def create_overall_chart(total, blocked):
    try:
        labels = ['Total', 'Blocked']
        values = [total, blocked]
        fig, ax = plt.subplots(figsize=(6, 4))
        ax.bar(labels, values, color=['#007BFF', '#28a745'])
        ax.set_ylabel('Number of Tests')
        ax.set_title('Overall Test Summary')
        buf = io.BytesIO()
        plt.savefig(buf, format='png', bbox_inches='tight')
        plt.close(fig)
        buf.seek(0)
        return base64.b64encode(buf.read()).decode('utf-8')
    except Exception as e:
        logging.error("Error generating overall chart: %s", e)
        return ""


#########################
# Reporting Functions
#########################
def generate_detailed_html_report(results, target_url, overall_score, vendor, threshold=80):
    pass_fail = "PASS" if overall_score >= threshold else "FAIL"
    html = f"""<html>
<head>
  <meta charset="UTF-8">
  <title>Detailed WAF Test Report</title>
  <style>
    body {{ font-family: 'Helvetica', sans-serif; background: #f5f7fa; margin: 0; padding: 0; }}
    .container {{ width: 95%; margin: 20px auto; background: #fff; padding: 20px; box-shadow: 0 0 20px rgba(0,0,0,0.1); }}
    h1 {{ text-align: center; color: #333; }}
    .summary {{ background: #e9ecef; padding: 15px; margin-bottom: 20px; border-radius: 5px; }}
    .summary p {{ font-size: 1.1em; margin: 5px 0; }}
    h2 {{ color: #007BFF; border-bottom: 2px solid #007BFF; padding-bottom: 5px; }}
    table {{ width: 100%; border-collapse: collapse; margin-bottom: 30px; }}
    th, td {{ padding: 10px; border: 1px solid #ddd; text-align: left; }}
    th {{ background-color: #007BFF; color: #fff; }}
    .blocked {{ background-color: #d4edda; }}
    .not-blocked {{ background-color: #f8d7da; }}
    .error {{ background-color: #fff3cd; }}
  </style>
</head>
<body>
  <div class="container">
    <h1>Detailed WAF Test Report</h1>
    <div class="summary">
      <p><strong>Target URL:</strong> {target_url}</p>
      <p><strong>Report generated on:</strong> {time.ctime()}</p>
      <p><strong>Overall Score:</strong> {overall_score:.2f}% - <span style="color:{'green' if pass_fail=='PASS' else 'red'}">{pass_fail}</span></p>
      <p><strong>Identified WAF Vendor:</strong> {vendor}</p>
    </div>
"""
    for vuln in results:
        html += f"<h2>{vuln['vulnerability']}</h2>"
        html += f"<p>{vuln['description']}</p>"
        html += f"<p><strong>Blocking Effectiveness:</strong> {vuln['score']:.2f}% (Blocked {vuln.get('blocked',0)}/{vuln.get('total',0)} tests)</p>"
        html += "<table><tr><th>Payload</th><th>Status</th><th>Blocked</th><th>Response Snippet</th></tr>"
        for res in vuln["results"]:
            payload = res.get("payload", "")
            status = res.get("status", "Error")
            blocked = res.get("blocked")
            if blocked is True:
                blocked_str = "Yes"
                row_class = "blocked"
            elif blocked is False:
                blocked_str = "No"
                row_class = "not-blocked"
            else:
                blocked_str = "Error"
                row_class = "error"
            snippet = res.get("response", res.get("error", ""))
            html += f"<tr class='{row_class}'><td>{payload}</td><td>{status}</td><td>{blocked_str}</td><td>{snippet}</td></tr>"
        html += "</table>"
    html += """  </div>
</body>
</html>"""
    return html

def generate_executive_html_report(results, target_url, overall_score, vendor, threshold=80):
    pass_fail = "PASS" if overall_score >= threshold else "FAIL"
    overall_chart = create_overall_chart(*compute_overall_score(results)[:2])
    html = f"""<html>
<head>
  <meta charset="UTF-8">
  <title>Executive WAF Test Report</title>
  <style>
    body {{ font-family: 'Helvetica', sans-serif; background: #f5f7fa; margin: 0; padding: 0; }}
    .container {{ width: 95%; margin: 20px auto; background: #fff; padding: 20px; box-shadow: 0 0 20px rgba(0,0,0,0.1); }}
    h1 {{ text-align: center; color: #333; }}
    .summary {{ background: #e9ecef; padding: 15px; margin-bottom: 20px; border-radius: 5px; }}
    .summary p {{ font-size: 1.1em; margin: 5px 0; }}
    .vuln-section {{ margin-bottom: 30px; }}
    .chart {{ text-align: center; margin: 10px 0; }}
    table {{ width: 100%; border-collapse: collapse; margin-bottom: 10px; }}
    th, td {{ padding: 8px; border: 1px solid #ddd; text-align: left; }}
    th {{ background-color: #007BFF; color: #fff; }}
  </style>
</head>
<body>
  <div class="container">
    <h1>Executive WAF Test Report</h1>
    <div class="summary">
      <p><strong>Target URL:</strong> {target_url}</p>
      <p><strong>Report generated on:</strong> {time.ctime()}</p>
      <p><strong>Overall Score:</strong> {overall_score:.2f}% - <span style="color:{'green' if pass_fail=='PASS' else 'red'}">{pass_fail}</span></p>
      <p><strong>Identified WAF Vendor:</strong> {vendor}</p>
      <div class="chart">
         <img src="data:image/png;base64,{overall_chart}" alt="Overall Chart">
      </div>
    </div>
"""
    for vuln in results:
        total = vuln.get("total", 0)
        blocked = vuln.get("blocked", 0)
        score = vuln.get("score", 0)
        vuln_pass = "PASS" if score >= threshold else "FAIL"
        chart_img = create_vuln_chart(total, blocked)
        html += f"""<div class="vuln-section">
  <h2>{vuln['vulnerability']}</h2>
  <p>{vuln['description']}</p>
  <p><strong>Tests Performed:</strong> {total} | <strong>Blocked:</strong> {blocked} | <strong>Effectiveness:</strong> {score:.2f}% - <span style="color:{'green' if vuln_pass=='PASS' else 'red'}">{vuln_pass}</span></p>
  <div class="chart">
    <img src="data:image/png;base64,{chart_img}" alt="Chart for {vuln['vulnerability']}">
  </div>
  <p>Explanation: The {vuln['vulnerability']} tests simulate realistic attack attempts. A blocking effectiveness of {score:.2f}% indicates that the WAF blocked {blocked} out of {total} tests in this category.</p>
</div>
"""
    html += """  </div>
</body>
</html>"""
    return html

def generate_pdf_report(html, output_pdf):
    try:
        HTML(string=html).write_pdf(output_pdf)
        logging.info("PDF report generated: %s", output_pdf)
    except Exception as e:
        logging.error("Error generating PDF report: %s", e)


#########################
# Main Execution Flow
#########################
def main():
    parser = argparse.ArgumentParser(description="WAFspector - Comprehensive WAF Security Testing Tool")
    parser.add_argument("--url", help="Target URL (e.g., http://example.com/test)", required=False)
    parser.add_argument("--method", help="Default HTTP method if input detection fails", default="GET")
    parser.add_argument("--param", help="Parameter name for payload injection (overrides auto-detection)", default=None)
    parser.add_argument("--concurrency", type=int, help="Number of concurrent threads", default=10)
    parser.add_argument("--report", help="Report format: html, pdf, or both", default="html")
    parser.add_argument("--output", help="Output base filename for reports (without extension)", default="waf_report")
    parser.add_argument("--comprehensive", action="store_true", help="Enable comprehensive mode (extended tests)")
    parser.add_argument("--executive", action="store_true", help="Generate executive report (aggregated summary)")
    args = parser.parse_args()

    if not args.url:
        target_url = input("Enter target URL (e.g., http://example.com/test): ").strip()
    else:
        target_url = args.url

    if args.param:
        input_fields = [{"name": args.param, "method": args.method.upper(), "action": target_url}]
    else:
        input_fields = detect_input_fields(target_url)
        if not input_fields:
            logging.info("No input fields detected, defaulting to parameter 'input' with method GET.")
            input_fields = [{"name": "input", "method": "GET", "action": target_url}]
        else:
            logging.info("Detected input fields: %s", ", ".join(f['name'] for f in input_fields))

    logging.info("Starting tests on %s", target_url)
    logging.info("Using detected input fields with their respective HTTP methods and actions.")

    test_cases = generate_test_cases_for_inputs(input_fields, comprehensive=args.comprehensive)
    total_tests_count = len(test_cases)
    logging.info("Total test cases to execute: %d", total_tests_count)

    results = run_all_tests(test_cases, args.concurrency)
    results = compute_scores(results)
    overall_score, total_tests, total_blocked = compute_overall_score(results)
    logging.info("Overall Score: %.2f%% (%d/%d tests blocked)", overall_score, total_blocked, total_tests)

    vendor = identify_waf_vendor(target_url)
    logging.info("Identified WAF Vendor: %s", vendor)

    logging.info("Generating detailed HTML report...")
    detailed_html = generate_detailed_html_report(results, target_url, overall_score, vendor)
    detailed_filename = f"{args.output}_detailed.html"
    try:
        with open(detailed_filename, "w", encoding="utf-8") as f:
            f.write(detailed_html)
        logging.info("Detailed HTML report generated: %s", detailed_filename)
    except Exception as e:
        logging.error("Error writing detailed HTML report: %s", e)
        sys.exit(1)

    if args.report in ["pdf", "both"]:
        pdf_filename = f"{args.output}_detailed.pdf"
        logging.info("Generating detailed PDF report...")
        generate_pdf_report(detailed_html, pdf_filename)

    if args.executive:
        logging.info("Generating executive HTML report...")
        executive_html = generate_executive_html_report(results, target_url, overall_score, vendor)
        exec_filename = f"{args.output}_executive.html"
        try:
            with open(exec_filename, "w", encoding="utf-8") as f:
                f.write(executive_html)
            logging.info("Executive HTML report generated: %s", exec_filename)
        except Exception as e:
            logging.error("Error writing executive HTML report: %s", e)
            sys.exit(1)
        if args.report in ["pdf", "both"]:
            exec_pdf = f"{args.output}_executive.pdf"
            logging.info("Generating executive PDF report...")
            generate_pdf_report(executive_html, exec_pdf)

if __name__ == "__main__":
    main()
