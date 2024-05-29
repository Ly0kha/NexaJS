import requests
from bs4 import BeautifulSoup
import re
import argparse
import os
from urllib.parse import urljoin
import json
import threading
import logging
from collections import defaultdict
import js2py
import time
import matplotlib.pyplot as plt

# Initialize logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define regex patterns for sensitive information, API endpoints, and suspicious keywords
patterns = {
    "API_KEY": re.compile(r"['\"](AIza[0-9A-Za-z-_]{35})['\"]"),
    "JWT": re.compile(r"eyJ[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+"),
    "URL": re.compile(r"https?://[^\s'\"<>]+"),
    "API_ENDPOINT": re.compile(r"https?://[^\s'\"<>]+(?:/api|/apigw|/v1|/v2|/v3|/graphql|/details|/miscellaneous)[^\s'\"<>]*"),
    "EMAIL": re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
    "PASSWORD": re.compile(r"['\"]password['\"]\s*:\s*['\"][^'\"]+['\"]"),
    "SUSPICIOUS_KEYWORD": re.compile(r"\b(eval|document\.write|innerHTML)\b"),
    "SUSPICIOUS_EXTENSION": re.compile(r"\.(exe|bat|cmd|sh|ps1)")
}

libraries = {
    "jQuery": re.compile(r"jQuery\s*\(\s*['\"]"),
    "React": re.compile(r"React\.createElement"),
    "AngularJS": re.compile(r"angular\.module"),
    "Vue.js": re.compile(r"new Vue\(")
}

vulnerable_libraries = {
    "jQuery": ["1.12.4", "2.2.4"],
    "AngularJS": ["1.6.5"],
    "React": ["16.0.0"],
    "Vue.js": ["2.5.13"]
}

deprecated_apis = [
    "document.write", "alert", "confirm", "prompt"
]

# Helper function to detect obfuscated code
def is_obfuscated(js_content):
    return bool(re.search(r'(\\x[\da-fA-F]{2}|\\u[\da-fA-F]{4})', js_content))

# Helper function to analyze CSP headers
def analyze_csp(headers):
    csp = headers.get('Content-Security-Policy', '')
    return csp

# Helper function to measure code complexity
def measure_complexity(js_content):
    lines = js_content.split('\n')
    return len(lines), sum(1 for line in lines if line.strip().startswith(('if', 'for', 'while', 'function', 'class')))

# Enhanced threat intelligence function (mock implementation)
def enhanced_threat_intelligence(url):
    # Mock threat intelligence check (replace with actual API call)
    threat_intelligence_list = ["malicious.com", "phishing-site.com"]
    return any(threat in url for threat in threat_intelligence_list)

def generate_logo(name):
    logo = f"""

  _  _                        _      
 | \| |  ___  __ __  __ _    (_)  ___
 | .` | / -_) \ \ / / _` |   | | (_-<
 |_|\_| \___| /_\_\ \__,_|  _/ | /__/
                           |__/      
    {name}
    """
    return logo

def fetch_html(url, timeout, retries):
    for _ in range(retries):
        try:
            response = requests.get(url, timeout=timeout)
            response.raise_for_status()
            return response.text, response.headers
        except requests.RequestException as e:
            logging.warning(f"Failed to fetch {url}: {e}")
    raise requests.RequestException(f"Failed to fetch {url} after {retries} retries")

def extract_js_files(html_content, base_url):
    soup = BeautifulSoup(html_content, 'html.parser')
    scripts = soup.find_all('script')
    js_files = []
    inline_scripts = []
    for script in scripts:
        if script.attrs.get('src'):
            src = urljoin(base_url, script.attrs.get('src'))
            js_files.append(src)
        else:
            inline_js = script.string
            if inline_js:
                inline_scripts.append(inline_js)
                js_files.append(inline_js)
    return js_files, inline_scripts

def fetch_js_content(js_file, js_content, timeout, retries):
    if js_file.startswith('http'):
        for _ in range(retries):
            try:
                response = requests.get(js_file, timeout=timeout)
                response.raise_for_status()
                js_content.append({"source": js_file, "content": response.text})
                return
            except requests.RequestException as e:
                logging.warning(f"Failed to fetch {js_file}: {e}")
    else:
        js_content.append({"source": "inline", "content": js_file})

def analyze_js_content(js_content):
    findings = []
    load_order = []
    for js in js_content:
        load_order.append(js['source'])
        # Static analysis
        for name, pattern in patterns.items():
            matches = pattern.findall(js['content'])
            for match in matches:
                findings.append({
                    "type": name,
                    "value": match,
                    "source": js['source']
                })
        # Library detection
        for lib_name, lib_pattern in libraries.items():
            if lib_pattern.search(js['content']):
                version_match = re.search(r'\d+\.\d+\.\d+', js['content'])
                version = version_match.group() if version_match else "unknown"
                findings.append({
                    "type": "LIBRARY",
                    "value": f"{lib_name} {version}",
                    "source": js['source'],
                    "vulnerable": version in vulnerable_libraries.get(lib_name, [])
                })
        # Obfuscated code detection
        if is_obfuscated(js['content']):
            findings.append({
                "type": "OBFUSCATED_CODE",
                "value": "Detected obfuscated code",
                "source": js['source']
            })
        # Code complexity
        lines, complexity = measure_complexity(js['content'])
        findings.append({
            "type": "CODE_COMPLEXITY",
            "value": f"Lines: {lines}, Complexity: {complexity}",
            "source": js['source']
        })
        # External API call analysis
        external_apis = re.findall(r'fetch\((["\'])(https?://[^\1]+)\1', js['content'])
        for api in external_apis:
            findings.append({
                "type": "EXTERNAL_API",
                "value": api[1],
                "source": js['source']
            })
        # Automated testing framework detection
        if re.search(r'(describe|it|expect)\s*\(', js['content']):
            findings.append({
                "type": "TESTING_FRAMEWORK",
                "value": "Detected testing framework usage",
                "source": js['source']
            })
        # Check for minification
        if len(js['content']) > 0 and float(len(js['content'].split('\n'))) / len(js['content']) < 0.01:
            findings.append({
                "type": "MINIFIED",
                "value": "Detected minified code",
                "source": js['source']
            })
        # Check for large files
        if len(js['content']) > 500000:  # threshold in bytes
            findings.append({
                "type": "LARGE_FILE",
                "value": f"File size: {len(js['content'])} bytes",
                "source": js['source']
            })
        # Deprecated API detection
        for api in deprecated_apis:
            if api in js['content']:
                findings.append({
                    "type": "DEPRECATED_API",
                    "value": f"Detected deprecated API usage: {api}",
                    "source": js['source']
                })
        # Environment-specific code detection
        if 'process.env' in js['content'] or 'require(' in js['content']:
            findings.append({
                "type": "ENVIRONMENT_SPECIFIC_CODE",
                "value": "Detected Node.js specific code",
                "source": js['source']
            })
        # Comment and documentation analysis
        comments = re.findall(r'(/\*.*?\*/|//.*?$)', js['content'], re.DOTALL | re.MULTILINE)
        if len(comments) / len(js['content'].split('\n')) < 0.05:  # less than 5% of lines are comments
            findings.append({
                "type": "COMMENT_ANALYSIS",
                "value": "Low comment-to-code ratio",
                "source": js['source']
            })
        # Code duplication detection
        lines = js['content'].split('\n')
        duplicate_lines = set([line for line in lines if lines.count(line) > 1 and len(line.strip()) > 0])
        if duplicate_lines:
            findings.append({
                "type": "CODE_DUPLICATION",
                "value": f"Detected duplicate lines of code: {len(duplicate_lines)} instances",
                "source": js['source']
            })
        # Real-time threat intelligence integration
        for url in re.findall(r"https?://[^\s'\"<>]+", js['content']):
            if enhanced_threat_intelligence(url):
                findings.append({
                    "type": "THREAT_INTELLIGENCE",
                    "value": f"Detected potential threat URL: {url}",
                    "source": js['source']
                })
        # User tracking script detection
        if re.search(r'(ga\(|_gaq\.push|gtag\()|google-analytics\.com', js['content']):
            findings.append({
                "type": "USER_TRACKING",
                "value": "Detected user tracking script",
                "source": js['source']
            })
        # Ad blocker detection script detection
        if re.search(r'adblock|adsbygoogle', js['content']):
            findings.append({
                "type": "ADBLOCKER_DETECTION",
                "value": "Detected ad blocker detection script",
                "source": js['source']
            })
        # Social media integration script detection
        if re.search(r'facebook\.com|twitter\.com|linkedin\.com', js['content']):
            findings.append({
                "type": "SOCIAL_MEDIA_INTEGRATION",
                "value": "Detected social media integration script",
                "source": js['source']
            })
        # GDPR/Privacy compliance check
        if re.search(r'cookie|consent|gdpr', js['content']):
            findings.append({
                "type": "GDPR_COMPLIANCE",
                "value": "Detected GDPR/privacy-related script",
                "source": js['source']
            })
        # Script execution time analysis
        start_time = time.time()
        try:
            js2py.eval_js(js['content'])
        except:
            pass
        execution_time = time.time() - start_time
        findings.append({
            "type": "EXECUTION_TIME",
            "value": f"Execution time: {execution_time:.2f} seconds",
            "source": js['source']
        })
    return findings, load_order

def generate_report(findings, load_order, output_file, output_format):
    unique_findings = {(f['type'], f['value'], f['source'], f.get('vulnerable', False)) for f in findings}
    report = {
        "findings": [],
        "load_order": load_order
    }
    for finding in unique_findings:
        report["findings"].append({
            "Type": finding[0],
            "Value": finding[1],
            "Source": finding[2],
            "Vulnerable": finding[3]
        })

    if output_format == "json":
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=4)
    elif output_format == "html":
        with open(output_file, 'w') as f:
            f.write("<html><head><title>JavaScript Analysis Report</title></head><body>")
            f.write("<h1>JavaScript Analysis Report</h1>")
            f.write("<h2>Findings</h2>")
            for finding in report["findings"]:
                f.write(f"<p><strong>Type:</strong> {finding['Type']}</p>")
                f.write(f"<p><strong>Value:</strong> {finding['Value']}</p>")
                f.write(f"<p><strong>Source:</strong> {finding['Source']}</p>")
                if finding['Vulnerable']:
                    f.write(f"<p><strong>Vulnerable:</strong> {finding['Vulnerable']}</p>")
                f.write("<hr>")
            f.write("<h2>Load Order</h2>")
            for script in load_order:
                f.write(f"<p>{script}</p>")
            f.write("</body></html>")
    else:
        with open(output_file, 'w') as f:
            for finding in report["findings"]:
                f.write(f"Type: {finding['Type']}\n")
                f.write(f"Value: {finding['Value']}\n")
                f.write(f"Source: {finding['Source']}\n")
                if finding['Vulnerable']:
                    f.write(f"Vulnerable: {finding['Vulnerable']}\n")
                f.write("\n" + "="*40 + "\n\n")
            f.write("\nLoad Order:\n")
            for script in load_order:
                f.write(f"{script}\n")

def main(url, output_file, output_format, timeout, retries, exclude_patterns, verbose, log_level):
    logging.basicConfig(level=log_level.upper(), format='%(asctime)s - %(levelname)s - %(message)s')
    
    logo = generate_logo("By @Ly0kha")
    print(logo)

    logging.info(f"Fetching HTML content from {url}...")
    html_content, headers = fetch_html(url, timeout, retries)
    logging.info("Analyzing Content Security Policy...")
    csp = analyze_csp(headers)
    logging.debug(f"CSP: {csp}")

    logging.info("Extracting JavaScript files...")
    js_files, inline_scripts = extract_js_files(html_content, url)
    logging.info("Filtering out excluded patterns...")
    js_files = [js for js in js_files if not any(re.search(pat, js) for pat in exclude_patterns)]
    
    logging.info("Fetching JavaScript content...")
    js_content = []
    threads = []
    for js_file in js_files:
        thread = threading.Thread(target=fetch_js_content, args=(js_file, js_content, timeout, retries))
        threads.append(thread)
        thread.start()
    
    for thread in threads:
        thread.join()

    logging.info("Analyzing JavaScript content...")
    findings, load_order = analyze_js_content(js_content)
    logging.info(f"Generating report to {output_file}...")
    generate_report(findings, load_order, output_file, output_format)
    logging.info("Done.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Scrape and analyze JavaScript files from a website.")
    parser.add_argument("--url", required=True, help="The URL of the website to scrape")
    parser.add_argument("--output", default="report.json", help="The output file for the report")
    parser.add_argument("--format", default="json", choices=["json", "text", "html"], help="The format of the output report")
    parser.add_argument("--timeout", type=int, default=10, help="Timeout for network requests")
    parser.add_argument("--retries", type=int, default=3, help="Number of retries for network requests")
    parser.add_argument("--exclude", nargs='*', default=[], help="Patterns to exclude from analysis")
    parser.add_argument("--verbose", action='store_true', help="Enable verbose output")
    parser.add_argument("--log-level", default="INFO", help="Set the logging level")
    args = parser.parse_args()

    main(args.url, args.output, args.format, args.timeout, args.retries, args.exclude, args.verbose, args.log_level)
