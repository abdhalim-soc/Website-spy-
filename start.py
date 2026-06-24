#!/usr/bin/env python3
# =============================================================================
# Advanced Web Vulnerability & Sensitive Data Scanner (Zero-Miss)
# Usage: python start.py -t <target_url_or_ip[:port]>
# =============================================================================

import sys
import argparse
import re
import urllib.parse
import requests
from bs4 import BeautifulSoup
import threading
import queue
import time
import random
import os
import ssl

# ======================== CONFIGURATION ========================
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Version/14.1.1 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36"
]
TIMEOUT = 10
THREADS = 15  # default threads
OUTPUT_FILE_TEMPLATE = "scan_{target}.txt"

# Sensitive files to probe
SENSITIVE_FILES = [
    "/.env", "/.git/config", "/wp-config.php", "/config.php", "/database.yml",
    "/admin.php", "/phpinfo.php", "/backup.sql", "/dump.sql", "/credentials.txt",
    "/.htaccess", "/.htpasswd", "/web.config", "/README.md", "/.DS_Store",
    "/server-status", "/server-info", "/actuator", "/.well-known/security.txt"
]

# Admin/common paths
ADMIN_PATHS = [
    "/admin", "/administrator", "/wp-admin", "/login", "/cpanel", "/phpmyadmin",
    "/manager", "/controlpanel", "/admin.php", "/user/login", "/auth/login",
    "/admin/login", "/dashboard", "/admin/index.php", "/administrator/index.php"
]

# SQLi payloads (extended)
SQLI_PAYLOADS = [
    "'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1", "' OR 1=1--", "\" OR 1=1--",
    "' OR '1'='1' --", "\" OR \"1\"=\"1\" --", "'; DROP TABLE users--", "\"; DROP TABLE users--",
    "' UNION SELECT NULL--", "\" UNION SELECT NULL--", "' AND 1=1--", "\" AND 1=1--"
]

# XSS payloads (more evasion)
XSS_PAYLOADS = [
    "<script>alert('XSS')</script>", "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>", "<body onload=alert(1)>",
    "<ScRiPt>alert(1)</ScRiPt>", "javascript:alert(1)"
]

# LFI payloads (Unix & Windows)
LFI_PAYLOADS = [
    "../../../../etc/passwd", "..\\..\\..\\..\\windows\\win.ini",
    "....//....//....//etc/passwd", "/etc/passwd", "/windows/win.ini",
    "file:///etc/passwd", "php://filter/convert.base64-encode/resource=index.php"
]

# Regular expressions for sensitive data extraction
REGEX_PATTERNS = {
    "email": r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
    "phone": r"(\+?\d{1,3}[-.\s]?)?\(?\d{2,4}\)?[-.\s]?\d{2,4}[-.\s]?\d{2,4}",
    "api_key": r"(?i)(api[_-]?key|apikey|secret|token)['\":\s]*[=:]\s*['\"]?([A-Za-z0-9+/=_-]{20,})['\"]?",
    "password_field": r"(?i)(password|passwd|pwd)[\s=:]+['\"]?([^'\"\s<>]+)",
    "hidden_input": r"<input[^>]*type=[\"']hidden[\"'][^>]*name=[\"']([^\"']+)[\"'][^>]*value=[\"']([^\"']*)[\"']",
    "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
    "credit_card": r"\b(?:\d{4}[ -]?){3}\d{4}\b",
    "ip_address": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    "url_in_comment": r"<!--.*?(https?://[^\s]+).*?-->",
    "jwt_token": r"eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*",
    "google_api": r"AIza[0-9A-Za-z\-_]{35}",
    "aws_key": r"AKIA[0-9A-Z]{16}",
    "private_key": r"-----BEGIN (RSA |EC )?PRIVATE KEY-----"
}

# ======================== GLOBAL STATE ========================
lock = threading.Lock()
url_queue = queue.Queue()
visited_urls = set()
vulnerabilities = []
found_sensitive_files = []
extracted_data = {k: set() for k in REGEX_PATTERNS if k != "hidden_input"}
extracted_data["hidden_input"] = {}
session = requests.Session()  # reuse connections

# ======================== HELPER FUNCTIONS ========================
def random_agent():
    return random.choice(USER_AGENTS)

def make_request(url, method="GET", params=None, data=None, headers=None, allow_redirects=True, timeout=TIMEOUT):
    """Returns response object or None on failure, with error handling."""
    if not headers:
        headers = {"User-Agent": random_agent()}
    try:
        if method.upper() == "GET":
            resp = session.get(url, params=params, headers=headers, timeout=timeout,
                               allow_redirects=allow_redirects, verify=False)
        else:
            resp = session.post(url, data=data, headers=headers, timeout=timeout,
                                allow_redirects=allow_redirects, verify=False)
        return resp
    except (requests.exceptions.ConnectionError, requests.exceptions.Timeout,
            requests.exceptions.TooManyRedirects, requests.exceptions.RequestException) as e:
        with lock:
            vulnerabilities.append(f"[ERROR] Request to {url} failed: {str(e)}")
        return None

def normalize_url(target):
    """Ensure target has scheme; if not, prepend http://."""
    if not target.startswith(('http://', 'https://')):
        target = 'http://' + target
    return target.rstrip('/')

def log_vuln(message):
    with lock:
        vulnerabilities.append(message)
        print(f"  [VULN] {message}")

def log_file_found(message):
    with lock:
        found_sensitive_files.append(message)
        print(f"  [FILE] {message}")

def add_extracted(category, value):
    if category == "hidden_input":
        # value is tuple (page_url, name=value string)
        page, nv = value
        with lock:
            if page not in extracted_data["hidden_input"]:
                extracted_data["hidden_input"][page] = []
            extracted_data["hidden_input"][page].append(nv)
    else:
        with lock:
            extracted_data[category].add(value)
    print(f"  [DATA] {category}: {value}")

# ======================== VULNERABILITY DETECTORS ========================
def test_sqli(url, param):
    """Test GET parameter for SQL injection using error-based detection."""
    errors = ["SQL syntax", "mysql_fetch", "ORA-", "PostgreSQL", "Unclosed quotation mark",
              "you have an error in your SQL syntax", "Warning: mysql", "Microsoft OLE DB",
              "ODBC Driver", "SQLite3", "PDOException", "valid MySQL result"]
    for payload in SQLI_PAYLOADS:
        test_url = url + "?" + param + "=" + urllib.parse.quote(payload)
        resp = make_request(test_url)
        if resp:
            content = resp.text.lower()
            for err in errors:
                if err.lower() in content:
                    log_vuln(f"[SQL Injection] Parameter '{param}' with payload '{payload}' on {url} -> Error detected: {err}")
                    return True
    return False

def test_xss(url, param):
    """Test for reflected XSS."""
    payload = "<scrIpt>alert(1)</scrIpt>"
    test_url = url + "?" + param + "=" + urllib.parse.quote(payload)
    resp = make_request(test_url)
    if resp and payload in resp.text:
        log_vuln(f"[XSS] Reflected XSS in parameter '{param}' on {url}")
        return True
    return False

def test_lfi(url, param):
    """Test for Local File Inclusion."""
    indicators = ["root:x:", "[boot loader]", "Windows", "[fonts]", "[extensions]"]
    for payload in LFI_PAYLOADS:
        test_url = url + "?" + param + "=" + urllib.parse.quote(payload)
        resp = make_request(test_url)
        if resp and any(ind in resp.text for ind in indicators):
            log_vuln(f"[LFI] Possible LFI in parameter '{param}' with payload '{payload}' on {url}")
            return True
    return False

def test_open_redirect(url, param):
    """Check if parameter redirects to an external URL."""
    evil = "https://evil.com"
    test_url = url + "?" + param + "=" + urllib.parse.quote(evil)
    resp = make_request(test_url, allow_redirects=False)
    if resp and resp.status_code in [301, 302, 303, 307, 308]:
        loc = resp.headers.get("Location", "")
        if evil in loc:
            log_vuln(f"[Open Redirect] Parameter '{param}' redirects to external site on {url}")
            return True
    return False

def check_sensitive_file(base_url, path):
    """Probe a specific file path on the target."""
    full_url = urllib.parse.urljoin(base_url, path)
    resp = make_request(full_url)
    if resp and resp.status_code == 200 and len(resp.content) > 10:
        log_file_found(f"[Sensitive File] {full_url} (size {len(resp.content)} bytes)")
        # Extract data from the file content
        extract_sensitive_data(resp.text, full_url)
        return True
    return False

def check_admin_panel(base_url, path):
    """Check if an admin panel exists at the given path."""
    full_url = urllib.parse.urljoin(base_url, path)
    resp = make_request(full_url)
    if resp and resp.status_code == 200:
        text = resp.text.lower()
        if any(kw in text for kw in ["password", "username", "admin", "login", "dashboard"]):
            log_vuln(f"[Admin Panel] Found at {full_url}")
            extract_sensitive_data(resp.text, full_url)
            return True
    return False

def extract_sensitive_data(html, source_url):
    """Run all regex patterns on HTML and store findings."""
    for category, pattern in REGEX_PATTERNS.items():
        if category == "hidden_input":
            matches = re.findall(pattern, html, re.IGNORECASE)
            for name, value in matches:
                add_extracted("hidden_input", (source_url, f"{name}={value}"))
        else:
            matches = re.findall(pattern, html, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    # pick non-empty group
                    match = match[0] if match[0] else match[1]
                match = str(match).strip()
                if match:
                    add_extracted(category, match)

# ======================== CRAWLER AND SCANNER ========================
def process_page(url):
    """Analyze a single page: detect forms, extract data, and test parameters."""
    if url in visited_urls:
        return
    with lock:
        visited_urls.add(url)
    resp = make_request(url)
    if not resp or resp.status_code != 200:
        return
    html = resp.text
    soup = BeautifulSoup(html, "lxml")
    # Extract and test forms
    forms = soup.find_all("form")
    for form in forms:
        action = form.get("action", "")
        method = form.get("method", "get").lower()
        inputs = form.find_all("input")
        params = {}
        for inp in inputs:
            name = inp.get("name")
            if name:
                params[name] = inp.get("value", "")
        action_url = urllib.parse.urljoin(url, action)
        # Test each input parameter
        for param in params:
            test_sqli(action_url, param)
            test_xss(action_url, param)
            test_lfi(action_url, param)
            test_open_redirect(action_url, param)
    # Also test query parameters in the URL itself
    parsed = urllib.parse.urlparse(url)
    query_params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    for param in query_params:
        test_sqli(url, param)
        test_xss(url, param)
        test_lfi(url, param)
        test_open_redirect(url, param)
    # Extract all sensitive data from this page
    extract_sensitive_data(html, url)
    # Additionally extract links for same-domain crawling (optional depth 1)
    # We only crawl one level deeper to avoid bloat
    for link in soup.find_all("a", href=True):
        href = link["href"]
        full_link = urllib.parse.urljoin(url, href)
        if (full_link.startswith(('http://', 'https://')) and
            urllib.parse.urlparse(full_link).netloc == urllib.parse.urlparse(url).netloc):
            with lock:
                if full_link not in visited_urls:
                    url_queue.put(full_link)

def worker():
    while True:
        try:
            url = url_queue.get(timeout=3)
        except queue.Empty:
            break
        process_page(url)
        url_queue.task_done()

# ======================== MAIN SCAN LOGIC ========================
def scan_target(target_url, threads=THREADS):
    """Main scan orchestration."""
    global visited_urls, vulnerabilities, found_sensitive_files, extracted_data
    # Reset state for new scan
    visited_urls = set()
    vulnerabilities = []
    found_sensitive_files = []
    extracted_data = {k: set() for k in REGEX_PATTERNS if k != "hidden_input"}
    extracted_data["hidden_input"] = {}
    target_url = normalize_url(target_url)
    parsed = urllib.parse.urlparse(target_url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    print(f"[*] Starting advanced scan on: {target_url}")
    print(f"[*] Using {threads} threads.")
    start = time.time()

    # Phase 1: Scan the root page and crawl one level
    url_queue.put(target_url)
    threads_list = []
    for _ in range(threads):
        t = threading.Thread(target=worker)
        t.daemon = True
        t.start()
        threads_list.append(t)
    url_queue.join()
    for t in threads_list:
        t.join(timeout=1)

    # Phase 2: Test sensitive files and admin paths
    print("\n[*] Probing for sensitive files and admin panels...")
    # Run these checks in a thread pool to speed up
    file_queue = queue.Queue()
    for f in SENSITIVE_FILES:
        file_queue.put(("file", f))
    for a in ADMIN_PATHS:
        file_queue.put(("admin", a))

    def file_worker():
        while True:
            try:
                typ, path = file_queue.get(timeout=2)
            except queue.Empty:
                break
            if typ == "file":
                check_sensitive_file(base_url, path)
            else:
                check_admin_panel(base_url, path)
            file_queue.task_done()

    # Use a subset of threads for file checks
    file_threads = []
    for _ in range(min(10, threads)):
        t = threading.Thread(target=file_worker)
        t.daemon = True
        t.start()
        file_threads.append(t)
    file_queue.join()
    for t in file_threads:
        t.join(timeout=1)

    elapsed = time.time() - start

    # Output report
    print("\n[+] ========== SCAN REPORT ==========")
    print(f"[+] Target: {target_url}")
    print(f"[+] Duration: {elapsed:.2f} seconds\n")
    print("[+] Vulnerabilities found:")
    if vulnerabilities:
        for v in vulnerabilities:
            print(f"    {v}")
    else:
        print("    No vulnerabilities detected.")
    print("\n[+] Sensitive Files Found:")
    if found_sensitive_files:
        for f in found_sensitive_files:
            print(f"    {f}")
    else:
        print("    No sensitive files exposed.")
    print("\n[+] Extracted Sensitive Data:")
    for category, data_set in extracted_data.items():
        if category == "hidden_input":
            for page, inputs in data_set.items():
                for inp in inputs:
                    print(f"    Hidden input on {page}: {inp}")
        else:
            for item in data_set:
                print(f"    {category}: {item}")

    # Save to file
    safe_name = re.sub(r'[^a-zA-Z0-9_.-]', '_', target_url)
    out_file = OUTPUT_FILE_TEMPLATE.replace("{target}", safe_name)
    with open(out_file, "w", encoding="utf-8") as f:
        f.write(f"===== SCAN REPORT FOR {target_url} =====\n\n")
        f.write("VULNERABILITIES:\n")
        for v in vulnerabilities:
            f.write(f"  {v}\n")
        f.write("\nSENSITIVE FILES:\n")
        for s in found_sensitive_files:
            f.write(f"  {s}\n")
        f.write("\nEXTRACTED DATA:\n")
        for cat, items in extracted_data.items():
            f.write(f"\n--- {cat} ---\n")
            if cat == "hidden_input":
                for page, inputs in items.items():
                    for inp in inputs:
                        f.write(f"  {page}: {inp}\n")
            else:
                for item in items:
                    f.write(f"  {item}\n")
    print(f"\n[*] Full report saved to {out_file}")
    return out_file

# ======================== COMMAND-LINE INTERFACE ========================
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Advanced Web Vulnerability & Sensitive Data Scanner")
    parser.add_argument("-t", "--target", required=True, help="Target URL or IP[:port] (e.g., https://example.com, 192.168.1.1:8080)")
    parser.add_argument("--threads", type=int, default=THREADS, help="Number of threads (default 15)")
    args = parser.parse_args()

    # Disable SSL warnings for scanning (optional)
    requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

    scan_target(args.target, args.threads)
