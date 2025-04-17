import re
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import argparse
import os
import time
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Accept": "*/*",
    "Accept-Language": "en-US,en;q=0.5",
    "Connection": "keep-alive",
}

def create_session():
    session = requests.Session()
    retries = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[403, 429, 500, 502, 503, 504],
        raise_on_status=False,
    )
    session.mount("http://", HTTPAdapter(max_retries=retries))
    session.mount("https://", HTTPAdapter(max_retries=retries))
    session.headers.update(DEFAULT_HEADERS)
    return session

session = create_session()

SECRET_PATTERNS = {
    "Google Cloud Service Account": r'"type": "service_account".?"project_id":.?"private_key_id":.*?"private_key": "-----BEGIN PRIVATE KEY-----[\s\S]+?-----END PRIVATE KEY-----"',
    "AWS Secret Access Key": r"(?i)aws(.{0,20})?(secret|access)?.{0,20}?[0-9a-zA-Z/+]{40}",
    "Slack Token": r"xox[baprs]-[0-9a-zA-Z]{10,48}",
    "Stripe API Key": r"sk_live_[0-9a-zA-Z]{24}",
    "Twilio API Key": r"SK[0-9a-fA-F]{32}",
    "GitHub Token": r"ghp_[0-9a-zA-Z]{36}",
    "Facebook Access Token": r"EAACEdEose0cBA[0-9A-Za-z]+",
    "Heroku API Key": r"[hH]eroku[a-zA-Z0-9]{25,35}",
    "Mailgun API Key": r"key-[0-9a-zA-Z]{32}",
    "RSA Private Key": r"-----BEGIN RSA PRIVATE KEY-----[\s\S]*?-----END RSA PRIVATE KEY-----",
    "SSH (OpenSSH) Private Key": r"-----BEGIN OPENSSH PRIVATE KEY-----[\s\S]*?-----END OPENSSH PRIVATE KEY-----",
    "PEM Certificate": r"-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----",
    "JWT Token": r"eyJ[A-Za-z0-9-]+\.[A-Za-z0-9-]+\.[A-Za-z0-9-_]+",
    "Basic Auth": r"[A-Za-z0-9_\-]+:[A-Za-z0-9_\-]+",
    "Bearer Token": r"Bearer\s+[A-Za-z0-9\-._~+/]+=*",
    "Generic API Key": r"(?i)(api|apikey|access)[-]?(key)?['\"=: ]+[A-Za-z0-9\-]{16,45}",
    "Generic Secret": r"(?i)(secret|passwd|password|token)['\"=: ]+[A-Za-z0-9\-_]{8,}",
}

CONTEXT_KEYWORDS = [
    'token', 'auth', 'apikey', 'secret', 'password', 'key', 'credentials', 'private_key', 'ssh', 'config',
    'env', '.env', 'dotenv', 'vault', 'firebase', 'aws_', 'gcp_', 'stripe_', 'twilio_', 'slack_', 'github_', 'webhook',
    'jwt', 'rsa', 'smtp_', 'connection_string'
]

def fetch_js_links(base_url):
    try:
        res = session.get(base_url, timeout=10)
        if res.status_code >= 400:
            print(f"[!] Failed to access {base_url} (HTTP {res.status_code})")
            return []
    except requests.RequestException as e:
        print(f"[!] Failed to connect with {base_url} ({type(e).__name__})")
        return []

    soup = BeautifulSoup(res.text, 'html.parser')
    js_links = []

    for script in soup.find_all('script'):
        src = script.get('src')
        if src:
            full_url = urljoin(base_url, src)
            js_links.append(full_url)

    return list(set(js_links))

def download_js_file(url):
    try:
        res = session.get(url, timeout=10)
        if res.status_code == 200:
            return res.text
        elif res.status_code == 403:
            print(f"    [403] Forbidden access to: {url}")
        elif res.status_code == 404:
            print(f"    [404] Not found: {url}")
        return ""
    except requests.RequestException as e:
        print(f"    [!] Error downloading {url}: {type(e).__name__}")
        return ""

def scan_for_secrets(js_code, js_url):
    findings = []
    lines = js_code.splitlines()

    for i, line in enumerate(lines):
        for name, pattern in SECRET_PATTERNS.items():
            matches = re.findall(pattern, line)
            for match in matches:
                context_score = any(kw in line.lower() for kw in CONTEXT_KEYWORDS)
                findings.append({
                    "type": name,
                    "match": match,
                    "context": line.strip(),
                    "confidence": "High" if context_score else "Medium",
                    "file": js_url,
                    "line": i + 1
                })

    return findings

def check_common_leaks(base_url):
    files_to_check = ['.env', 'config.js', '.git/config', 'debug.log']
    leaks = []

    for file in files_to_check:
        url = urljoin(base_url, file)
        try:
            res = session.get(url, timeout=10)
            if res.status_code == 200 and any(word in res.text.lower() for word in CONTEXT_KEYWORDS):
                leaks.append({
                    "file": url,
                    "preview": res.text[:200].replace('\n', ' ')
                })
            elif res.status_code == 403:
                print(f"    [403] Forbidden access to file: {url}")
            elif res.status_code == 404:
                continue  # Don't show messages for not found files
        except requests.RequestException:
            continue

    return leaks

def scan_domain(target_url):
    print(f"\n============================")
    print(f"[🏁] Scanning: {target_url}")
    print(f"============================")

    js_links = fetch_js_links(target_url)
    if not js_links:
        print("[-] No JS files found or website could not be accessed.")
        return

    print(f"[+] Found {len(js_links)} JS files")

    all_findings = []

    for js_url in js_links:
        print(f"    [-] Scanning JS: {js_url}")
        js_code = download_js_file(js_url)
        secrets = scan_for_secrets(js_code, js_url)
        all_findings.extend(secrets)
        time.sleep(1)

    leaks = check_common_leaks(target_url)

    print("\n--- 🔍 Secrets Found ---")
    if all_findings:
        for item in all_findings:
            print(f"[!] {item['type']} ({item['confidence']}) in {item['file']} (line {item['line']})")
            print(f"    Context: {item['context']}")
    else:
        print("[-] No secrets found.")

    print("\n--- ⚠ Exposed Configuration Files ---")
    if leaks:
        for leak in leaks:
            print(f"[!] Public file: {leak['file']}")
            print(f"    Preview: {leak['preview']}")
    else:
        print("[-] No sensitive files found.")

def is_valid_url(url):
    return url.startswith("http://") or url.startswith("https://")

def main(input_arg):
    if os.path.isfile(input_arg):
        try:
            with open(input_arg, 'r') as f:
                urls = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"[!] File not found: {input_arg}")
            return

        for url in urls:
            if is_valid_url(url):
                scan_domain(url)
            else:
                print(f"[!] Invalid URL skipped: {url}")
    elif is_valid_url(input_arg):
        scan_domain(input_arg)
    else:
        print(f"[!] Invalid input: provide a URL or the path to a .txt file")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analyzes exposed secrets in JS files and configuration leaks.")
    parser.add_argument("input", help="URL or path to .txt file with URLs")
    args = parser.parse_args()

    main(args.input)
