import os
import sys
import subprocess
import requests
import re
import json
import jsbeautifier
from tqdm import tqdm
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import random
import hashlib
import argparse

# Tool paths
LINKFINDER_PATH = "./LinkFinder/linkfinder.py"
SECRETFINDER_PATH = "./SecretFinder/SecretFinder.py"
GF_PATTERNS = ["xss", "s3-buckets", "ssrf", "json-sec", "potential", "redirect", "api-keys"]
GF_PATH = os.path.expanduser("~/.gf")

HEADERS_LIST = [
    {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
    {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"},
    {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64)"},
]

regex_patterns = {
    "api_key": r"(?i)(api[-]?key)['\"=:\s]*[0-9a-zA-Z-]{16,45}",
    "access_token": r"(?i)(access[-]?token)['\"=:\s]*[0-9a-zA-Z-]{16,45}",
    "auth_basic": r"(?i)(authorization)['\"=:\s]*(Basic\s+[a-zA-Z0-9=:_\-/+]+)",
    "bearer_token": r"(?i)(authorization)['\"=:\s]*(Bearer\s+[a-zA-Z0-9\-_\.=]+)",
    "aws_key": r"AKIA[0-9A-Z]{16}",
}

downloaded_hashes = set()
results_db = {}

def run_command(cmd):
    try:
        result = subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.DEVNULL)
        return result.strip().splitlines()
    except subprocess.CalledProcessError as e:
        print(f"Erro ao executar comando: {e}")
        return []

def extract_live_js(target):
    print(f"[+] Extracting live JS from: {target}")
    js_links = set()

    subjs_output = run_command(f"subjs {target}")
    js_links.update(subjs_output)

    getjs_output = run_command(f"getJS --url {target}")
    js_links.update(getjs_output)

    return list(js_links)

def extract_wayback_js(domain):
    print(f"[+] Extracting Wayback JS from: {domain}")
    urls = run_command(f"echo {domain} | waybackurls")
    js_urls = [url for url in urls if url.endswith('.js') and domain in url]
    return js_urls

def download_js_file(js_url):
    try:
        headers = random.choice(HEADERS_LIST)
        response = requests.get(js_url, headers=headers, timeout=10)
        if response.status_code == 200:
            content = response.text
            content_hash = hashlib.sha256(content.encode()).hexdigest()
            if content_hash in downloaded_hashes:
                return js_url, None
            downloaded_hashes.add(content_hash)
            return js_url, jsbeautifier.beautify(content)
    except:
        return js_url, None
    return js_url, None

def scan_with_regex(content):
    findings = {}
    for name, pattern in regex_patterns.items():
        matches = re.findall(pattern, content)
        if matches:
            findings[name] = list(set(matches))
    return findings

def run_gf(content, gf_name):
    try:
        with open(".temp.js", "w") as f:
            f.write(content)
        output = run_command(f"gf {gf_name} < .temp.js")
        return output
    finally:
        if os.path.exists(".temp.js"):
            os.remove(".temp.js")

def analyze_js(js_url, content):
    analysis = {"url": js_url, "regex": {}, "gf": {}}

    regex_results = scan_with_regex(content)
    if regex_results:
        analysis["regex"] = regex_results

    for gf_pattern in GF_PATTERNS:
        matches = run_gf(content, gf_pattern)
        if matches:
            analysis["gf"][gf_pattern] = matches

    print(f"  - [*] LinkFinder on {js_url}")
    os.system(f"python3 {LINKFINDER_PATH} -i {js_url} -o cli")

    print(f"  - [*] SecretFinder on {js_url}")
    os.system(f"python3 {SECRETFINDER_PATH} -i {js_url} -o cli")

    results_db[js_url] = analysis

def analyze_all_js(js_links, label=""):
    print(f"\n[+] Downloading and analyzing {len(js_links)} JS files from {label}...\n")
    results = []

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(download_js_file, url) for url in js_links]
        for future in tqdm(as_completed(futures), total=len(js_links)):
            js_url, js_content = future.result()
            if js_content:
                results.append((js_url, js_content))

    for js_url, js_content in results:
        analyze_js(js_url, js_content)

def save_results():
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    filename = f"jsReconHunter-results-{timestamp}.json"
    with open(filename, "w") as f:
        json.dump(results_db, f, indent=2)
    print(f"\n[✔] Results saved to: {filename}")

def process_target(target):
    live_links = extract_live_js(target)
    if len(live_links) < 3:
        print(f"[!] Few live JS files found for {target}, switching to archive...")
        parsed_url = urlparse(target)
        domain = parsed_url.netloc
        if not domain:
            domain = target # Se não for uma URL válida, tenta usar o input direto como domínio
        wayback_links = extract_wayback_js(domain)
        analyze_all_js(wayback_links, label="WAYBACK")
    else:
        analyze_all_js(live_links, label="LIVE")

def main():
    parser = argparse.ArgumentParser(description="A tool to hunt for secrets and vulnerabilities in JavaScript files.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--url", help="Target URL to scan.")
    group.add_argument("--list", help="Path to a file containing a list of URLs to scan (one per line).")

    args = parser.parse_args()

    targets = []

    if args.url:
        targets.append(args.url)
    elif args.list:
        try:
            with open(args.list, "r") as f:
                targets = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"[!] Error: File not found at {args.list}")
            sys.exit(1)

    for target in targets:
        print(f"\n====== Processing target: {target} ======\n")
        process_target(target)

    if targets:
        save_results()
    else:
        print("[!] No targets provided.")

if __name__ == "__main__":
    main()
