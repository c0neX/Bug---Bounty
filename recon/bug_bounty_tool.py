import subprocess
import threading
import requests
import os
import time

# Configuration
target = "example.com"
output_dir = f"results/{target}"
os.makedirs(output_dir, exist_ok=True)

# Tool paths
AMASS = "amass"
SUBFINDER = "subfinder"
HTTPX = "httpx"
NAABU = "naabu"
NUCLEI = "nuclei"

# Shodan and Censys API config (replace with actual API keys)
SHODAN_API_KEY = "your_shodan_api_key"
CENSYS_API_ID = "your_censys_api_id"
CENSYS_SECRET = "your_censys_api_secret"

# Helper: Run a tool and save output
def run_tool(command, output_file):
    print(f"[+] Running: {' '.join(command)}")
    with open(output_file, "w") as f:
        subprocess.run(command, stdout=f, stderr=subprocess.DEVNULL)

# Subdomain enumeration
def subdomain_enum():
    subfinder_file = f"{output_dir}/subfinder.txt"
    amass_file = f"{output_dir}/amass.txt"

    run_tool([SUBFINDER, "-d", target], subfinder_file)
    run_tool([AMASS, "enum", "-passive", "-d", target], amass_file)

    with open(subfinder_file) as f1, open(amass_file) as f2:
        subs = set(f1.read().splitlines()) | set(f2.read().splitlines())

    all_subs_file = f"{output_dir}/all_subdomains.txt"
    with open(all_subs_file, "w") as f:
        f.write("\n".join(sorted(subs)))
    return all_subs_file

# Probing live hosts
def probe_hosts(subdomains_file):
    live_file = f"{output_dir}/live_hosts.txt"
    run_tool([HTTPX, "-l", subdomains_file], live_file)
    return live_file

# Port scanning
def port_scan(live_hosts_file):
    naabu_output = f"{output_dir}/ports.txt"
    run_tool([NAABU, "-list", live_hosts_file], naabu_output)

# Vulnerability scanning
def vuln_scan(live_hosts_file):
    nuclei_output = f"{output_dir}/vulns.txt"
    run_tool([NUCLEI, "-l", live_hosts_file], nuclei_output)

# Integrate Shodan API
def shodan_lookup():
    result_file = f"{output_dir}/shodan_results.txt"
    print("[+] Querying Shodan API")
    url = f"https://api.shodan.io/dns/domain/{target}?key={SHODAN_API_KEY}"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            with open(result_file, "w") as f:
                f.write(response.text)
        else:
            print("[!] Shodan API error", response.status_code)
    except Exception as e:
        print(f"[!] Shodan lookup failed: {e}")

# Integrate Censys API
def censys_lookup():
    result_file = f"{output_dir}/censys_results.txt"
    print("[+] Querying Censys API")
    try:
        response = requests.get(
            "https://search.censys.io/api/v2/hosts/search",
            auth=(CENSYS_API_ID, CENSYS_SECRET),
            params={"q": target}
        )
        if response.status_code == 200:
            with open(result_file, "w") as f:
                f.write(response.text)
        else:
            print("[!] Censys API error", response.status_code)
    except Exception as e:
        print(f"[!] Censys lookup failed: {e}")

# Run all tasks
def main():
    start = time.time()
    print(f"[*] Starting Bug Bounty Scanner on {target}\n")

    subs_file = subdomain_enum()
    live_hosts = probe_hosts(subs_file)

    t1 = threading.Thread(target=port_scan, args=(live_hosts,))
    t2 = threading.Thread(target=vuln_scan, args=(live_hosts,))
    t3 = threading.Thread(target=shodan_lookup)
    t4 = threading.Thread(target=censys_lookup)

    t1.start()
    t2.start()
    t3.start()
    t4.start()

    t1.join()
    t2.join()
    t3.join()
    t4.join()

    print(f"\n[+] Scanning complete in {round(time.time() - start, 2)} seconds.")
    print(f"[+] Results saved in: {output_dir}")

if _name_ == "_main_":
    main()
