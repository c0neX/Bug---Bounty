import scapy.all as scapy
import socket
import threading
import requests
import json
from datetime import datetime

VULNERS_API_KEY = "YOUR_VULNERS_API_KEY"  # Replace with your key

def arp_scan(ip_range):
    arp_req = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_req_broadcast = broadcast / arp_req
    answered = scapy.srp(arp_req_broadcast, timeout=2, verbose=False)[0]

    devices = []
    for element in answered:
        devices.append({'ip': element[1].psrc, 'mac': element[1].hwsrc})
    return devices

def scan_ports(ip, ports=range(1, 65536), max_threads=100):
    open_ports = []
    lock = threading.Lock()

    def scan(port):
        try:
            with socket.socket() as sock:
                sock.settimeout(0.3)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    try:
                        banner = sock.recv(1024).decode(errors="ignore").strip()
                    except:
                        banner = ''
                    with lock:
                        open_ports.append((port, banner))
        except:
            pass

    threads = []
    for port in ports:
        while threading.active_count() >= max_threads:
            pass  # throttle threads
        thread = threading.Thread(target=scan, args=(port,))
        thread.start()
        threads.append(thread)

    for t in threads:
        t.join()
    return open_ports

def check_vulners_api(banner):
    try:
        if not banner:
            return None
        response = requests.get(
            'https://vulners.com/api/v3/burp/software/',
            params={'software': banner},
            headers={'X-Api-Key': VULNERS_API_KEY},
            timeout=5
        )
        if response.status_code == 200:
            data = response.json()
            if data.get("data", {}).get("search"):
                cves = [item.get("id") for item in data["data"]["search"]]
                return cves if cves else None
    except Exception as e:
        print(f"[!] Error querying Vulners: {e}")
    return None

def save_to_json(results, filename="scan_results.json"):
    with open(filename, "w") as f:
        json.dump(results, f, indent=4)

def main():
    ip_range = input("Enter IP range (e.g., 192.168.1.1/24): ")
    print("[*] Starting ARP scan...")
    devices = arp_scan(ip_range)

    full_results = {
        "scan_date": datetime.now().isoformat(),
        "devices": []
    }

    for device in devices:
        ip = device['ip']
        print(f"\n[*] Scanning all ports on {ip}...")
        open_ports = scan_ports(ip)
        device_result = {
            "ip": ip,
            "mac": device['mac'],
            "ports": []
        }

        for port, banner in open_ports:
            vulns = check_vulners_api(banner)
            device_result["ports"].append({
                "port": port,
                "banner": banner,
                "cves": vulns
            })
            print(f"[+] Port {port} open - Banner: {banner}")
            if vulns:
                for cve in vulns:
                    print(f"    [!] CVE: {cve}")

        full_results["devices"].append(device_result)

    save_to_json(full_results)
    print("\n[✓] Scan complete. Results saved to 'scan_results.json'.")

if __name__ == "__main__":
    main()
