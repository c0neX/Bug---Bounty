#!/usr/bin/env python3
import requests
import time
import random
import json
from datetime import datetime
from urllib.parse import urljoin
import sys
import re
from fake_useragent import UserAgent
import os
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_not_exception_type
import ssl
import hashlib

# Obfuscated configuration
CONFIG = {
    'critical_objects': ['REDACTED_OBJ_1', 'REDACTED_OBJ_2', '__Metadata'],
    'api_endpoints': ['/path1', '/path2', '/path3'],
    'timeout': 15,
    'max_attempts': 2,
    'tls_version': ssl.TLSVersion.TLSv1_2
}

class SecurityScanner:
    def __init__(self, proxy_config=None):
        self.user_agent = UserAgent()
        self.http_session = requests.Session()
        self._configure_tls()
        self.scan_results = {}
        if proxy_config:
            self._setup_proxy(proxy_config)

    def _configure_tls(self):
        """Hardened TLS configuration"""
        self.http_session.verify = True
        ssl_context = ssl.create_default_context()
        ssl_context.minimum_version = CONFIG['tls_version']
        ssl_context.verify_mode = ssl.CERT_REQUIRED
        self.http_session.ssl_context = ssl_context

    def _setup_proxy(self, proxy_config):
        """Obfuscated proxy setup"""
        self.http_session.proxies = {
            'http': proxy_config,
            'https': proxy_config
        }

    def scan_target(self, target_url):
        """Main scanning method"""
        validated_url = self._sanitize_url(target_url)
        if not validated_url:
            return None
            
        print(f"\n[+] Scanning {validated_url}")
        
        target_scanner = TargetAnalyzer(validated_url, 
                                     proxy=getattr(self.http_session, 'proxies', None))
        return target_scanner.execute_scan()

    def _sanitize_url(self, raw_url):
        """URL validation and sanitization"""
        clean_url = raw_url.strip()
        if not clean_url:
            return None
        if not re.match(r'^https?://', clean_url, re.I):
            clean_url = f'https://{clean_url}'
        return clean_url.rstrip('/')

class TargetAnalyzer:
    def __init__(self, base_target, proxy=None):
        self.target_url = base_target
        self.http_client = requests.Session()
        self._init_secure_session(proxy)
        
    def _init_secure_session(self, proxy):
        """Initialize secure HTTP session"""
        self.http_client.verify = True
        ssl_context = ssl.create_default_context()
        ssl_context.minimum_version = CONFIG['tls_version']
        self.http_client.ssl_context = ssl_context
        
        self.http_client.headers.update({
            'User-Agent': UserAgent().random,
            'Accept': 'application/json',
            'X-Forwarded-For': self._generate_random_ip(),
            'Accept-Language': 'en-US,en;q=0.9'
        })
        if proxy:
            self.http_client.proxies = proxy
        
        self.analysis_results = {
            'findings': [],
            'metrics': self._init_metrics(),
            'security': {
                'tls_enforced': True,
                'tls_version': str(CONFIG['tls_version']),
                'host_verification': True
            }
        }

    def _generate_random_ip(self):
        """Generate obfuscated origin IP"""
        return f"{random.randint(1,255)}.{random.randint(1,255)}." + \
               f"{random.randint(1,255)}.{random.randint(1,255)}"

    def _init_metrics(self):
        """Initialize tracking metrics"""
        return {
            'start': datetime.now().isoformat(),
            'requests': 0,
            'errors': 0,
            'timeouts': 0,
            'ssl_issues': 0
        }

    @retry(stop=stop_after_attempt(CONFIG['max_attempts']),
          wait=wait_exponential(multiplier=1, min=4, max=10),
          retry=retry_if_not_exception_type(requests.exceptions.SSLError))
    def _send_request(self, endpoint):
        """Secure request execution"""
        full_url = urljoin(self.target_url, endpoint)
        self.analysis_results['metrics']['requests'] += 1
        
        try:
            time.sleep(random.uniform(1.0, 2.5))
            response = self.http_client.get(
                full_url,
                timeout=CONFIG['timeout'],
                allow_redirects=False
            )
            return response if response.status_code == 200 else None
                
        except requests.exceptions.SSLError as e:
            self._record_ssl_issue(full_url, str(e))
            return None
        except requests.exceptions.Timeout:
            self.analysis_results['metrics']['timeouts'] += 1
            raise
        except Exception as e:
            self.analysis_results['metrics']['errors'] += 1
            raise

    def _record_ssl_issue(self, url, error):
        """Log SSL issues securely"""
        self.analysis_results['metrics']['ssl_issues'] += 1
        issue_id = hashlib.sha256(url.encode()).hexdigest()[:8]
        self.analysis_results.setdefault('security_issues', []).append({
            'id': issue_id,
            'type': 'ssl_error',
            'url': url,
            'timestamp': datetime.now().isoformat()
        })
        print(f"[!] SSL Issue detected (ID: {issue_id})")

    def execute_scan(self):
        """Execute full security scan"""
        print(f"[*] Security Scan Started - {datetime.now().isoformat()}")
        
        # Check for sensitive objects
        for obj in CONFIG['critical_objects']:
            if self._check_object_access(obj):
                self.analysis_results['findings'].append(obj)

        # Check API endpoints
        vulnerable_endpoints = self._check_api_endpoints()
        if vulnerable_endpoints:
            self.analysis_results['findings'].extend(vulnerable_endpoints)

        # Finalize results
        self._finalize_results()
        return self.analysis_results

    def _check_object_access(self, object_name):
        """Check object accessibility"""
        test_endpoints = [
            f"services/data/v56.0/sobjects/{object_name}/describe",
            f"services/data/v56.0/sobjects/{object_name}/listviews"
        ]
        return any(self._send_request(e) for e in test_endpoints)

    def _check_api_endpoints(self):
        """Test sensitive API endpoints"""
        return [ep for ep in CONFIG['api_endpoints'] 
               if self._send_request(ep)]

    def _finalize_results(self):
        """Complete scan results processing"""
        end_time = datetime.now()
        self.analysis_results['metrics']['duration'] = (
            end_time - datetime.fromisoformat(
                self.analysis_results['metrics']['start'])
        ).total_seconds()
        self.analysis_results['metrics']['end'] = end_time.isoformat()
        self.analysis_results['vulnerable'] = bool(
            self.analysis_results.get('findings'))

def generate_security_report(scan_data):
    """Generate formatted security report"""
    report = []
    for target, results in scan_data.items():
        status = "VULNERABLE" if results['vulnerable'] else "SECURE"
        report.append(f"\n[ {status} ] {target}")
        
        if results.get('security_issues'):
            report.append("\nSECURITY ISSUES FOUND:")
            for issue in results['security_issues']:
                report.append(f" - {issue['type'].upper()} (ID: {issue['id']})")
        
        report.append("\nSCAN METRICS:")
        report.append(f"Requests: {results['metrics']['requests']}")
        report.append(f"Duration: {results['metrics']['duration']:.2f}s")
        
    return "\n".join(report)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 security_scanner.py <target> [proxy]")
        sys.exit(1)
        
    target_input = sys.argv[1]
    proxy_input = sys.argv[2] if len(sys.argv) > 2 else None
    
    scanner = SecurityScanner(proxy_config=proxy_input)
    
    if target_input.endswith('.txt'):
        # Multi-target scan
        pass  # Implementation omitted for brevity
    else:
        scan_result = scanner.scan_target(target_input)
        print("\n=== SCAN RESULTS ===")
        print(json.dumps(scan_result, indent=2))
