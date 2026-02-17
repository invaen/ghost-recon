#!/usr/bin/env python3
"""
Ghost Recon - Reconnaissance That Thinks About What It Finds

Multi-phase reconnaissance pipeline with intelligent analysis.
Subdomain discovery, DNS intelligence, live host probing, port scanning,
TLS analysis, technology fingerprinting, security scoring, and
endpoint discovery — zero external dependencies.

Usage:
    ghost-recon target.com
    ghost-recon target.com --deep
    ghost-recon target.com --stealth
    ghost-recon target.com --ports
"""

import subprocess
import json
import sys
import re
import argparse
import secrets
import socket
import urllib.error
from datetime import datetime, timezone
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
import ssl
import http.client


VERSION = "2.1.1"


class C:
    R = '\033[91m'
    G = '\033[92m'
    Y = '\033[93m'
    B = '\033[94m'
    M = '\033[95m'
    C = '\033[96m'
    W = '\033[97m'
    DIM = '\033[2m'
    BOLD = '\033[1m'
    E = '\033[0m'

    @classmethod
    def disable(cls):
        cls.R = cls.G = cls.Y = cls.B = cls.M = cls.C = cls.W = cls.E = ''
        cls.BOLD = cls.DIM = ''


def banner():
    print(f"""{C.M}
   ▄████  ██░ ██  ▒█████    ██████ ▄▄▄█████▓
  ██▒ ▀█▒▓██░ ██▒▒██▒  ██▒▒██    ▒ ▓  ██▒ ▓▒
 ▒██░▄▄▄░▒██▀▀██░▒██░  ██▒░ ▓██▄   ▒ ▓██░ ▒░
 ░▓█  ██▓░▓█ ░██ ▒██   ██░  ▒   ██▒░ ▓██▓ ░
 ░▒▓███▀▒░▓█▒░██▓░ ████▓▒░▒██████▒▒  ▒██▒ ░
  ░▒   ▒  ▒ ░░▒░▒░ ▒░▒░▒░ ▒ ▒▓▒ ▒ ░  ▒ ░░
    R E C O N  {C.W}v{VERSION}{C.E}
    """)


def validate_domain(domain: str) -> str:
    """Validate and normalize a domain name.

    Raises ValueError if the domain is not a valid hostname.
    """
    domain = domain.replace('https://', '').replace('http://', '').rstrip('/')
    if not re.match(r'^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)+$', domain.lower()):
        raise ValueError(f"Invalid domain: {domain}")
    if len(domain) > 253:
        raise ValueError(f"Domain too long: {len(domain)} chars (max 253)")
    return domain.lower()


class GhostRecon:
    def __init__(self, target, output_dir=None, deep=False, stealth=False, ports=False, json_output=False):
        self.target = validate_domain(target)
        self.deep = deep
        self.stealth = stealth
        self.ports = ports
        self.json_output = json_output
        self.output_dir = output_dir or Path.home() / '.bounty' / 'targets' / self.target
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.subdomains = set()
        self.live_hosts = []
        self.technologies = {}
        self.interesting = []
        self.attack_surface = {}
        self.dns_records = {}
        self.wayback_urls = set()
        self.port_results = {}
        self.tls_info = {}
        self.security_scores = {}
        self.scan_start = None
        self.scan_end = None

    def log(self, msg, level='info'):
        icons = {
            'info': f'{C.B}[*]{C.E}',
            'success': f'{C.G}[+]{C.E}',
            'warn': f'{C.Y}[!]{C.E}',
            'error': f'{C.R}[-]{C.E}',
            'think': f'{C.M}[~]{C.E}',
            'port': f'{C.C}[>]{C.E}',
        }
        print(f"{icons.get(level, icons['info'])} {msg}")

    def think(self, observation, conclusion):
        """Reasoning layer — correlates findings into actionable conclusions"""
        print(f"\n{C.M}  ~ Observation:{C.E} {observation}")
        print(f"{C.C}  > Conclusion:{C.E} {conclusion}\n")

    # ==================== SUBDOMAIN ENUMERATION ====================

    def enum_crtsh(self):
        """Certificate Transparency logs via crt.sh"""
        self.log("Querying Certificate Transparency (crt.sh)...")
        try:
            import urllib.request
            url = f"https://crt.sh/?q=%25.{self.target}&output=json"
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=30) as response:
                data = json.loads(response.read().decode())
                for entry in data:
                    name = entry.get('name_value', '')
                    for sub in name.split('\n'):
                        sub = sub.strip().lower()
                        if sub and '*' not in sub and sub.endswith(self.target):
                            self.subdomains.add(sub)
            self.log(f"crt.sh: Found {len(self.subdomains)} entries", 'success')
        except (urllib.error.URLError, json.JSONDecodeError, socket.timeout, OSError) as e:
            self.log(f"crt.sh failed: {e}", 'warn')

    def enum_dns_brute(self):
        """DNS bruteforce with common subdomains"""
        self.log("DNS bruteforce (common subdomains)...")
        common = [
            'www', 'mail', 'ftp', 'admin', 'api', 'dev', 'staging', 'test',
            'beta', 'app', 'mobile', 'm', 'shop', 'store', 'blog', 'news',
            'support', 'help', 'docs', 'status', 'cdn', 'static', 'assets',
            'img', 'images', 'media', 'video', 'auth', 'login', 'sso',
            'portal', 'dashboard', 'panel', 'cpanel', 'webmail', 'mail2',
            'smtp', 'pop', 'imap', 'ns1', 'ns2', 'dns', 'vpn', 'remote',
            'git', 'gitlab', 'github', 'svn', 'jenkins', 'ci', 'build',
            'jira', 'confluence', 'wiki', 'internal', 'intranet', 'corp',
            'demo', 'sandbox', 'uat', 'qa', 'stage', 'prod', 'production',
            'db', 'database', 'mysql', 'postgres', 'mongo', 'redis', 'elastic',
            'kibana', 'grafana', 'prometheus', 'logs', 'monitoring', 'metrics',
            'backup', 'bak', 'old', 'new', 'v1', 'v2', 'api-v1', 'api-v2',
            'graphql', 'rest', 'ws', 'websocket', 'socket', 'realtime',
            'payments', 'pay', 'billing', 'invoice', 'checkout', 'cart',
            'accounts', 'account', 'user', 'users', 'profile', 'oauth',
            'connect', 'integration', 'webhook', 'hooks', 'callback',
            'upload', 'uploads', 'files', 'download', 'downloads', 'export',
            'proxy', 'gateway', 'edge', 'lb', 'loadbalancer', 'cache',
            'search', 'queue', 'worker', 'cron', 'scheduler', 'notify',
            'email', 'mx', 'autodiscover', 'exchange', 'owa',
            'vault', 'secrets', 'config', 'consul', 'etcd', 'zk',
            # Cloud & DevOps
            'k8s', 'kubernetes', 'docker', 'registry', 'harbor', 'argocd',
            'terraform', 'ansible', 'puppet', 'chef',
            # Observability
            'jaeger', 'zipkin', 'datadog', 'newrelic', 'sentry', 'pagerduty',
            # SSO / Identity
            'idp', 'identity', 'keycloak', 'okta', 'saml', 'adfs',
            # Misc services
            'minio', 's3', 'storage', 'bucket', 'cdn2', 'preview',
            'canary', 'nightly', 'release', 'hotfix',
        ]

        def check_subdomain(sub):
            fqdn = f"{sub}.{self.target}"
            try:
                socket.gethostbyname(fqdn)
                return fqdn
            except socket.gaierror:
                return None

        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = {executor.submit(check_subdomain, sub): sub for sub in common}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    self.subdomains.add(result)

        self.log(f"DNS brute: {len(self.subdomains)} total subdomains", 'success')

    def run_subfinder(self):
        """Run subfinder if available"""
        try:
            result = subprocess.run(
                ['subfinder', '-d', self.target, '-silent'],
                capture_output=True, text=True, timeout=120
            )
            for line in result.stdout.strip().split('\n'):
                if line.strip():
                    self.subdomains.add(line.strip().lower())
            self.log(f"Subfinder: {len(self.subdomains)} total", 'success')
        except FileNotFoundError:
            self.log("Subfinder not installed, skipping", 'warn')
        except subprocess.TimeoutExpired as e:
            self.log(f"Subfinder error: {e}", 'warn')

    # ==================== WAYBACK MACHINE ====================

    def enum_wayback(self):
        """Discover historical URLs via Wayback Machine CDX API (passive)"""
        self.log("Querying Wayback Machine CDX API...")
        try:
            import urllib.request
            url = (
                f"https://web.archive.org/cdx/search/cdx"
                f"?url=*.{self.target}/*&output=json&collapse=urlkey"
                f"&fl=original,statuscode,mimetype&limit=500"
            )
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=30) as response:
                data = json.loads(response.read().decode())
                # First row is headers
                for row in data[1:]:
                    original_url = row[0] if row else ''
                    if original_url:
                        self.wayback_urls.add(original_url)

            self.log(f"Wayback: {len(self.wayback_urls)} historical URLs", 'success')

            # Extract subdomains from wayback URLs
            wb_subs = set()
            for url in self.wayback_urls:
                try:
                    parsed = urlparse(url)
                    host = parsed.netloc.lower()
                    if host and host.endswith(self.target):
                        wb_subs.add(host)
                except (ValueError, AttributeError):
                    pass

            new_from_wb = wb_subs - self.subdomains
            if new_from_wb:
                self.subdomains.update(wb_subs)
                self.think(
                    f"Wayback Machine revealed {len(new_from_wb)} subdomains not found by other methods",
                    "Historical data exposes subdomains that may have been decommissioned but not cleaned up"
                )

            # Identify interesting URL patterns
            interesting_patterns = [
                'admin', 'debug', 'test', 'backup', 'config',
                'upload', '.sql', '.bak', '.old', '.zip',
                'phpinfo', '.env', 'wp-config', 'credentials',
                'api/v', 'swagger', 'graphql', 'internal',
            ]
            flagged = []
            for wb_url in self.wayback_urls:
                lower = wb_url.lower()
                for pattern in interesting_patterns:
                    if pattern in lower:
                        flagged.append(wb_url)
                        break

            if flagged:
                self.interesting.append({
                    'type': 'wayback_interesting',
                    'count': len(flagged),
                    'samples': flagged[:10],
                    'note': 'Historical URLs with sensitive patterns — may still be accessible'
                })

        except (urllib.error.URLError, json.JSONDecodeError, socket.timeout, OSError) as e:
            self.log(f"Wayback failed: {e}", 'warn')

    # ==================== DNS INTELLIGENCE ====================

    def enumerate_dns(self):
        """Full DNS record enumeration"""
        self.log(f"Enumerating DNS records for {self.target}...")
        records = {}

        # A records
        try:
            ips = socket.getaddrinfo(self.target, None, socket.AF_INET)
            records['A'] = list(set(addr[4][0] for addr in ips))
        except (socket.gaierror, OSError):
            records['A'] = []

        # AAAA records
        try:
            ips6 = socket.getaddrinfo(self.target, None, socket.AF_INET6)
            records['AAAA'] = list(set(addr[4][0] for addr in ips6))
        except (socket.gaierror, OSError):
            records['AAAA'] = []

        # Use dig for MX, TXT, NS, CNAME, SOA if available
        dig_available = True
        try:
            subprocess.run(['dig', '+version'], capture_output=True, timeout=5)
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            dig_available = False

        if dig_available:
            for rtype in ['MX', 'TXT', 'NS', 'CNAME', 'SOA']:
                try:
                    result = subprocess.run(
                        ['dig', '+short', rtype, self.target],
                        capture_output=True, text=True, timeout=10
                    )
                    lines = [l.strip() for l in result.stdout.strip().split('\n') if l.strip()]
                    if lines:
                        records[rtype] = lines
                except (subprocess.TimeoutExpired, OSError):
                    pass
        else:
            self.log("dig not available, DNS limited to A/AAAA", 'warn')

        self.dns_records = records

        # Print and analyze
        for rtype, values in records.items():
            if values:
                self.log(f"  {C.C}{rtype:>5}{C.E}: {', '.join(values[:3])}" +
                         (f" (+{len(values)-3} more)" if len(values) > 3 else ""))

        # Intelligence analysis
        if records.get('TXT'):
            for txt in records['TXT']:
                txt_lower = txt.lower()
                if 'v=spf1' in txt_lower:
                    # SPF record — extract allowed senders
                    includes = re.findall(r'include:(\S+)', txt)
                    if includes:
                        self.think(
                            f"SPF record includes: {', '.join(includes)}",
                            "These are authorized email services — reveals third-party integrations"
                        )
                if 'v=dmarc' in txt_lower:
                    if 'p=none' in txt_lower:
                        self.interesting.append({
                            'type': 'weak_dmarc',
                            'host': self.target,
                            'note': 'DMARC policy is "none" — domain is susceptible to email spoofing'
                        })

        if records.get('MX'):
            mx_providers = []
            for mx in records['MX']:
                mx_lower = mx.lower()
                if 'google' in mx_lower or 'gmail' in mx_lower:
                    mx_providers.append('Google Workspace')
                elif 'outlook' in mx_lower or 'microsoft' in mx_lower:
                    mx_providers.append('Microsoft 365')
                elif 'protonmail' in mx_lower:
                    mx_providers.append('ProtonMail')
                elif 'mimecast' in mx_lower:
                    mx_providers.append('Mimecast')
            if mx_providers:
                self.think(
                    f"Mail handled by: {', '.join(set(mx_providers))}",
                    "Email provider identified — useful for phishing simulation scope and social engineering awareness"
                )

        # Check for wildcard DNS
        try:
            random_sub = f"ghost-recon-wildcard-check-{secrets.token_hex(8)}.{self.target}"
            socket.gethostbyname(random_sub)
            self.interesting.append({
                'type': 'wildcard_dns',
                'host': self.target,
                'note': 'Wildcard DNS detected — subdomain enumeration results may include false positives'
            })
            self.think(
                "Wildcard DNS is enabled for this domain",
                "All subdomain results need verification — wildcard resolves everything"
            )
        except socket.gaierror:
            pass  # No wildcard — expected

    # ==================== PORT SCANNING ====================

    def scan_ports(self, host):
        """TCP port scan on common service ports"""
        common_ports = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
            53: 'DNS', 80: 'HTTP', 110: 'POP3', 143: 'IMAP',
            443: 'HTTPS', 445: 'SMB', 993: 'IMAPS', 995: 'POP3S',
            1433: 'MSSQL', 2049: 'NFS', 3000: 'Dev-HTTP',
            3306: 'MySQL', 3389: 'RDP', 4443: 'HTTPS-Alt3',
            5000: 'Dev-HTTP2', 5432: 'PostgreSQL', 5900: 'VNC',
            6379: 'Redis', 8000: 'Dev-HTTP3', 8080: 'HTTP-Alt',
            8443: 'HTTPS-Alt', 8888: 'HTTP-Alt2', 9090: 'Prometheus',
            9200: 'Elasticsearch', 9300: 'ES-Transport',
            11211: 'Memcached', 15672: 'RabbitMQ', 27017: 'MongoDB',
        }

        open_ports = {}

        def check_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1.5)
                result = sock.connect_ex((host, port))
                sock.close()
                if result == 0:
                    return port
            except (socket.error, OSError):
                pass
            return None

        with ThreadPoolExecutor(max_workers=24) as executor:
            futures = {executor.submit(check_port, port): port for port in common_ports}
            for future in as_completed(futures):
                result = future.result()
                if result is not None:
                    open_ports[result] = common_ports[result]

        return open_ports

    def run_port_scan(self):
        """Scan ports on live hosts"""
        hosts_to_scan = [h['host'] for h in self.live_hosts[:15]]
        if not hosts_to_scan:
            hosts_to_scan = [self.target]

        self.log(f"Port scanning {len(hosts_to_scan)} hosts (32 common ports)...")

        for host in hosts_to_scan:
            self.log(f"  Scanning {host}...")
            open_ports = self.scan_ports(host)
            if open_ports:
                self.port_results[host] = open_ports
                ports_str = ', '.join(f"{p}/{s}" for p, s in sorted(open_ports.items()))
                self.log(f"  {C.G}{host}{C.E}: {ports_str}", 'port')

        # Analyze port scan results
        if self.port_results:
            # Check for database ports exposed
            db_ports = {3306: 'MySQL', 5432: 'PostgreSQL', 27017: 'MongoDB',
                        6379: 'Redis', 9200: 'Elasticsearch', 1433: 'MSSQL'}
            exposed_dbs = []
            for host, ports in self.port_results.items():
                for port, service in ports.items():
                    if port in db_ports:
                        exposed_dbs.append((host, port, service))

            if exposed_dbs:
                self.think(
                    f"Found {len(exposed_dbs)} exposed database port(s)",
                    "Database services directly reachable — check for default credentials and auth bypass"
                )
                for host, port, service in exposed_dbs:
                    self.interesting.append({
                        'type': 'exposed_database',
                        'host': host,
                        'port': port,
                        'service': service,
                        'note': f'{service} on port {port} is externally reachable'
                    })

            # Check for management ports
            mgmt_ports = {22: 'SSH', 3389: 'RDP', 5900: 'VNC'}
            for host, ports in self.port_results.items():
                for port, service in ports.items():
                    if port in mgmt_ports:
                        self.interesting.append({
                            'type': 'exposed_management',
                            'host': host,
                            'port': port,
                            'service': service,
                            'note': f'{service} exposed — potential brute force target'
                        })

    # ==================== TLS CERTIFICATE ANALYSIS ====================

    def analyze_tls(self, host):
        """Extract and analyze TLS certificate information"""
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = ctx.wrap_socket(socket.socket(), server_hostname=host)
            conn.settimeout(5)
            conn.connect((host, 443))
            cert = conn.getpeercert(binary_form=True)
            conn.close()

            # Parse with ssl module
            ctx2 = ssl.create_default_context()
            conn2 = ctx2.wrap_socket(socket.socket(), server_hostname=host)
            conn2.settimeout(5)
            try:
                conn2.connect((host, 443))
                cert_info = conn2.getpeercert()
                conn2.close()
            except ssl.SSLCertVerificationError as e:
                # Self-signed or invalid cert
                return {
                    'host': host,
                    'valid': False,
                    'error': str(e),
                    'self_signed': 'self-signed' in str(e).lower() or 'CERTIFICATE_VERIFY_FAILED' in str(e),
                }
            except Exception:
                return None

            # Extract useful fields
            subject = dict(x[0] for x in cert_info.get('subject', ()))
            issuer = dict(x[0] for x in cert_info.get('issuer', ()))
            sans = [entry[1] for entry in cert_info.get('subjectAltName', ())]

            not_after = cert_info.get('notAfter', '')
            expiry = None
            days_until_expiry = None
            if not_after:
                try:
                    expiry = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
                    days_until_expiry = (expiry - datetime.now(timezone.utc)).days
                except (ValueError, TypeError):
                    pass

            info = {
                'host': host,
                'valid': True,
                'subject_cn': subject.get('commonName', ''),
                'issuer_org': issuer.get('organizationName', ''),
                'issuer_cn': issuer.get('commonName', ''),
                'sans': sans,
                'not_after': not_after,
                'days_until_expiry': days_until_expiry,
            }

            # Add new subdomains from SANs
            new_sans = set()
            for san in sans:
                san_clean = san.lower().strip()
                if san_clean.endswith(self.target) and '*' not in san_clean:
                    if san_clean not in self.subdomains:
                        new_sans.add(san_clean)
                        self.subdomains.add(san_clean)

            if new_sans:
                self.think(
                    f"TLS certificate for {host} contains {len(new_sans)} new subdomain(s) in SANs",
                    "Certificate SANs reveal additional infrastructure not found by DNS/CT"
                )

            # Flag issues
            if days_until_expiry is not None and days_until_expiry < 30:
                self.interesting.append({
                    'type': 'tls_expiry_warning',
                    'host': host,
                    'days_remaining': days_until_expiry,
                    'note': f'TLS certificate expires in {days_until_expiry} days'
                })

            return info

        except (socket.error, ssl.SSLError, OSError):
            return None

    def run_tls_analysis(self):
        """Analyze TLS on live HTTPS hosts"""
        https_hosts = set()
        https_hosts.add(self.target)
        for host_data in self.live_hosts:
            if host_data.get('https'):
                https_hosts.add(host_data['host'])

        self.log(f"Analyzing TLS certificates on {len(https_hosts)} hosts...")

        for host in list(https_hosts)[:20]:
            info = self.analyze_tls(host)
            if info:
                self.tls_info[host] = info
                if info.get('valid'):
                    status = f"{C.G}valid{C.E}"
                    if info.get('days_until_expiry') is not None and info['days_until_expiry'] < 30:
                        status = f"{C.Y}expires in {info['days_until_expiry']}d{C.E}"
                    self.log(f"  {host}: {status} (issuer: {info.get('issuer_org', 'unknown')})")
                else:
                    self.log(f"  {host}: {C.R}invalid{C.E} — {info.get('error', 'unknown')[:60]}", 'warn')
                    self.interesting.append({
                        'type': 'tls_invalid',
                        'host': host,
                        'note': 'Invalid or self-signed TLS certificate'
                    })

    # ==================== SECURITY SCORING ====================

    def calculate_security_score(self, host_data):
        """Calculate security posture score (0-100) for a host"""
        host = host_data['host']
        score = 100
        deductions = []

        # Check HTTPS availability
        if not host_data.get('https'):
            score -= 20
            deductions.append(('No HTTPS', -20))
        else:
            headers = host_data['https'].get('headers', {})

            # Security headers
            header_checks = [
                ('Strict-Transport-Security', 15, 'Missing HSTS'),
                ('Content-Security-Policy', 10, 'Missing CSP'),
                ('X-Frame-Options', 5, 'Missing X-Frame-Options'),
                ('X-Content-Type-Options', 5, 'Missing X-Content-Type-Options'),
                ('X-XSS-Protection', 3, 'Missing X-XSS-Protection'),
                ('Referrer-Policy', 3, 'Missing Referrer-Policy'),
                ('Permissions-Policy', 3, 'Missing Permissions-Policy'),
            ]

            for header, penalty, reason in header_checks:
                if not headers.get(header):
                    score -= penalty
                    deductions.append((reason, -penalty))

            # Server version disclosure
            server = headers.get('Server', '')
            if re.search(r'\d+\.\d+', server):
                score -= 5
                deductions.append(('Server version disclosed', -5))

            # X-Powered-By disclosure
            if headers.get('X-Powered-By'):
                score -= 5
                deductions.append(('X-Powered-By header present', -5))

            # Cookie security
            set_cookie = headers.get('Set-Cookie', '')
            if set_cookie:
                if 'httponly' not in set_cookie.lower():
                    score -= 8
                    deductions.append(('Cookie missing HttpOnly', -8))
                if 'secure' not in set_cookie.lower():
                    score -= 8
                    deductions.append(('Cookie missing Secure', -8))
                if 'samesite' not in set_cookie.lower():
                    score -= 5
                    deductions.append(('Cookie missing SameSite', -5))

        # Check HTTP (should redirect to HTTPS)
        if host_data.get('http') and host_data.get('https'):
            http_status = host_data['http'].get('status')
            if http_status and http_status not in [301, 302, 307, 308]:
                score -= 10
                deductions.append(('HTTP does not redirect to HTTPS', -10))

        score = max(0, score)

        return {
            'host': host,
            'score': score,
            'grade': self._score_to_grade(score),
            'deductions': deductions
        }

    def _score_to_grade(self, score):
        if score >= 90: return 'A'
        if score >= 80: return 'B'
        if score >= 70: return 'C'
        if score >= 60: return 'D'
        return 'F'

    def _grade_color(self, grade):
        colors = {'A': C.G, 'B': C.G, 'C': C.Y, 'D': C.Y, 'F': C.R}
        return colors.get(grade, C.W)

    # ==================== HOST ANALYSIS ====================

    def check_host_alive(self, host):
        """Check if host responds on HTTP/HTTPS"""
        results = {'host': host, 'http': None, 'https': None, 'redirect': None}

        for scheme in ['https', 'http']:
            try:
                if scheme == 'https':
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    conn = http.client.HTTPSConnection(host, timeout=5, context=context)
                else:
                    conn = http.client.HTTPConnection(host, timeout=5)

                conn.request('GET', '/', headers={'User-Agent': 'Mozilla/5.0', 'Host': host})
                resp = conn.getresponse()

                # Preserve duplicate headers (e.g. Set-Cookie) by grouping values
                raw_headers = resp.getheaders()
                headers = {}
                for name, value in raw_headers:
                    if name in headers:
                        headers[name] = headers[name] + ', ' + value
                    else:
                        headers[name] = value

                results[scheme] = {
                    'status': resp.status,
                    'headers': headers,
                    'server': resp.getheader('Server', 'Unknown'),
                }

                if resp.status in [301, 302, 303, 307, 308]:
                    results['redirect'] = resp.getheader('Location')

                conn.close()
            except (socket.error, http.client.HTTPException, ssl.SSLError, OSError):
                pass

        return results if (results['http'] or results['https']) else None

    def probe_live_hosts(self):
        """Check which subdomains are alive"""
        self.log(f"Probing {len(self.subdomains)} subdomains...")

        with ThreadPoolExecutor(max_workers=30) as executor:
            futures = {executor.submit(self.check_host_alive, sub): sub for sub in self.subdomains}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    self.live_hosts.append(result)

        self.log(f"Found {len(self.live_hosts)} live hosts", 'success')

        if self.live_hosts:
            self.analyze_hosts()

    def analyze_hosts(self):
        """Think about what the hosts tell us"""
        servers = {}
        interesting_status = []

        for host_data in self.live_hosts:
            host = host_data['host']

            for scheme in ['http', 'https']:
                if host_data[scheme]:
                    server = host_data[scheme].get('server', 'Unknown')
                    servers[server] = servers.get(server, 0) + 1

                    status = host_data[scheme]['status']
                    if status in [401, 403]:
                        interesting_status.append((host, status, scheme))

        if servers:
            most_common = max(servers, key=servers.get)
            self.think(
                f"Most common server: {most_common} ({servers[most_common]} hosts)",
                f"Target primarily uses {most_common}. Focus exploits accordingly."
            )

        if interesting_status:
            self.think(
                f"Found {len(interesting_status)} hosts returning 401/403",
                "These are protected areas — potential high-value targets for auth bypass"
            )
            for host, status, scheme in interesting_status[:5]:
                self.interesting.append({
                    'type': 'protected_endpoint',
                    'host': host,
                    'status': status,
                    'note': 'Try auth bypass, default creds, parameter manipulation'
                })

    # ==================== TECHNOLOGY DETECTION ====================

    def detect_technologies(self, host_data):
        """Fingerprint technologies from headers and responses"""
        techs = []
        host = host_data['host']

        for scheme in ['https', 'http']:
            if not host_data[scheme]:
                continue

            headers = host_data[scheme].get('headers', {})

            # Server detection
            server = headers.get('Server', '')
            if 'nginx' in server.lower():
                techs.append('nginx')
            elif 'apache' in server.lower():
                techs.append('Apache')
            elif 'cloudflare' in server.lower():
                techs.append('Cloudflare')
            elif 'microsoft' in server.lower() or 'iis' in server.lower():
                techs.append('IIS')
            elif 'gunicorn' in server.lower():
                techs.append('Gunicorn')
            elif 'openresty' in server.lower():
                techs.append('OpenResty')
            elif 'caddy' in server.lower():
                techs.append('Caddy')
            elif 'litespeed' in server.lower():
                techs.append('LiteSpeed')

            # Framework detection
            powered_by = headers.get('X-Powered-By', '')
            if 'php' in powered_by.lower():
                techs.append(f'PHP ({powered_by})')
            elif 'asp.net' in powered_by.lower():
                techs.append('ASP.NET')
            elif 'express' in powered_by.lower():
                techs.append('Express.js')
            elif 'next.js' in powered_by.lower():
                techs.append('Next.js')

            # CDN/WAF detection from headers
            if headers.get('CF-RAY'):
                techs.append('Cloudflare CDN')
            if headers.get('X-Amz-Cf-Id') or headers.get('X-Amz-Cf-Pop'):
                techs.append('AWS CloudFront')
            if headers.get('X-Vercel-Id'):
                techs.append('Vercel')
            if headers.get('X-Served-By') and 'cache' in headers.get('X-Served-By', '').lower():
                techs.append('Varnish/Fastly')
            if 'akamai' in str(headers).lower():
                techs.append('Akamai')

            # Security headers analysis
            if not headers.get('X-Frame-Options'):
                self.interesting.append({
                    'type': 'missing_header',
                    'host': host,
                    'header': 'X-Frame-Options',
                    'note': 'Potential clickjacking'
                })

            if not headers.get('Content-Security-Policy'):
                self.interesting.append({
                    'type': 'missing_header',
                    'host': host,
                    'header': 'CSP',
                    'note': 'XSS may be easier to exploit'
                })

            # Cookie analysis
            set_cookie = headers.get('Set-Cookie', '')
            if set_cookie:
                if 'httponly' not in set_cookie.lower():
                    self.interesting.append({
                        'type': 'cookie_issue',
                        'host': host,
                        'note': 'Session cookie missing HttpOnly flag'
                    })
                if 'secure' not in set_cookie.lower() and scheme == 'https':
                    self.interesting.append({
                        'type': 'cookie_issue',
                        'host': host,
                        'note': 'HTTPS but cookie missing Secure flag'
                    })

        return list(set(techs))

    # ==================== INTERESTING ENDPOINT DISCOVERY ====================

    def find_interesting_endpoints(self, host):
        """Check for common interesting paths"""
        interesting_paths = [
            '/.git/HEAD', '/.env', '/.DS_Store', '/robots.txt', '/sitemap.xml',
            '/swagger.json', '/api/swagger.json', '/swagger/v1/swagger.json',
            '/openapi.json', '/api-docs', '/graphql', '/graphiql',
            '/.well-known/security.txt', '/server-status', '/server-info',
            '/phpinfo.php', '/info.php', '/test.php', '/debug',
            '/actuator', '/actuator/health', '/actuator/env',
            '/elmah.axd', '/trace.axd', '/wp-config.php.bak',
            '/config.php.bak', '/.htaccess', '/.htpasswd',
            '/backup.sql', '/dump.sql', '/database.sql',
            '/admin', '/admin/', '/administrator', '/wp-admin',
            '/phpmyadmin', '/pma', '/adminer.php',
            '/.svn/entries', '/.hg/', '/CVS/Root',
            '/crossdomain.xml', '/clientaccesspolicy.xml',
            '/api/health', '/api/status', '/api/version',
            '/metrics', '/prometheus', '/_debug/vars',
            '/wp-json/wp/v2/users', '/api/users', '/api/v1/users',
        ]

        found = []
        for path in interesting_paths:
            for scheme in ['https', 'http']:
                try:
                    if scheme == 'https':
                        context = ssl.create_default_context()
                        context.check_hostname = False
                        context.verify_mode = ssl.CERT_NONE
                        conn = http.client.HTTPSConnection(host, timeout=3, context=context)
                    else:
                        conn = http.client.HTTPConnection(host, timeout=3)

                    conn.request('GET', path, headers={'User-Agent': 'Mozilla/5.0'})
                    resp = conn.getresponse()

                    if resp.status == 200:
                        try:
                            content_length = int(resp.getheader('Content-Length', '0'))
                        except (ValueError, TypeError):
                            content_length = 1
                        if content_length > 0:
                            found.append({
                                'path': path,
                                'status': resp.status,
                                'size': content_length,
                                'scheme': scheme
                            })
                            break
                    elif resp.status in [401, 403]:
                        found.append({
                            'path': path,
                            'status': resp.status,
                            'note': 'Exists but protected',
                            'scheme': scheme
                        })
                        break

                    conn.close()
                except (socket.error, http.client.HTTPException, ssl.SSLError, OSError, ValueError):
                    pass

        return found

    # ==================== REPORT GENERATION ====================

    def generate_report(self):
        """Generate JSON and Markdown reports"""
        self.scan_end = datetime.now()
        duration = (self.scan_end - self.scan_start).total_seconds()

        print()
        self.log(f"{C.Y}=== Analysis Report ==={C.E}", 'info')

        report = {
            'version': VERSION,
            'target': self.target,
            'scan_start': self.scan_start.isoformat(),
            'scan_end': self.scan_end.isoformat(),
            'duration_seconds': round(duration, 1),
            'subdomains': sorted(self.subdomains),
            'live_hosts': len(self.live_hosts),
            'dns_records': self.dns_records,
            'technologies': self.technologies,
            'interesting_findings': self.interesting,
            'attack_surface': self.attack_surface,
            'wayback_urls_count': len(self.wayback_urls),
            'port_scan': {h: {str(p): s for p, s in ports.items()} for h, ports in self.port_results.items()},
            'tls_certificates': {h: {k: v for k, v in info.items() if k != 'host'} for h, info in self.tls_info.items()},
            'security_scores': self.security_scores,
        }

        # Save JSON
        with open(self.output_dir / 'report.json', 'w') as f:
            json.dump(report, f, indent=2, default=str)

        # Save wayback URLs
        if self.wayback_urls:
            with open(self.output_dir / 'wayback_urls.txt', 'w') as f:
                f.write('\n'.join(sorted(self.wayback_urls)))

        # Save subdomains
        with open(self.output_dir / 'subdomains.txt', 'w') as f:
            f.write('\n'.join(sorted(self.subdomains)))

        # Generate Markdown report
        self._generate_markdown_report(report, duration)

        # Print summary
        print(f"\n{C.C}+{'='*46}+{C.E}")
        print(f"{C.C}|{C.E}          {C.W}{C.BOLD}GHOST RECON SUMMARY{C.E}               {C.C}|{C.E}")
        print(f"{C.C}+{'='*46}+{C.E}")
        print(f"{C.C}|{C.E} Subdomains found:     {C.G}{len(self.subdomains):>15}{C.E}   {C.C}|{C.E}")
        print(f"{C.C}|{C.E} Live hosts:           {C.G}{len(self.live_hosts):>15}{C.E}   {C.C}|{C.E}")
        print(f"{C.C}|{C.E} Wayback URLs:         {C.B}{len(self.wayback_urls):>15}{C.E}   {C.C}|{C.E}")
        print(f"{C.C}|{C.E} Open ports found:     {C.C}{sum(len(p) for p in self.port_results.values()):>15}{C.E}   {C.C}|{C.E}")
        print(f"{C.C}|{C.E} TLS certs analyzed:   {C.B}{len(self.tls_info):>15}{C.E}   {C.C}|{C.E}")
        print(f"{C.C}|{C.E} Interesting findings: {C.Y}{len(self.interesting):>15}{C.E}   {C.C}|{C.E}")
        print(f"{C.C}|{C.E} Scan duration:        {C.DIM}{duration:>13.1f}s{C.E}   {C.C}|{C.E}")
        print(f"{C.C}+{'='*46}+{C.E}")

        # Security scores summary
        if self.security_scores:
            print(f"\n{C.Y}Security Scores:{C.E}")
            for host, data in sorted(self.security_scores.items(), key=lambda x: x[1]['score']):
                grade = data['grade']
                color = self._grade_color(grade)
                print(f"  {color}{grade}{C.E} ({data['score']:>3}/100) {host}")

        # High-value targets
        if self.interesting:
            print(f"\n{C.Y}High-Value Targets:{C.E}")
            seen_types = set()
            for finding in self.interesting[:15]:
                key = f"{finding['type']}:{finding.get('host', '')}"
                if key not in seen_types:
                    seen_types.add(key)
                    print(f"  {C.R}>{C.E} {finding['type']}: {finding.get('host', finding.get('count', 'N/A'))}")
                    print(f"    {C.C}  {finding.get('note', '')}{C.E}")

        print(f"\n{C.G}Results saved to: {self.output_dir}{C.E}\n")

    def _generate_markdown_report(self, report, duration):
        """Generate a clean Markdown report"""
        lines = []
        lines.append(f"# Ghost Recon Report: {self.target}")
        lines.append(f"\n**Scanned:** {self.scan_start.strftime('%Y-%m-%d %H:%M:%S')} ({duration:.1f}s)")
        lines.append(f"**Mode:** {'Deep' if self.deep else 'Stealth' if self.stealth else 'Standard'}"
                     + (' + Port Scan' if self.ports else ''))
        lines.append(f"**Version:** {VERSION}\n")

        # Summary table
        lines.append("## Summary\n")
        lines.append("| Metric | Count |")
        lines.append("|--------|-------|")
        lines.append(f"| Subdomains | {len(self.subdomains)} |")
        lines.append(f"| Live Hosts | {len(self.live_hosts)} |")
        lines.append(f"| Wayback URLs | {len(self.wayback_urls)} |")
        lines.append(f"| Open Ports | {sum(len(p) for p in self.port_results.values())} |")
        lines.append(f"| TLS Certs | {len(self.tls_info)} |")
        lines.append(f"| Findings | {len(self.interesting)} |")

        # DNS Records
        if self.dns_records:
            lines.append("\n## DNS Records\n")
            for rtype, values in self.dns_records.items():
                if values:
                    lines.append(f"**{rtype}:** {', '.join(values[:5])}")

        # Security Scores
        if self.security_scores:
            lines.append("\n## Security Scores\n")
            lines.append("| Host | Score | Grade | Issues |")
            lines.append("|------|-------|-------|--------|")
            for host, data in sorted(self.security_scores.items(), key=lambda x: x[1]['score']):
                issues = '; '.join(d[0] for d in data['deductions'][:3])
                if len(data['deductions']) > 3:
                    issues += f" (+{len(data['deductions'])-3} more)"
                lines.append(f"| {host} | {data['score']}/100 | {data['grade']} | {issues} |")

        # Technologies
        if self.technologies:
            lines.append("\n## Technologies Detected\n")
            for host, techs in self.technologies.items():
                lines.append(f"- **{host}**: {', '.join(techs)}")

        # Port Scan Results
        if self.port_results:
            lines.append("\n## Open Ports\n")
            for host, ports in self.port_results.items():
                port_list = ', '.join(f"{p}/{s}" for p, s in sorted(ports.items()))
                lines.append(f"- **{host}**: {port_list}")

        # TLS Info
        if self.tls_info:
            lines.append("\n## TLS Certificates\n")
            for host, info in self.tls_info.items():
                if info.get('valid'):
                    expiry_note = ""
                    if info.get('days_until_expiry') is not None:
                        expiry_note = f" (expires in {info['days_until_expiry']}d)"
                    lines.append(f"- **{host}**: {info.get('issuer_org', 'Unknown')}{expiry_note}")
                    if info.get('sans'):
                        lines.append(f"  - SANs: {', '.join(info['sans'][:5])}")
                else:
                    lines.append(f"- **{host}**: INVALID - {info.get('error', 'unknown')[:80]}")

        # Interesting Findings
        if self.interesting:
            lines.append("\n## Findings\n")
            for finding in self.interesting[:20]:
                lines.append(f"- **{finding['type']}**: {finding.get('host', finding.get('count', ''))}")
                lines.append(f"  - {finding.get('note', '')}")

        # Attack Surface
        if self.attack_surface:
            lines.append("\n## Exposed Endpoints\n")
            for host, endpoints in self.attack_surface.items():
                lines.append(f"\n### {host}\n")
                for ep in endpoints:
                    status_note = f" ({ep.get('note', '')})" if ep.get('note') else ""
                    lines.append(f"- `{ep['path']}` — {ep['status']}{status_note}")

        # Subdomains
        lines.append(f"\n## Subdomains ({len(self.subdomains)})\n")
        lines.append("<details><summary>Click to expand</summary>\n")
        for sub in sorted(self.subdomains):
            lines.append(f"- {sub}")
        lines.append("\n</details>")

        md_path = self.output_dir / 'report.md'
        md_path.write_text('\n'.join(lines))

    def get_json_report(self):
        """Return scan results as a JSON-serializable dict."""
        self.scan_end = datetime.now()
        duration = (self.scan_end - self.scan_start).total_seconds()
        return {
            'version': VERSION,
            'target': self.target,
            'scan_start': self.scan_start.isoformat(),
            'scan_end': self.scan_end.isoformat(),
            'duration_seconds': round(duration, 1),
            'subdomains': sorted(self.subdomains),
            'live_hosts': len(self.live_hosts),
            'dns_records': self.dns_records,
            'technologies': self.technologies,
            'interesting_findings': self.interesting,
            'attack_surface': self.attack_surface,
            'wayback_urls_count': len(self.wayback_urls),
            'port_scan': {h: {str(p): s for p, s in ports.items()} for h, ports in self.port_results.items()},
            'tls_certificates': {h: {k: v for k, v in info.items() if k != 'host'} for h, info in self.tls_info.items()},
            'security_scores': self.security_scores,
        }

    # ==================== MAIN EXECUTION ====================

    def run(self):
        """Execute full recon pipeline"""
        if not self.json_output:
            banner()
        self.scan_start = datetime.now()
        self.log(f"Target: {C.G}{self.target}{C.E}")
        self.log(f"Output: {self.output_dir}")
        self.log(f"Mode: {'Deep' if self.deep else 'Stealth' if self.stealth else 'Standard'}"
                 + (f" + Port Scan" if self.ports else ""))
        print()

        # Phase 1: DNS Intelligence
        self.log(f"{C.Y}=== Phase 1: DNS Intelligence ==={C.E}", 'info')
        self.enumerate_dns()

        # Phase 2: Subdomain Discovery
        print()
        self.log(f"{C.Y}=== Phase 2: Subdomain Discovery ==={C.E}", 'info')
        self.subdomains.add(self.target)
        self.enum_crtsh()
        self.enum_dns_brute()
        if not self.stealth:
            self.run_subfinder()
        self.enum_wayback()

        # Phase 3: Live Host Detection
        print()
        self.log(f"{C.Y}=== Phase 3: Live Host Detection ==={C.E}", 'info')
        self.probe_live_hosts()

        # Phase 4: TLS Certificate Analysis
        print()
        self.log(f"{C.Y}=== Phase 4: TLS Certificate Analysis ==={C.E}", 'info')
        self.run_tls_analysis()

        # Phase 5: Technology Detection + Security Scoring
        print()
        self.log(f"{C.Y}=== Phase 5: Technology Fingerprinting ==={C.E}", 'info')
        for host_data in self.live_hosts:
            techs = self.detect_technologies(host_data)
            if techs:
                self.technologies[host_data['host']] = techs
                self.log(f"{host_data['host']}: {', '.join(techs)}")

            # Security scoring
            score_data = self.calculate_security_score(host_data)
            self.security_scores[host_data['host']] = score_data

        # Phase 6: Port Scanning (optional)
        if self.ports and not self.stealth:
            print()
            self.log(f"{C.Y}=== Phase 6: Port Scanning ==={C.E}", 'info')
            self.run_port_scan()

        # Phase 7: Endpoint Discovery (deep mode)
        if self.deep and self.live_hosts:
            print()
            self.log(f"{C.Y}=== Phase {'7' if self.ports else '6'}: Endpoint Discovery ==={C.E}", 'info')
            sample = self.live_hosts[:10]
            for host_data in sample:
                host = host_data['host']
                self.log(f"Scanning {host}...")
                endpoints = self.find_interesting_endpoints(host)
                if endpoints:
                    self.attack_surface[host] = endpoints
                    for ep in endpoints:
                        self.log(f"  {C.G}Found:{C.E} {ep['path']} ({ep['status']})", 'success')

        # Generate Report
        if self.json_output:
            print(json.dumps(self.get_json_report(), indent=2, default=str))
        else:
            self.generate_report()

        return self


def main():
    parser = argparse.ArgumentParser(
        description='Ghost Recon - Reconnaissance that thinks about what it finds',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  ghost-recon target.com                Basic scan
  ghost-recon target.com --deep         Full scan with endpoint discovery
  ghost-recon target.com --stealth      Skip subfinder/port scan
  ghost-recon target.com --ports        Include port scanning
  ghost-recon target.com --deep --ports Full scan with ports
        """
    )
    parser.add_argument('target', help='Target domain (e.g., example.com)')
    parser.add_argument('--deep', action='store_true', help='Deep scan with endpoint discovery')
    parser.add_argument('--stealth', action='store_true', help='Stealth mode (skips subfinder and port scanning)')
    parser.add_argument('--ports', action='store_true', help='Include port scanning')
    parser.add_argument('-o', '--output', help='Output directory')
    parser.add_argument('--no-color', action='store_true', help='Disable colored output')
    parser.add_argument('--json', action='store_true', help='Output results as JSON to stdout')
    parser.add_argument('--version', action='version', version=f'Ghost Recon v{VERSION}')

    args = parser.parse_args()

    if args.no_color:
        C.disable()

    try:
        recon = GhostRecon(
            target=args.target,
            output_dir=Path(args.output) if args.output else None,
            deep=args.deep,
            stealth=args.stealth,
            ports=args.ports,
            json_output=args.json,
        )
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    recon.run()


if __name__ == '__main__':
    main()
