#!/usr/bin/env python3
"""
Ghost Recon - AI-Powered Intelligent Reconnaissance

Not just running tools - THINKING about what they find.
Combines multiple sources, deduplicates, analyzes, prioritizes.

Usage:
    python ghost.py target.com
    python ghost.py target.com --deep
    python ghost.py target.com --stealth
"""

import subprocess
import json
import sys
import os
import re
import argparse
import hashlib
import socket
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
import ssl
import http.client

# Colors
class C:
    R = '\033[91m'  # Red
    G = '\033[92m'  # Green
    Y = '\033[93m'  # Yellow
    B = '\033[94m'  # Blue
    M = '\033[95m'  # Magenta
    C = '\033[96m'  # Cyan
    W = '\033[97m'  # White
    E = '\033[0m'   # End

def banner():
    print(f"""{C.M}
   ▄████  ██░ ██  ▒█████    ██████ ▄▄▄█████▓
  ██▒ ▀█▒▓██░ ██▒▒██▒  ██▒▒██    ▒ ▓  ██▒ ▓▒
 ▒██░▄▄▄░▒██▀▀██░▒██░  ██▒░ ▓██▄   ▒ ▓██░ ▒░
 ░▓█  ██▓░▓█ ░██ ▒██   ██░  ▒   ██▒░ ▓██▓ ░
 ░▒▓███▀▒░▓█▒░██▓░ ████▓▒░▒██████▒▒  ▒██▒ ░
  ░▒   ▒  ▒ ░░▒░▒░ ▒░▒░▒░ ▒ ▒▓▒ ▒ ░  ▒ ░░
    R E C O N  {C.W}v1.0{C.E}
    """)

class GhostRecon:
    def __init__(self, target, output_dir=None, deep=False, stealth=False):
        self.target = target.replace('https://', '').replace('http://', '').rstrip('/')
        self.deep = deep
        self.stealth = stealth
        self.output_dir = output_dir or Path.home() / '.bounty' / 'targets' / self.target
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.subdomains = set()
        self.live_hosts = []
        self.technologies = {}
        self.interesting = []
        self.attack_surface = {}

    def log(self, msg, level='info'):
        icons = {'info': f'{C.B}[*]{C.E}', 'success': f'{C.G}[+]{C.E}',
                 'warn': f'{C.Y}[!]{C.E}', 'error': f'{C.R}[-]{C.E}',
                 'think': f'{C.M}[◆]{C.E}'}
        print(f"{icons.get(level, icons['info'])} {msg}")

    def think(self, observation, conclusion):
        """AI-like reasoning about findings"""
        print(f"\n{C.M}  ◆ Observation:{C.E} {observation}")
        print(f"{C.C}  → Conclusion:{C.E} {conclusion}\n")

    # ==================== SUBDOMAIN ENUMERATION ====================

    def enum_crtsh(self):
        """Certificate Transparency logs"""
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
        except Exception as e:
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
            'upload', 'uploads', 'files', 'download', 'downloads', 'export'
        ]

        def check_subdomain(sub):
            fqdn = f"{sub}.{self.target}"
            try:
                socket.gethostbyname(fqdn)
                return fqdn
            except:
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
        except Exception as e:
            self.log(f"Subfinder error: {e}", 'warn')

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

                results[scheme] = {
                    'status': resp.status,
                    'headers': dict(resp.getheaders()),
                    'server': resp.getheader('Server', 'Unknown'),
                }

                # Check for redirects
                if resp.status in [301, 302, 303, 307, 308]:
                    results['redirect'] = resp.getheader('Location')

                conn.close()
            except Exception as e:
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

        # Analyze what we found
        if self.live_hosts:
            self.analyze_hosts()

    def analyze_hosts(self):
        """Think about what the hosts tell us"""
        servers = {}
        interesting_status = []

        for host_data in self.live_hosts:
            host = host_data['host']

            # Collect server types
            for scheme in ['http', 'https']:
                if host_data[scheme]:
                    server = host_data[scheme].get('server', 'Unknown')
                    servers[server] = servers.get(server, 0) + 1

                    status = host_data[scheme]['status']
                    if status in [401, 403]:
                        interesting_status.append((host, status, scheme))

        # Think about servers
        if servers:
            most_common = max(servers, key=servers.get)
            self.think(
                f"Most common server: {most_common} ({servers[most_common]} hosts)",
                f"Target primarily uses {most_common}. Focus exploits accordingly."
            )

        # Think about 401/403
        if interesting_status:
            self.think(
                f"Found {len(interesting_status)} hosts returning 401/403",
                "These are protected areas - potential high-value targets for auth bypass"
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

            # Framework detection
            powered_by = headers.get('X-Powered-By', '')
            if 'php' in powered_by.lower():
                techs.append(f'PHP ({powered_by})')
            elif 'asp.net' in powered_by.lower():
                techs.append('ASP.NET')
            elif 'express' in powered_by.lower():
                techs.append('Express.js')

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
            '/.svn/entries', '/.hg/', '/CVS/Root'
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
                        content_length = resp.getheader('Content-Length', '0')
                        if int(content_length) > 0:
                            found.append({
                                'path': path,
                                'status': resp.status,
                                'size': content_length,
                                'scheme': scheme
                            })
                            break  # Found on one scheme, no need to check other
                    elif resp.status in [401, 403]:
                        found.append({
                            'path': path,
                            'status': resp.status,
                            'note': 'Exists but protected',
                            'scheme': scheme
                        })
                        break

                    conn.close()
                except:
                    pass

        return found

    # ==================== MAIN EXECUTION ====================

    def run(self):
        """Execute full recon pipeline"""
        banner()
        self.log(f"Target: {C.G}{self.target}{C.E}")
        self.log(f"Output: {self.output_dir}")
        print()

        # Phase 1: Subdomain Enumeration
        self.log(f"{C.Y}═══ Phase 1: Subdomain Discovery ═══{C.E}", 'info')
        self.subdomains.add(self.target)  # Add main domain
        self.enum_crtsh()
        self.enum_dns_brute()
        if not self.stealth:
            self.run_subfinder()

        # Save subdomains
        with open(self.output_dir / 'subdomains.txt', 'w') as f:
            f.write('\n'.join(sorted(self.subdomains)))

        # Phase 2: Live Host Detection
        print()
        self.log(f"{C.Y}═══ Phase 2: Live Host Detection ═══{C.E}", 'info')
        self.probe_live_hosts()

        # Phase 3: Technology Detection
        print()
        self.log(f"{C.Y}═══ Phase 3: Technology Fingerprinting ═══{C.E}", 'info')
        for host_data in self.live_hosts:
            techs = self.detect_technologies(host_data)
            if techs:
                self.technologies[host_data['host']] = techs
                self.log(f"{host_data['host']}: {', '.join(techs)}")

        # Phase 4: Interesting Endpoint Discovery (sample of hosts)
        if self.deep and self.live_hosts:
            print()
            self.log(f"{C.Y}═══ Phase 4: Endpoint Discovery ═══{C.E}", 'info')
            sample = self.live_hosts[:10]  # Check first 10 hosts
            for host_data in sample:
                host = host_data['host']
                self.log(f"Scanning {host}...")
                endpoints = self.find_interesting_endpoints(host)
                if endpoints:
                    self.attack_surface[host] = endpoints
                    for ep in endpoints:
                        self.log(f"  {C.G}Found:{C.E} {ep['path']} ({ep['status']})", 'success')

        # Generate Report
        self.generate_report()

        return self

    def generate_report(self):
        """Generate analysis report"""
        print()
        self.log(f"{C.Y}═══ Analysis Report ═══{C.E}", 'info')

        report = {
            'target': self.target,
            'timestamp': datetime.now().isoformat(),
            'subdomains': list(self.subdomains),
            'live_hosts': len(self.live_hosts),
            'technologies': self.technologies,
            'interesting_findings': self.interesting,
            'attack_surface': self.attack_surface
        }

        # Save JSON report
        with open(self.output_dir / 'report.json', 'w') as f:
            json.dump(report, f, indent=2)

        # Print summary
        print(f"\n{C.C}╔══════════════════════════════════════════╗{C.E}")
        print(f"{C.C}║{C.E}          {C.W}GHOST RECON SUMMARY{C.E}             {C.C}║{C.E}")
        print(f"{C.C}╠══════════════════════════════════════════╣{C.E}")
        print(f"{C.C}║{C.E} Subdomains found:     {C.G}{len(self.subdomains):>15}{C.E}   {C.C}║{C.E}")
        print(f"{C.C}║{C.E} Live hosts:           {C.G}{len(self.live_hosts):>15}{C.E}   {C.C}║{C.E}")
        print(f"{C.C}║{C.E} Interesting findings: {C.Y}{len(self.interesting):>15}{C.E}   {C.C}║{C.E}")
        print(f"{C.C}╚══════════════════════════════════════════╝{C.E}")

        # Print high-value targets
        if self.interesting:
            print(f"\n{C.Y}High-Value Targets:{C.E}")
            for finding in self.interesting[:10]:
                print(f"  • {finding['type']}: {finding.get('host', 'N/A')}")
                print(f"    {C.C}→ {finding.get('note', '')}{C.E}")

        print(f"\n{C.G}Results saved to: {self.output_dir}{C.E}\n")


def main():
    parser = argparse.ArgumentParser(description='Ghost Recon - Reconnaissance that thinks about what it finds')
    parser.add_argument('target', help='Target domain (e.g., example.com)')
    parser.add_argument('--deep', action='store_true', help='Deep scan (slower, more thorough)')
    parser.add_argument('--stealth', action='store_true', help='Stealth mode (passive only)')
    parser.add_argument('-o', '--output', help='Output directory')

    args = parser.parse_args()

    recon = GhostRecon(
        target=args.target,
        output_dir=Path(args.output) if args.output else None,
        deep=args.deep,
        stealth=args.stealth
    )
    recon.run()


if __name__ == '__main__':
    main()
