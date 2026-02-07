<p align="center">
  <h1 align="center">Ghost Recon</h1>
  <p align="center">
    <b>Reconnaissance that thinks about what it finds.</b>
    <br />
    <i>DNS intelligence, subdomain discovery, Wayback Machine history, TLS analysis, port scanning, security scoring — zero dependencies.</i>
  </p>
</p>

<p align="center">
  <a href="#features">Features</a> &bull;
  <a href="#install">Install</a> &bull;
  <a href="#usage">Usage</a> &bull;
  <a href="#how-it-works">How It Works</a> &bull;
  <a href="#output">Output</a>
</p>

---

Most recon tools dump raw data and leave analysis to you. Ghost Recon runs a multi-phase pipeline and adds a reasoning layer that correlates findings, flags security misconfigurations, and prioritizes targets by exploitability.

```
  ~ Observation: SPF record includes: _spf.google.com, mailgun.org
  > Conclusion: These are authorized email services — reveals third-party integrations

  ~ Observation: Found 3 hosts returning 401/403
  > Conclusion: These are protected areas — potential high-value targets for auth bypass

  ~ Observation: Wayback Machine revealed 4 subdomains not found by other methods
  > Conclusion: Historical data exposes subdomains that may have been decommissioned but not cleaned up

Security Scores:
  F ( 35/100) staging.example.com
  C ( 72/100) api.example.com
  A ( 95/100) www.example.com
```

## Features

- **DNS intelligence** — Full record enumeration (A, AAAA, MX, TXT, NS, CNAME, SOA), SPF/DMARC analysis, wildcard detection, email provider identification
- **Multi-source subdomain enumeration** — Certificate Transparency (crt.sh), DNS brute force (140+ common names), subfinder integration
- **Wayback Machine discovery** — Historical URL extraction via CDX API, subdomain extraction from archived URLs, sensitive pattern detection
- **Live host probing** — Concurrent HTTP/HTTPS checks with redirect detection
- **TLS certificate analysis** — Validity checks, expiry warnings, issuer identification, SAN extraction for additional subdomains
- **Technology fingerprinting** — Server, framework, and CDN/WAF detection (nginx, Apache, Cloudflare, AWS CloudFront, Vercel, Akamai, and more)
- **Security scoring** — 0-100 score per host with letter grades (A-F) based on headers, cookies, TLS, and configuration
- **Port scanning** — Concurrent TCP scan on 32 common service ports with database/management exposure alerts
- **Endpoint discovery** — 50+ sensitive path checks (.git, .env, swagger, graphql, admin, metrics, user enumeration)
- **Intelligent analysis** — Reasoning layer correlates findings into actionable conclusions
- **Dual reporting** — JSON (machine-readable) and Markdown (human-readable) reports
- **Zero external dependencies** — Pure Python 3 standard library
- **Stealth mode** — Skips subfinder and port scanning, but still performs DNS brute force, HTTP probing, and TLS checks

## Install

```bash
# Clone and use directly
git clone https://github.com/invaen/ghost-recon.git
cd ghost-recon
python ghost_recon.py target.com

# Or install with pip
pip install .

# Then use from anywhere
ghost-recon target.com
```

**Requirements:** Python 3.8+. No external packages.

Optional tools (auto-detected):
- [subfinder](https://github.com/projectdiscovery/subfinder) — additional subdomain sources
- `dig` — extended DNS record types (MX, TXT, NS, CNAME, SOA). Pre-installed on macOS/Linux.

## Usage

```bash
# Basic reconnaissance
ghost-recon target.com

# Deep scan — includes endpoint discovery on live hosts
ghost-recon target.com --deep

# Include port scanning
ghost-recon target.com --ports

# Full scan — everything enabled
ghost-recon target.com --deep --ports

# Stealth mode — skips subfinder/port scanning, still does DNS/HTTP/TLS checks
ghost-recon target.com --stealth

# Custom output directory
ghost-recon target.com -o ./results

# Check version
ghost-recon --version
```

### Scan Modes

| Mode | DNS | Subdomains | Wayback | Live Probe | TLS | Tech + Score | Ports | Endpoints |
|------|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| Default | Yes | crt.sh + DNS + subfinder | Yes | Yes | Yes | Yes | No | No |
| `--ports` | Yes | crt.sh + DNS + subfinder | Yes | Yes | Yes | Yes | Yes | No |
| `--deep` | Yes | crt.sh + DNS + subfinder | Yes | Yes | Yes | Yes | No | Yes |
| `--deep --ports` | Yes | crt.sh + DNS + subfinder | Yes | Yes | Yes | Yes | Yes | Yes |
| `--stealth` | Yes | crt.sh + DNS only | Yes | Yes | Yes | Yes | No | No |

## How It Works

Ghost Recon runs a seven-phase pipeline:

```
Phase 1: DNS Intelligence
├── A/AAAA record resolution
├── MX, TXT, NS, CNAME, SOA via dig
├── SPF/DMARC policy analysis
├── Email provider identification
└── Wildcard DNS detection

Phase 2: Subdomain Discovery
├── Certificate Transparency (crt.sh)
├── DNS brute force (140+ names, 50 threads)
├── subfinder (if installed)
└── Wayback Machine CDX API
    ├── Historical URL extraction
    ├── Subdomain extraction from archived URLs
    └── Sensitive pattern flagging

Phase 3: Live Host Detection
└── Concurrent HTTP/HTTPS probing (30 threads)
    └── Redirect chain tracking

Phase 4: TLS Certificate Analysis
├── Certificate validity and expiry
├── Issuer identification
├── SAN extraction (discovers new subdomains)
└── Self-signed certificate detection

Phase 5: Technology Fingerprinting + Security Scoring
├── Server header analysis (nginx, Apache, Cloudflare, IIS, Caddy, LiteSpeed, ...)
├── Framework detection (PHP, ASP.NET, Express.js, Next.js)
├── CDN/WAF detection (Cloudflare, CloudFront, Vercel, Akamai, Fastly)
├── Security header audit (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, ...)
├── Cookie security (HttpOnly, Secure, SameSite)
└── Security score calculation (0-100, A-F grades)

Phase 6: Port Scanning (--ports)
├── 32 common TCP ports (concurrent)
├── Database exposure detection (MySQL, PostgreSQL, MongoDB, Redis, Elasticsearch)
└── Management port alerts (SSH, RDP, VNC)

Phase 7: Endpoint Discovery (--deep)
└── 50+ sensitive path checks
    ├── Version control (.git, .svn, .hg)
    ├── Config files (.env, .htaccess, .htpasswd)
    ├── API documentation (swagger, openapi, graphql)
    ├── Admin panels (admin, wp-admin, phpmyadmin)
    ├── Monitoring (actuator, metrics, prometheus)
    └── User enumeration (wp-json/users, api/users)
```

At each phase, the reasoning layer generates observations and conclusions based on aggregate data.

## Output

Results are saved to `~/.bounty/targets/<domain>/` (or custom path with `-o`):

```
target.com/
├── subdomains.txt      # One subdomain per line
├── wayback_urls.txt    # Historical URLs from Wayback Machine
├── report.json         # Full structured JSON report
└── report.md           # Human-readable Markdown report
```

### Report Structure (JSON)

```json
{
  "version": "2.0.0",
  "target": "example.com",
  "scan_start": "2026-01-27T12:00:00",
  "duration_seconds": 45.2,
  "subdomains": ["api.example.com", "staging.example.com"],
  "dns_records": {
    "A": ["93.184.216.34"],
    "MX": ["10 mail.example.com"],
    "TXT": ["v=spf1 include:_spf.google.com ~all"]
  },
  "technologies": {
    "api.example.com": ["nginx", "Express.js", "Cloudflare CDN"]
  },
  "security_scores": {
    "api.example.com": {
      "score": 72,
      "grade": "C",
      "deductions": [["Missing HSTS", -15], ["Missing CSP", -10]]
    }
  },
  "port_scan": {
    "api.example.com": {"80": "HTTP", "443": "HTTPS", "22": "SSH"}
  },
  "tls_certificates": {
    "api.example.com": {
      "valid": true,
      "issuer_org": "Let's Encrypt",
      "days_until_expiry": 47,
      "sans": ["api.example.com", "www.example.com"]
    }
  }
}
```

## Integrating with Other Tools

```bash
# Feed subdomains into httpx
cat ~/.bounty/targets/target.com/subdomains.txt | httpx -silent

# Feed into nuclei
ghost-recon target.com --deep
cat ~/.bounty/targets/target.com/subdomains.txt | httpx -silent | nuclei -t cves/

# Parse security scores with jq
cat report.json | jq '.security_scores | to_entries[] | select(.value.grade == "F") | .key'

# Extract hosts with exposed databases
cat report.json | jq '.interesting_findings[] | select(.type == "exposed_database")'

# Check Wayback URLs for sensitive patterns
cat ~/.bounty/targets/target.com/wayback_urls.txt | grep -iE '(admin|config|backup|\.sql|\.env)'
```

## Changelog

### v2.0.0
- Added DNS intelligence phase (MX, TXT, NS, CNAME, SOA, SPF/DMARC analysis, wildcard detection)
- Added Wayback Machine URL discovery via CDX API
- Added TLS certificate analysis (validity, expiry, issuer, SAN extraction)
- Added port scanning (32 common ports, database/management exposure detection)
- Added security scoring system (0-100 with A-F grades)
- Added Markdown report generation
- Expanded technology detection (CDN/WAF: Cloudflare, CloudFront, Vercel, Akamai, Fastly)
- Expanded endpoint checks to 50+ paths
- Expanded DNS brute force wordlist to 140+ entries
- Added `--ports` and `--version` flags
- Added scan timing and duration tracking

### v1.0.0
- Initial release

## Legal Disclaimer

This tool is intended for **authorized security testing only**. Always obtain written permission before scanning any target. Unauthorized scanning may violate applicable laws. The author assumes no liability for misuse.

## License

MIT
