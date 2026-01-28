<p align="center">
  <h1 align="center">Ghost Recon</h1>
  <p align="center">
    <b>Reconnaissance that thinks about what it finds.</b>
    <br />
    <i>Subdomain discovery, live host probing, technology fingerprinting, and intelligent analysis — zero dependencies.</i>
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

Most recon tools dump raw data and leave analysis to you. Ghost Recon runs the same enumeration pipeline — crt.sh, DNS brute force, subfinder — but adds a reasoning layer that correlates findings, flags security misconfigurations, and prioritizes targets by exploitability.

```
  ◆ Observation: Most common server: nginx (12 hosts)
  → Conclusion: Target primarily uses nginx. Focus exploits accordingly.

  ◆ Observation: Found 3 hosts returning 401/403
  → Conclusion: These are protected areas - potential high-value targets for auth bypass
```

## Features

- **Multi-source subdomain enumeration** — Certificate Transparency (crt.sh), DNS brute force (120+ common names), subfinder integration
- **Live host probing** — Concurrent HTTP/HTTPS checks with redirect detection
- **Technology fingerprinting** — Server identification, framework detection via headers (X-Powered-By, cookies)
- **Security header analysis** — Missing CSP, X-Frame-Options, cookie flags (HttpOnly, Secure)
- **Intelligent analysis** — Correlates findings and surfaces high-value targets with reasoning
- **Endpoint discovery** — Checks 40+ common sensitive paths (.git, .env, swagger, actuator, admin panels)
- **Zero external dependencies** — Pure Python 3 standard library
- **Stealth mode** — Passive-only enumeration (no active probing)
- **JSON reports** — Machine-readable output for pipeline integration

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

Optional: Install [subfinder](https://github.com/projectdiscovery/subfinder) for additional subdomain sources. Ghost Recon auto-detects and integrates it if available.

## Usage

```bash
# Basic reconnaissance
ghost-recon target.com

# Deep scan — includes endpoint discovery on live hosts
ghost-recon target.com --deep

# Stealth mode — passive sources only, no active connections to target
ghost-recon target.com --stealth

# Custom output directory
ghost-recon target.com -o ./results
```

### Scan Modes

| Mode | Subdomain Enum | Live Probing | Tech Detection | Endpoint Scan |
|------|:-:|:-:|:-:|:-:|
| Default | crt.sh + DNS + subfinder | Yes | Yes | No |
| `--deep` | crt.sh + DNS + subfinder | Yes | Yes | Yes (top 10 hosts) |
| `--stealth` | crt.sh + DNS only | Yes | Yes | No |

## How It Works

Ghost Recon runs a four-phase pipeline:

```
Phase 1: Subdomain Discovery
├── Certificate Transparency (crt.sh)
├── DNS brute force (120+ common names, 50 concurrent threads)
└── subfinder (if installed)

Phase 2: Live Host Detection
└── Concurrent HTTP/HTTPS probing (30 threads)
    └── Redirect chain tracking

Phase 3: Technology Fingerprinting
├── Server header analysis (nginx, Apache, Cloudflare, IIS)
├── Framework detection (PHP, ASP.NET, Express.js)
├── Security header audit (CSP, X-Frame-Options, HSTS)
└── Cookie security analysis (HttpOnly, Secure flags)

Phase 4: Endpoint Discovery (--deep)
└── 40+ sensitive path checks (.git, .env, swagger, graphql, admin)
```

At each phase, the reasoning layer generates observations and conclusions based on the aggregate data — not just individual findings.

## Output

Results are saved to `~/.bounty/targets/<domain>/` (or custom path with `-o`):

```
target.com/
├── subdomains.txt    # One subdomain per line
└── report.json       # Full structured report
```

### Report Structure

```json
{
  "target": "example.com",
  "timestamp": "2026-01-27T12:00:00",
  "subdomains": ["api.example.com", "staging.example.com", "..."],
  "live_hosts": 15,
  "technologies": {
    "api.example.com": ["nginx", "Express.js"],
    "staging.example.com": ["Apache", "PHP (7.4)"]
  },
  "interesting_findings": [
    {
      "type": "missing_header",
      "host": "api.example.com",
      "header": "CSP",
      "note": "XSS may be easier to exploit"
    }
  ],
  "attack_surface": {
    "example.com": [
      {"path": "/.git/HEAD", "status": 200, "size": "23"}
    ]
  }
}
```

## Integrating with Other Tools

Ghost Recon outputs are designed to feed into your existing workflow:

```bash
# Feed subdomains into httpx
cat ~/.bounty/targets/target.com/subdomains.txt | httpx -silent

# Feed into nuclei
ghost-recon target.com --deep
cat ~/.bounty/targets/target.com/subdomains.txt | httpx -silent | nuclei -t cves/

# Parse report with jq
cat ~/.bounty/targets/target.com/report.json | jq '.interesting_findings[] | select(.type == "missing_header")'
```

## Legal Disclaimer

This tool is intended for **authorized security testing only**. Always obtain written permission before scanning any target. Unauthorized scanning may violate applicable laws. The author assumes no liability for misuse.

## License

MIT
