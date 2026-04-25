# py-AutoRecon

A modular Python-based reconnaissance toolkit built for target validation, subdomain enumeration, TCP port scanning, security header analysis, technology fingerprinting, OSINT collection, directory discovery, and structured report generation.

## Overview

py-AutoRecon is designed as a clean, extensible recon framework rather than a single-purpose script. Each recon capability is implemented as an independent async module, and the scan pipeline orchestrates them into one structured result with progress indicators and rich terminal output.

## Features

### Target Validation
Normalizes and validates domains, IP addresses, and URLs before scanning. Supports single targets and bulk file input.

### Subdomain Enumeration
Discovers subdomains using:
- crt.sh certificate transparency data
- DNS brute-force with configurable wordlist

### Port Scanning
Performs async TCP connect scans with:
- Configurable port ranges and specifications (e.g. `22,80-443,8080`)
- Service detection from known port mappings
- Banner grabbing with protocol-aware probing

### Security Header Analysis
Checks for critical HTTP security headers:
- Content-Security-Policy
- Strict-Transport-Security
- X-Frame-Options
- X-Content-Type-Options
- Referrer-Policy
- Permissions-Policy

### Technology Fingerprinting
Identifies web technologies from:
- Server and X-Powered-By headers
- CDN/WAF detection (Cloudflare, etc.)
- CMS detection (WordPress, Drupal, Joomla)
- Frontend framework hints (React, Vue, Angular, Next.js)
- Meta generator tags

### OSINT Collection
Gathers:
- DNS records (A, AAAA, MX, NS, TXT)
- Summarized WHOIS information with date normalization

### Directory Discovery
Wordlist-based directory and file brute-forcing with:
- HTTPS/HTTP fallback
- Status code filtering
- Concurrency control
- Disabled by default (requires explicit opt-in)

### Reporting
Generates per-target report directories containing:
- `final.json` — Full structured scan data
- `summary.csv` — Module status overview
- `report.html` — HTML dashboard

## Project Structure

```text
py-autoRecon/
├── autorecon/
│   ├── core/
│   │   ├── config_loader.py    # YAML config with deep merge
│   │   ├── pipeline.py         # Async pipeline orchestrator
│   │   └── target.py           # Target parsing & DNS resolution
│   ├── modules/
│   │   ├── base.py             # Abstract base module with timing
│   │   ├── subdomain.py        # crt.sh + DNS brute-force
│   │   ├── portscan.py         # TCP scan + banner grabbing
│   │   ├── headers.py          # Security header analysis
│   │   ├── techfinder.py       # Technology fingerprinting
│   │   ├── osint.py            # WHOIS + DNS records
│   │   └── dirbrute.py         # Directory discovery
│   ├── reporting/
│   │   ├── dashboard.py        # HTML report generator
│   │   └── export.py           # JSON + CSV export
│   ├── wordlists/
│   │   ├── subdomains.txt
│   │   └── directories.txt
│   ├── cli.py                  # CLI entry point with Rich output
│   ├── exceptions.py           # Custom exception hierarchy
│   └── models.py               # Dataclass models for all findings
├── config/
│   └── default.yaml            # Default scan configuration
├── tests/
│   ├── test_target.py          # 14 tests for target parsing
│   ├── test_portscan.py        # 16 tests for port scanning
│   └── test_subdomain.py       # 2 tests for subdomain module
├── reports/                    # Generated reports
├── requirements.txt
├── setup.py
└── README.md
```

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/Tauqeerkhan187/py-autoRecon.git
cd py-autoRecon
```

### 2. Create a virtual environment

```bash
python -m venv .venv
```

### 3. Activate the virtual environment

#### Windows CMD

```cmd
.venv\Scripts\activate
```

#### PowerShell

```powershell
.venv\Scripts\Activate.ps1
```

#### Linux/macOS

```bash
source .venv/bin/activate
```

### 4. Install dependencies

```bash
pip install -r requirements.txt
```

## Usage

### Validate a target

```bash
python -m autorecon.cli validate example.com
```

### Run a full scan

```bash
python -m autorecon.cli scan example.com --full
```

### Print JSON results to terminal

```bash
python -m autorecon.cli scan example.com --full --json
```

### Scan multiple targets from a file

```bash
python -m autorecon.cli scan -f targets.txt --full
```

### Custom output directory

```bash
python -m autorecon.cli scan example.com --full --output my-reports
```

## Example Output

```text
    ___         __        ____
   /   | __  __/ /_____  / __ \___  _________  ____
  / /| |/ / / / __/ __ \/ /_/ / _ \/ ___/ __ \/ __ \
 / ___ / /_/ / /_/ /_/ / _, _/  __/ /__/ /_/ / / / /
/_/  |_\__,_/\__/\____/_/ |_|\___/\___/\____/_/ /_/
                                          v1.0 by TK
Loaded 1 target(s).

──────────────────────── example.com ────────────────────────
  Running dirbrute...

                 Target Summary
┏━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Field        ┃ Value                         ┃
┡━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ Original     │ example.com                   │
│ Normalized   │ example.com                   │
│ Hostname     │ example.com                   │
│ Scheme       │ http                          │
│ Port         │ None                          │
│ Is IP        │ False                         │
│ Resolvable   │ True                          │
│ Resolved IPs │ 104.20.23.154, 172.66.147.243 │
│ Errors       │ -                             │
└──────────────┴───────────────────────────────┘
             Module Summary
┏━━━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━┳━━━━━━━━┓
┃ Module     ┃ Status  ┃ Items ┃ Errors ┃
┡━━━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━╇━━━━━━━━┩
│ subdomain  │ success │     1 │      0 │
│ portscan   │ success │     2 │      0 │
│ headers    │ success │     6 │      0 │
│ techfinder │ success │     2 │      0 │
│ osint      │ success │    10 │      0 │
│ dirbrute   │ skipped │     0 │      1 │
└────────────┴─────────┴───────┴────────┘
Modules run: subdomain, portscan, headers, techfinder, osint, dirbrute
Duration: 4.57 seconds
```

## Running Tests

```bash
pytest tests/ -v
```

32 tests covering target parsing, port scanning, and subdomain enumeration.

```text
tests/test_portscan.py::TestPortParsing::test_single_port PASSED
tests/test_portscan.py::TestPortParsing::test_multiple_ports PASSED
tests/test_portscan.py::TestPortParsing::test_port_range PASSED
...
tests/test_target.py::TestParseTarget::test_resolvable_domain PASSED
tests/test_target.py::TestLoadTargetsFromFile::test_valid_file PASSED
========================= 32 passed in 0.37s =========================
```

## Output

Each scan creates a dedicated report directory:

```text
reports/<target>/
├── final.json      # Complete structured scan data
├── summary.csv     # Module status summary
└── report.html     # HTML dashboard report
```

## Configuration

Default scan behavior is controlled through `config/default.yaml`:

```yaml
scan:
  timeout: 10
  concurrency: 100
  rate_limit: 0.2
  user_agent: "AutoRecon/1.0"

subdomains:
  enable_crtsh: true
  enable_bruteforce: true

portscan:
  ports: "80,443"
  banner_grab: true

dirbrute:
  enabled: false          # Requires explicit opt-in
```

You can override any setting with a custom config file:

```bash
python -m autorecon.cli --config my_config.yaml scan example.com --full
```

## Current Status — v1.0

All core modules are implemented and tested:

* 6 recon modules (subdomain, portscan, headers, techfinder, osint, dirbrute)
* Async pipeline with per-module progress indicators
* 3 report formats (JSON, CSV, HTML)
* 32 unit tests passing
* CLI with banner and rich terminal output

## Roadmap

* Interactive HTML dashboard with dark theme
* Optional module selection from CLI flags
* Rate limiting between requests
* TLS certificate analysis
* GitHub Actions CI pipeline
* Expanded wordlists

## Legal Notice

Use this tool only on systems, domains, and infrastructure that you own or are explicitly authorized to assess. Unauthorized scanning may be illegal and unethical.

## Author

**TK**