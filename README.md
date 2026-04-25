````markdown
# Py-AutoRecon

A modular Python-based reconnaissance tool built for validating targets, enumerating subdomains, scanning TCP ports, analyzing security headers, fingerprinting web technologies, collecting OSINT, and generating structured reports.

## Overview

Py-AutoRecon is designed as a clean, extensible recon framework rather than a single-purpose script. Each recon capability is implemented as an independent module, and the scan pipeline orchestrates them into one structured result.

The current implementation supports:

- Target parsing and validation
- Subdomain enumeration
  - crt.sh certificate transparency lookup
  - DNS brute-force
- TCP connect port scanning
- Basic banner grabbing
- HTTP security header analysis
- Technology fingerprinting
- OSINT collection
  - DNS records
  - WHOIS summary
- Report generation
  - JSON
  - CSV
  - HTML

## Features

### Target Validation
Normalizes and validates domains, IP addresses, and URLs before scanning.

### Subdomain Enumeration
Discovers subdomains using:
- crt.sh certificate transparency data
- DNS brute-force using a wordlist

### Port Scanning
Performs TCP connect scans on configured ports and attempts basic banner detection.

### Security Header Analysis
Checks for important HTTP response headers such as:
- Content-Security-Policy
- Strict-Transport-Security
- X-Frame-Options
- X-Content-Type-Options
- Referrer-Policy
- Permissions-Policy

### Technology Fingerprinting
Extracts high-confidence and medium-confidence technology indicators from:
- response headers
- HTML content
- known framework/CMS hints

### OSINT
Collects:
- A / AAAA / MX / NS / TXT records
- summarized WHOIS information

### Reporting
Writes scan artifacts into a per-target report folder:
- `final.json`
- `summary.csv`
- `report.html`

## Project Structure

```text
autorecon/
├── autorecon/
│   ├── core/
│   │   ├── config_loader.py
│   │   ├── pipeline.py
│   │   └── target.py
│   ├── modules/
│   │   ├── base.py
│   │   ├── subdomain.py
│   │   ├── portscan.py
│   │   ├── headers.py
│   │   ├── techfinder.py
│   │   ├── osint.py
│   │   └── dirbrute.py
│   ├── reporting/
│   │   ├── export.py
│   │   ├── dashboard.py
│   │   └── templates/
│   ├── wordlists/
│   │   ├── subdomains.txt
│   │   └── directories.txt
│   ├── cli.py
│   ├── exceptions.py
│   ├── models.py
│   └── __init__.py
├── config/
│   └── default.yaml
├── reports/
├── tests/
├── README.md
├── requirements.txt
└── setup.py
````

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/YOUR-USERNAME/py-autorecon.git
cd py-autorecon
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

### Print JSON to the terminal

```bash
python -m autorecon.cli scan example.com --full --json
```

### Scan multiple targets from a file

```bash
python -m autorecon.cli scan -f targets.txt --full
```

## Output

Each scan creates a dedicated report directory:

```text
reports/<target>/
├── final.json
├── summary.csv
└── report.html
```

## Configuration

Default scan behavior is controlled through:

```text
config/default.yaml
```

You can customize:

* timeout
* concurrency
* rate limiting
* port ranges
* enabled/disabled modules
* wordlist paths
* output behavior

## Example Modules

### Subdomain Module

Enumerates subdomains from external data and DNS brute-force.

### PortScan Module

Finds open TCP ports and identifies basic services from port numbers and banners.

### Headers Module

Checks common web security headers and summarizes missing protections.

### TechFinder Module

Identifies web stack hints such as:

* server software
* CDN/WAF usage
* CMS/framework clues

### OSINT Module

Collects DNS records and summarized WHOIS information.

### DirBrute Module

Supports wordlist-based directory and file discovery against web targets.

## Current Status

The current version already supports:

* working CLI execution
* target validation
* modular pipeline execution
* report generation
* JSON, CSV, and HTML outputs

## Roadmap

Planned improvements include:

* smarter module chaining based on discovered services
* better TLS-aware probing
* improved HTML dashboard styling
* more advanced tech fingerprinting
* stronger directory brute-force logic
* better test coverage
* cleaner terminal summaries
* optional module selection from CLI

## Legal Notice

Use this tool only on systems, domains, and infrastructure that you own or are explicitly authorized to assess.

Unauthorized scanning may be illegal and unethical.

## Author

**TK**

```
