# 🌊 WAVE - Website Assessment Vulnerability Engine

[![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)](https://www.python.org/)
[![OWASP](https://img.shields.io/badge/OWASP-Top%2010%202025-orange.svg)](https://owasp.org/Top10/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**WAVE** is a Python-based CLI tool for automated web vulnerability assessment and attack surface enumeration. It integrates industry-standard tools (Gobuster) with custom OWASP Top 10 scanners to generate comprehensive PDF security reports.

## 🚀 Features

### 🔍 Reconnaissance
- **Directory Enumeration** (Gobuster dir mode)
- **Subdomain Discovery** (Gobuster DNS mode)
- **Internal Link Scraping** (Regex-based)

### 🛡️ OWASP Top 10 2025 Scanners
- ✅ **A02:2025** - Security Misconfiguration (HTTP headers: CSP, HSTS, X-Frame-Options)
- ✅ **A04:2025** - Cryptographic Failures (HTTPS redirect, SSL/TLS validation, certificate expiry)

### 📊 Reporting
- **PDF Report Generation** (ReportLab)
- **Executive Summary** with vulnerability counts
- **Categorized Findings** (Directories, Security Issues, Crypto Issues, Injection Risks)

## 📦 Installation

### Prerequisites
- Python 3.9+
- [Gobuster](https://github.com/OJ/gobuster) (for directory/subdomain enumeration)
- Linux/macOS (tested on Kali Linux)

### Install from source

```bash
# Clone the repository
git clone https://github.com/Henry-Felix-Faure/wave-project
cd wave

# Install with pipx (recommended for CLI tools)
pipx install -e .
```

### Verify installation

```bash
wave --version
```

## 🎯 Usage

### Basic Scan

```bash
wave scan https://example.com
```

This runs all checks (Gobuster, security headers, crypto, injection) and generates a PDF report.

### Options

```bash
wave scan https://example.com \
  --output report.pdf \
  --gobuster-wordlist /path/to/wordlist.txt \
  --subdomain-wordlist /path/to/subdomains.txt \
  --link-limit 50
```

| Option | Description | Default |
|--------|-------------|---------|
| `--output, -o` | Output PDF path | `wave_report_<domain>.pdf` |
| `--gobuster-wordlist, -g` | Gobuster dir wordlist | `dir-big.txt` |
| `--subdomain-wordlist, -s` | Subdomain wordlist | `subdomains-top1million-20000.txt` |
| `--link-limit, -l` | Max internal links to scrape | `100` |

## 📁 Project Structure

```
wave/
├── src/wave/
│   ├── cli.py              # Click CLI commands
│   ├── scanners/
│   │   ├── gobuster_scanner.py
│   │   ├── subdomain_scanner.py
│   │   ├── internal_links_scraper.py
│   │   └── owasp/
│   │       ├── A02_security_headers.py
│   │       └── A04_cryptographic_failures.py
│   ├── report_parser.py    # Parses scan outputs
│   ├── report_generator.py # PDF generation (ReportLab)
│   └── utils.py            # Helper functions
├── wordlists/              # Embedded wordlists
├── pyproject.toml
└── README.md
```

## ⚠️ Disclaimer

**WAVE is for authorized security testing only.** Always obtain written permission before scanning systems you don't own. Unauthorized use may violate laws (CFAA, GDPR, local regulations).

## 🙏 Credits

- [OWASP Top 10](https://owasp.org/Top10/)
- [Gobuster](https://github.com/OJ/gobuster)
- [ReportLab](https://www.reportlab.com/)
- Built with [Click](https://click.palletsprojects.com/)

---

**Author:** Henry Félix-Faure  
**Version:** 0.1.6 
**Status:** Alpha (Active Development)