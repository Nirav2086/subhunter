# SubHunter — Subdomain Finder Tool

![Python](https://img.shields.io/badge/Python-3.7%2B-blue?style=flat-square&logo=python)
![Platform](https://img.shields.io/badge/Platform-Linux-orange?style=flat-square&logo=linux)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)

A Python-based subdomain enumeration tool built for learning, bug bounty reconnaissance, and college project purposes. SubHunter combines **5 discovery techniques** simultaneously — DNS brute-force, SSL certificate logs, passive DNS databases, and web archive mining — to find as many subdomains as possible using only free resources.

> ⚠️ **Legal Notice:** Only use this tool on domains you own or have explicit written permission to test. Unauthorized scanning may be illegal in your country.

---

## What It Does

Given a target domain like `example.com`, SubHunter discovers subdomains like:
- `mail.example.com`
- `api.example.com`
- `dev.example.com`
- `staging.example.com`

It also detects **potential subdomain takeovers** — where a CNAME record points to a dead third-party service — which is a real bug bounty finding worth $200–$3000+.

---

## Features

<img width="938" height="570" alt="image" src="https://github.com/user-attachments/assets/6c006772-6408-43bf-9d70-a722209392f5" />

- **DNS Brute-Force** — tries common subdomain names from a wordlist using multi-threading
- **crt.sh** — searches SSL Certificate Transparency logs (free, no API key)
- **HackerTarget** — queries their free subdomain database
- **AlienVault OTX** — searches passive DNS history (free, no API key)
- **Web Archive** — mines subdomains from Wayback Machine URLs
- **Wildcard DNS Detection** — automatically detects and filters wildcard records to avoid false positives
- **Subdomain Takeover Detection** — flags dead CNAME targets in magenta
- **Multi-threaded** — runs up to 50+ DNS queries simultaneously for speed
- **Flexible Output** — save results as `.txt` or `.json`
- **Color-coded terminal output** — easy to read at a glance

---

## Prerequisites

Before installing SubHunter, make sure your Linux system has the following:

### 1. Python 3.7 or higher

Check if Python 3 is installed:
```bash
python3 --version
```

If not installed, install it:
```bash
# Debian / Ubuntu / Kali Linux
sudo apt update
sudo apt install python3 -y

# Fedora / RHEL / CentOS
sudo dnf install python3 -y

# Arch Linux
sudo pacman -S python
```

### 2. pip (Python package manager)

Check if pip is installed:
```bash
pip3 --version
```

If not installed:
```bash
# Debian / Ubuntu / Kali Linux
sudo apt install python3-pip -y

# Fedora / RHEL
sudo dnf install python3-pip -y

# Arch Linux
sudo pacman -S python-pip
```

### 3. git (to clone the repository)

Check if git is installed:
```bash
git --version
```

If not installed:
```bash
sudo apt install git -y
```

### 4. Internet Connection

SubHunter queries multiple online APIs. An active internet connection is required for the passive sources (crt.sh, HackerTarget, AlienVault, Web Archive). DNS brute-force works as long as you can reach a DNS resolver.

---

## Installation

### Step 1 — Clone the Repository

```bash
git clone https://github.com/Nirav2086/subhunter.git
cd subhunter
```

### Step 2 — Install Required Python Libraries

```bash
pip3 install requests dnspython colorama
```

Or if you prefer using a virtual environment (recommended):

```bash
# Create virtual environment
python3 -m venv venv

# Activate it
source venv/bin/activate

# Install libraries inside the environment
pip install requests dnspython colorama
```

### Step 3 — Make the Script Executable (Optional)

```bash
chmod +x subhunter.py
```

Now you can run it directly as `./subhunter.py` instead of `python3 subhunter.py`.

### Step 4 — Verify Installation

```bash
python3 subhunter.py --help
```

You should see the SubHunter banner and the help menu. If you see it — you are ready.

---

## Usage

### Basic Syntax

```bash
python3 subhunter.py -d <domain> [options]
```

### All Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-d`, `--domain` | Required | Target domain (e.g. `example.com`) |
| `-w`, `--wordlist` | `wordlist.txt` | Path to wordlist file |
| `-o`, `--output` | None | Save results to file (`.txt` or `.json`) |
| `-t`, `--threads` | `50` | Number of parallel DNS threads |
| `--no-bruteforce` | False | Skip brute-force, use APIs only |
| `--only-bruteforce` | False | Skip APIs, use brute-force only |

### Examples

```bash
# Basic scan — runs all 5 techniques
python3 subhunter.py -d example.com

# Save results as plain text
python3 subhunter.py -d example.com -o results.txt

# Save results as JSON (full details)
python3 subhunter.py -d example.com -o results.json

# Use a bigger wordlist for more findings
python3 subhunter.py -d example.com -w /path/to/big-wordlist.txt

# Increase threads for faster scanning
python3 subhunter.py -d example.com -t 100

# Only passive APIs — no brute-force
python3 subhunter.py -d example.com --no-bruteforce

# Only brute-force — skip all APIs
python3 subhunter.py -d example.com --only-bruteforce

# Full scan with all options
python3 subhunter.py -d example.com -w wordlist.txt -t 100 -o results.json

# Stop at any time
Ctrl+C   # Tool exits cleanly
```

---

## Understanding the Output

```
[*]  Blue     — status / progress information
[+]  Green    — subdomain found and alive
[!]  Yellow   — warning (wildcard DNS detected, API limit, etc.)
[-]  Red      — error (timeout, connection issue)
[TAKEOVER] Magenta — dead CNAME target found (possible subdomain takeover)
```

### Example Output

```
[*] Target domain : example.com
[*] Threads       : 50
[*] Wordlist      : wordlist.txt

[*] Step 1/4 — Checking for wildcard DNS...
[*] No wildcard DNS detected. Good — brute-force will be accurate.

[*] Step 2/4 — Querying passive sources (APIs)...
[*] crt.sh: searching certificate transparency logs...
[*] crt.sh: found 45 unique entries
[*] HackerTarget: querying subdomain database...
[*] HackerTarget: found 12 entries

[*] Step 3/4 — Running DNS brute-force...
[+] mail.example.com       →  192.168.1.10
[+] api.example.com        →  10.0.0.5  (CNAME: api-lb.example.com)
[TAKEOVER] shop.example.com  →  CNAME  →  example.myshopify.com  (DEAD TARGET)

============================================================
  SCAN COMPLETE — RESULTS SUMMARY
============================================================
  Target domain    : example.com
  Total found      : 23 subdomains
  Takeover risks   : 1 potential subdomain takeovers!
============================================================
```

---

## Getting a Bigger Wordlist

The bundled `wordlist.txt` has 172 common subdomain names. For more thorough scanning, use **SecLists** — the industry standard free wordlist collection:

```bash
# Clone SecLists (warning: large repository ~1GB)
git clone https://github.com/danielmiessler/SecLists.git

# Use the 5000-name wordlist
python3 subhunter.py -d example.com -w SecLists/Discovery/DNS/subdomains-top1million-5000.txt

# Use the 20000-name wordlist
python3 subhunter.py -d example.com -w SecLists/Discovery/DNS/subdomains-top1million-20000.txt
```

---

## Discovery Techniques Explained

| Technique | Source | Cost | What it finds |
|-----------|--------|------|---------------|
| DNS Brute-Force | Direct DNS queries | Free | Subdomains matching wordlist names |
| crt.sh | SSL certificate logs | Free, no key | Subdomains from real HTTPS certificates |
| HackerTarget | Internet scan database | Free (limited/day) | Known subdomains from their scans |
| AlienVault OTX | Passive DNS history | Free, no key | Historical DNS records |
| Web Archive | Wayback Machine URLs | Free, no key | Subdomains seen in archived web pages |

---

## Project Structure

```
subhunter/
├── subhunter.py              # Main tool — all 9 modules
├── wordlist.txt              # 172 common subdomain names
├── SubHunter_Documentation.docx  # Full technical documentation
└── README.md                 # This file
```

---

## How It Works Internally

```
python3 subhunter.py -d target.com
        │
        ├── Step 1: detect_wildcard()         — wildcard DNS check
        │
        ├── Step 2: search_crtsh()            — SSL cert logs
        │           search_hackertarget()     — HackerTarget API
        │           search_alienvault()       — AlienVault OTX
        │           search_webarchive()       — Wayback Machine
        │
        ├── Step 3: bruteforce_subdomains()   — wordlist + threading
        │               └── resolve_subdomain()   (per word)
        │
        ├── Step 4: verify_subdomains()       — live DNS check
        │               └── resolve_subdomain()   (per passive result)
        │
        └── Merge + deduplicate + sort + print + save_results()
```

---

## Ethical Usage

This tool is built for:
- Learning how subdomain enumeration works
- Bug bounty reconnaissance on **in-scope** targets
- Testing domains you personally own
- CTF (Capture The Flag) challenges

**Never use this tool against:**
- Domains you do not own or have permission to test
- Government websites
- Out-of-scope bug bounty targets
- Any target with malicious intent

Unauthorized use of this tool may violate laws including the **Information Technology Act (India)**, **CFAA (USA)**, **Computer Misuse Act (UK)**, and equivalents in your country.

---

## Built With

- [Python 3](https://python.org) — core language
- [dnspython](https://www.dnspython.org/) — DNS queries
- [requests](https://requests.readthedocs.io/) — HTTP API calls
- [colorama](https://pypi.org/project/colorama/) — colored terminal output
- [crt.sh](https://crt.sh) — SSL certificate transparency logs
- [HackerTarget](https://hackertarget.com) — subdomain database
- [AlienVault OTX](https://otx.alienvault.com) — passive DNS
- [Wayback Machine](https://web.archive.org) — web archive

---

## Author

Built for learning bug bounty reconnaissance and as a college project.  
Feel free to fork, improve, and learn from it.

---

## License

This project is licensed under the MIT License — you are free to use, modify, and distribute it with attribution.
