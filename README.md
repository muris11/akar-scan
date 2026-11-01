# akar-scan

> 🇬🇧 English | [🇮🇩 Bahasa Indonesia](README.id.md)

**Deep web application scanner** — reconnaissance, crawling, fingerprinting, and active
vulnerability checks, with console / JSON / HTML reporting.

`akar` (akar = "root" in Indonesian) digs from the roots: it enumerates subdomains and
ports, crawls the site, fingerprints the stack, then actively probes for common
vulnerabilities — exposed files, misconfigurations, injection points, and more.

> ⚠️ **For authorized targets only.** Scanning systems you do not own or have written
> permission to test may be illegal in your jurisdiction. You are responsible for how
> you use this tool.

---

## Table of contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
  - [Quick download (Windows .exe)](#quick-download-windows-exe)
  - [Windows](#windows)
  - [macOS](#macos)
  - [Linux](#linux)
  - [Verify the install](#verify-the-install)
- [Quick start](#quick-start)
- [Usage guide](#usage-guide)
- [CLI reference (all flags)](#cli-reference-all-flags)
- [Modules](#modules)
- [Reports & output](#reports--output)
- [Exit codes & CI integration](#exit-codes--ci-integration)
- [How it works](#how-it-works)
- [Troubleshooting / FAQ](#troubleshooting--faq)
- [Project structure](#project-structure)
- [Contributing](#contributing)
- [Uninstall](#uninstall)
- [Responsible use](#responsible-use)

---

## Features

- **Recon**: subdomain enumeration (crt.sh certificate transparency + DNS brute-force,
  170-word wordlist, live resolution) and async TCP port scanning with banner grab.
- **Crawler**: async, depth- and page-limited, single-host by default, dedupes canonical
  URLs, extracts links from `<a>` / `<link>` / `srcset` / meta-refresh / inline JS,
  and ingests `robots.txt` + `sitemap.xml`.
- **Fingerprinting**: server, language, framework, CMS, JS libraries (from headers,
  cookies, paths, and body signatures).
- **15 check modules** across passive and active layers (see [Modules](#modules)):
  security headers, clickjacking, cookies, CORS, TLS, exposed files, known-vulnerable
  paths (CVEs), open redirect, XSS, SQLi, LFI, CSRF, info leaks, HTTP methods,
  HTTP policy.
- **False-positive aware**: a random 404 baseline is requested first, so SPA fallback
  pages don't produce bogus "exposed file" hits.
- **Bounded & polite**: active tests are capped by `--max-tests` (default 500 requests)
  and sampled by `--max-test-pages` (default 25 pages); `--rate` can throttle requests.
- **Reports**: colored console output, machine-readable JSON, and a self-contained
  HTML report.
- **Zero-dependency core**: only `httpx` (with HTTP/2) — everything else is Python
  standard library (ssl, socket, asyncio, html.parser).

---

## Requirements

- **Python 3.10 or newer** (3.10 – 3.13 all work; the code uses modern typing and
  `asyncio` features that need 3.10+).
- `pip` (comes with any python.org installer; on Windows it's the `py` launcher's pip).
- Internet access if you use `--subdomains` (queries crt.sh). Everything else works
  against the target directly.
- No admin/root privileges needed.

Check your version:

```bash
python --version      # or: python3 --version  (macOS/Linux)
# Windows may need:   py --version
```

If it prints `Python 3.10.x` or higher, you're good. If not, see
[Troubleshooting](#troubleshooting--faq).

---

## Installation

### Quick download (Windows .exe)

No Python needed — grab the standalone executable from the
[Releases page](https://github.com/muris11/akar-scan/releases):

1. Download the latest `akar.exe` (under *Assets*).
2. Open PowerShell / CMD where you saved it and run:
   ```powershell
   .\akar.exe --version
   .\akar.exe https://example.com
   ```

> Windows may show a SmartScreen warning for unsigned binaries (common for any
> downloaded .exe). Click *More info → Run anyway* — or build from source below
> if you prefer to audit the code first. The `.exe` is also rebuilt
> automatically by GitHub Actions on every `v*` tag (see
> [.github/workflows/release.yml](.github/workflows/release.yml)).

### Windows

> Tested with PowerShell and CMD. The steps below assume the official python.org
> installer.

**1. Install Python (skip if you already have ≥ 3.10)**

- Download the installer from <https://www.python.org/downloads/windows/>.
- Run it and — this is important — **check "Add python.exe to PATH"** on the first
  screen before clicking *Install Now*.
- If you use **Laragon/XAMPP's bundled Python** (e.g. `C:\laragon\bin\python\python-3.10\`),
  that works too — just make sure that directory (and its `Scripts\` subfolder) is on
  your `PATH`.

**2. Open a terminal**

- Press `Win + X` → **Windows Terminal** / **PowerShell**, or press
  `Win + R`, type `powershell`, Enter.

**3. Verify Python is reachable**

```powershell
python --version
# If that fails, try the py launcher:
py --version
```

**4. (Recommended) Create a virtual environment**

In PowerShell, from the project folder:

```powershell
cd C:\path\to\akar-scan
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

- Activation script blocked by policy? Run this once, then retry activation:
  ```powershell
  Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
  ```
- Prefer CMD instead? Activate with `.\.venv\Scripts\activate.bat`.
- In CMD/PowerShell the activated env is shown as `(.venv)` at the start of your
  prompt line.

**5. Install the scanner**

```powershell
# from inside the project folder, with the venv activated:
pip install -e .
```

This installs `httpx` + `httpx[http2]` and creates the `akar` command.

Alternatively, without installing (no `akar` command, run via module):

```powershell
pip install -r requirements.txt
python -m akar --version
```

**6. Run it**

```powershell
akar --version
# or, if you didn't `pip install -e .`:
python -m akar --version
```

> Note: on Windows the `akar` command lives in `.venv\Scripts\` (editable installs put
> console scripts next to the interpreter). If `akar` is "not recognized", just use
> `python -m akar ...` — it's equivalent.

---

### macOS

> Works on both Apple Silicon (M1/M2/M3…) and Intel. macOS ships a stub `python3` that
> opens the App Store — install a real Python first.

**Option A — Homebrew (recommended if you have Homebrew)**

```bash
# install Homebrew first if needed: https://brew.sh
brew install python@3.12
```

**Option B — python.org installer**

- Download from <https://www.python.org/downloads/macos/> and run the package.
- This installs `python3` and `pip3` into `/Library/Frameworks/Python.framework`.

**Then, in Terminal (zsh by default):**

```bash
cd ~/path/to/akar-scan

# 1. virtual environment (recommended — keeps your system Python clean)
python3 -m venv .venv
source .venv/bin/activate

# 2. install
pip install -e .
# or, no-install route:
#   pip install -r requirements.txt
#   python -m akar --version

# 3. verify
akar --version
# or: python -m akar --version
```

Deactivate the venv anytime with `deactivate`.

---

### Linux

```bash
# Debian/Ubuntu
sudo apt update && sudo apt install -y python3 python3-venv python3-pip

cd ~/path/to/akar-scan
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
akar --version
```

Fedora/RHEL: `sudo dnf install python3 python3-pip`; Arch: `sudo pacman -S python python-pip`.

---

### Verify the install

All platforms — these should all succeed:

```bash
akar --version          # prints: akar 1.1.2
akar --list-modules     # prints the module table
akar --help             # full usage
```

If `--version` works but a scan fails immediately, jump to
[Troubleshooting](#troubleshooting--faq).

---

## Quick start

```bash
# Full scan of a site (crawl + all checks), console report:
akar https://example.com

# Write JSON + HTML reports as well:
akar https://example.com --format console,json,html -o report

# Recon: subdomains + port scan on top of the normal scan:
akar https://example.com --subdomains --ports 80,443,8000-8100

# Route traffic through Burp / ZAP:
akar https://example.com --proxy http://127.0.0.1:8080

# Authenticated scan (session cookie / basic auth / custom headers):
akar https://example.com --cookie "session=abc123" --header "X-Env: staging"
akar https://example.com --auth admin:password

# Run only some modules / skip some:
akar https://example.com --only cors,tls,exposed-files
akar https://example.com --skip xss,sqli          # passive-only run
```

Without `pip install -e .`, replace `akar` with `python -m akar` (or `python3 -m akar`).

---

## Usage guide

### Scan a target

```bash
akar example.com                # scheme optional; https is tried first, then http
akar https://example.com:8443   # non-standard port is respected
akar http://localhost:8000      # local/dev targets work too
akar https://example.com/app    # paths are followed as the crawl base
```

If the URL has no scheme, the scanner tries `https://` first and falls back to
`http://` automatically. If the first scheme fails, it retries the other one before
giving up (exit code 2).

### Tune the crawl

```bash
akar example.com --depth 5 --max-pages 500      # bigger site
akar example.com --depth 1 --max-pages 20       # quick pass
akar example.com --no-js                        # skip inline-JS link extraction
akar example.com --robots                       # also crawl robots-disallowed paths
```

### Tune the requests

```bash
akar example.com --threads 50 --timeout 20      # slow server, be patient
akar example.com --rate 5                       # max 5 req/s per host (polite mode)
akar example.com --insecure                     # skip TLS cert verification (self-signed)
akar example.com --no-http2                     # force HTTP/1.1
akar example.com --user-agent "MyScanner/1.0"
```

### Recon

```bash
# subdomains: crt.sh + DNS brute force (needs internet for crt.sh)
akar example.com --subdomains
akar example.com --subdomains --no-crt          # DNS brute only (offline-ish)

# port scan: bare flag = common list; or pass an explicit list/ranges
akar example.com --ports
akar example.com --ports 80,443,3306,8000-8100
akar example.com --ports 1-1024 --port-timeout 3
```

### Control the active tests

```bash
akar example.com --max-tests 1000               # bigger probe budget (default 500)
akar example.com --max-test-pages 50            # sample more pages (default 25)
akar example.com --sqli-aggressive              # enable slow time-based SQLi probes
akar example.com --test-forms                   # include HTML forms in injection tests
akar example.com --only cors,tls
akar example.com --skip xss,sqli,lfi            # passive-only / lighter run
akar --list-modules                             # see every module id
```

### Authenticated scans

```bash
# session cookie (copy from your browser's dev tools):
akar example.com --cookie "PHPSESSID=...; token=..."

# HTTP basic auth:
akar example.com --auth user:password

# arbitrary headers (repeatable):
akar example.com --header "Authorization: Bearer eyJ..." --header "X-Env: staging"
```

### Through a proxy (Burp Suite / OWASP ZAP)

```bash
# Burp default listener:
akar example.com --proxy http://127.0.0.1:8080

# ZAP default listener:
akar example.com --proxy http://127.0.0.1:8081
```

To intercept HTTPS through Burp, install Burp's CA certificate into your system trust
store (or pass `--insecure` to skip verification).

---

## CLI reference (all flags)

Run `akar --help` for the live reference. Flags grouped by area:

### Positional

| Flag | Description |
|---|---|
| `url` | Target URL. Scheme optional (`example.com` works). Omit when using `--list-modules`. |
| `--version` | Print version and exit. |

### Crawling

| Flag | Default | Description |
|---|---|---|
| `--depth N` | `3` | Max crawl depth from the start URL. |
| `--max-pages N` | `120` | Max pages to crawl. |
| `--no-js` | off | Don't extract links from inline JavaScript. |
| `--robots` | off | Also crawl paths disallowed in robots.txt. |
| `--max-test-pages N` | `25` | Pages sampled for active tests. |

### Requests

| Flag | Default | Description |
|---|---|---|
| `--threads N` | `20` | Concurrent requests. |
| `--timeout S` | `10.0` | Per-request timeout in seconds (float ok). |
| `--rate R` | `0.0` | Requests/sec per host; `0` = unlimited. |
| `--proxy URL` | — | Proxy, e.g. `http://127.0.0.1:8080`. |
| `--header K:V` | — | Custom header; repeatable. |
| `--cookie VALUE` | — | `Cookie` header value. |
| `--auth USER:PASS` | — | HTTP basic auth. |
| `--user-agent UA` | `AkarScan/1.1.2 (+security-scanner)` | Custom User-Agent. |
| `--insecure` | off | Skip TLS certificate verification. |
| `--no-http2` | off | Disable HTTP/2. |

### Recon

| Flag | Default | Description |
|---|---|---|
| `--subdomains` | off | Enumerate subdomains (crt.sh + DNS brute). |
| `--no-crt` | off | Skip crt.sh during subdomain enumeration. |
| `--ports [LIST]` | off | Scan ports. Bare `--ports` = common list; or `80,443,8000-8100`. |
| `--port-timeout S` | `1.2` | Per-port probe timeout. |

### Active tests

| Flag | Default | Description |
|---|---|---|
| `--max-tests N` | `500` | Budget of active test requests. |
| `--sqli-aggressive` | off | Enable time-based SQLi probes (slow). |
| `--test-forms` | off | Include HTML forms in injection tests. |
| `--only IDS` | — | Comma-separated module ids to run. |
| `--skip IDS` | — | Comma-separated module ids to skip. |
| `--list-modules` | — | List available modules and exit. |

### Output

| Flag | Default | Description |
|---|---|---|
| `--format FMT` | `console` | Comma-separated: `console`, `json`, `html`. |
| `-o, --output PREFIX` | `akar-<host>-<timestamp>` | Output file prefix for json/html reports. |
| `--fail-on SEV` | — | `low` / `medium` / `high` / `critical` — exit non-zero if any finding ≥ this severity. |
| `-v, --verbose` | off | Debug logging on stderr. |

---

## Modules

17 modules total: 15 checks + 2 recon. Enable/disable with `--only` / `--skip`.
Recon modules only run when their flag (`--subdomains` / `--ports`) is passed.

| id | layer | what it checks |
|---|---|---|
| `security-headers` | passive | missing/weak headers, HSTS, CSP directives (unsafe-inline/eval, wildcards, missing default-src/base-uri/form-action) |
| `clickjacking` | passive | X-Frame-Options / frame-ancestors |
| `cookies` | passive | Secure / HttpOnly / SameSite flags |
| `cors` | active | origin reflection, wildcard + credentials, permissive preflight |
| `tls` | active | cert expiry, self-signed, SAN mismatch, TLS 1.0/1.1, weak ciphers (RC4/3DES/NULL/EXPORT) |
| `exposed-files` | active | `.env`, `.git`, SSH keys, DB dumps, backups, `wp-config` backups, actuator, phpinfo, IDE/SFTP configs, logs |
| `cve` | active | PHPUnit eval-stdin (CVE-2017-9841), Ignition, actuator/env+heapdump, Werkzeug console, Solr, unauth Elasticsearch, Swagger, WP xmlrpc/user enum, jQuery/AngularJS version advisories, debug-mode stack traces |
| `open-redirect` | active | 40+ redirect parameters, 6 bypass payloads (absolute, `//`, `///`, encoded, double-encoded, backslash) |
| `xss` | active | canary reflection in query params and GET forms (raw vs encoded) |
| `sqli` | active | error-based signatures (6 engines) + boolean blind differential; time-based behind `--sqli-aggressive` |
| `lfi` | active | traversal payloads for unix/windows + `php://filter` base64 source-read confirmation |
| `csrf` | passive | state-changing forms without tokens, credentials over GET |
| `info-leak` | passive | server banners, stack traces, directory listings, sensitive HTML comments, internal IPs, robots.txt/sitemap, `.js.map` source maps |
| `http-methods` | active | OPTIONS/TRACE enumeration, unsafe verbs, WebDAV, XST |
| `http-policy` | active | HTTPS→HTTP downgrade, Host header injection (cache/pw-reset poisoning signals) |
| `subdomains` | recon | crt.sh certificate transparency + 170-word DNS brute force, live resolution (enable with `--subdomains`) |
| `ports` | recon | async TCP port scan with banner grab (enable with `--ports`) |

Severity legend: **critical** > **high** > **medium** > **low** > **info**.

---

## Reports & output

```bash
# console only (default)
akar example.com

# all three at once
akar example.com --format console,json,html -o report
#   → report.json + report.html  (plus the console report)

# file names default to akar-<host>-<timestamp>.json/.html when -o is omitted
akar example.com --format json,html
```

- **console** — colored, grouped by severity, with evidence and remediation hints.
- **json** — machine-readable; contains findings, tech fingerprint, crawl stats,
  TLS info, subdomains, and open ports. Good for piping into other tools.
- **html** — self-contained single-file report you can open in a browser or attach
  to a client deliverable.

---

## Exit codes & CI integration

| Code | Meaning |
|---|---|
| `0` | Scan completed; no findings at/above the `--fail-on` threshold (or no threshold set). |
| `1` | Findings at/above `--fail-on` severity exist. |
| `2` | Target unreachable (or a fatal runtime error). |
| `130` | Interrupted (Ctrl+C). |

Gate a CI pipeline on severity:

```bash
akar https://staging.example.com --format json -o scan --fail-on high
# exit code != 0 → the pipeline fails
```

Example GitHub Actions step:

```yaml
- name: Security scan
  run: |
    pip install -e .
    akar https://staging.example.com --format console,json --fail-on high -o akar-report
- uses: actions/upload-artifact@v4
  if: always()
  with:
    name: akar-report
    path: akar-report.*
```

---

## How it works

Pipeline (implemented in `akar/engine.py`):

1. **Reach the target** — normalize URL, try https then http (and vice versa on
   failure). Unreachable → exit 2.
2. **Fingerprint** — collect tech signals from headers, cookies, and body.
3. **Crawl** — BFS with depth/page limits; ingests robots.txt + sitemap.xml; dedupes
   canonical URLs.
4. **404 baseline** — fetch a random nonexistent path so SPA fallback responses
   (soft-404s) don't produce false positives on `exposed-files` and friends.
5. **Passive + active checks** — every selected module runs `on_page()` over up to
   `--max-test-pages` sampled pages, then `run()` site-wide. Active probes share a
   request budget (`--max-tests`) so big sites stay fast.
6. **Recon (optional)** — subdomain enumeration and/or port scan when enabled.
7. **Report** — findings sorted by severity; console/JSON/HTML renderers consume the
   same context object.

Design constraints:

- Injection probes use a **random canary** or **differential comparison** — no
  exploitation payloads, no brute forcing, no DoS.
- All probing HTTP goes through one shared async `httpx` client (connection reuse,
  proxy support, HTTP/2).

---

## Troubleshooting / FAQ

**`python` is not recognized (Windows)**
Python isn't on PATH. Use the `py` launcher instead (`py -m akar ...`,
`py -m venv .venv`), or reinstall from python.org with *"Add python.exe to PATH"*
checked.

**`akar` is not recognized after `pip install -e .` (Windows)**
Editable installs put the `akar.exe` shim in the active venv's `Scripts\` folder. Make
sure the venv is activated, or just use the universal form: `python -m akar ...`.

**`pip : File ...\pip.ps1 cannot be loaded ... security restriction` (PowerShell)**
Execution-policy blocked pip's shim. Run once per session:
`Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`, then retry.

**`ModuleNotFoundError: httpx`**
Dependencies aren't installed in the interpreter you're using. Activate the venv and
run `pip install -e .` (or `pip install -r requirements.txt`). If you use `python -m
akar`, that `python` must be the one with httpx installed.

**`ssl.SSLError` / certificate verify failed**
Self-signed or expired cert on the target → add `--insecure`. Behind Burp/ZAP, import
the proxy's CA certificate into your trust store (preferred) or use `--insecure`.

**`error: target unreachable: ...` (exit code 2)**
The scanner couldn't get any HTTP response. Check the URL, try the other scheme
(`http://` vs `https://`), check your network/proxy, or add `--insecure`.

**Scanning is too slow on a big site**
Lower the crawl budget: `--depth 2 --max-pages 40 --max-test-pages 10 --max-tests 200`.
Or run passive-only: `--skip xss,sqli,lfi,open-redirect,cors,http-methods,http-policy,exposed-files,cve,tls`.

**I want every link, including robots-disallowed ones**
Add `--robots` (and consider raising `--max-pages`).

**Time-based SQLi checks never run**
They're opt-in because they're slow: pass `--sqli-aggressive`.

**macOS says "command not found: python3"**
You haven't installed a real Python (the OS stub only opens the App Store). Install
via `brew install python@3.12` or the python.org package, then restart Terminal.

**Apple Silicon / "pip install" wants to build from source**
Use Homebrew's `python@3.12` or a python.org universal2 build — both ship wheels for
`httpx` and `h2`.

**Windows Defender / antivirus flags the scan**
Active checks send probe strings (traversal, SQL errors). Some AV products heuristically
flag scanners. Add an exclusion for the project folder if you trust the source (this
repo) — that's a local heuristic, not malware.

**Port scan finds nothing**
Only runs with `--ports`; the target host (not the URL path) is scanned. Raise
`--port-timeout` for slow networks.

**Subdomain enumeration returns nothing**
crt.sh can be slow or rate-limiting; retry, or use `--no-crt` for DNS brute force only.
Subdomains are discovered passively via certificate transparency — sites without CT
logs may yield zero results.

**How do I scan localhost / a dev server?**
`akar http://localhost:8000` works. For HTTPS with a self-signed dev certificate add
`--insecure`.

---

## Project structure

```
akar-scan/
├── akar/
│   ├── __init__.py          # version
│   ├── __main__.py          # python -m akar entry
│   ├── cli.py               # argparse CLI, output dispatch, exit codes
│   ├── engine.py            # scan pipeline & shared Context
│   ├── crawl.py             # async crawler (robots/sitemap, link extraction)
│   ├── fingerprint.py       # tech detection
│   ├── http.py              # shared async httpx client
│   ├── models.py            # Finding / Page / Severity
│   ├── utils.py             # URL helpers
│   ├── checks/              # 15 check modules + registry
│   ├── recon/               # subdomains + ports
│   └── reporting/           # console / json / html renderers
├── pyproject.toml           # packaging, `akar` console script
├── requirements.txt         # httpx[http2]>=0.27
└── README.md
```

Development without installing:

```bash
python -m venv .venv && source .venv/bin/activate   # Windows: .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m akar example.com --format console
```

---

## Contributing

Contributions are welcome — new check modules, fixes, docs, translations!

- Read [CONTRIBUTING.md](CONTRIBUTING.md) for the dev setup, the "add a check
  module" walkthrough, code style, and the PR checklist.
- Follow the [Code of Conduct](CODE_OF_CONDUCT.md).
- Use the issue templates (bug report / feature request) and the PR template.
- PRs must keep `README.md` and `README.id.md` in sync, and CI (Linux +
  Windows) must pass.

Quick dev loop:

```bash
pip install -e .
python -m akar --list-modules
```

## Uninstall

```bash
pip uninstall akar-scan
```

If you ran from a venv, you can delete the whole `.venv` folder instead.

---

## Responsible use

- Only scan targets you **own** or have **explicit written authorization** to test.
- Respect `--rate` and site terms; don't run aggressive modes against production
  without the owner's consent.
- Findings may contain sensitive data (exposed files, tokens). Handle reports
  accordingly and don't redistribute them.

---

*akar-scan v1.1.2 — built with Python + httpx.*
