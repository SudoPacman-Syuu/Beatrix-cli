# BEATRIX CLI — The Black Mamba

> *"Revenge is a dish best served with a working PoC."*

![Python](https://img.shields.io/badge/Python-3.11%2B-blue?style=flat-square&logo=python) ![License](https://img.shields.io/badge/License-Source%20Available-lightgrey?style=flat-square) ![Platform](https://img.shields.io/badge/Platform-Linux-orange?style=flat-square&logo=linux) ![GitHub Stars](https://img.shields.io/github/stars/SudoPacman-Syuu/Beatrix-cli?style=flat-square)

**License:** Source Available — Free for non-commercial use. Commercial use requires a separate license. See [LICENSE](LICENSE).

A command-line bug bounty hunting framework. 32 scanner modules, 22 external tool integrations, 57K+ payloads, a 7-phase Kill Chain methodology, and AI-assisted analysis. Targets can be domains, URLs, or raw IP addresses.

---

<img src="beatrix.gif" width="1920" alt="Demo">

---

## Table of Contents

- [Why Beatrix?](#why-beatrix)
- [The Manual](#the-manual)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Command Reference](#command-reference)
- [Requirements](#requirements)
- [Presets](#presets)
- [Verbosity](#verbosity)
- [The Kill Chain](#the-kill-chain)
- [Scanner Modules](#scanner-modules)
- [External Tool Integrations](#external-tool-integrations)
- [IP Address Targets](#ip-address-targets)
- [Network Testing (Full Preset)](#network-testing-full-preset)
- [Usage Examples](#usage-examples)
- [Authenticated Scanning](#authenticated-scanning)
- [GitHub Secret Scanning](#github-secret-scanning)
- [Validation](#validation)
- [Output Format](#output-format)
- [Scan Output Directory](#scan-output-directory)
- [Configuration](#configuration)
- [Getting Help](#getting-help)
- [Architecture](#architecture)
- [Legal](#legal)

---

## Why Beatrix?

Most bug bounty tools solve one problem. Beatrix solves the whole workflow.

**Nuclei** is excellent at template-based scanning — known CVEs and patterns against a target. It doesn't crawl, doesn't manage auth sessions, doesn't chain tools together, and doesn't tell you what to do next. You still have to run subfinder, then amass, then nmap, then nuclei, then sqlmap, then dalfox, then manually correlate the output.

**Burp Suite Pro** is the industry standard for manual web testing. It requires a GUI, costs $449/year, isn't scriptable, and doesn't run in headless environments like Codespaces or CI pipelines.

Beatrix is the orchestration layer that was missing.

| Feature | Beatrix | Nuclei | Burp Suite Pro |
|---------|:-------:|:------:|:--------------:|
| 7-phase Kill Chain methodology | ✅ | ❌ | ❌ |
| Auto-login & session management | ✅ | ❌ | Manual |
| Autonomous AI pentester (GHOST) | ✅ | ❌ | ❌ |
| 22 external tool orchestration | ✅ | ❌ | ❌ |
| Built-in OOB / PoC server | ✅ | ❌ | ✅ (Collaborator) |
| Authenticated crawling | ✅ | ❌ | ✅ |
| CLI / automation-friendly | ✅ | ✅ | ❌ |
| Runs in headless environments | ✅ | ✅ | ❌ |
| Cost | Free | Free | $449/yr |

One command. Every phase. All the tools.

```bash
beatrix hunt example.com --preset full
```

---

## The Manual

Beatrix ships with an interactive HTML manual covering every command, every module, all flags, presets, and real-world workflows:

```bash
beatrix manual
```

Opens in your default browser — no internet required. Also available at [`docs/manual/index.html`](docs/manual/index.html).

---

## Installation

```bash
git clone https://github.com/SudoPacman-Syuu/Beatrix-cli.git && cd Beatrix-cli && ./install.sh
```

The installer auto-detects your Python, selects the best install method, puts `beatrix` on your PATH, and installs all 21 external security tools (nuclei, nmap, sqlmap, subfinder, ffuf, and others).

**Install method priority:**

1. **uv** (fastest) — auto-installed if missing
2. **venv** — Python virtual environment at `~/.beatrix`
3. **pipx** — isolated app install
4. **pip --user** — fallback

Alternative methods:

```bash
make install            # same as ./install.sh via make
make install-dev        # editable install for development
uv tool install .       # direct uv install
pipx install .          # direct pipx install
make install-venv       # dedicated venv + symlink to /usr/local/bin
```

Custom venv location: `BEATRIX_VENV=~/my-venv ./install.sh`

**Uninstall:**

```bash
./uninstall.sh    # or: make uninstall
```

---

## Quick Start

```bash
beatrix                              # show all commands
beatrix hunt example.com             # scan a domain
beatrix hunt 192.168.1.1             # scan an IP address
beatrix hunt -f targets.txt          # scan all targets from a file
beatrix strike api.com -m cors       # single module, single target
beatrix help hunt                    # detailed command help
beatrix arsenal                      # full module reference
```

---

## Command Reference

| Command | Description | Example |
|---------|-------------|---------|
| `hunt TARGET` | Full vulnerability scan | `beatrix hunt example.com` |
| `hunt -f FILE` | Scan targets from file | `beatrix hunt -f targets.txt` |
| `strike TARGET -m MOD` | Single module against a target | `beatrix strike api.com -m cors` |
| `probe TARGET` | Quick alive check | `beatrix probe example.com` |
| `recon DOMAIN` | Reconnaissance only | `beatrix recon example.com --deep` |
| `batch FILE -m MOD` | Mass single-module scanning | `beatrix batch targets.txt -m cors` |
| `rapid` | Multi-target quick sweep | `beatrix rapid -d example.com` |
| `haiku-hunt TARGET` | AI-assisted hunting | `beatrix haiku-hunt example.com` |
| `ghost TARGET` | Autonomous AI pentester | `beatrix ghost https://api.com` |
| `github-recon ORG` | GitHub secret scanner | `beatrix github-recon acme-corp` |
| `validate FILE` | Validate findings | `beatrix validate report.json` |
| `mobile [sub]` | Mobile traffic intercept | `beatrix mobile intercept` |
| `browser [sub]` | Playwright browser scanning | `beatrix browser scan https://app.com` |
| `creds [sub]` | Credential validation | `beatrix creds validate jwt_secret TOKEN` |
| `origin-ip DOMAIN` | Origin IP behind CDN | `beatrix origin-ip example.com` |
| `inject TARGET` | Deep parameter injection | `beatrix inject https://api.com --deep` |
| `polyglot [sub]` | XSS polyglot generation | `beatrix polyglot generate` |
| `auth [sub]` | Auth and auto-login | `beatrix auth login example.com` |
| `auth browser TARGET` | Manual browser login | `beatrix auth browser example.com` |
| `auth import TARGET FILE` | Import session from HAR or cookie string | `beatrix auth import example.com session.har` |
| `auth sessions` | Manage saved sessions | `beatrix auth sessions --clear example.com` |
| `config` | Configuration | `beatrix config --show` |
| `list` | List modules/presets | `beatrix list --modules` |
| `arsenal` | Full module reference | `beatrix arsenal` |
| `help CMD` | Detailed command help | `beatrix help hunt` |
| `manual` | Open HTML manual | `beatrix manual` |
| `setup` | Install external tools | `beatrix setup` |

---

## Requirements

- **Python 3.11+**
- **Linux** (Debian, Ubuntu, Fedora, Arch, and others)

21 external tools are installed automatically by `./install.sh`. To reinstall or update them later:

```bash
beatrix setup            # install all missing tools
beatrix setup --check    # show what is installed
```

Verify the installation:

```bash
beatrix --version
beatrix list --modules
```

---

## Presets

| Preset | Description | Approximate Time |
|--------|-------------|-----------------|
| `quick` | Surface scan, recon only | ~5 min |
| `standard` | Balanced scan (default) | ~15 min |
| `full` | Complete kill chain + full network recon | ~45-60 min |
| `stealth` | Low-noise passive recon | ~10 min |
| `injection` | Injection-focused testing | ~20 min |
| `api` | API security testing | ~15 min |
| `web` | Web application focused | ~20 min |
| `recon` | Reconnaissance only | ~10 min |

```bash
beatrix hunt example.com --preset full
beatrix hunt example.com --preset injection
```

---

## Verbosity

Both `hunt` and `strike` accept a `-v` flag with three levels. By default, Beatrix shows phase transitions, scanner names, and findings as they arrive. The verbosity flag exposes progressively more detail without requiring any configuration changes.

```bash
beatrix hunt example.com -v       # show all info events; log buffer raised to 200
beatrix hunt example.com -vv      # show URL, parameter, and evidence for each finding as discovered
beatrix hunt example.com -vvv     # route all internal debug logging to the terminal in real time

beatrix strike api.com -m cors -vvv
```

At `-vvv`, Python's logging module is configured at DEBUG level with a Rich handler. Every internal scanner operation, every HTTP call dispatched by a scanner, and the raw stdout and stderr of all external tool subprocesses (amass, katana, gospider, dirsearch, dalfox, and others) stream to the terminal line by line as they happen. Tools that normally suppress output (using `-silent`, `-q`, or `--silence` flags) have those flags removed in this mode. Amass also receives its own `-v` flag for detailed source-level enumeration output.

The log buffer is unlimited at `-vvv`, capped at 500 lines at `-vv`, and 200 at `-v` (default is 50).

---

## The Kill Chain

Every `hunt` runs a 7-phase methodology. Phases run sequentially; the output of each phase feeds into the next.

**Phase 1 — CDN Bypass**
Detects Cloudflare, Akamai, Fastly, CloudFront, Sucuri, Incapsula, PerimeterX, DataDome, and Kasada via IP range and header fingerprinting. Discovers origin IPs through DNS history, crt.sh SSL certificates, MX records, subdomain correlation, misconfiguration checks, and WHOIS. When an origin IP is confirmed, all subsequent network scans target it directly rather than the CDN edge. Optional API keys (SecurityTrails, Censys, Shodan) extend this via environment variables.

**Phase 2 — Reconnaissance**
Subdomain enumeration via `subfinder` and `amass`, crawling via `katana`, `gospider`, `hakrawler`, and `gau` (with `waymore` for deeper historical URL mining when present), full 65535-port TCP scan via `nmap -sS -p-` against origin IP when available, service fingerprinting, NSE vuln/discovery/auth scripts, UDP top-50 scan, firewall fingerprinting and bypass testing via `scapy`, SSH deep audit via `paramiko`, JS bundle analysis, endpoint probing, API route discovery via `kiterunner`, hidden parameter mining via `arjun`, deep TLS fingerprinting via `tlsx`, tech fingerprinting via `whatweb` and `webanalyze`, nuclei recon templates, and nuclei network protocol checks.

**Phase 3 — Weaponization**
Subdomain takeover (30+ cloud services), error disclosure, cache poisoning, prototype pollution, and systematic 403 bypass via `nomore403` when present.

**Phase 4 — Delivery**
CORS, open redirects, OAuth redirect URI manipulation, HTTP request smuggling (CL.TE / TE.CL / TE.TE), WebSocket testing.

**Phase 5 — Exploitation**
Injection (SQLi, XSS, CMDi) with `response_analyzer` behavioral detection and WAF bypass fallback (11 WAF profiles, 3-strategy retry with adaptive learning), SSRF, IDOR, broken access control, auth bypass, SSTI, XXE, deserialization, GraphQL (with `clairvoyance` schema reconstruction when introspection is disabled), mass assignment, business logic (including single-packet / last-byte-sync race-condition testing), ReDoS, payment flow manipulation, CRLF injection via `crlfuzz`, nuclei exploit scan (CVEs, workflows, interactsh OOB, WAF bypass via realistic UA and CDN-aware rate limiting), and nuclei headless (DOM XSS, prototype pollution). Nuclei samples large URL sets down to a representative set and shares a per-host rate ceiling with the other scanners, so a 429 flood seen by one scanner throttles nuclei on the same host. SmartFuzzer runs ffuf-verified fuzzing with profile-targeted WAF encoding. Confirmed findings are escalated to `sqlmap`, `dalfox`, `commix`, and `jwt_tool`.

**Phase 6 — Installation**
File upload extension bypass, polyglot uploads, path traversal.

**Phase 7 — C2**
OOB callback correlation via the built-in `PoCServer` (pure asyncio, auto-binds a free port) or external `interactsh`. Blind SSRF, XXE, and RCE confirmation from callbacks registered during Phase 5. `LocalPoCClient` provides offset-based dedup polling.

**Phase 8 — Objectives**
VRT classification (Bugcrowd VRT + CVSS 3.1), exploit chain generation via `PoCChainEngine` (correlates two or more related findings), deduplication, and impact assessment.

---

## Scanner Modules

Run `beatrix arsenal` for the full table. 32 modules across 5 kill chain phases.

**Phase 1 — Reconnaissance**

| Module | What It Does |
|--------|-------------|
| `origin_ip` | CDN detection and origin IP discovery via DNS history, SSL certs, MX records, subdomain correlation, and misconfiguration checks |
| `crawl` | Depth-limited spider with soft-404 detection, form/param extraction |
| `endpoint_prober` | Probes 200+ common API, admin, and debug paths |
| `js_analysis` | Extracts API routes, secrets, and source maps from JS bundles |
| `headers` | CSP, HSTS, X-Frame-Options, and security header analysis |
| `github_recon` | GitHub org secret scanning, git history analysis |
| `nmap_nse` | Full TCP 65535-port scan, service identification, NSE vuln/discovery/auth scripts, UDP top-50 |
| `ssh_auditor` | SSH fingerprint, weak KEX/cipher/MAC detection, default credential brute-force |
| `packet_crafter` | Firewall fingerprint, source-port bypass, IP fragment bypass, TTL mapping |

**Phase 2 — Weaponization**

| Module | What It Does |
|--------|-------------|
| `takeover` | Dangling CNAME detection for 30+ cloud services |
| `error_disclosure` | Stack traces, SQL errors, framework debug info leaks |
| `cache_poisoning` | Unkeyed header injection, fat GET, parameter cloaking |
| `prototype_pollution` | Server-side and client-side JS prototype pollution |

**Phase 3 — Delivery**

| Module | What It Does |
|--------|-------------|
| `cors` | 6 bypass techniques, credential leak detection |
| `redirect` | Open redirect detection |
| `oauth_redirect` | OAuth redirect URI manipulation |
| `http_smuggling` | CL.TE / TE.CL / TE.TE desync |
| `websocket` | WebSocket origin, CSWSH, message injection |

**Phase 4 — Exploitation**

| Module | What It Does |
|--------|-------------|
| `injection` | SQLi, XSS, CMDi, LFI, SSTI — 57K+ payloads, behavioral detection, 11-profile WAF bypass |
| `ssrf` | 44+ payloads, cloud metadata endpoints, internal service access |
| `idor` | Sequential, UUID, and negative ID manipulation |
| `bac` | Method override, force browsing, privilege escalation |
| `auth` | JWT attacks, 2FA bypass, session management |
| `ssti` | Server-side template injection (Jinja2, Twig, and others) |
| `xxe` | XML external entity injection |
| `deserialization` | Insecure deserialization (Java, PHP, Python, .NET) |
| `graphql` | Introspection, batching, injection |
| `mass_assignment` | Hidden field binding exploitation |
| `business_logic` | Race conditions, boundary testing |
| `redos` | Regular expression denial of service |
| `payment` | Checkout flow manipulation, price tampering |
| `nuclei` | Multi-phase scanner — recon, exploit, network, headless. 18,000+ templates with WAF bypass |

**Phase 5 — Installation**

| Module | What It Does |
|--------|-------------|
| `file_upload` | Extension bypass, polyglot uploads, path traversal |

---

## External Tool Integrations

Beatrix wraps 22 external tools via async subprocess runners. All runners support real-time output streaming when `-vvv` is active.

| Tool | Phase | Purpose |
|------|-------|---------|
| `subfinder` | Recon | Passive subdomain enumeration |
| `amass` | Recon | Active/passive subdomain enumeration |
| `nmap` | Recon | Full TCP/UDP port scanning, NSE scripts |
| `katana` | Recon | Deep crawling, JS rendering |
| `gospider` | Recon | Fast crawling, form and JS extraction |
| `hakrawler` | Recon | URL discovery |
| `gau` | Recon | Historical URL harvesting |
| `waymore` † | Recon | Exhaustive historical URL mining (Wayback, OTX, URLScan, Common Crawl) beyond `gau` |
| `whatweb` | Recon | Technology fingerprinting |
| `webanalyze` | Recon | Wappalyzer-based tech detection |
| `dirsearch` | Recon | Directory brute-forcing |
| `kiterunner` † | Recon | API route discovery via real-world (assetnote) route wordlists |
| `arjun` † | Recon | Hidden GET/POST/JSON parameter discovery |
| `tlsx` † | Recon | TLS certificate inspection and cipher-suite enumeration |
| `nomore403` † | Weaponization | Systematic 403 bypass via header manipulation and path tricks |
| `clairvoyance` † | Exploitation | GraphQL schema reconstruction despite disabled introspection |
| `crlfuzz` † | Exploitation | Dedicated CRLF injection / response-splitting scanner |
| `sqlmap` | Exploitation | Deep SQLi exploitation, DB enumeration |
| `dalfox` | Exploitation | XSS validation, WAF bypass |
| `commix` | Exploitation | OS command injection exploitation |
| `jwt_tool` | Exploitation | JWT vulnerability analysis, claim tampering |
| `metasploit` | PoC Chain | Exploit search, resource file generation |

**†** These seven tools are **optional** — Beatrix auto-detects them on your `PATH` and runs them when present, but `./install.sh` / `beatrix setup` does **not** install them (they cover 21 core tools). Install any of them yourself to unlock the extra coverage; Beatrix degrades gracefully when they're absent.

---

## IP Address Targets

Beatrix fully supports raw IPv4 and IPv6 targets. Domain-only operations are skipped automatically:

- **Skipped:** Subdomain enumeration, origin IP discovery, GitHub recon, subdomain takeover checks
- **Active:** All HTTP-based scanners (injection, CORS, SSRF, IDOR, XXE, and others), port scanning, service detection, firewall testing

```bash
beatrix hunt 192.168.1.1
beatrix hunt 10.0.0.1 --preset full
beatrix strike http://192.168.1.1:8080/api -m injection

# IPs work in target files too
echo "192.168.1.1
10.0.0.2
https://172.16.0.1:443" > targets.txt
beatrix hunt -f targets.txt
```

---

## Network Testing (Full Preset)

`--preset full` runs a 4-phase adaptive network pipeline inside the Reconnaissance phase.

### CDN Bypass (origin_ip_discovery)

Runs before port scanning. Detects CDN/WAF and discovers origin IPs.

| Technique | Source | API Key | Confidence |
|-----------|--------|---------|------------|
| DNS History | ViewDNS, DNSDumpster | No | 0.5-0.6 |
| SSL Certificate Search | crt.sh | No | 0.7 |
| MX Record Analysis | dig MX records | No | 0.8 |
| Subdomain Correlation | 40+ bypass subdomains | No | 0.7 |
| Misconfiguration Check | Header leaks, /server-status | No | 0.9 |
| Historical WHOIS | whois | No | 0.4 |
| SecurityTrails History | SecurityTrails API | `SECURITYTRAILS_API_KEY` | 0.85 |
| Censys Certificate Search | Censys API | `CENSYS_API_ID` + `CENSYS_API_SECRET` | 0.8 |
| Shodan Host Search | Shodan API | `SHODAN_API_KEY` | 0.75 |

Discovered IPs are validated (HTTP/HTTPS with Host header). The highest-confidence validated IP replaces the CDN edge for all subsequent network scans.

### Phase 1 — Discovery (nmap)

| Step | Command | Timeout |
|------|---------|---------|
| 1a | `nmap -sS -p- --min-rate 3000 -T4` — all 65535 TCP ports | 600s |
| 1b | Service/version fingerprint on open ports | 300s |
| 1c | NSE `vuln and safe` — CVEs, misconfigs | 600s |
| 1d | NSE `discovery and safe` — http-enum, ssl-cert, banners | 600s |
| 1e | NSE `auth and safe` — default creds, anonymous access | 600s |
| 1f | UDP top-50 — DNS, SNMP, NTP, SSDP | 120s |

### Phase 2 — Firewall Analysis (scapy)

Runs only when Phase 1 finds filtered ports.

| Step | What |
|------|------|
| 2a | Firewall fingerprint — SYN/FIN/NULL/XMAS/ACK/Window probes |
| 2b | Source port bypass — SYN from ports 53/80/443/88/20 |
| 2c | IP fragmentation bypass — split TCP headers |
| 2d | TTL mapping — locate firewall hop position |

Each successful bypass generates a HIGH or CRITICAL finding.

### Phase 3 — Service Audit (paramiko / NSE)

| Service | Tool | Checks |
|---------|------|--------|
| SSH | paramiko | Banner, KEX/cipher/MAC weakness, key strength, 20+ default credentials |
| FTP | NSE | Anonymous access, bounce attack, vsftpd backdoor |
| SMTP | NSE | Open relay, user enumeration, NTLM info |
| MySQL/Postgres | NSE | Empty password, brute-force, version |
| Redis/MongoDB | NSE | Unauthenticated access |
| TLS | NSE | ssl-enum-ciphers, Heartbleed, POODLE, CCS injection |

### Context Flow

Network results propagate to downstream phases:

- CDN Bypass → Discovery: origin IP replaces CDN edge for all nmap scans
- Delivery: HTTP smuggling tested on all discovered HTTP ports plus origin IP directly
- Exploitation: injection/SSRF/XSS on all HTTP ports plus origin IP
- C2: firewall profile informs exfiltration channel assessment

### API Keys (Optional)

```bash
export SECURITYTRAILS_API_KEY=your_key
export CENSYS_API_ID=your_id
export CENSYS_API_SECRET=your_secret
export SHODAN_API_KEY=your_key
```

Without API keys, the six free techniques cover most targets.

---

## Usage Examples

### Basic Scanning

```bash
beatrix hunt example.com --preset quick
beatrix hunt example.com --preset full
beatrix hunt example.com --preset full --ai

# File-based (one URL/IP per line, # for comments)
beatrix hunt -f targets.txt
beatrix hunt -f targets.txt --preset full -o ./reports

# With verbosity
beatrix hunt example.com --preset full -vvv
beatrix hunt example.com --preset full -vvv -o results.json > scan.log
```

### Targeted Strikes

```bash
beatrix strike https://api.example.com/v1/users -m cors
beatrix strike https://example.com/fetch?url=test -m ssrf
beatrix strike https://app.example.com -m js_analysis
beatrix strike https://api.example.com -m injection -vvv
```

### Reconnaissance

```bash
beatrix recon example.com
beatrix recon example.com --deep
beatrix recon example.com --deep -j -o recon.json
```

### Batch Scanning

```bash
# Single module across many targets
beatrix batch targets.txt -m cors -o ./reports

# Full kill chain across a file of targets
beatrix hunt -f targets.txt --preset full --ai -o ./reports
```

### GHOST — Autonomous AI Pentester

```bash
beatrix ghost https://api.example.com/users?id=1
beatrix ghost https://api.example.com -X POST -d '{"user":"admin"}' -o "Test for SQL injection"
beatrix ghost https://example.com -H "Authorization: Bearer TOKEN" --max-turns 50
```

---

## Authenticated Scanning

Beatrix supports authenticated scanning via config file, CLI flags, environment variables, auto-login, manual browser login, and HAR file import. Credentials flow automatically to all scanners — nuclei receives `-H` flags, the IDOR scanner gets user sessions, and the crawler gets cookies.

### Auto-Login

Beatrix can authenticate before scanning by probing login endpoints, similar to a Burp Suite login macro.

```bash
# Interactive wizard (saves to ~/.beatrix/auth.yaml)
beatrix auth login example.com

# CLI flags
beatrix hunt target.com --login-user user@example.com --login-pass 'password'
beatrix hunt target.com --login-user user@example.com --login-pass 'password' \
    --login-url https://target.com/api/auth/login

# Environment variables
export BEATRIX_LOGIN_USER="user@example.com"
export BEATRIX_LOGIN_PASS="password"
export BEATRIX_LOGIN_URL="https://target.com/api/auth/login"
beatrix hunt target.com
```

How auto-login works:

1. Collects cookies from the target's home page (CSRF tokens, etc.)
2. Probes 24 common API login endpoints with JSON payloads (`/api/auth/login`, `/api/v1/session`, `/oauth/token`, and others)
3. Tries 12 traditional form login endpoints (`/login`, `/signin`, `/wp-login.php`, and others)
4. Uses 10 field-name combinations per endpoint (`email`/`password`, `username`/`passwd`, and others)
5. Skips 404s quickly; stops on 401/403 (endpoint found, credentials wrong)
6. Detects OTP/2FA challenges and prompts for the code interactively
7. Captured session cookies and tokens flow to all scanners
8. Session is saved to `~/.beatrix/sessions/` and reused for 24 hours

### OTP / 2FA Handling

When Beatrix detects a 2FA response (by scanning JSON for `requires_2fa`, `verification_required`, `otp`, and similar fields), it prompts for the code interactively.

For CAPTCHA, WAF blocks, or complex 2FA flows, use manual browser login or HAR import:

```bash
# Open a browser, log in manually — Beatrix captures the complete session
# (including HttpOnly cookies and localStorage tokens)
beatrix auth browser example.com

# Or pass cookies directly from DevTools
beatrix hunt example.com --cookie "session=abc123" --cookie "XSRF-TOKEN=xyz"
```

> **Note:** In environments without a display (e.g., GitHub Codespaces), `auth browser` falls back to a cookie-paste prompt. To capture all cookies including HttpOnly ones, open the target in your local browser, go to **DevTools → Network**, click any authenticated request, and copy the full `Cookie:` request header value. Avoid the Application → Storage → Cookies panel, which misses HttpOnly cookies.

### HAR Import

The easiest way to hand Beatrix a fully authenticated session is to export a HAR file from your browser's DevTools and import it directly. This captures all cookies (including HttpOnly), Authorization headers, and API keys exactly as they appeared in real requests.

```bash
# 1. Log in with your browser normally
# 2. DevTools → Network → right-click any request → "Save all as HAR with content"
# 3. Import into Beatrix
beatrix auth import example.com session.har

# Also accepts a plain text cookie string
beatrix auth import example.com cookies.txt

# Verify the imported session
beatrix auth show -t example.com
```

Beatrix scores every entry in the HAR by request URL (preferring authenticated API calls over static assets), extracts the best `Cookie` header, `Authorization: Bearer` token, and any `X-Api-Key` / `X-Auth-Token` headers, then saves the result as a normal session file that all scanners pick up automatically.

### IDOR Dual-Account Setup from HAR

The IDOR scanner needs two authenticated accounts to prove cross-user access. Rather than handing Beatrix two sets of credentials (and dealing with 2FA twice), capture a HAR for each account and load them straight into the IDOR slots with `--idor-slot`:

```bash
# Capture a HAR while logged in as each account, then import one per slot
beatrix auth import example.com account1.har --idor-slot user1
beatrix auth import example.com account2.har --idor-slot user2

# Now hunt — the IDOR scanner swaps between the two sessions per request
beatrix hunt example.com
```

Each import merges into `~/.beatrix/auth.yaml` under `idor.<slot>` without clobbering the other slot, so the two commands are independent. Because a HAR captures an already-authenticated session, this works around 2FA entirely — no credentials are stored.

### Bot-Fingerprinting Targets (Browser Auth)

Some targets (e.g. Akamai bot management) fingerprint scripted HTTP clients and block or redirect an otherwise-valid authenticated session regardless of correct cookies. Beatrix's `SessionValidator` auto-detects this — when an `httpx`-based session probe fails but a real-Chromium probe succeeds, authenticated scanner requests are routed through a Playwright-backed transport (`browser_transport.py`) that shares Chromium's real TLS/network fingerprint.

The auto-detection samples a fixed list of common auth-check paths, so it can miss path-specific blocking. Force browser-backed authenticated requests with `--browser-auth`:

```bash
beatrix hunt example.com --browser-auth
```

This is slower per request and only affects authenticated scanner traffic (not bulk unauthenticated requests). Requires Playwright (installed by `beatrix setup`).

### Session Persistence

Authenticated sessions are saved to `~/.beatrix/sessions/<domain>.json` and reused for 24 hours. If the session contains a JWT, Beatrix additionally checks the token's `exp` claim on every load — a token expiring within 5 minutes is discarded automatically so stale sessions never reach scanners. During a scan, `SessionValidator` periodically re-probes the target and triggers re-authentication if the session goes dead mid-hunt.

```bash
beatrix auth sessions                         # list all saved sessions
beatrix auth sessions --clear example.com     # clear one
beatrix auth sessions --clear-all             # clear all
beatrix hunt example.com --fresh-login        # force re-authentication
beatrix hunt example.com --manual-login       # browser login for this scan
```

### Static Credentials

```bash
beatrix auth init                             # generate sample config
beatrix hunt target.com --token "Bearer eyJ..."
beatrix hunt target.com --cookie "session=abc123"
beatrix hunt target.com --header "X-API-Key: key123"
beatrix hunt target.com --auth-user admin --auth-pass password
beatrix auth show
beatrix auth show -t example.com
beatrix auth config                           # edit in default editor
```

Auth config supports per-target credentials and IDOR dual-session testing. See `~/.beatrix/auth.yaml`.

---

## GitHub Secret Scanning

```bash
beatrix github-recon acme-corp
beatrix github-recon acme-corp --quick                              # skip git history
beatrix github-recon acme-corp --repo acme-corp/api-server -o report.md
```

---

## Validation

```bash
beatrix validate beatrix_report.json
beatrix validate scan_results.json -v
```

Accepts both envelope format (`{"findings": [...], "metadata": {...}}`) and bare lists (`[...]`).

---

## Output Format

All `-o` / `--output` JSON exports use a standardized envelope:

```json
{
  "findings": [
    {
      "title": "CORS Misconfiguration",
      "severity": "high",
      "confidence": "confirmed",
      "url": "https://example.com/api",
      "scanner_module": "cors",
      "description": "...",
      "evidence": "...",
      "remediation": "..."
    }
  ],
  "metadata": {
    "tool": "beatrix",
    "version": "1.0.0",
    "target": "example.com",
    "total_findings": 1,
    "generated_at": "2026-02-23T12:00:00Z"
  }
}
```

---

## Scan Output Directory

Every `hunt` creates an organized output directory in the current working directory, named after the target and timestamped:

```
example.com-scan-09-Mar-2026_17-53-48/
├── scan_info.txt               # target, start time, duration
├── recon/                      # katana, amass, nmap, whatweb raw output
├── weaponization/              # takeover, error disclosure results
├── delivery/                   # CORS, redirect, smuggling results
├── exploitation/               # sqlmap, dalfox, injection results
├── installation/               # file upload results
├── c2/                         # OOB callback results
├── actions/                    # VRT classification results
└── findings/                   # aggregated findings JSON and summary
```

All external tool runners capture raw stdout automatically. Scanner results are written as JSON after each module completes. No extra flags are needed.

---

## Configuration

Config file: `~/.beatrix/config.yaml`

```bash
beatrix config --show
beatrix config --set scanning.rate_limit 50
beatrix config --set ai.enabled true
beatrix config --set output.dir ./my_results
```

### Config Keys

| Key | Default | Description |
|-----|---------|-------------|
| `scanning.threads` | 50 | Concurrent threads |
| `scanning.rate_limit` | 100 | Requests per second |
| `scanning.timeout` | 10 | HTTP timeout (seconds) |
| `ai.enabled` | false | Enable AI features |
| `ai.provider` | bedrock | AI provider (bedrock/anthropic) |
| `ai.model` | claude-haiku | Model name |
| `output.dir` | . | Default output directory |
| `output.verbose` | false | Verbose logging |

### Environment Variables

| Variable | Purpose |
|----------|---------|
| `ANTHROPIC_API_KEY` | Anthropic API key (for GHOST) |
| `AWS_REGION` | AWS region for Bedrock |
| `GITHUB_TOKEN` | GitHub token for recon |
| `SECURITYTRAILS_API_KEY` | SecurityTrails DNS history (CDN bypass) |
| `CENSYS_API_ID` | Censys certificate search (CDN bypass) |
| `CENSYS_API_SECRET` | Censys API secret (CDN bypass) |
| `SHODAN_API_KEY` | Shodan host search (CDN bypass) |

---

## Getting Help

```bash
beatrix manual          # full interactive HTML manual
beatrix                 # quick reference
beatrix help hunt
beatrix help strike
beatrix help ghost
beatrix arsenal         # full module reference
beatrix list --modules
beatrix list --presets
```

---

## Architecture

```
beatrix/
├── cli/main.py               # CLI entry point — 26 commands via Click + Rich
├── core/
│   ├── engine.py             # BeatrixEngine — orchestrates all modules
│   ├── kill_chain.py         # 7-phase kill chain executor + 3-phase network pipeline
│   ├── nmap_scanner.py       # Full TCP/UDP scanning, NSE scripts
│   ├── packet_crafter.py     # Scapy firewall fingerprint, source-port/fragment bypass
│   ├── ssh_auditor.py        # SSH fingerprint, weak crypto, default credential brute-force
│   ├── external_tools.py     # 20 async subprocess tool runners with streaming support
│   ├── browser_transport.py  # Chromium-backed HTTP transport for bot-fingerprinting targets
│   ├── auth_config.py        # Auth credentials + SessionValidator (session liveness, browser fallback)
│   ├── types.py              # Finding, Severity, Confidence, ScanContext
│   ├── seclists_manager.py   # Dynamic wordlist engine (SecLists + PayloadsAllTheThings)
│   ├── oob_detector.py       # OOB callback manager (LocalPoCClient + interactsh)
│   ├── poc_server.py         # Built-in PoC validation server (pure asyncio)
│   ├── correlation_engine.py # MITRE ATT&CK correlation
│   ├── findings_db.py        # SQLite findings storage (WAL mode)
│   ├── issue_consolidator.py # Finding deduplication
│   ├── poc_chain_engine.py   # PoC generation + Metasploit integration
│   └── scan_output.py        # Per-scan organized output directory
├── scanners/
│   ├── base.py               # BaseScanner — rate limiting, httpx client, logging
│   ├── crawler.py            # Target spider — foundation for all scanning
│   ├── origin_ip_discovery.py # CDN bypass + origin IP discovery
│   ├── injection.py          # SQLi, XSS, CMDi, LFI, SSTI (57K+ payloads, WAF bypass)
│   ├── ssrf.py               # 44-payload SSRF scanner
│   ├── cors.py               # 6-technique CORS bypass scanner
│   ├── auth.py               # JWT, OAuth, 2FA, session attacks
│   ├── idor.py               # IDOR and BAC scanners
│   ├── nuclei.py             # Nuclei v3 — multi-phase, authenticated, WAF bypass
│   └── ...                   # 30 scanner modules total
├── validators/               # ImpactValidator, ReadinessGate
├── reporters/                # Markdown, JSON, HTML chain reports
├── recon/                    # ReconRunner — subfinder/amass/nmap integration
├── ai/                       # GHOST agent, Haiku integration
├── integrations/             # External service clients
└── utils/                    # WAF bypass, VRT classifier, response_analyzer
```

---

## Legal

This tool is for authorized security testing only. Only use Beatrix against targets you have explicit written permission to test. Unauthorized access to computer systems is illegal in most jurisdictions.

---
