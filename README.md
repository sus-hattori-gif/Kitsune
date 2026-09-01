# Kitsune 🦊

Kitsune is a lightweight, modular, CLI-based security scanner written in
pure Python. It performs host discovery, port scanning, banner/service
detection, HTTP security header analysis, OS fingerprinting, and
lightweight vulnerability assessment — either as a full chained
pipeline or as independent, standalone commands.

Kitsune is built for **authorized security testing**: personal systems,
home labs, CTFs, and networks you have explicit permission to assess.

---

## Features

- **Host Discovery** — ICMP ping sweep with automatic TCP fallback when
  ICMP is filtered. Supports single IPs, hostnames, and CIDR ranges.
- **Port Scanning** — concurrent TCP connect scan with configurable
  ports, timeouts, and concurrency. Classifies ports as open / closed /
  filtered.
- **Banner Grabbing / Service Detection** — connects to open ports and
  extracts banners and version hints where a service exposes them.
- **HTTP Header Analysis** — checks for CSP, HSTS, X-Frame-Options,
  X-Content-Type-Options, Referrer-Policy, Permissions-Policy; inspects
  cookies, redirects, TLS issues, and server disclosure.
- **OS Detection** — combines TTL, open-port fingerprint, and banner
  hints into a weighted, explicitly probabilistic OS guess with a
  confidence score.
- **Vulnerability Assessment** — rule-based, conservative detection of
  missing security headers, risky exposed services, weak cookie flags,
  plaintext HTTP, and clearly outdated service versions. Every finding
  is labeled confirmed / likely / possible.
- **Full Scan Pipeline** — chains every stage above, reusing results
  between stages and intelligently skipping stages that don't apply
  (e.g. no open ports → skip banner grabbing and HTTP analysis).
- **Error Isolation** — a failure in one module never crashes the whole
  scan; the report simply marks that stage unavailable.
- **Structured Output** — human-readable text (default) or JSON
  (`--json` / `--out FILE`).

Kitsune deliberately does **not** include a plugin system, exploitation
modules, or stealth/evasion features in this version — see
[Limitations](#limitations) and [Security & Authorized Use](#security--authorized-use).

---

## Requirements

- Python 3.9+
- The system `ping` utility available on `PATH` (used for ICMP host
  discovery; present by default on Linux, macOS, and Windows). If it's
  missing, Kitsune automatically falls back to TCP-based discovery.
- No required third-party Python packages — see `requirements.txt`.

---

## Installation

```bash
git clone <this-repo-or-extract-the-zip>
cd Kitsune
python3 -m venv venv          # optional but recommended
source venv/bin/activate      # on Windows: venv\Scripts\activate
pip install -r requirements.txt   # currently a no-op; kept for future use
```

No build step is required — Kitsune runs directly with `python3 main.py`.

---

## Usage

```
kitsune <command> <target> [options]
```

Global options (apply to every command):

| Flag | Description |
|---|---|
| `-v`, `-vv` | increase verbosity (info / debug) |
| `-q`, `--quiet` | suppress non-error output |
| `--json` | print JSON instead of human-readable text |
| `--out FILE` | write JSON results to `FILE` |
| `--timeout N` | override the default per-probe timeout (seconds) |

### CLI Commands

```
kitsune scan <target> [--ports RANGE] [--concurrency N] [--max-hosts N] [--skip-vuln]
kitsune host-scan <target/CIDR> [--concurrency N] [--max-hosts N]
kitsune port-scan <target> [--ports RANGE] [--concurrency N]
kitsune banner <target> [--ports RANGE] [--concurrency N]
kitsune headers <url-or-host>
kitsune os-detect <target> [--ports RANGE]
kitsune vuln-scan <target> [--ports RANGE]
```

`<target>` accepts a single IP, a hostname, or (for `scan`/`host-scan`)
a CIDR range such as `192.168.1.0/24`.

`--ports` accepts a comma-separated list and/or ranges, e.g. `22,80,443`
or `1-1024` or `22,80,1000-2000`. When omitted, Kitsune uses a curated
list of ~25 commonly-scanned ports.

### Examples

```bash
# Full scan of a single host
python3 main.py scan 192.168.1.10

# Full scan of a subnet, custom port range, JSON saved to disk
python3 main.py scan 192.168.1.0/28 --ports 1-1000 --out results/lab_scan.json

# Just discover which hosts are up on a network
python3 main.py host-scan 192.168.1.0/24

# Scan specific ports on one host
python3 main.py port-scan 192.168.1.10 --ports 22,80,443,8080

# Grab banners from open ports
python3 main.py banner 192.168.1.10

# Analyze a website's security headers
python3 main.py headers https://example.com

# OS fingerprint only
python3 main.py os-detect 192.168.1.10

# Vulnerability assessment only
python3 main.py vuln-scan 192.168.1.10
```

### Sample Output

```
Host Discovery
----------------------------------------
192.168.1.1     UP (via icmp)
192.168.1.5     UP (via icmp)
192.168.1.20    DOWN
```

```
HTTP SECURITY ANALYSIS
----------------------------------------
URL: https://example.com/
Status: 200

CSP                     MISSING
HSTS                    PRESENT
X-Frame-Options         MISSING
X-Content-Type-Options  PRESENT
Referrer-Policy         MISSING
Permissions-Policy      MISSING

Server: nginx
```

---

## Project Structure

```
Kitsune/
│
├── main.py                 # CLI entry point / argument parsing / dispatch
├── requirements.txt
├── README.md
│
├── scanner/
│   ├── __init__.py
│   ├── host.py              # Host discovery (ICMP + TCP fallback)
│   ├── ports.py              # TCP connect port scanning
│   ├── banner.py             # Banner grabbing / service detection
│   ├── headers.py            # HTTP security header analysis
│   ├── os_detect.py          # OS fingerprinting (TTL + ports + banners)
│   └── vulnerability.py      # Lightweight vulnerability assessment
│
├── pipeline/
│   ├── __init__.py
│   └── scan.py               # Full pipeline orchestration + skip logic
│
├── utils/
│   ├── __init__.py
│   ├── network.py            # Socket helpers, retry logic, ping/TTL probing
│   ├── output.py             # Centralized text/JSON rendering & saving
│   └── common.py             # Target/port parsing, logging setup
│
├── results/                  # Default location for saved JSON reports
│
└── tests/
    ├── __init__.py
    ├── test_common.py
    ├── test_host.py
    ├── test_ports.py
    ├── test_headers.py
    ├── test_os_detect.py
    ├── test_vulnerability.py
    ├── test_pipeline.py
    └── test_output.py
```

---

## Testing

Run the full test suite from the project root:

```bash
python3 -m unittest discover -s tests -v
```

The suite covers target/CIDR/port parsing, port-state classification,
HTTP header analysis (against a local test server), OS-fingerprint
scoring logic, vulnerability rules, pipeline skip logic, and pipeline
error isolation. Network-dependent tests use local loopback servers or
mocks rather than reaching out to the internet, so the suite runs
reliably offline.

---

## Limitations

- Port scanning uses a TCP **connect** scan (not a raw SYN scan), so it
  needs no special privileges but is slightly more visible to the
  target than a stealth scan — by design, this project does not aim
  for stealth.
- OS detection is a lightweight heuristic (TTL + open ports + banners),
  not a full TCP/IP stack fingerprinting engine (e.g. no raw-socket
  analysis of TCP options/window scaling). It always reports a
  confidence score and never claims certainty.
- Vulnerability assessment is rule-based and intentionally conservative
  — it is **not** a CVE database or exploit framework, and does not
  attempt exploitation.
- ICMP host discovery depends on the system `ping` binary; if it isn't
  present or ICMP is filtered network-wide, Kitsune automatically falls
  back to a TCP-based liveness check.
- No plugin system in this version, by design (see project spec).

---

## Security & Authorized Use

Kitsune is intended for use against:

- Systems and networks you own,
- Systems you have **explicit authorization** to test,
- CTFs, security labs, and other controlled environments.

Do not use Kitsune against systems you do not have permission to test.
Kitsune is built around detection and assessment, not exploitation: it
does not attempt to gain unauthorized access, exfiltrate data, harvest
credentials, or bypass security controls, and it includes no stealth
features intended to conceal scanning activity from a target's
defenses. Scanning networks without authorization may be illegal in
your jurisdiction — you are responsible for using this tool lawfully
and ethically.
