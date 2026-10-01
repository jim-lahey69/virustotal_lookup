# GTI / VirusTotal CVE Enricher

## Project Overview

This tool helps security engineers **prioritize CVEs** using **Google Threat Intelligence (GTI)** Vulnerability Intelligence, accessed through the VirusTotal API.

Given a CSV of CVE IDs, it queries:

```text
GET https://www.virustotal.com/api/v3/collections/vulnerability--{cve-lowercase}
```

…and produces:

- A structured **CSV** for tickets, SIEM, or spreadsheets  
- **Rich terminal cards** for interactive review  
- A self-contained primary **HTML report** per CVE; the first opens automatically
- A companion **IOC report** per CVE with a working link from its primary report
- A companion **Associations / Associated Threats report** per CVE with actors,
  campaigns, supporting intelligence, Tcodes, and an evidence-labeled ATT&CK mapping

It is built for **corporate Windows environments**: API key and proxy live in a project `.env` file (no session-level `$env:` every time you open PowerShell), and TLS works with **corporate SSL inspection** via an explicit CA bundle—never by disabling certificate verification.

**License required:** GTI **Enterprise** or **Enterprise Plus** with **Vulnerability Intelligence**. Standard free/public VirusTotal keys return `401`/`403` for this endpoint.

---

## Features

- **VirusTotal / GTI CVE enrichment** — risk rating, EPSS, CVSS, CISA KEV, exploitation state, affected products, and more  
- **Internal priority (P0–P3)** — deterministic local 0–100 score from CVSS severity, active-exploitation evidence, EPSS percentile, exploit maturity, and CVSS v4 automatability
- **Auditable score breakdown** — every report and CSV exposes the five component scores, normalized inputs, total, and final rating; VirusTotal's native `priority` is retained only as `vt_priority_raw` comparison data and cannot override the result
- **Supporting intelligence visualization** — offline inline SVG of normalized Risk Rating, Exploit Availability, and Exploitation State; these contextual axes no longer calculate priority
- **Separate IOC workflow** — complete, paginated IOC rows live in a companion report; its visible count is the number of unique rows actually rendered
- **Associated-threat workflow** — paginated direct associations are filtered into threat actors, campaigns, malware/tools, reports, and relevant IOC collections
- **Evidence-backed attack-chain view** — direct VirusTotal Tcodes are mapped to returned MITRE ATT&CK tactics; mapped stages are explicitly distinguished from observed relationships and are never presented as observed chronology
- **Lightweight report selection** — multi-CVE runs create one three-report set per CVE and offer a numbered CLI selector in input order
- **`.env` configuration** — single source of truth for API key, HTTP proxy, and corporate CA path (loaded via `python-dotenv`)  
- **Corporate proxy support** — `HTTP_PROXY` / `HTTPS_PROXY` applied to the `requests` session  
- **Corporate SSL inspection** — use a PEM/CRT root CA (`CORPORATE_CA_BUNDLE` or `./certs/corporate-ca.pem`); TLS verification is always on  
- **Always-on HTML report** — written and opened after every run, including total failure (missing key, SSL errors, network issues)  
- **Resilient API client** — request delay, retries on 429/5xx/network errors, optional early stop on privilege errors  
- **Flexible input CSV** — single-column or multi-column files with common CVE header names  

---

## Prerequisites

| Requirement | Notes |
|-------------|--------|
| **Python 3.10+** | Check with `python --version` |
| **Network path to VirusTotal** | Usually via corporate proxy `http://webproxy:` (or your org’s proxy) |
| **GTI API key** | Enterprise / Enterprise Plus + Vulnerability Intelligence |
| **Corporate root CA** (if SSL inspection is enabled) | PEM/Base-64 CER exported from the Windows trust store |

**Packages** (installed from `requirements.txt`):

- `requests` — HTTP client  
- `rich` — terminal UI  
- `python-dotenv` — load `.env`  
- `urllib3` — dependency of `requests`  

**Corporate network assumptions:**

- Outbound HTTPS may be forced through an HTTP proxy.  
- The proxy may perform **SSL inspection (MITM)** with an internal root CA.  
- Python’s default trust store (certifi) does **not** include that CA until you supply it.

---

## Installation

From PowerShell (or any terminal), in the project directory:

```powershell
# 1. Change to the project folder
cd C:\Users\username\virustotal_lookup

# 2. (Recommended) create and activate a virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# 3. Install dependencies
pip install -r requirements.txt
```

If you use git:

```powershell
git clone <repository-url>
cd virustotal
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

---

## Configuration

### Create and populate `.env`

`.env` is the **single source of truth** for secrets and proxy settings. The script loads it automatically—you do **not** need to set `$env:VIRUSTOTAL_API_KEY` or `$env:HTTP_PROXY` in every PowerShell session.

```powershell
Copy-Item .env.example .env
notepad .env
```

**Required / typical variables:**

```env
# VirusTotal / GTI API key (required)
VIRUSTOTAL_API_KEY=your_actual_api_key_here

# Corporate HTTP proxy (both schemes usually use http:// for the proxy URL)
HTTP_PROXY=http://webproxy:
HTTPS_PROXY=http://webproxy:

# Corporate root CA for SSL inspection (uncomment after the file exists)
# CORPORATE_CA_BUNDLE=./certs/corporate-ca.pem

# Optional: seconds between API requests (default 1.0)
# VT_REQUEST_DELAY=1.0
```

| Variable | Purpose |
|----------|---------|
| `VIRUSTOTAL_API_KEY` | GTI API key (**required**). Alias: `VT_API_KEY` |
| `HTTP_PROXY` | Proxy for HTTP traffic (e.g. `http://webproxy:`) |
| `HTTPS_PROXY` | Proxy for HTTPS targets (usually the same URL as `HTTP_PROXY`) |
| `CORPORATE_CA_BUNDLE` | Path to org root CA PEM/CRT |
| `VT_REQUEST_DELAY` | Inter-request delay in seconds |
| `VT_HTTP_PROXY` / `VT_HTTPS_PROXY` | Optional aliases for the standard proxy vars |

**Keep `.env` out of version control.** It is listed in `.gitignore`. Commit only `.env.example` (placeholders).

### Obtain and place the corporate CA certificate

Corporate SSL inspection presents certificates signed by an **internal root CA**. Without that CA, `requests` raises certificate verification errors.

**Do not disable TLS verification.** This tool never uses `verify=False`.

#### Steps (Windows Certificate Manager)

1. Press **Win+R**, run `certmgr.msc` (user) or `certlm.msc` (local machine).  
2. Open **Trusted Root Certification Authorities → Certificates**.  
3. Find your corporate / proxy inspection CA (company name, Zscaler, Netskope, Palo Alto, Blue Coat, etc.—ask IT if unsure).  
4. Right-click → **All Tasks → Export…**.  
5. Choose **Base-64 encoded X.509 (.CER)**.  
6. Save and place the file as:

```text
certs\corporate-ca.pem
```

(Base-64 CER and PEM are the same text format.)

#### Optional: set the path in `.env`

```env
CORPORATE_CA_BUNDLE=./certs/corporate-ca.pem
```

If `CORPORATE_CA_BUNDLE` is **not** set, the script still auto-uses `./certs/corporate-ca.pem` **when that file exists**. If you set the variable, the file **must** exist or the run fails with a clear error (and still opens an HTML failure report).

More export options (PowerShell, browser path): see [certs/README.md](certs/README.md) and [SETUP.md](SETUP.md).

### Proxy settings

Many corporate networks require an HTTP proxy for outbound API traffic.

```env
HTTP_PROXY=http://webproxy:
HTTPS_PROXY=http://webproxy:
```

Notes:

- Use a full URL including scheme and port.  
- Both variables typically use the `http://` scheme for the **proxy itself**; the client still requests HTTPS destinations through that proxy.  
- If IT gives only `host:port`, prefix with `http://`.  
- Credentials (if required): `http://username:password@proxy:port`—prefer `.env` over shell history.  
- CLI overrides: `--http-proxy` / `--https-proxy`.

After load, the script applies proxies to `requests.Session.proxies` so every API call uses the corporate path.

---

## Usage

### Input CSV

Edit `cve_list.csv` (or pass another file with `-i`):

```csv
CVE
CVE-2024-3400
CVE-2021-44228
CVE-2023-34362
```

Headers such as `CVE`, `cve_id`, `cve`, or `id` are accepted. Duplicates and invalid IDs are skipped.

### Run the enricher

**PowerShell (typical day-to-day—no session env vars needed once `.env` is set):**

```powershell
cd C:\Users\username\virustotal_lookup
python cve_enricher.py -i cve_list.csv -o cve_enriched.csv --html report.html
```

**Minimal (uses defaults for input/output/HTML paths):**

```powershell
python cve_enricher.py
```

**Verbose (debug logging):**

```powershell
python cve_enricher.py -i cve_list.csv -o cve_enriched.csv --html report.html -v
```

**Single CVE (`--input` wins over the CSV from `-i`):**

```powershell
python cve_enricher.py --input CVE-2026-12345
```

### Command-line arguments

| Flag | Description | Default |
|------|-------------|---------|
| `--input CVE` | Single CVE identifier to enrich (example: `CVE-2026-12345`). When set, this ID is the sole target and the CSV from `-i` is ignored. | none |
| `-i FILE` | Input CSV of CVE IDs (ignored when `--input` is set) | `cve_list.csv` |
| `-o` / `--output` | Enriched CSV path | `cve_enriched.csv` |
| `--html PATH` | Single-CVE HTML path; for multi-CVE runs, supplies the directory for `CVE-…_report.html` files | `report.html` |
| `--ioc-html PATH` | Single-CVE IOC path; for multi-CVE runs, supplies the directory for `CVE-…_iocs.html` files | `ioc_report.html` beside `--html` |
| `--associations-html PATH` | Single-CVE Associations path; for multi-CVE runs, supplies the directory for `CVE-…_associations.html` files | `associations_report.html` beside `--html` |
| `--no-open` | Write HTML but do not open a browser | off |
| `--no-rich` | Skip Rich terminal cards | off |
| `--api-key` | API key (prefer `.env`) | from `.env` |
| `--http-proxy` / `--https-proxy` | Proxy URLs | from `.env` |
| `--ca-bundle PATH` | Corporate CA PEM/CRT | from `.env` / `certs/` |
| `--env-file PATH` | Alternate `.env` path | `.env` next to script |
| `--delay SECONDS` | Pause between API requests | `1.0` / `VT_REQUEST_DELAY` |
| `--max-retries N` | Retries on 429 / 5xx / network errors | `5` |
| `--continue-on-forbidden` | Do not stop after first 401/403 | off |
| `--dump-raw DIR` | Save raw JSON responses per CVE | off |
| `-v` / `--verbose` | Debug logging | off |

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | At least one CVE enriched successfully |
| `1` | All CVEs failed / not found / runtime error |
| `2` | Config / input / missing API key / missing CA path |
| `3` | Privilege error (401/403) and zero successes |

---

## HTML Report

For a single CVE, after **every** run—success, partial success, or complete failure—the tool:

1. Writes the self-contained primary report (default `report.html`)
2. Writes its companion IOC report (default `ioc_report.html`)
3. Writes its companion Associations report (default `associations_report.html`)
4. Opens the primary report in the default browser; companion reports open from their links

For a CSV with multiple CVEs, the tool writes `CVE-…_report.html`, `CVE-…_iocs.html`, and `CVE-…_associations.html` for every record in the original input order. It opens the first CVE report, prints the numbered list, and accepts repeated selections until Enter is pressed. Invalid and out-of-range selections are reported without ending the enrichment run. `--no-open` skips both the automatic open and numbered selector.

Reports stay available throughout review. Press Enter at the final prompt (`Press Enter to exit and remove generated HTML reports...`, or the equivalent numbered selector prompt) to delete only the primary, IOC, and Associations HTML files written by that invocation. This also applies to single-CVE runs, failure reports, custom output paths, and manual review with `--no-open`. CSV and raw JSON exports, older reports at other paths, and unrelated HTML files are preserved. Missing files are skipped; a deletion failure identifies the file in a warning and cleanup continues.

EOF (closed input) or Ctrl+C at the review prompt exits without deleting reports, since cleanup requires Enter. Files left by interrupted runs may need manual removal. The default report names and per-CVE report patterns are gitignored as an additional safeguard; custom filenames may need their own ignore rules.

### What the report contains

**On success / partial success:**

- Summary chips (counts by priority)  
- Per-CVE cards: internal 0–100 priority breakdown, P0–P3 rating, supporting VirusTotal intelligence visualization, risk, EPSS, CVSS, exploitation, CISA KEV, products, summary, IOC and Associated Threats deep links, and link to VirusTotal
- Associations report sections: threat actors, campaigns, supporting threat intelligence, Tcodes, ATT&CK-aligned attack-chain mapping, and evidence/provenance

**On failure (missing key, SSL, proxy, network, etc.):**

- Title indicates failure  
- Prominent **Run failed** banner with exception message and traceback summary  
- Any partial per-CVE results still appear below the banner  

For automation/CI, use `--no-open` with closed standard input to retain reports without waiting for review. Supplying a blank input line instead confirms cleanup and removes the generated HTML reports.

### Report mapping notes

Scoring rules are isolated in `priority_scoring.py`; `cve_enricher.py` handles acquisition, normalization, record mapping, and presentation. The separation keeps the priority calculation reusable and prevents report code from changing policy.

**CVE identifier.** CVE is the canonical vulnerability identifier in the API mapping, internal record, CSV, terminal output, and HTML report. Context still includes CWE, disclosure/last-modified dates, products, risk factors, and the VirusTotal collection URL.

**IOCs.** `counters.iocs` / `files_count` / etc. are counts only. When a count is greater than zero the client fetches relationship objects (`files`, `urls`, `domains`, `ip_addresses`) once as part of enrichment using the same proxy, corporate CA bundle, throttle, and retry path as the collection GET. Each relationship uses a 40-object page size and follows VirusTotal's supported `links.next` pagination; next-page URLs are restricted to the configured API origin and relationship path before the API key-bearing request is sent. The IOC report groups files, URLs, domains, IPv4, IPv6, and unclassified values, preserves full values, and removes only identical indicators within the same relationship type. It does not slice the returned collection. The visible `Indicators of Compromise` count is computed from the unique table rows actually rendered, and report generation verifies that the collected and rendered row totals match. A counter/relationship shortfall is marked partial and explained in the report. Explicit zero, absent counters, request failure, partial pagination, and response-parsing failure remain distinct statuses.

**Associations.** The client requests complete, paginated objects from `GET /api/v3/collections/vulnerability--<cve-lowercase>/associations?limit=40`. That documented relationship can return heterogeneous Reports, Campaigns, IOC Collections, Malware Families, Software/Toolkits, Vulnerabilities, and Threat Actors. The report filters out other vulnerabilities and unknown types, groups direct threat actors and campaigns separately, and retains malware/toolkit/report/IOC-collection objects only as supporting intelligence. This single broad request avoids duplicate actor- and campaign-specific calls. The same origin/path checks, session cache, request delay, proxy/CA configuration, retry rules, and 50-page safety guard used by the IOC workflow apply here.

**Tcodes and attack-chain mapping.** “Tcodes” are not read from an assumed `tcodes` property. They are the MITRE technique IDs returned by `GET /api/v3/collections/vulnerability--<cve-lowercase>/attack_techniques?limit=40` (for example, `T1190`). For each returned technique, the client requests its documented `GET /api/v3/attack_techniques/<Tcode>/attack_tactics?limit=40` relationship. A stage is created only when VirusTotal returns that technique-to-tactic edge. Recognized Enterprise tactics are displayed in canonical ATT&CK lifecycle order; unfamiliar Mobile/ICS/other tactics retain API order. The sequence is labeled **Analytical Mapping** and **not observed chronology**. Direct VirusTotal objects remain labeled as observed relationship data. CVE-level actors, campaigns, malware, tools, and IOCs are not assigned to an individual stage because co-association alone does not prove that attribution.

**Missing data and licensing.** Empty direct associations produce the explicit no-associations state, and missing usable tactic evidence produces the explicit insufficient-intelligence state instead of a fabricated chain. Partial pagination, parsing failures, 401/403 privilege failures, 429 rate limits, and other request errors are retained in the Associations report without preventing the primary or IOC report from being generated. Vulnerabilities, Threat Actors, and Campaigns require Google TI Enterprise or Enterprise Plus access; object coverage and relationship visibility can vary by license and by the intelligence available for a CVE. Data visible in the web interface may therefore be absent from the API response available to the configured key.

**Exploitation State.** The value is shown with the existing color treatment plus an info icon. Tooltip text is the official definition (“Indicates our knowledge of the current exploitation landscape…”) and the level legend: 0 = No Known, 1 = Suspected, 2 = Reported, 3 = Confirmed, 4 = Wide. Missing or unrecognized API values render as **Unknown**, not “No Known”.

**Internal Priority Score.** The application calculates 0–100 locally: CVSS v4.0 base score (or v3.1 fallback) contributes up to 40; CISA KEV, ransomware association, or malware-kit association contributes 25 when any one is positive; EPSS percentile contributes 0, 4.95, 9.90, or 15; normalized exploit maturity contributes 0, 5, or 10; and an explicitly parsed CVSS v4 `AU:Y` contributes 10. Ratings are `P0 >= 90`, `P1 >= 70`, `P2 >= 50`, and `P3 < 50`. Missing or malformed optional inputs score zero without becoming positive evidence. The undefined EPSS 76th–79th percentile range is isolated in `EPSS_PERCENTILE_BANDS` and temporarily receives the conservative adjacent 4.95-point tier. Calculations retain full precision and totals are bounded to 0–100.

**VirusTotal priority.** The native API `priority` field is stored as `vt_priority_raw` for comparison/debug only. It is explicitly labeled “not used” in reports and is never passed to `calculate_internal_priority()` or `classify_priority()`; even a native value such as `P0` cannot override the application's rating.

**Supporting intelligence visualization.** The supported Vulnerability API schema exposes categorical inputs but no visualization image/asset or separate numeric graph fields, so the report retains the GTI-style Y-axis graphic as contextual inline SVG. It is explicitly non-scoring. Normalization happens once in the `CVERecord`, and both SVG markers and text consume those same labels/levels. Mapping: Risk Rating `Unrated=0`, `Low=1`, `Medium=2`, `High=3`, `Critical=4`; Exploit Availability `No Known/None=0`, `Interest Observed=1`, `Unverified=2`, `Privately Held=3`, `Publicly Available/Known/Trivial=4`; Exploitation State `No Known=0`, `Suspected=1`, `Reported=2`, `Confirmed=3`, `Wide=4`. Missing/unrecognized values remain unavailable and are not silently plotted at zero.

**Exploited in the Wild.** GTI’s Vulnerability object does not document a top-level `exploited_in_the_wild` attribute. The client therefore queries the documented `vulnerability_filter:"Observed In The Wild"` search filter for the exact CVE. A successful match maps to **Yes**, a successful empty result maps to **No**, and request/parsing failure maps to **Unknown**. Exploitation State, CISA KEV, and exploit availability remain independent metrics and are not substituted for this filter.

Finding for **CVE-2026-34621**: the GUI showed Exploited in the Wild = Yes while an earlier report printed **no** because the mapper read an undocumented, absent object key with `default=False`. The corrected path is `Observed In The Wild filtered search -> exact CVE membership -> normalized three-state field -> HTML badge`. Sanitized vulnerability and filter-response fixtures cover the regression without a CVE-specific code path. Exploitation key snapshots are DEBUG-log only and never dumped into the HTML body.

---

## Troubleshooting

### SSL / certificate errors

| Symptom | Cause | Fix |
|---------|--------|-----|
| `SSLError`, `CERTIFICATE_VERIFY_FAILED`, or similar | Corporate SSL inspection; Python does not trust the MITM CA | Export org root CA → `certs\corporate-ca.pem` or set `CORPORATE_CA_BUNDLE` |
| `CA bundle not found` | `.env` points at a path that does not exist | Create the file or fix/remove the path |
| Still failing after placing CA | Wrong cert (intermediate instead of root) or incomplete chain | Export the **root** from the certification path; ask IT for the inspection CA PEM |

Never set `verify=False`. The tool will refuse to run with TLS verification disabled.

### Proxy-related issues

| Symptom | Cause | Fix |
|---------|--------|-----|
| Timeouts / connection errors | Proxy not set or wrong host/port | Set `HTTP_PROXY` and `HTTPS_PROXY` in `.env` |
| Works in browser but not in script | Browser uses system proxy; Python uses `.env` only | Match IT’s proxy URL exactly in `.env` |
| Auth required by proxy | Missing credentials | Use `http://user:pass@host:port` in `.env` (gitignored) |

Confirm load: logs should show `Loaded configuration from ...\.env` and `Using proxies: {...}` (passwords redacted).

### Missing or invalid API key

| Symptom | Cause | Fix |
|---------|--------|-----|
| `No API key` / placeholder rejected | `.env` missing, empty, or still `your_key_here` | Set a real `VIRUSTOTAL_API_KEY` in `.env` |
| `401` / `403` / exit code `3` | Key lacks GTI Vulnerability Intelligence | Use Enterprise / Enterprise Plus key with VI privilege |
| Key “set” but not loaded | Wrong working directory or wrong `--env-file` | Run from project root; check the “Loaded configuration from …” log line |

The HTML failure report always includes the same error detail for sharing with teammates (do not paste the API key itself).

### Other

| Symptom | Fix |
|---------|-----|
| `429` rate limited | Increase `--delay` (e.g. `1.5` or `2.0`) |
| Browser did not open | Open `report.html` manually; try without headless/restricted desktop; use `--no-open` only when intentional |
| No valid CVEs | Check CSV format and `CVE-YYYY-NNNN` pattern |

---

## Security Notes

- **Never commit `.env`.** It holds API keys and possibly proxy credentials. It is gitignored; only commit `.env.example`.  
- **Never commit corporate CA private keys.** You only need the **public** root CA certificate (PEM/CER). Private keys do not belong in this project. `certs/*.pem` and similar are gitignored.  
- **Do not hard-code secrets** in `cve_enricher.py` or paste keys into tickets/screenshots.  
- **Prefer `.env` over `--api-key`** on shared machines (CLI args can appear in shell history).  
- **TLS verification stays enabled.** Use a proper CA bundle for SSL inspection—never disable verification.  
- **Treat the API key like a password** and rotate it if exposed.  

---

## File Structure

```text
virustotal/
├── cve_enricher.py      # Main tool: config, API client, CSV/HTML/Rich output
├── priority_scoring.py   # Pure internal 0–100 scoring and P0–P3 classification
├── cve_list.csv         # Example input CVE list
├── requirements.txt     # Python dependencies
├── .env.example         # Template for secrets/proxy/CA (safe to commit)
├── .env                 # Local secrets (gitignored — create from .env.example)
├── .gitignore           # Excludes .env, certs/*.pem, reports, __pycache__, etc.
├── certs/
│   ├── .gitkeep
│   └── README.md        # How to export and place corporate-ca.pem
├── tests/               # CLI/report regressions, fixtures, and priority policy tests
├── README.md            # This document
└── SETUP.md             # Extended first-time setup (API key, proxy, CA)
```

**Generated at runtime (typically gitignored):**

| File | Purpose |
|------|---------|
| `cve_enriched.csv` | Flattened enrichment results |
| `report.html` / `ioc_report.html` / `associations_report.html` | Single-CVE or pre-enrichment-failure report set |
| `CVE-…_report.html` / `CVE-…_iocs.html` / `CVE-…_associations.html` | Per-CVE report sets for multi-CVE CSV runs |

---

## Quick reference

```powershell
# One-time setup
pip install -r requirements.txt
Copy-Item .env.example .env
# Edit .env → VIRUSTOTAL_API_KEY, HTTP_PROXY, HTTPS_PROXY
# Place certs\corporate-ca.pem if SSL inspection is in use

# Every run
python cve_enricher.py -i cve_list.csv -o cve_enriched.csv --html report.html
```

For a longer walkthrough (certificate export PowerShell snippets, persistent env alternatives, connectivity checks), see **[SETUP.md](SETUP.md)**.
