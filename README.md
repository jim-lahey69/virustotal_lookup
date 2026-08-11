# GTI / VirusTotal CVE Enricher

Production-ready Python tool that enriches CVE IDs using **Google Threat Intelligence (GTI)** Vulnerability Intelligence via the VirusTotal collections API:

```text
GET https://www.virustotal.com/api/v3/collections/vulnerability--{cve-lowercase}
```

**License required:** GTI **Enterprise** or **Enterprise Plus** (Vulnerability Intelligence privilege). Standard VT keys will receive `401`/`403`.

---

## Quick start

> **First-time install?** Follow **[SETUP.md](SETUP.md)** for API key, proxy, and corporate CA certificate setup.  
> **Corporate Windows tip:** secrets and proxy live in `.env` — you do **not** need to set `$env:HTTP_PROXY` in every PowerShell window.

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Create local config (never commit .env)
copy .env.example .env
# Edit .env: set VIRUSTOTAL_API_KEY, proxies, and CORPORATE_CA_BUNDLE

# 3. Place corporate root CA for SSL inspection (see SETUP.md / certs/README.md)
#    → certs/corporate-ca.pem

# 4. Run (HTML report is always written and opened)
python cve_enricher.py --input cve_list.csv --output cve_enriched.csv --html report.html
```

### Configuration: `.env` is the single source of truth

| Variable | Purpose |
|----------|---------|
| `VIRUSTOTAL_API_KEY` | GTI / VirusTotal API key (**required**) |
| `HTTP_PROXY` / `HTTPS_PROXY` | Corporate proxy, e.g. `http://webproxy:8080` |
| `CORPORATE_CA_BUNDLE` | Path to org root CA PEM for SSL inspection |

The script loads `.env` with **python-dotenv** at startup and applies proxy + key + CA settings automatically. Keep `.env` **out of source control** (listed in `.gitignore`).

CLI flags (`--api-key`, `--http-proxy`, `--ca-bundle`, …) still override when needed. Aliases `VT_API_KEY`, `VT_HTTP_PROXY`, and `VT_HTTPS_PROXY` are also accepted.

### Corporate SSL inspection (no `verify=False`)

TLS verification is **always enabled**. Behind a corporate MITM proxy:

1. Export your org root CA (PEM/Base-64 CER) — steps in [SETUP.md](SETUP.md) and [certs/README.md](certs/README.md).
2. Save it as `certs/corporate-ca.pem` **or** set `CORPORATE_CA_BUNDLE` in `.env`.
3. `requests` uses that path via `session.verify = "<path>"`.

Disabling verification is **not supported** and will raise an error if attempted.

### HTML report always opens

After every run — success, partial success, or complete failure (missing key, SSL error, network issues, etc.) — the tool:

1. Writes a self-contained HTML report (default `report.html`)
2. Opens it in the default browser (new window/tab when possible)

Failure reports include a **prominent error banner** with the exception message and traceback summary. Use `--no-open` only if you must suppress the browser (CI); the file is still written.

### CLI options

| Flag | Description |
|------|-------------|
| `-i / --input` | Input CSV (default `cve_list.csv`) |
| `-o / --output` | Enriched CSV (default `cve_enriched.csv`) |
| `--html PATH` | HTML report path (default `report.html`; always written) |
| `--no-open` | Do not open the HTML report in a browser |
| `--no-rich` | Skip Rich terminal cards |
| `--api-key` | API key (prefer `VIRUSTOTAL_API_KEY` in `.env`) |
| `--http-proxy` / `--https-proxy` | Corporate proxy URLs |
| `--ca-bundle PATH` | Corporate root CA PEM/CRT |
| `--env-file PATH` | Alternate `.env` path |
| `--delay SECONDS` | Inter-request delay (default `1.0`) |
| `--max-retries N` | Retries on 429 / 5xx / network errors |
| `--continue-on-forbidden` | Do not stop after 401/403 |
| `--dump-raw DIR` | Save raw JSON responses |
| `-v / --verbose` | Debug logging |

Example:

```bash
python cve_enricher.py -i cve_list.csv -o enriched.csv --html report.html --delay 1.5 -v
```

---

## Input CSV

Accepts a single column or a multi-column file with a header named `CVE`, `cve_id`, `cve`, or `id`:

```csv
CVE
CVE-2024-3400
CVE-2021-44228
CVE-2023-34362
```

CVE IDs are normalized to uppercase for display and **lowercased** for the API path (`vulnerability--cve-2024-3400`).

---

## Outputs

### 1. Structured CSV (`cve_enriched.csv`)

Flattened fields for spreadsheet / SIEM / ticket workflows, including:

- **Priority (P0–P4)** derived + raw API `priority` field  
- Risk rating, predicted risk, risk factors  
- Exploitation state / availability / in-the-wild / zero-day  
- CISA KEV (presence, added, due, ransomware use)  
- EPSS score + percentile  
- CVSSv3.1 base + temporal + vector  
- CVSSv4.0 BT score + vector + exploit maturity  
- Affected products (from `cpes`)  
- Description, MVE ID, CWE, dates, mitigations, VT URL  

### 2. Rich terminal cards

Color-coded panels per CVE:

| Signal | Color |
|--------|--------|
| Critical / P0 | Deep red |
| High / P1 | Orange-red |
| Medium / P2 | Amber |
| Low / P3–P4 | Green / cyan |

### 3. HTML report (`--html report.html`)

Self-contained dark-theme card layout — always generated and opened after the run, including failure cases with a full error section.

---

## GTI attributes used (schema map)

Mapped against the official [Vulnerability object](https://gtidocs.virustotal.com/reference/vulnerability-object):

| Report field | API attribute |
|--------------|---------------|
| Risk Rating | `attributes.risk_rating` |
| Predicted Risk | `attributes.predicted_risk_rating` |
| Risk Factors | `attributes.risk_factors` |
| Exploitation State | `attributes.exploitation_state` (fallback: nested under `exploitation`) |
| Exploit Availability | `attributes.exploit_availability` |
| Exploited in Wild | `attributes.exploited_in_the_wild` (best-effort; may be absent) |
| Exploited as Zero Day | `attributes.exploited_as_zero_day` (best-effort) |
| Exploitation dates | `attributes.exploitation.first_exploitation`, `exploit_release_date` |
| CISA KEV | `attributes.cisa_known_exploited.{added_date,due_date,ransomware_use}` |
| EPSS | `attributes.epss.{score,percentile}` |
| CVSSv3.1 | `attributes.cvss.cvssv3_x.{base_score,temporal_score,vector}` |
| CVSSv4.0 | `attributes.cvss.cvssv4_x.{score,vector,threat.exploit_maturity}` |
| CVSSv2 | `attributes.cvss.cvssv2_0.{base_score,temporal_score,vector}` |
| Affected products | `attributes.cpes[]` (`start_cpe` / `end_cpe` vendor, product, version, rel) |
| MVE ID | `attributes.mve_id` |
| Description / analysis | `attributes.description`, `executive_summary`, `analysis` |
| CWE | `attributes.cwe.{id,title}` |
| Dates | `creation_date`, `last_modification_date`, `date_of_disclosure` |
| Raw priority | `attributes.priority` (documented as **boolean** in the API) |

> **Privilege note:** If the key lacks Vulnerability Intelligence, the tool exits with a clear Enterprise/Enterprise Plus message (exit code `3` when nothing could be enriched).

---

## Priority (P0–P4) derivation

The API `priority` field is a boolean and is **not** the P0–P4 badge shown in the GTI UI. This tool derives **Priority Rating** from GTI’s published model ([vulnerability report guide](https://gtidocs.virustotal.com/docs/vulnerability-report)):

Combine **Risk Rating** + **Exploitation State** + **Exploit Availability**:

| Priority | Rules (summary) |
|----------|-----------------|
| **P0** | Risk = Critical; **or** High + state ∈ {Wide, Confirmed, Reported}; **or** Medium + state = Wide |
| **P1** | High + state ∈ {Suspected, No Known} + exploit availability ≠ No Known; **or** Medium + state ∈ {Confirmed, Reported, Suspected}; **or** Low + state ∈ {Wide, Confirmed} |
| **P2** | High + No Known + No Known availability; **or** Medium + No Known + availability ∈ {Trivial, Publicly Available, Privately Held, Unverified}; **or** Low + state ∈ {Reported, Suspected} |
| **P3** | Medium + No Known + availability ∈ {Interest Observed, No Known}; **or** Low + No Known + exploit-code-present set |
| **P4** | Low + No Known + availability ∈ {Interest Observed, No Known} |

Both the **derived** `priority_rating` and the **raw** API `priority` are written to CSV and shown in reports.

---

## Rate limiting & proxies

- Default **1s** delay between requests (`--delay` / `VT_REQUEST_DELAY`).
- HTTP **429**: exponential backoff with jitter; honors `Retry-After` when present.
- **5xx** and network errors are retried (`--max-retries`).
- Proxies via `.env` (`HTTP_PROXY` / `HTTPS_PROXY`) or `--http-proxy` / `--https-proxy`.
- TLS: always verified; use `CORPORATE_CA_BUNDLE` for corporate SSL inspection.

Step-by-step key, proxy, and CA setup: **[SETUP.md](SETUP.md)**.

---

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | At least one CVE enriched successfully |
| 1 | All CVEs failed / not found / runtime error |
| 2 | Usage / input / missing API key / missing CA path |
| 3 | Privilege error (401/403) and zero successes |

---

## Files

| File | Purpose |
|------|---------|
| `cve_enricher.py` | Main tool |
| `cve_list.csv` | Example input |
| `.env.example` | Template for secrets / proxy / CA path |
| `.env` | Local config (**gitignored** — do not commit) |
| `certs/` | Place `corporate-ca.pem` here |
| `requirements.txt` | `requests`, `rich`, `python-dotenv`, `urllib3` |
| `SETUP.md` | First-time API key, proxy, and CA setup |
| `README.md` | This document |
