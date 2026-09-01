# First-time setup: API key, proxy, and corporate CA

This guide walks you through configuring **cve_enricher.py** after a fresh install. You do **not** edit `cve_enricher.py` to add secrets. API key, proxies, and the corporate CA path live in a project **`.env`** file loaded by **python-dotenv**.

---

## Prerequisites

1. **Python 3.10+** available on your PATH (`python --version`).
2. **Dependencies installed** from the project directory:

   ```bash
   pip install -r requirements.txt
   ```

3. A **VirusTotal / Google Threat Intelligence (GTI)** API key with:
   - **Enterprise** or **Enterprise Plus** license
   - **Vulnerability Intelligence** privilege  

   Standard (free or non-GTI) keys will get `401` / `403` and cannot enrich CVEs with this tool.

---

## 1. Create the `.env` file (single source of truth)

```powershell
cd path\to\virustotal
Copy-Item .env.example .env
# Then edit .env in your editor
notepad .env
```

Minimum contents:

```env
VIRUSTOTAL_API_KEY=your_key_here
HTTP_PROXY=http://webproxy:8080
HTTPS_PROXY=http://webproxy:8080
CORPORATE_CA_BUNDLE=./certs/corporate-ca.pem
```

Replace:

| Value | With |
|-------|------|
| `your_key_here` | Your real GTI API key |
| `http://webproxy:8080` | Your corporate proxy URL (host/port from IT) |
| `./certs/corporate-ca.pem` | Path to the exported corporate root CA |

### Why `.env` instead of PowerShell session variables?

| Approach | Problem |
|----------|---------|
| `$env:HTTP_PROXY = "..."` each session | Lost when you close the window; easy to forget |
| User/system environment variables | Shared, harder to rotate, still separate from project docs |
| **Project `.env` (this tool)** | Loaded automatically every run; stays with the project; gitignored |

You do **not** need to set `$env:HTTP_PROXY` or `$env:VIRUSTOTAL_API_KEY` in every new PowerShell window.

### Security: keep `.env` out of source control

- `.env` is listed in `.gitignore`.
- Commit only `.env.example` (placeholders).
- Never paste production keys into tickets, screenshots, or chat logs.

---

## 2. Obtain your API key

1. Sign in to your VirusTotal / GTI enterprise account.
2. Open your user or organization **API key** page (typically under account or API settings).
3. Copy the key into `.env` as `VIRUSTOTAL_API_KEY=...`.

Treat it like a password: do not commit it, do not paste it into `cve_enricher.py`.

### Resolution order

1. `--api-key` on the command line  
2. `VIRUSTOTAL_API_KEY` (preferred name in `.env`)  
3. `VT_API_KEY` (alias)

If none are set (or the value is still a placeholder like `your_key_here`), the tool fails with a clear error, still writes an HTML failure report, and opens it in the browser.

---

## 3. Configure the web proxy

Skip this section if your machine can reach `https://www.virustotal.com` directly.

### Variable names

| Purpose | Preferred (in `.env`) | Also accepted |
|---------|----------------------|---------------|
| HTTP proxy | `HTTP_PROXY` | `VT_HTTP_PROXY`, `http_proxy`, `--http-proxy` |
| HTTPS proxy | `HTTPS_PROXY` | `VT_HTTPS_PROXY`, `https_proxy`, `--https-proxy` |

### Proxy URL format

```text
http://webproxy:8080
http://username:password@proxy.example.com:8080
```

Notes:

- Most corporate proxies use `http://` for **both** `HTTP_PROXY` and `HTTPS_PROXY` (the proxy is contacted over HTTP; the client still requests HTTPS targets through it).
- If IT gives only `host:port`, prefix with `http://`.
- Prefer putting credentials in `.env` (gitignored) rather than shell history.

When proxies are active, the tool logs something like `Using proxies: {'http': '...', 'https': '...'}` (passwords in the URL are redacted in logs).

---

## 4. Fix SSL inspection correctly (required on most corporate networks)

Corporate SSL inspection (MITM) presents certificates signed by an **internal root CA**. Python’s default trust store (certifi) does not include that CA, which causes `SSLError` / certificate verify failures.

**Do not disable TLS verification.** This tool never uses `verify=False` and will refuse to run if verification is disabled.

### Preferred approach: custom CA bundle for `requests`

1. Export the corporate root CA (see below).
2. Place it at `certs/corporate-ca.pem` **or** set `CORPORATE_CA_BUNDLE` in `.env`.
3. The script passes that path to `requests` as `session.verify = "<path>"`.

### How to export the corporate CA from Windows

#### Option A — Certificate Manager

1. **Win+R** → `certmgr.msc` (Current User) or `certlm.msc` (Local Machine).
2. **Trusted Root Certification Authorities → Certificates**.
3. Locate the inspection CA (company name, Zscaler, Blue Coat, Netskope, Palo Alto, etc.).
4. Right-click → **All Tasks → Export…**.
5. **Base-64 encoded X.509 (.CER)**.
6. Save and copy to:

   ```text
   certs\corporate-ca.pem
   ```

#### Option B — PowerShell

```powershell
# Find candidates
Get-ChildItem Cert:\LocalMachine\Root |
  Where-Object { $_.Subject -match 'YourOrg|Zscaler|Proxy' } |
  Select-Object Subject, Thumbprint

$thumb = "PASTE_THUMBPRINT_HERE"
$cert = Get-Item "Cert:\LocalMachine\Root\$thumb"
$bytes = $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
$b64 = [Convert]::ToBase64String($bytes, 'InsertLineBreaks')
@(
  '-----BEGIN CERTIFICATE-----'
  $b64
  '-----END CERTIFICATE-----'
) | Set-Content -Path .\certs\corporate-ca.pem -Encoding ascii
```

#### Option C — From browser certificate path

1. Open any HTTPS site that goes through the inspection proxy.
2. Padlock → certificate → **Certification Path** → select the **root** → export Base-64.

More detail: [certs/README.md](certs/README.md).

### Optional alternative: install CA into the system / certifi store

If IT installs the org root into the Windows trust store **and** your Python build uses the system store, default `verify=True` may work with no `CORPORATE_CA_BUNDLE`.

You can also append the PEM to certifi (mutates the environment — prefer the explicit bundle path):

```powershell
python -c "import certifi; print(certifi.where())"
# Review the path, then (with IT approval) append corporate-ca.pem to that file
```

### CA resolution order in the script

1. `--ca-bundle` CLI flag  
2. `CORPORATE_CA_BUNDLE` in `.env` / environment  
3. `REQUESTS_CA_BUNDLE` / `SSL_CERT_FILE` (standard Python vars)  
4. File present at `./certs/corporate-ca.pem`  
5. Otherwise: default trust store (`verify=True`)

If a configured path does not exist, the run fails with a clear message (and still opens an HTML error report).

---

## 5. First successful run

From the project directory, with `.env` filled in and the CA file in place:

```powershell
python cve_enricher.py -i cve_list.csv --output cve_enriched.csv --html report.html
```

What you should see:

1. Log line: `Loaded configuration from ...\.env`  
2. Log line: TLS verification (custom CA bundle or default trust store)  
3. Optional proxy line  
4. Progress while each CVE is queried  
5. Enriched CSV at `cve_enriched.csv`  
6. HTML report written **and opened in your browser** (even if the run fails)

### Quick connectivity check (optional)

```powershell
# Uses system proxy settings — confirm routing independently of this tool
Invoke-WebRequest -Uri "https://www.virustotal.com" -Method Head -UseBasicParsing
```

```bash
# With the same proxy as .env
curl -I -x http://webproxy:8080 --cacert ./certs/corporate-ca.pem https://www.virustotal.com
```

---

## 6. Configuration reference

| Setting | Required? | How to set | Default |
|---------|-----------|------------|---------|
| API key | **Yes** | `VIRUSTOTAL_API_KEY` / `VT_API_KEY` / `--api-key` | none |
| HTTP proxy | If required by network | `HTTP_PROXY` / `VT_HTTP_PROXY` / `--http-proxy` | none (direct) |
| HTTPS proxy | If required by network | `HTTPS_PROXY` / `VT_HTTPS_PROXY` / `--https-proxy` | none (direct) |
| Corporate CA | If SSL inspection breaks verify | `CORPORATE_CA_BUNDLE` / `--ca-bundle` / `certs/corporate-ca.pem` | system/certifi trust |
| Request delay | No | `VT_REQUEST_DELAY` / `--delay` | `1.0` seconds |
| HTML report | Always written | `--html` | `report.html` |
| Open browser | Yes by default | `--no-open` to disable | open on every run |

There are **no** hard-coded key or proxy placeholders inside `cve_enricher.py`. Placeholder key values such as `your_key_here` are rejected.

---

## 7. HTML report behavior (always open)

| Outcome | HTML report | Browser |
|---------|-------------|---------|
| All CVEs enriched | Full cards | Opens |
| Partial success | Cards + error cards | Opens |
| Missing API key / bad input | Error banner + traceback summary | Opens |
| SSL / proxy / network failure | Error banner + traceback summary | Opens |
| Privilege 401/403 | Per-CVE + summary banner | Opens |

Use `--no-open` only for automation/CI. The report file is still written.

---

## 8. Troubleshooting

| Symptom | Likely cause | What to do |
|---------|--------------|------------|
| `No API key` / placeholder rejected | `.env` missing or still `your_key_here` | Edit `.env`; confirm load log shows `.env` path |
| Exit code **2** | Missing key, bad CSV, or missing CA file | Fix config; open the HTML report for details |
| `401` / `403` / exit code **3** | Key lacks GTI Vulnerability Intelligence | Use Enterprise / Enterprise Plus key with VI |
| Connection timeouts / proxy errors | Wrong proxy host/port or auth | Fix `HTTP_PROXY` / `HTTPS_PROXY` in `.env` |
| SSL / certificate verify failed | Corporate TLS inspection without org CA | Export root CA → `certs/corporate-ca.pem` or set `CORPORATE_CA_BUNDLE` |
| CA bundle not found | Path in `.env` wrong or file not created | Check path relative to project root |
| `429` rate limited | Too many requests | Increase `--delay` (e.g. `1.5` or `2.0`) |
| Browser did not open | Restricted desktop / headless | Open `report.html` manually; or check logs |

---

## 9. Security checklist

- [ ] Key stored in `.env` or secret manager — not in source, not in `cve_list.csv`  
- [ ] `.env` is gitignored and never committed  
- [ ] Corporate CA PEM gitignored (`certs/*.pem`)  
- [ ] Proxy credentials (if any) not shared in tickets or screenshots  
- [ ] TLS verification left **on** (enforced by the tool)  
- [ ] No `verify=False` workarounds  

---

## Next steps

- Put CVE IDs in `cve_list.csv` (see [README.md](README.md#input-csv)).  
- Review full CLI options and outputs in [README.md](README.md).  
- For bulk runs, keep the default delay (or higher) to reduce rate-limit risk.  

**Typical day-to-day session (PowerShell):**

```powershell
cd path\to\virustotal
# No $env: setup needed when .env is configured
python cve_enricher.py -i cve_list.csv -o cve_enriched.csv --html report.html
```
