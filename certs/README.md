# Corporate root CA certificate

Place your organization's **root CA** certificate here so the enricher can
verify TLS when traffic is intercepted by a corporate SSL-inspection proxy.

## Expected file

| Path | Format |
|------|--------|
| `certs/corporate-ca.pem` | PEM (Base64) or DER-encoded CRT exported to PEM |

You can also set a custom path in `.env`:

```env
CORPORATE_CA_BUNDLE=./certs/corporate-ca.pem
```

## How to export the CA on Windows

### Option A — Certificate Manager (most common)

1. Press **Win+R**, run `certmgr.msc` (user store) or `certlm.msc` (local machine).
2. Open **Trusted Root Certification Authorities → Certificates**.
3. Find your corporate / proxy inspection CA (often named after your company,
   Zscaler, Blue Coat, Netskope, Palo Alto, etc. — ask IT if unsure).
4. Right-click the CA → **All Tasks → Export…**.
5. Choose **Base-64 encoded X.509 (.CER)**.
6. Save as `corporate-ca.cer`, then rename/copy to:
   ```text
   certs\corporate-ca.pem
   ```
   (PEM and Base-64 CER content are the same text format.)

### Option B — PowerShell export

```powershell
# List candidate roots (filter by your org name)
Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Subject -match 'YourOrg|Proxy|Zscaler' } |
  Select-Object Subject, Thumbprint

# Export a specific cert by thumbprint to PEM
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

### Option C — From the browser (when visiting an internal HTTPS site)

1. Open an HTTPS site that is inspected by the proxy.
2. Click the padlock → **Connection is secure** → **Certificate is valid**.
3. Open the **Certification Path** tab → select the **root** CA → **View Certificate**.
4. **Details → Copy to File…** → Base-64 X.509 → save under `certs/`.

## Optional: install the CA into Python's certifi bundle

If you prefer default `verify=True` without a custom path (system-wide for that
Python environment):

```powershell
python -c "import certifi; print(certifi.where())"
# Append the corporate PEM to that file (admin/IT approval may be required)
Get-Content .\certs\corporate-ca.pem | Add-Content -Path (python -c "import certifi; print(certifi.where())")
```

Prefer the explicit `CORPORATE_CA_BUNDLE` approach: it is reversible, auditable,
and does not mutate the environment's certifi store.

## Security notes

- Do **not** commit `*.pem` / `*.crt` from this folder (gitignored).
- Never use `verify=False` — the enricher refuses to disable TLS verification.
