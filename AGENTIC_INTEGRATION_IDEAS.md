# Agentic Integration Ideas: GTI / VirusTotal CVE Enrichment

How to evolve the current local CLI (`cve_enricher.py`) into a capability an AI agent can call to enrich vulnerability detections — without abandoning corporate-network constraints, the existing enrichment quality, or the human-facing HTML report.

This is an options and design document, not an implementation plan. Effort estimates assume one engineer who already understands this repo.

---

## 1. Executive Summary

Today the enricher is a **local, analyst-driven CLI**. After cloning the repo, an operator fills a gitignored `.env` (API key, corporate proxy, CA bundle path), drops CVE IDs into a CSV, and runs `python cve_enricher.py`. The script talks to `GET /api/v3/collections/vulnerability--{cve}` through the corporate proxy with TLS verification always on, flattens GTI Vulnerability Intelligence into a `CVERecord`, and always writes a professional HTML report (plus CSV and Rich terminal cards). The desired end-state is the opposite operating model: **enrichment becomes a shared capability inside an AI agent**. When a detection, ticket, or scanner finding contains a CVE, the agent calls a tool, receives structured JSON it can reason over (priority, EPSS, CVSS, CISA KEV, exploitation, products, mitigations), and optionally attaches the same HTML report for humans. Analysts stop cloning the repo and running the script by hand; the GTI Enterprise key, proxy, and CA bundle live with the service rather than on every workstation.

---

## 2. Core Design Principles

Non-negotiable constraints. Any integration path that violates these is a non-starter.

- **Corporate proxy remains mandatory and explicit.** `HTTP_PROXY` / `HTTPS_PROXY` (and the `VT_*` aliases) must still be applied on the outbound VirusTotal session. Direct egress from a locked-down desktop or from an internal agent host will fail or violate policy.
- **Corporate CA bundle remains mandatory when SSL inspection is present.** Resolve `CORPORATE_CA_BUNDLE`, `REQUESTS_CA_BUNDLE` / `SSL_CERT_FILE`, `~/certs/corporate_trust_bundle.pem` (`Path.expanduser()`), or `certs/corporate-ca.pem`. **Never `verify=False`.** `GTIClient` already refuses it; every future wrapper must keep that guard.
- **Secrets stay out of code, tickets, prompts, logs, and HTML.** The GTI key (`VIRUSTOTAL_API_KEY` / `VT_API_KEY`) and any proxy credentials never appear in source, function-call arguments, agent transcripts, or the report. Prefer env / secret manager over `--api-key` (CLI args land in shell history).
- **Structured output is primary for agents.** The current CLI is human-first (Rich on stdout, HTML always opened). An agent needs a stable JSON contract on stdout or over HTTP. HTML is a *side artifact*, not the tool result.
- **HTML report remains optional, not deleted.** Humans still want the card layout (priority chips, EPSS, CVSS, KEV, products, VirusTotal link). Agents request it with a flag; default for agent invocations is **do not open a browser**.
- **Reuse the existing core, do not reimplement GTI parsing.** `GTIClient`, `extract_record()`, `derive_priority_rating()`, `normalize_cve()`, `build_proxies()`, and `resolve_ssl_verify()` are the product. Wrappers should call them, not scrape HTML or re-walk the collections schema.
- **Per-CVE structured errors, never silent drops.** Status values already exist: `ok`, `not_found`, `forbidden`, `rate_limited`, `error`. Agents must see a row for every requested CVE, including skips after early-stop on 401/403.
- **Respect GTI quota.** Vulnerability Intelligence rate-limits aggressively (HTTP 429). Default 1.0s inter-request delay, retries with jitter, and early-stop on privilege errors must survive. A multi-user agent must **share one throttle and a cache**, not spawn unbounded parallel CLI processes.
- **Enterprise license is a hard dependency.** Free / public VirusTotal keys return 401/403 on this endpoint. The capability must fail clearly (`forbidden`) rather than hallucinating enrichment.
- **No secrets in the data contract.** `vt_url` is a GUI deep-link (`https://www.virustotal.com/gui/collection/vulnerability--cve-…`). Raw API key, proxy password, and CA path never appear in the JSON the agent sees.
- **Idempotent, deterministic records.** Same CVE + same GTI payload → same flattened fields and same derived P0–P4. Agents and caches rely on this.
- **Least privilege for the agent.** The agent can request enrichment of CVE IDs. It cannot dump the API key, change TLS verification, or issue arbitrary VirusTotal queries beyond this capability.

---

## 3. Integration Patterns

Ranked from simplest (ship this week) to most sophisticated (shared production capability). Patterns compose: Pattern A is the foundation for B–E; Pattern E is the output policy that should apply to all of them.

### Pattern A — Local subprocess / CLI tool called by the agent

**Description.** Keep `cve_enricher.py` as the implementation. Add an **agent mode**: JSON on stdout, logs on stderr, no browser, HTML optional. The agent (or the host that runs the agent) shells out to the same venv the analyst already uses.

This is the smallest delta from today. The CLI already writes logs to stderr and Rich cards to stdout; the missing piece is a `--json` (or `--format json`) path that prints one JSON document and implies `--no-open --no-rich`.

**How the agent would invoke it.**

```text
python cve_enricher.py --json --no-open --no-rich \
  --cve CVE-2021-44228 CVE-2024-3400
```

Or, until a `--cve` flag exists, write a temp CSV and call:

```text
python cve_enricher.py -i %TEMP%\cves.csv --no-open --no-rich --json
```

The host captures **stdout** as the tool result. Exit codes stay as they are today:

| Code | Meaning |
|------|---------|
| `0` | At least one CVE enriched |
| `1` | All failed / runtime error |
| `2` | Config / missing key / missing CA / bad input |
| `3` | Privilege 401/403 and zero successes |

**Pros**

- Days of work, not weeks. Most logic already exists.
- Zero new network surface (no listening port, no service account for the enricher itself).
- `.env`, proxy, and CA bundle keep working exactly as documented in `SETUP.md`.
- Easy to demo: wrap the command as a Grok / Claude / Cursor tool or a LangChain `ShellTool` with a tight allowlist.

**Cons**

- Process-per-call overhead; cold Python startup on every tool call.
- Easy to stampede GTI if the agent fans out one subprocess per CVE (each process has its own 1.0s delay but **no shared throttle**).
- Secrets still live in a workstation `.env`. Fine for a single analyst’s agent, not for a team.
- Output contract is implicit until `--json` is specified. Today, piping stdout captures Rich markup, not records.
- HTML-always-open is a footgun if the agent forgets `--no-open` on a desktop session.

**Estimated effort.** 1–3 days: `--json` / `--cve`, disable browser by default when `--json` is set, document the stdout schema, add a tiny `tools.json` / MCP stdio wrapper if the agent host wants it.

**Corporate-environment considerations**

- The agent **must run on a host that already has working proxy + CA + GTI key** — typically the analyst’s Windows workstation or a jump box that can already run the CLI.
- Inherit the process environment; do not ask the LLM to pass `VIRUSTOTAL_API_KEY` or `HTTP_PROXY` as tool arguments.
- Set `CORPORATE_CA_BUNDLE` to `%USERPROFILE%\certs\corporate_trust_bundle.pem` (or the project `certs\corporate-ca.pem`) in the agent host’s env, not in the prompt.
- Allowlist the executable path (`vtenv\Scripts\python.exe` + `cve_enricher.py`). Do not give the agent a generic shell.

**When to choose this.** Proof of concept, a single-user “SOC copilot” on a laptop, or a bridge while the library extraction in Pattern B is underway.

---

### Pattern B — FastAPI / Flask microservice (REST or JSON-RPC)

**Description.** Extract the enricher into a small library (`gti_client`, `records`, `priority`, `config`) and put a thin HTTP API in front. One long-lived process owns the `requests.Session`, the proxy, the CA bundle, the API key, and a process-wide throttle. Agents become HTTP clients.

Suggested surface (REST, JSON in / JSON out):

```http
POST /v1/enrich
Content-Type: application/json

{
  "cves": ["CVE-2021-44228", "CVE-2024-3400"],
  "include_html": false,
  "include_raw": false
}
```

```http
GET /v1/enrich/CVE-2021-44228
GET /healthz          # liveness; does not call VirusTotal
GET /readyz           # config present: key, proxy reachable, CA file exists
```

JSON-RPC is optional (`method: "enrich_cves"`) if the agent framework already speaks it; REST is the better default.

**How the agent would invoke it.** An HTTP tool:

```text
POST https://gti-enricher.internal.example.com/v1/enrich
Authorization: Bearer <agent-workload-token>
```

The VirusTotal key never leaves the service. The agent authenticates to *this* API with a separate, rotatable credential (see §5).

**Pros**

- One throttle, one session, one cache for every agent and every analyst.
- Natural place for auth, audit logs, request size limits, and HTML-as-optional-artifact.
- Hosts that cannot reach VirusTotal (some agent sandboxes) can still reach an **internal** enricher that sits on the allowed egress path.
- Health endpoints make corporate-proxy/CA misconfig visible without burning GTI quota.
- Matches how most production “tool servers” are operated.

**Cons**

- You now run a service: packaging, TLS *to* the service, auth, deployment, patching.
- Must be placed on a network segment that can use the corporate proxy to reach `www.virustotal.com`.
- FastAPI/Flask on a workstation is not production; you need a real host (internal VM, container on the allowed subnet, or a small Windows service).
- If the agent host is the same locked-down desktop, you may still need the proxy **between agent and service** as well as **between service and VirusTotal**.

**Estimated effort.** 1–2 weeks for a hardened internal MVP (library split, FastAPI, auth, health, optional HTML, OpenAPI, basic cache). Another 1–2 weeks to productionize (TLS, secrets manager, systemd/NSSM/IIS, dashboards, rate-limit headers).

**Corporate-environment considerations**

- **Two TLS problems, not one.** (1) Outbound to VirusTotal: keep `session.verify = <corporate PEM>`. (2) Inbound from agents: serve the API with an *internal* certificate the agent runtime trusts (corp PKI). Do not disable either.
- Bind to localhost or an internal hostname; never the public internet. GTI keys are enterprise credentials.
- Inject `VIRUSTOTAL_API_KEY`, `HTTP_PROXY`, `HTTPS_PROXY`, `CORPORATE_CA_BUNDLE` via the service account / container secret, not a committed `.env` on a share.
- Honor `VT_REQUEST_DELAY` globally. Return `429` + `Retry-After` to agents when GTI is the bottleneck so the agent backs off instead of retrying immediately.
- Windows service vs Linux container: the CA path and proxy URL are the same; only the secret-injection mechanism changes.

**When to choose this.** More than one consumer (agent + dashboards + SOAR), or any case where the agent runtime cannot hold the GTI key.

---

### Pattern C — Native tool / function-calling schema (LangGraph, CrewAI, AutoGen, OpenAI Agents SDK, MCP)

**Description.** Expose enrichment as a **typed tool** the model can call: name, JSON Schema parameters, structured return. The *transport* can be Pattern A (local function) or Pattern B (HTTP behind the tool). The important part is the **schema the LLM sees**, which should be small and decision-oriented.

This is how Grok Build, Claude Desktop, Cursor, Copilot Studio, LangGraph, CrewAI, AutoGen, and the OpenAI Agents SDK all attach capabilities. MCP (Model Context Protocol) is the portable packaging of the same idea: a stdio or HTTP server that lists tools and executes them.

**How the agent would invoke it.** The model emits a function call; the host executes it.

Example tool definition (OpenAI / MCP style):

```json
{
  "name": "enrich_cves",
  "description": "Enrich CVE IDs via Google Threat Intelligence Vulnerability Intelligence. Returns priority (P0–P4), EPSS, CVSS, CISA KEV, exploitation, affected products, mitigations, and a VirusTotal collection URL. Use when a detection, advisory, or ticket mentions a CVE and triage/priority is needed. Do not guess CVSS or KEV; call this tool.",
  "parameters": {
    "type": "object",
    "properties": {
      "cves": {
        "type": "array",
        "items": { "type": "string" },
        "minItems": 1,
        "maxItems": 25,
        "description": "CVE IDs (CVE-YYYY-NNNN). Duplicates and invalid IDs are dropped."
      },
      "include_html": {
        "type": "boolean",
        "default": false,
        "description": "If true, also write a self-contained HTML report and return its path."
      }
    },
    "required": ["cves"]
  }
}
```

Framework sketches:

| Framework | Integration |
|-----------|-------------|
| **MCP** | Small stdio server wrapping Pattern A or HTTP client to Pattern B. Best fit for Grok / Claude / Cursor hosts. |
| **OpenAI Agents SDK / Chat Completions tools** | Same JSON Schema; Python function calls `enrich_cves()`. |
| **LangGraph** | `@tool` on a node; graph routes “has CVE → enrich → decide”. |
| **CrewAI** | `BaseTool` with `_run(cves: list[str])`. |
| **AutoGen** | Function registered on the assistant; executor runs in a tool agent. |
| **Semantic Kernel / Copilot Studio** | OpenAPI from Pattern B imported as a plugin. |

Keep the LLM-visible schema **narrow**. Do not expose delay, retries, proxy, CA, or API key as tool parameters — those are runtime config.

**Pros**

- This is the actual “agent capability” the business asked for. Patterns A/B are plumbing; this is the contract the model uses.
- Portable: one schema, many orchestrators.
- Easy to add a second tool later (`render_html_report`, `explain_priority`) without changing GTI access.
- Guardrails live in the schema (`maxItems: 25`) rather than in prompt text.

**Cons**

- A schema without a disciplined backend still stampedes GTI (especially AutoGen/Crew multi-agent loops that re-call the tool).
- Models will call the tool with messy IDs (`cve 2021-44228`, `CVE-2021-44228, Log4Shell`). `normalize_cve()` already handles several of these; the tool handler must run it **before** the API.
- Tool-result size: full `executive_summary` + `analysis` + 200 CPEs can blow the context window. Return a **compact view** by default (see §4) and an `include_narrative` / `include_products` flag if needed.

**Estimated effort.** 2–5 days **on top of** Pattern A or B: tool schema, MCP or LangGraph wrapper, truncation policy, and a golden-path eval (Log4j, a KEV CVE, a 404, a forbidden key).

**Corporate-environment considerations**

- The **tool executor** is the process that needs proxy + CA, not the LLM provider. If the model is cloud-hosted, keep GTI calls on-prem in the executor.
- Do not send enrichment JSON to a public model if policy forbids vulnerability + asset context leaving the boundary. Prefer an internal LLM or strip `affected_products` / narrative fields.
- MCP stdio on a Windows analyst box is the lowest-friction corporate path (no inbound port). MCP-over-HTTP needs the same TLS/auth story as Pattern B.

**When to choose this.** As soon as an agent is actually expected to *decide* (priority, ticket text, whether to page). Do it in parallel with A or B; do not wait for a perfect service.

---

### Pattern D — Message-queue / event-driven enrichment

**Description.** Detections already flow through a pipeline (EDR → SIEM → SOAR → ticket). Instead of the agent making a synchronous tool call and waiting on GTI (1s+ per CVE, retries on 429), the agent — or the detection pipeline — **publishes** CVE IDs and later **consumes** enrichment.

```text
detection.found  →  enrich.request  →  GTI worker  →  enrich.result
                         ↑                                ↓
                    agent (or SOAR)                 agent / ticket / cache
```

Topics (names illustrative): `vuln.enrich.requested`, `vuln.enrich.completed`, `vuln.enrich.failed`. Payload is the §4 data contract. The worker is the same library as Pattern B, with the same proxy/CA/key/throttle.

**How the agent would invoke it.**

1. **Fire-and-forget:** agent publishes `{ "cves": [...], "correlation_id": "..." }` and continues other work.
2. **Wait-with-poll:** agent publishes then reads from a results cache / inbox keyed by `correlation_id` or CVE.
3. **Fully automatic (no agent in the loop):** scanner findings always get enriched; the agent only *reads* `enrich.result` when it drafts a ticket.

**Pros**

- Natural fit for bursty vuln scans (thousands of CVEs) where a synchronous tool call would time out or 429.
- Back-pressure: the queue absorbs spikes; the worker keeps `VT_REQUEST_DELAY`.
- Results can land in the same store the agent already searches (ticket comments, a vector DB, a SIEM index).
- Decouples agent uptime from GTI uptime.

**Cons**

- Highest operational cost: broker (internal Kafka / Azure Service Bus / RabbitMQ), consumer group, poison-message handling, idempotency keys.
- Worse UX for interactive chat (“enrich this CVE now”) unless you also keep a synchronous path.
- Correlation and exactly-once semantics are easy to get wrong; duplicate publishes must hit the cache, not double-charge GTI.

**Estimated effort.** 3–6 weeks after Pattern B exists, assuming the organization already runs a broker. Do not introduce a queue solely for this tool.

**Corporate-environment considerations**

- Broker is almost always internal-only; still encrypt payloads (they include vuln intelligence and possibly product lists).
- The **worker** is the only process that needs VirusTotal egress, proxy, and CA bundle. Agents and scanners need only broker credentials.
- Identity: worker uses a service principal + secret manager; publishers use least-privilege write to `enrich.requested`.
- Watch for data-residency: do not dump GTI narrative fields into a cloud bus if the GTI license or corp policy forbids it.

**When to choose this.** Enrichment is part of the detection pipeline itself (every new CVE in the environment is enriched automatically), and the agent is a *consumer* of that stream rather than the thing that triggers HTTP GETs.

---

### Pattern E — Hybrid: HTML for humans, JSON for the agent (recommended output policy)

**Description.** Not a separate runtime — a **response shape** that every other pattern should implement. One enrichment run produces:

1. **Primary:** structured JSON (the data contract in §4) returned to the agent.
2. **Optional:** the existing self-contained HTML report written to disk (or object storage), path/URL returned as `artifacts.html_report`.
3. **Never by default in agent mode:** browser launch, Rich panels on stdout.

This matches the current code’s strengths. `render_html_report()` already consumes `list[CVERecord]`. `write_csv()` is a third artifact for SIEM/spreadsheet users and can remain available but is secondary for agents.

**How the agent would invoke it.**

```json
{
  "cves": ["CVE-2021-44228"],
  "include_html": true
}
```

Returns JSON plus:

```json
{
  "artifacts": {
    "html_report": "file:///C:/data/gti-reports/2026-08-24/CVE-2021-44228.html"
  }
}
```

The agent can attach that file to a ticket, or skip it for a 20-CVE batch triage.

**Pros**

- No lost investment in the HTML cards (priority chips, KEV, products, VirusTotal link, failure banner).
- Agents stay within token budgets; humans get the same report they already trust.
- Failure path stays honest: HTML still carries the “Run failed” banner for SSL/proxy/key issues; JSON carries `run.error` plus per-CVE `status`.

**Cons**

- Two consumers means two truncation policies (HTML already caps products at 40 and summary at 900 chars; JSON should use typed fields and let the *tool layer* truncate for the LLM).
- Report files need a retention/cleanup policy once a service writes them continuously.
- If `include_html: true` is the default, chatty agents will fill disks.

**Estimated effort.** Almost free once Pattern A `--json` or Pattern B exists — `render_html_report()` is already parameterized. The work is **changing the default**: agent mode must not open the browser.

**Corporate-environment considerations**

- Write reports under a dedicated directory with ACLs (SOC share or ticket-attachment store), not the agent’s working directory.
- HTML is self-contained (inline CSS, no CDN) — that remains correct behind proxies that block Google Fonts.
- Do not embed the API key or CA path in HTML. Current renderer does not; keep it that way.
- Opening a browser from a Windows service or a headless agent host will fail or annoy; `--no-open` is required in those contexts.

**When to choose this.** Always. Treat A–D as *how you call* enrichment; treat E as *what you return*.

---

### Pattern comparison

| Pattern | Sync? | Shared throttle | New network surface | Best first user | Effort |
|---------|-------|-----------------|---------------------|-----------------|--------|
| A. CLI / subprocess | Yes | No (per process) | None | Single-user agent on the analyst PC | 1–3 days |
| B. FastAPI / Flask | Yes | Yes | Internal HTTP | Multiple agents / SOAR | 1–2 weeks MVP |
| C. Native tool / MCP | Yes | Depends on A vs B | Stdio or HTTP | Any LLM agent host | +2–5 days |
| D. Queue / events | Async | Yes (worker) | Broker | Detection pipeline | 3–6 weeks after B |
| E. Hybrid JSON + HTML | n/a | n/a | n/a | All of the above | Included |

---

## 4. Recommended Data Contract

Agents should not receive CSV strings or HTML. They should receive JSON with **native types**, a **run envelope**, and **one object per CVE**. The current `CVERecord` is a flat, display-oriented dataclass (`"True"` / `"N/A"` strings) designed for CSV and HTML. Keep that internally if useful; **translate at the tool boundary**.

### Design rules for the contract

- Use `null` for missing values, not `"N/A"`.
- Use JSON booleans and numbers for KEV, EPSS, CVSS, counts.
- Keep derived `priority` (`P0`–`P4` | `null`) as a first-class field; also keep `priority_raw` from the API (boolean-ish) so nothing is lost.
- Always include `status` so the agent can branch (`ok` vs `not_found` vs `forbidden`).
- Default **compact** payload for the LLM; put long narrative and full CPE lists behind flags or a `detail` object the tool layer can omit.
- Version the contract (`contract_version`) so agents can detect breaking changes.

### Pydantic outline

```python
from datetime import datetime
from enum import Enum
from typing import Literal, Optional
from pydantic import BaseModel, Field, HttpUrl


class CveStatus(str, Enum):
    ok = "ok"
    not_found = "not_found"
    forbidden = "forbidden"
    rate_limited = "rate_limited"
    error = "error"


class Priority(str, Enum):
    P0 = "P0"
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"
    P4 = "P4"


class RunError(BaseModel):
    type: str                      # ConfigError | SSLError | ProxyError | ProxyAuthError | NetworkError | RateLimited | UpstreamError
    message: str                   # agent-safe; no secrets, no PEM paths with usernames
    retryable: bool = False
    retry_after_seconds: Optional[int] = None
    http_status: Optional[int] = None   # GTI or proxy status if known


class CvssV3(BaseModel):
    base: Optional[float] = None
    temporal: Optional[float] = None
    vector: Optional[str] = None


class CvssV4(BaseModel):
    score: Optional[float] = None
    vector: Optional[str] = None
    exploit_maturity: Optional[str] = None


class CvssV2(BaseModel):
    base: Optional[float] = None
    temporal: Optional[float] = None
    vector: Optional[str] = None


class Epss(BaseModel):
    score: Optional[float] = None
    percentile: Optional[float] = None


class CisaKev(BaseModel):
    listed: bool = False
    added_date: Optional[str] = None      # YYYY-MM-DD
    due_date: Optional[str] = None
    ransomware_use: Optional[str] = None


class Exploitation(BaseModel):
    state: Optional[str] = None           # Wide / Confirmed / Reported / Suspected / No Known
    availability: Optional[str] = None    # Publicly Available / Trivial / ...
    in_the_wild: bool = False
    as_zero_day: bool = False
    consequence: Optional[str] = None
    vectors: Optional[str] = None
    first_exploitation: Optional[str] = None
    exploit_release_date: Optional[str] = None


class AffectedProduct(BaseModel):
    vendor: Optional[str] = None
    product: Optional[str] = None
    version_range: Optional[str] = None   # e.g. ">= 2.0.0 and < 2.17.0"
    display: str                          # current "vendor / product (range)" line


class CveEnrichment(BaseModel):
    """One CVE — the object the agent reasons over."""
    cve: str
    status: CveStatus
    error_message: Optional[str] = None

    name: Optional[str] = None
    priority: Optional[Priority] = None          # derived P0–P4 (GTI-style table)
    priority_raw: Optional[str] = None           # API field as string
    risk_rating: Optional[str] = None            # Critical / High / Medium / Low
    predicted_risk_rating: Optional[str] = None
    risk_factors: list[str] = Field(default_factory=list)

    epss: Epss = Field(default_factory=Epss)
    cvss_v3: CvssV3 = Field(default_factory=CvssV3)
    cvss_v4: CvssV4 = Field(default_factory=CvssV4)
    cvss_v2: CvssV2 = Field(default_factory=CvssV2)

    exploitation: Exploitation = Field(default_factory=Exploitation)
    cisa_kev: CisaKev = Field(default_factory=CisaKev)

    cwe_id: Optional[str] = None
    cwe_title: Optional[str] = None
    tags: list[str] = Field(default_factory=list)
    date_of_disclosure: Optional[str] = None
    last_modification_date: Optional[str] = None
    origin: Optional[str] = None
    mve_id: Optional[str] = None
    ioc_count: Optional[int] = None

    summary: Optional[str] = None                # executive_summary, else description
    available_mitigation: list[str] = Field(default_factory=list)
    workarounds: list[str] = Field(default_factory=list)

    affected_products_count: int = 0
    affected_products: list[AffectedProduct] = Field(default_factory=list)
    # Tool layer should cap this list (e.g. 25) when returning to an LLM.

    vt_url: Optional[HttpUrl] = None             # GUI collection URL
    # Optional, omitted by default for agents:
    # description, analysis, extra_json / raw GTI fragment


class Artifacts(BaseModel):
    html_report: Optional[str] = None            # filesystem path or internal URL
    csv_report: Optional[str] = None


class EnrichmentRequest(BaseModel):
    cves: list[str] = Field(min_length=1, max_length=25)
    include_html: bool = False
    include_narrative: bool = False              # description + analysis
    include_raw: bool = False                    # extra_json / dump-raw
    product_limit: int = 25


class EnrichmentResponse(BaseModel):
    contract_version: Literal["1.0"] = "1.0"
    generated_at: datetime
    requested: int
    enriched: int                                # status == ok
    failed: int
    records: list[CveEnrichment]
    artifacts: Artifacts = Field(default_factory=Artifacts)
    error: Optional[RunError] = None             # run-level (missing key, SSL, etc.)
```

### Compact “LLM view” (what the tool should return by default)

Enough to triage, small enough for a context window:

```json
{
  "contract_version": "1.0",
  "generated_at": "2026-08-24T18:01:00Z",
  "requested": 1,
  "enriched": 1,
  "failed": 0,
  "records": [
    {
      "cve": "CVE-2021-44228",
      "status": "ok",
      "name": "Apache Log4j2 JNDI RCE",
      "priority": "P0",
      "risk_rating": "Critical",
      "epss": { "score": 0.97, "percentile": 0.99 },
      "cvss_v3": { "base": 10.0, "temporal": 9.1, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H" },
      "cvss_v4": { "score": 10.0, "vector": "CVSS:4.0/...", "exploit_maturity": "Attacked" },
      "exploitation": {
        "state": "Wide",
        "availability": "Publicly Available",
        "in_the_wild": true,
        "as_zero_day": true
      },
      "cisa_kev": {
        "listed": true,
        "added_date": "2021-12-10",
        "due_date": "2021-12-24",
        "ransomware_use": "Known"
      },
      "summary": "…",
      "available_mitigation": ["Patch"],
      "affected_products_count": 42,
      "affected_products": [
        { "vendor": "apache", "product": "log4j", "version_range": ">= 2.0.0 and < 2.17.0", "display": "apache / log4j (>= 2.0.0 and < 2.17.0)" }
      ],
      "vt_url": "https://www.virustotal.com/gui/collection/vulnerability--cve-2021-44228",
      "cwe_id": "CWE-917",
      "cwe_title": "Expression Language Injection"
    }
  ],
  "artifacts": { "html_report": null },
  "error": null
}
```

### Mapping from today’s `CVERecord`

| Agent field | Source today |
|-------------|--------------|
| `priority` | `priority_rating` (derived P0–P4) |
| `priority_raw` | `priority_raw` |
| `risk_rating`, `predicted_risk_rating`, `risk_factors` | same names (`risk_factors` split on `;`) |
| `epss.score` / `percentile` | `epss_score`, `epss_percentile` parsed as float |
| `cvss_v3.*`, `cvss_v4.*`, `cvss_v2.*` | existing CVSS fields |
| `exploitation.*` | `exploitation_state`, `exploit_availability`, `exploited_in_the_wild`, `exploited_as_zero_day`, consequence, vectors, dates |
| `cisa_kev.listed` | `cisa_kev` (`"True"`/`"False"` → bool) |
| `cisa_kev.added_date` / `due_date` / `ransomware_use` | `cisa_added_date`, `cisa_due_date`, `cisa_ransomware_use` |
| `summary` | `executive_summary` if present else `description` |
| `affected_products` | split `affected_products` on ` \| ` |
| `vt_url` | `vt_url` |
| `available_mitigation` / `workarounds` / `tags` | split list-ish strings |
| `status` / `error_message` | same |

Preserve `extra_json` only when `include_raw: true` (SIEM/debug). Do not send it to the LLM by default.

### Agent-side decision hints (optional, computed, not GTI)

A later revision can add a small `triage` object so the model does not have to re-derive policy:

```json
{
  "triage": {
    "urgency": "immediate",
    "reasons": ["priority=P0", "cisa_kev=true", "in_the_wild=true", "epss>=0.9"]
  }
}
```

Keep this **policy-owned and explicit**. Do not hide it inside the prompt.

---

## 5. Authentication, Secrets & Corporate Network Handling

This is the section that usually sinks “just wrap it in an agent.” The enricher already solved workstation egress: explicit proxy, corporate CA bundle (including `%USERPROFILE%\certs\corporate_trust_bundle.pem` via `Path.expanduser()`), and a hard refuse of `verify=False`. A multi-user or service deployment must **keep that handling**, not undo it, and must not put the GTI key in the model’s tool arguments.

Network handling here means two distinct hops. Mixing them is the most common production failure.

```text
Hop 1 (internal):   Agent runtime  ──►  Tool executor / enricher API
Hop 2 (inspected):  Enricher       ──►  https://www.virustotal.com  (via corp proxy + MITM CA)
```

Hop 2 is already implemented in `build_proxies()` + `resolve_ssl_verify()` + `GTIClient`. Hop 1 is new the moment you leave Pattern A.

### 5.1 Secret inventory

| Secret / material | Where it lives today | Where it should live for an agent |
|-------------------|----------------------|-----------------------------------|
| GTI / VirusTotal API key | `.env` → `VIRUSTOTAL_API_KEY` | Process env or secret manager on the **executor** (CLI host, FastAPI service, or queue worker). Never in tool params. |
| Proxy URL (may include user:password) | `.env` → `HTTP_PROXY` / `HTTPS_PROXY` | Same. Redact passwords in logs (the CLI already does). |
| Corporate root CA (public cert, not a private key) | `CORPORATE_CA_BUNDLE` or `%USERPROFILE%\certs\corporate_trust_bundle.pem` or `certs/corporate-ca.pem` | Mounted file or org-managed trust bundle. Still public cert only. |
| Agent → enricher credential (new) | n/a | Bearer token, mTLS, or IAP in front of Pattern B. Separate from the GTI key. |
| LLM provider key | outside this repo | Unrelated; must not be mixed into `.env` used for GTI if that file is broadly readable. |

### 5.2 Identity model

```text
[Analyst or detection] → [Agent runtime] → [Tool executor] → [VirusTotal / GTI]
                                   ↑                ↑
                             LLM API key      GTI API key + proxy + CA
                             (cloud/internal) (on-prem / corp network only)
```

Rules:

1. **The model never sees the GTI key.** Tool schemas must not include `api_key`, `proxy`, or `ca_bundle`.
2. **One GTI key for the capability**, not one key per analyst, unless licensing requires it. Shared key ⇒ shared throttle and audit (who requested which CVE).
3. **Authenticate callers of Pattern B** with a workload identity (service principal, SPIFFE, or a minted JWT from the agent host). A static shared “agent password” in a prompt is just a second leaked secret.
4. **Rotate** the GTI key independently of agent tokens.
5. **Network config is identity-adjacent.** Proxy credentials and the CA path are as sensitive as “how we leave the building.” Treat them as runtime config of the executor, not as agent-visible knobs.

### 5.3 Corporate proxy handling (Hop 2 — enricher → VirusTotal)

Keep `build_proxies()` as the single implementation. Do not re-derive proxy URLs in FastAPI, MCP, or a worker.

Behavior to preserve:

- Resolve CLI/env: `VT_HTTP_PROXY` / `HTTP_PROXY` / `http_proxy` (and HTTPS equivalents).
- Mirror a single scheme onto the other so HTTPS to VirusTotal does not go direct.
- Apply on `requests.Session.proxies`, not via ad-hoc `os.environ` inside request code. Explicit session proxies beat “hope the process inherited WPAD.”
- Typical corporate URL shape is `http://webproxy:8080` for **both** `HTTP_PROXY` and `HTTPS_PROXY`. The proxy itself is HTTP; the target is still HTTPS.
- If IT issues `host:port` only, prefix `http://`. If the proxy requires auth, put `http://user:pass@host:port` in the secret store, never in the tool schema.
- For Pattern B/D, set these on the **service/worker**, not on every agent replica (agent replicas may have no internet at all).

**Do not blindly reuse Hop-2 proxy settings for Hop 1.** If the agent calls `https://gti-enricher.internal.example.com`, sending that request through `webproxy` often:

- Breaks internal DNS / split-horizon names
- Intercepts or strips mTLS
- Returns a captive-portal HTML 200 that the agent then tries to parse as enrichment JSON

Use `NO_PROXY` / `no_proxy` for internal names (`localhost`, `*.internal.example.com`, the enricher hostname). Document this next to `HTTP_PROXY` in `.env.example` when Pattern B exists.

Windows-specific: browsers follow WPAD/PAC; **Python `requests` does not** unless you set env vars. That is why today’s `.env` is the source of truth. An agent subprocess must inherit it. A Windows service must have the same values in its service environment, not “whatever IE Auto-detect would have done.”

### 5.4 TLS / SSL inspection handling (Hop 2)

Keep `resolve_ssl_verify()` and the `verify is False` reject in `GTIClient`. Corporate SSL inspection (Zscaler, Netskope, Blue Coat, Palo Alto, etc.) presents a cert signed by an **internal root CA** that is not in certifi. The supported fix is `session.verify = "<pem path>"`.

Resolution order to preserve:

1. Explicit config (`--ca-bundle` / service setting)
2. `CORPORATE_CA_BUNDLE`
3. `REQUESTS_CA_BUNDLE` / `SSL_CERT_FILE`
4. Project `certs/corporate-ca.pem` if present
5. `True` (certifi / system store)

`Path.expanduser()` must keep working so `%USERPROFILE%\certs\corporate_trust_bundle.pem` and `~/certs/corporate_trust_bundle.pem` remain valid. If a path is **explicitly** configured and missing, **fail loud** (`FileNotFoundError` → run-level error JSON). Silent fallback to certifi produces a worse `SSLError`.

For a containerized service:

- Mount the PEM at a known path (`/etc/ssl/corp/corporate_trust_bundle.pem`).
- Point `CORPORATE_CA_BUNDLE` at it.
- Do not append blindly to certifi in the image unless IT owns that process; the explicit path is reversible and auditable.
- The container still needs **outbound** access to the corporate proxy; “we put the CA in the image” does not replace `HTTP_PROXY`.

Inbound TLS (Pattern B, Hop 1): use the **corporate issuing CA** so agent runtimes that already trust internal PKI just work. This is a different cert than the SSL-inspection root. Document the SNI hostname. The enricher must not use the inspection-bundle to verify its *own* server certificate.

### 5.5 Hop 1 handling (agent → enricher)

Only applies once Pattern B/C-over-HTTP/D exists.

| Concern | Handling |
|---------|----------|
| Address | Internal DNS name, not a public IP. Bind localhost for single-host MCP/stdio. |
| TLS | Corp PKI server cert; agent HTTP client trusts corp roots (often the OS store). |
| Auth | Bearer / mTLS / IAP — see 5.2. No GTI key on this hop. |
| Proxy | Usually **direct**. Set `NO_PROXY` for the enricher host. |
| Timeouts | Agent-side timeout must exceed GTI sequential delay: 25 CVEs × (1.0s + RTT + retries) can be minutes. Prefer small batches or async (Pattern D). |
| Streaming | Not required. One JSON document per call. |

MCP stdio (Pattern C on a workstation) **avoids Hop 1 entirely**: no listening port, no extra TLS, inherits the analyst `.env`. That is the lowest-friction way to register the Phase 1 JSON CLI as a tool before a FastAPI hop exists.

### 5.6 What the agent is allowed to pass

| Parameter | Allowed? |
|-----------|----------|
| CVE IDs | Yes |
| `include_html`, `include_narrative`, `product_limit` | Yes |
| API key, proxy URL, CA path, `verify` | **No** |
| Arbitrary VirusTotal URL / collection ID | **No** (prevents using the key as a general VT exfil tool) |
| Raw dump of GTI JSON to the model | Default **no**; opt-in for debug with audit |

### 5.7 Logging and redaction

- Continue redacting `://user:pass@` in proxy URLs.
- Never log `x-apikey` or the `.env` file contents.
- Audit **caller identity + CVE list + status + latency**, not full narratives, unless a SIEM sink is approved.
- HTML failure banners may include exception text (SSL, missing CA path). That is useful; still strip env dumps and key material if a future traceback formatter gets chatty.
- `/readyz` may say `tls=custom CA bundle` and `proxy=configured` without printing the PEM path’s directory tree or the proxy password.

### 5.8 Laptop `.env` vs service / container injection

The workstation model is: a gitignored `.env` next to `cve_enricher.py`, loaded with `override=False`, plus an optional PEM under the user profile. That is correct for Pattern A. It is **wrong** to copy into a container image, a shared network drive, or the agent’s tool schema.

Three materials have to move. None of them belong in Git, in the Dockerfile, or in LLM-visible arguments.

| Material | Laptop (today) | Service / container (Pattern B/D) |
|----------|----------------|-----------------------------------|
| **API key** | `VIRUSTOTAL_API_KEY` in `.env` | Secret store → process env or tmpfs file. One org key on the executor. |
| **Proxy** | `HTTP_PROXY` / `HTTPS_PROXY` in `.env` (may include `user:pass`) | Injected env on the **egress workload** only. Server-subnet proxy may differ from the desktop PAC. |
| **CA bundle** | `CORPORATE_CA_BUNDLE=%USERPROFILE%\certs\corporate_trust_bundle.pem` or `certs/corporate-ca.pem` | Mounted file (ConfigMap/volume). Public cert; still not committed. Same resolver order. |

**API key handling**

- Inject at process start as `VIRUSTOTAL_API_KEY` so `resolve_api_key()` stays unchanged.
- Prefer a secret manager (Vault, Azure Key Vault, AWS Secrets Manager, DPAPI-backed file, Kubernetes Secret / CSI driver). The application code should keep calling `os.getenv`, not a vendor SDK, unless you later add a thin `load_secrets()` that writes env before `load_project_dotenv`.
- **Never** `COPY .env` in a Dockerfile. **Never** bake the key into the image or a Helm `values.yaml` committed to git.
- Rotation: update the secret and rolling-restart (or re-read a mounted file). Do not require an image rebuild. Keep placeholder rejection (`your_key_here`) so a forgotten secret fails `/readyz` instead of sending junk to VirusTotal.
- The agent authenticates to the *enricher* with a separate workload token (5.2). That token is not the GTI key and must be rotatable on a shorter cycle.

**Corporate CA bundle handling**

- The PEM is a **public root certificate**, not a private key. Treat it as config, but still keep it out of git (`certs/*.pem` is already gitignored).
- Mount at a stable path, e.g. `/etc/ssl/corp/corporate_trust_bundle.pem` (Linux) or `C:\certs\corporate_trust_bundle.pem` (Windows service). Set `CORPORATE_CA_BUNDLE` to that path.
- `Path.expanduser()` continues to work if you use `~/certs/...` in non-container hosts; **do not rely on `%USERPROFILE%` inside a container** — the service account profile is empty or wrong.
- If the path is set and the file is missing, fail startup (`FileNotFoundError` today). Do not fall back to certifi and do not set `verify=False` “because the container has no Windows trust store.”
- Kubernetes: ConfigMap (or Secret) volume mount is enough. A corporate base image that already includes the inspection CA is acceptable **if IT owns that image**; still set `CORPORATE_CA_BUNDLE` so Python/`requests` does not depend on whether the image mutated certifi.
- The inspection CA (Hop 2, VirusTotal) is **not** the same cert as the internal PKI used to serve Hop 1 TLS. Mount both if needed; point `CORPORATE_CA_BUNDLE` only at the inspection/trust bundle used for `session.verify`.

**Proxy handling**

- Set `HTTP_PROXY` and `HTTPS_PROXY` on the container/service that performs Hop 2. `build_proxies()` already reads them (and `VT_*` aliases) and mirrors a single scheme.
- Desktop PAC/WPAD will **not** apply inside a container or Windows service. Explicit URLs are mandatory, same as today’s `.env`.
- The proxy host reachable from a laptop (`webproxy:8080`) may **not** be reachable from a server VLAN. Confirm the **data-center / AKS / VM** proxy with network/IT; put that URL in the service secret, not a copy of an analyst’s `.env`.
- Authenticated proxies: store `http://user:pass@host:port` in the secret manager. Logs already redact `user:pass`; keep that.
- Set `NO_PROXY` for Kubernetes API, metadata IPs, and the enricher’s own hostname so Hop 1 and cluster traffic are not forced through the web proxy.
- Docker Desktop “proxies” settings are for building/pulling images on a laptop; they are not a substitute for injecting `HTTP_PROXY` into the **runtime** container that calls VirusTotal.

**Minimal container contract (illustrative)**

```text
# runtime env — injected, not baked
VIRUSTOTAL_API_KEY=...          # from secret store
HTTP_PROXY=http://webproxy:8080
HTTPS_PROXY=http://webproxy:8080
NO_PROXY=localhost,127.0.0.1,10.0.0.0/8,.internal.example.com
CORPORATE_CA_BUNDLE=/etc/ssl/corp/corporate_trust_bundle.pem
VT_REQUEST_DELAY=1.0

# volume
/etc/ssl/corp/corporate_trust_bundle.pem   # mode 0444, public cert
```

The Python process then starts the same way the CLI does after `.env` load: `resolve_api_key` → `build_proxies` → `resolve_ssl_verify` → `GTIClient`. Adapters (FastAPI, worker) must not grow a second config path.

**What stays on the laptop (Phase 1)**

Pattern A (JSON CLI) and stdio tool wrappers: keep `.env` + user-profile PEM. The agent subprocess inherits the analyst environment. No container required until a second consumer or a centralized key is needed (Phase 2).

### 5.9 Network failure modes the agent must receive as data

Do not turn SSL/proxy failures into an empty tool result or a generic “something went wrong” string the model will hallucinate around. Map them onto the run-level `error` object from §4:

| What happened | `error.type` (illustrative) | `retryable` | Notes |
|---------------|-----------------------------|-------------|--------|
| Missing / placeholder API key | `ConfigError` | false | Exit 2 today |
| `CORPORATE_CA_BUNDLE` path missing | `ConfigError` | false | Fail loud, as now |
| `CERTIFICATE_VERIFY_FAILED` / `SSLError` | `SSLError` | false | CA bundle wrong or incomplete chain |
| Proxy connection refused / timed out | `ProxyError` | true | Wrong host/port or proxy down |
| HTTP 407 from proxy | `ProxyAuthError` | false | Credentials missing/expired |
| DNS failure for `www.virustotal.com` | `NetworkError` | true | Often “direct egress blocked, proxy not applied” |
| Connect to VT without proxy, hung | `NetworkError` | true | Enforce timeouts (client already uses 60s) |
| Captive-portal HTML instead of JSON | `ProxyError` | false | Body preview already truncated in `_safe_error_body` |
| GTI 401/403 | per-CVE `forbidden` | false | Early-stop rest of batch |
| GTI 429 after retries | per-CVE `rate_limited` | true | Honor `Retry-After` |
| GTI 404 | per-CVE `not_found` | false | Not a network failure |

`/readyz` should check **config presence** (key non-empty, CA file exists if configured, proxy vars present if your deployment requires them) without calling VirusTotal on every probe. An optional infrequent authenticated probe can sit behind a longer cache so liveness checks do not spend VI quota.

Full operator telemetry, HTTP mapping, and **how the agent must behave** on each failure are in **§6 Observability & Failure Modes**.

### 5.10 Handling checklist (copy into the runbook)

- [ ] Hop 2 uses the same `build_proxies()` + `resolve_ssl_verify()` as the CLI
- [ ] `verify=False` is still impossible
- [ ] CA path works for `%USERPROFILE%\certs\corporate_trust_bundle.pem` and for a mounted service PEM
- [ ] GTI key and proxy password are not tool parameters and not in HTML/JSON
- [ ] Agent subprocess or service inherits `HTTP_PROXY` / `HTTPS_PROXY` (WPAD is not enough)
- [ ] `NO_PROXY` covers the internal enricher hostname (Hop 1) when Pattern B is used
- [ ] Timeouts on the agent side allow sequential 1.0s GTI delays
- [ ] SSL / proxy / 407 / 401 failures return structured `error` / per-CVE `status`
- [ ] `/readyz` (or CLI startup logs) show TLS mode and redacted proxy without printing secrets
- [ ] Browser is never opened from a service account or MCP session

---

## 6. Observability & Failure Modes

Agents cannot screenshot a PowerShell window. They need **structured, stable failure signals** they can branch on, plus enough operator telemetry that SSL/proxy/quota problems are visible without reading GTI key material. The current CLI already does part of this for humans (stderr logs, exit codes 0/1/2/3, always-on HTML failure banner). Agentic mode must expose the same facts as JSON, metrics, and health — not as a browser pop-up.

### 6.1 What “healthy” means

Split liveness from readiness. Never call VirusTotal on every probe.

| Endpoint / check | Purpose | Must not |
|------------------|---------|----------|
| **Liveness** (`/healthz`) | Process is up | Touch GTI, the proxy, or the CA file |
| **Readiness** (`/readyz`) | Config is present: non-placeholder key, CA file exists if `CORPORATE_CA_BUNDLE` is set, proxy vars present if the deployment requires them | Spend VI quota; print secrets |
| **Optional probe** (cached, e.g. every 15–30 min) | One authenticated GET to a known collection or a cheap VT endpoint | Run on the k8s probe interval |

Readiness payload (safe to log):

```json
{
  "ready": false,
  "api_key": "configured",
  "tls": "custom CA bundle",
  "proxy": "configured",
  "ca_bundle_present": true
}
```

CLI equivalent: the existing startup lines (`Loaded configuration from …`, `TLS verification: custom CA bundle → …`, `Using proxies: {…}` with passwords redacted) are Phase 1 observability. Keep them on **stderr** so `--json` stdout stays a single document.

### 6.2 Correlation and logs

Every enrichment call (CLI invocation, HTTP request, or queue message) should have a **`correlation_id`**. The agent may supply it; otherwise generate a UUID. Put it on:

- The JSON response envelope
- Every log line for that run
- Audit records (caller identity + CVE list + statuses + duration)
- Optional HTML artifact metadata (not the API key)

Log at INFO for run start/end and per-CVE outcome (`cve`, `status`, `priority`, `http_status`, `cache_hit`, `latency_ms`). Log at DEBUG for request URL (the collections path is not secret) and truncated GTI error bodies (already capped by `_safe_error_body`).

Never log:

- `VIRUSTOTAL_API_KEY` / `x-apikey`
- Proxy passwords (keep the `://user:***@` redaction)
- Full `.env` dumps
- Raw GTI payloads at INFO (they can include narrative and product lists; DEBUG or `--dump-raw` only, with ACL)

### 6.3 Metrics that matter

Low-cardinality metrics; CVE IDs are **not** labels.

| Metric | Why |
|--------|-----|
| `gti_enrich_requests_total{result}` | `ok` / `not_found` / `forbidden` / `rate_limited` / `error` / `config_error` |
| `gti_enrich_cves_total{status}` | Per-CVE status histogram |
| `gti_http_request_duration_seconds` | GTI GET latency (histogram) |
| `gti_http_retries_total{reason}` | `429` / `5xx` / `network` |
| `gti_rate_limited_total` | 429 after retries — page if sustained |
| `gti_cache_hit_total` / `miss_total` | Quota stewardship |
| `gti_in_flight` | Gauge; catch agent fan-out |
| `gti_ready` | 0/1 from `/readyz` |
| `gti_html_reports_written_total` | Artifact volume |

Alert on: `/readyz` down, sustained `forbidden` (key/license), sustained `SSLError`/`ProxyError` (CA or proxy drift), 429 rate above a baseline, in-flight climbing (agent retry storm).

### 6.4 Failure catalog (operator + agent)

Two layers, matching the current code:

1. **Run-level** — never talked to GTI usefully (missing key, missing CA, unreadable input, process crash). Today: HTML “Run failed” banner + exit 2/1. Agent: `response.error` set, `records` possibly empty.
2. **Per-CVE** — `ok` / `not_found` / `forbidden` / `rate_limited` / `error`. Today: error cards in HTML/CSV. Agent: one object per requested CVE; never drop IDs.

| Failure | Layer | `retryable` | Agent should | Operator looks at |
|---------|-------|-------------|--------------|-------------------|
| Placeholder / missing API key | Run | false | Tell user the capability is misconfigured; do **not** invent CVSS | Secret injection, `/readyz` |
| CA path set but file missing | Run | false | Same | Volume mount, `CORPORATE_CA_BUNDLE` |
| `CERTIFICATE_VERIFY_FAILED` | Run or per-CVE | false | Do not retry in a loop; report SSL inspection/CA | PEM is root CA? Container missing mount? |
| Proxy refused / timeout | Run or per-CVE | true (bounded) | Back off; then surface “egress/proxy down” | Hop 2 proxy URL, VLAN, `HTTP_PROXY` |
| HTTP 407 proxy auth | Run | false | Do not retry with backoff forever | Secret password rotation |
| Captive-portal / HTML body | Per-CVE `error` | false | Not a CVE 404 | Traffic not actually reaching VT |
| DNS failure for `www.virustotal.com` | Per-CVE / run | true | Often means proxy not applied | `build_proxies()`, `NO_PROXY` over-matching |
| GTI 401/403 | Per-CVE `forbidden` | false | Stop the batch; “license/privilege” | Enterprise + VI on the key |
| GTI 429 after retries | Per-CVE `rate_limited` | true | Honor `Retry-After`; shrink batch; use cache | Shared throttle, agent fan-out |
| GTI 5xx | Per-CVE `error` | true | Bounded retry already done in `GTIClient` | VT status; do not add a second retry loop in the agent |
| GTI 404 | Per-CVE `not_found` | false | “Not in GTI” ≠ “not vulnerable” | Coverage, very new CVE |
| Invalid CVE ID | Dropped before GET (warn) | false | Ask the user to correct; do not call GTI | `normalize_cve()` |
| Agent timeout too short | Apparent tool failure | — | Timeouts ≥ `n × (delay + 60s timeout)` or smaller batches | Hop 1 timeout config |
| Browser / Rich in agent mode | Operator footgun | — | `--json` must imply `--no-open --no-rich` | Phase 1 CLI flags |

Exit codes (Pattern A) stay useful for shells:

| Code | Meaning | Typical JSON |
|------|---------|--------------|
| `0` | ≥1 CVE `ok` | `error=null`, mixed per-CVE statuses allowed |
| `1` | Zero successes / runtime | `error` or all records non-ok |
| `2` | Config / input / CA / key | `error.type=ConfigError` |
| `3` | Privilege and zero successes | all `forbidden` |

HTTP mapping for Pattern B (suggested): `200` with per-CVE statuses for partial success; `422` invalid request; `503` + `error.retryable=true` when GTI/proxy is down or 429’d; `500` only for unexpected crashes. **Do not use HTTP 401 for GTI 401** — that confuses “agent token bad” with “VirusTotal key lacks VI.” GTI privilege belongs in the body as `forbidden`.

### 6.5 What the agent must know when enrichment fails

The model will fill gaps. If the tool returns a traceback, an empty string, or HTML, it will invent a CVSS. Surface every failure as the **same envelope** as success (`EnrichmentResponse`), with `error` and/or per-CVE `status` set. Put the following rules in the **tool description**, not only in operator docs.

**Standing rules for the agent**

- If `error` is set or a record’s `status != "ok"`, **do not guess** EPSS, CVSS, KEV, priority, or exploitation. Say the enrichment failed and quote `message` / `error_message`.
- `not_found` means “GTI has no collection for this ID,” not “the asset is not vulnerable” and not “the CVE is fake.”
- `forbidden` is a **platform/config** problem (key lacks Vulnerability Intelligence). Stop calling the tool; tell the operator. It is not a property of the CVE.
- `rate_limited` or `error.retryable === true`: wait `retry_after_seconds` (default 30 if missing). Do not fan out more parallel calls.
- Partial batches are valid: use `ok` rows; report the rest as unknown.
- Never scrape the HTML report for facts. JSON is authoritative; HTML is for humans (`include_html`).
- Never ask the user to paste an API key, proxy URL, or CA path into chat.

**How the service should surface errors (clean contract)**

| Field | Who reads it | Rule |
|-------|----------------|------|
| `error.type` | Agent + monitors | Stable enum, not exception class names from Python |
| `error.message` | Agent (may quote to user) | One or two sentences, no secrets, no `C:\Users\…` if avoidable |
| `error.retryable` | Agent retry logic | Boolean; agent must honor it |
| `error.retry_after_seconds` | Agent backoff | From GTI `Retry-After` or a conservative default |
| `error.http_status` | Operators / debug | 0 if never reached GTI |
| `records[].status` | Agent per CVE | Always present for IDs that were accepted |
| `records[].error_message` | Agent per CVE | Same cleanliness as `error.message` |
| HTTP status (Pattern B) | Non-LLM clients | See mapping below — **do not reuse HTTP 401 for GTI 401** |

**Example — missing CA bundle (config, not retryable)**

Maps from today’s `FileNotFoundError` / exit 2 / HTML “Run failed” banner.

```json
{
  "contract_version": "1.0",
  "generated_at": "2026-08-24T18:01:00Z",
  "requested": 1,
  "enriched": 0,
  "failed": 0,
  "records": [],
  "artifacts": { "html_report": null },
  "error": {
    "type": "ConfigError",
    "message": "Corporate CA bundle is configured but the file is missing. Enrichment cannot verify TLS. An operator must mount the PEM and set CORPORATE_CA_BUNDLE.",
    "retryable": false,
    "retry_after_seconds": null,
    "http_status": null
  }
}
```

**Example — SSL inspection / wrong CA (not retryable in a loop)**

```json
{
  "error": {
    "type": "SSLError",
    "message": "TLS verification failed reaching VirusTotal (certificate verify failed). The corporate inspection CA is missing or is not the root of the proxy chain. Do not disable verification.",
    "retryable": false,
    "retry_after_seconds": null,
    "http_status": null
  },
  "records": [],
  "enriched": 0
}
```

**Example — GTI rate limit after client retries**

`GTIClient` already backs off on HTTP 429. If it still fails, the agent sees `rate_limited` and waits — it must not start its own tight retry loop.

```json
{
  "requested": 2,
  "enriched": 1,
  "failed": 1,
  "error": null,
  "records": [
    {
      "cve": "CVE-2021-44228",
      "status": "ok",
      "priority": "P0",
      "error_message": null
    },
    {
      "cve": "CVE-2024-3400",
      "status": "rate_limited",
      "priority": null,
      "error_message": "VirusTotal rate-limited this request after retries (HTTP 429). Wait 45s and retry this CVE only; do not parallelize.",
      "vt_url": "https://www.virustotal.com/gui/collection/vulnerability--cve-2024-3400"
    }
  ]
}
```

Optional run-level companion when the *whole* batch is 429’d:

```json
{
  "error": {
    "type": "RateLimited",
    "message": "Google Threat Intelligence is rate-limiting Vulnerability Intelligence requests. Wait before calling again. Reduce batch size.",
    "retryable": true,
    "retry_after_seconds": 45,
    "http_status": 429
  }
}
```

**Example — VirusTotal / GTI outage or proxy to VT down**

```json
{
  "error": {
    "type": "UpstreamError",
    "message": "VirusTotal did not return a usable response (HTTP 503) after retries. This is an upstream or network issue, not a property of the CVE.",
    "retryable": true,
    "retry_after_seconds": 60,
    "http_status": 503
  },
  "records": [
    {
      "cve": "CVE-2024-3400",
      "status": "error",
      "error_message": "Request failed (HTTP 503)."
    }
  ]
}
```

**Example — missing Enterprise / VI privilege**

Early-stop as today (`stop_on_forbidden`): remaining CVEs are `forbidden` with a skip message so the list is complete.

```json
{
  "requested": 3,
  "enriched": 0,
  "failed": 3,
  "error": {
    "type": "Forbidden",
    "message": "The VirusTotal key lacks Google Threat Intelligence Vulnerability Intelligence (HTTP 403). This is a license/config issue. Stop calling enrich_cves until an operator fixes the key.",
    "retryable": false,
    "http_status": 403
  },
  "records": [
    { "cve": "CVE-2021-44228", "status": "forbidden", "error_message": "Access denied (401/403). Enterprise or Enterprise Plus with Vulnerability Intelligence is required." },
    { "cve": "CVE-2024-3400", "status": "forbidden", "error_message": "Skipped: earlier request returned 401/403 (privilege missing)." }
  ]
}
```

**HTTP mapping (Phase 2 service)** — keep GTI failures in the **body**, not as lookalike HTTP auth errors:

| Situation | HTTP | Body |
|-----------|------|------|
| Agent token missing/bad | `401` | gateway problem; never GTI |
| Malformed CVE list | `422` | `error.type=ConfigError` |
| Partial success (mix of ok / not_found / rate_limited) | `200` | per-CVE `status` |
| Missing CA / missing GTI key | `503` | `error.type=ConfigError`, `retryable=false` |
| Proxy/SSL to VirusTotal | `503` | `SSLError` / `ProxyError` |
| GTI 429 / 5xx after retries | `503` | `retryable=true`, `Retry-After` header + `retry_after_seconds` |
| Unexpected crash | `500` | `error.type=InternalError` |

CLI (Phase 1) keeps exit codes 0/1/2/3; tool hosts should still parse **stdout JSON** rather than treating a non-zero exit as “no body.” Always print the envelope before exiting.

If `include_html: true`, `render_html_report()` still writes the existing failure banner for humans. The agent must not depend on that file.

### 6.6 Suggested tool-description snippet (copy into MCP / function schema)

```text
Enrich CVE IDs via Google Threat Intelligence (VirusTotal Vulnerability
Intelligence). Returns priority (P0–P4), EPSS, CVSS, CISA KEV, exploitation,
affected products, mitigations, and a VirusTotal collection URL.

On failure the JSON still conforms to the same schema:
- error.type / error.message / error.retryable / error.retry_after_seconds
- records[].status: ok | not_found | forbidden | rate_limited | error

Do not invent CVSS, EPSS, KEV, or priority when status is not ok.
not_found means GTI has no collection, not "not vulnerable".
forbidden means the API key/license is wrong — stop calling this tool.
If retryable is true, wait retry_after_seconds (or 30s) and retry once;
do not fire parallel calls. Never request API keys, proxy URLs, or CA paths.
```

### 6.7 Tracing (optional, Phase 2+)

If the org already has OpenTelemetry: one span per tool call, child span per GTI GET, attributes `cve.count`, `cache.hit`, `gti.http_status`. **No** API key, no proxy password, no full response body. Phase 1 only needs stderr logs + JSON errors.

---

## 7. Phased Roadmap

Ordered by **value vs risk**. Each phase is shippable on its own. Do not skip Phase 1 — FastAPI on top of Rich-on-stdout is still not agent-safe. Do not start with a message bus.

Reuse what already exists: `enrich_cves()`, `GTIClient`, `extract_record()`, `derive_priority_rating()`, `render_html_report()`, `build_proxies()`, `resolve_ssl_verify()`. This document is not an implementation; the steps below are the intended sequence.

| Phase | Outcome | Risk | Effort |
|-------|---------|------|--------|
| **1** | Structured JSON on stdout; HTML optional, browser off in agent mode | Low — CLI only, same `.env` / CA / proxy | 1–3 days |
| **2** | Thin FastAPI (or Flask) wrapper; shared throttle; secrets/CA as mounts | Medium — new hop, auth, deploy | 1–2 weeks MVP |
| **3** | Native agent tool registration (MCP / LangGraph / Copilot / OpenAPI) | Low–medium if Phase 1–2 contract is stable | 2–5 days on top |
| **4** | Optional: detection-pipeline / queue consumer | High ops cost | Only if a broker already exists |

### Phase 1 — Expose structured JSON and keep the existing HTML

**Goal.** An agent (or a human piping the CLI) gets the §4 envelope. Analysts who run the script as today still get CSV + HTML + browser.

**Do**

- Add `--json` (implies `--no-open --no-rich`). Print one `EnrichmentResponse` on stdout; keep logs on stderr.
- Add repeatable `--cve` so agents are not forced to write a temp CSV (keep `-i` for humans).
- Map `CVERecord` → agent DTO at the boundary (`null` not `"N/A"`, bools/floats native).
- On config/SSL/key failure, still print that JSON envelope (then exit 2/1). Optionally write HTML if `--html` was set; **do not open a browser** when `--json`.
- Document stdout contract + exit codes next to `README.md` usage (docs only when you implement).

**Do not**

- Change default human behavior when `--json` is absent.
- Expose `--api-key` / proxy / CA as something an LLM should pass.
- Introduce FastAPI yet.

**Success.** `python cve_enricher.py --json --cve CVE-2021-44228` prints valid JSON, does not launch a browser, and still can write HTML with `include`/`--html` when asked. Failure cases in §6.5 produce the envelope, not Rich markup on stdout.

This is Pattern A + Pattern E.

### Phase 2 — Thin FastAPI (or Flask) wrapper

**Goal.** One long-lived process an agent host can `POST` to. Shared `requests.Session`, `VT_REQUEST_DELAY`, and cache. GTI key / proxy / CA leave the laptop (see §5.8).

**Do**

- Import the same functions the CLI uses (`enrich_cves`, DTO mapper, optional `render_html_report`). No second GTI client.
- `POST /v1/enrich`, `GET /healthz`, `GET /readyz` as in Pattern B. Same JSON contract as `--json`.
- Inject `VIRUSTOTAL_API_KEY`, `HTTP_PROXY`, `HTTPS_PROXY`, `CORPORATE_CA_BUNDLE` from the platform secret/volume. `verify=False` still impossible.
- In-process cache + single-flight (canonical CVE key, 12–24h TTL, shorter negative cache for 404). Cap `cves` at 25.
- HTTP mapping from §6.5. `Retry-After` on 503 when GTI 429s.
- Internal hostname + corp PKI; `NO_PROXY` for that hostname.

**Do not**

- Put the service on the public internet.
- Copy `.env` into the image.
- Parallelize GTI GETs until quota is confirmed in writing.
- Treat this as the *agent-facing schema* — that is Phase 3. This is the transport.

**Success.** Two callers share one key without double-throttling. `/readyz` is red on missing CA or placeholder key. An agent HTTP tool gets the same JSON as `--json`.

### Phase 3 — Full agent tool registration

**Goal.** The model can *choose* to enrich. Plumbing from Phases 1–2 stays; this is the schema and host binding.

**Do**

- Register `enrich_cves` with the schema and description in §3 Pattern C and §6.6.
- Bind to the **actual** first host (MCP stdio wrapping Phase 1 is enough if only one analyst laptop; HTTP tool against Phase 2 if multiple hosts).
- Frameworks: MCP (Grok / Claude / Cursor), OpenAI Agents SDK, LangGraph `@tool`, CrewAI `BaseTool`, AutoGen function, Copilot Studio / Semantic Kernel via OpenAPI from Phase 2.
- Golden-path evals (manual is fine): Log4j-class P0, KEV CVE, `not_found`, invalid ID, missing key, SSL/CA failure. Confirm the model does **not** invent scores.
- Compact default payload (`product_limit`, no `analysis` unless asked).

**Do not**

- Add tool parameters for delay, proxy, CA, API key, or `verify`.
- Register a generic “run shell” tool that happens to call the enricher.

**Success.** An analyst pastes a detection; the agent calls `enrich_cves`, cites `priority` / KEV / `vt_url`, and on failure quotes `error.message` instead of hallucinating CVSS.

### Phase 4 — Pipeline integration (only when needed)

Wire scanner/SIEM → Phase 2 (or a queue worker using the same library) so detections are enriched **before** the agent talks. Agent becomes a reader. Requires an existing broker and a place to store results. Skip if the business goal is “SOC copilot,” not “enrich every finding.”

### Implementation notes (all phases)

- **Library split** can start in Phase 1 (thin `to_agent_dto`) and finish in Phase 2. `enrich_cves()` is already the API.
- **Cache and quota** become mandatory in Phase 2; Phase 1 should still cap `--cve` count and keep 1.0s delay.
- **Example flow after Phase 3:** alert with `CVE-2024-3400` → tool call → triage note from JSON → optional `include_html: true` attached to the ticket.

---

## 8. Open Questions / Decisions Needed

These block Phase 2–3 more than Phase 1. Phase 1 can proceed on a single workstation with today’s `.env` while the team answers them.

| # | Decision | Options | Suggested default |
|---|----------|---------|-------------------|
| 1 | **First agent host** | Grok Build / MCP; Claude Desktop / Cursor MCP; Copilot Studio; LangGraph in-process; CrewAI / AutoGen | MCP stdio wrapping Phase 1 CLI if the copilot is laptop-based; OpenAPI/HTTP once Phase 2 exists |
| 2 | **May enrichment JSON leave the corp boundary?** (cloud LLM + products / narrative) | Internal model only; cloud with fields stripped; cloud with full payload | Internal or strip `affected_products` + long narrative until legal/GTI license confirms |
| 3 | **GTI key model** | One org key on the executor; per-analyst keys | One org key + audit of caller identity. Confirm Enterprise/VI and the **documented rate limit** with the GTI admin |
| 4 | **Where HTML artifacts live** | Next to CLI cwd; SOC share; ticket attachment API; object storage | Phase 1: path on disk, ACL’d folder. Phase 2: dedicated report dir or ticket attach. Default `include_html: false` |
| 5 | **Cache TTL for 404 / `not_found`** | No cache; 1 hour; 24 hours | 1 hour negative cache so brand-new CVEs can appear; 12–24h for `ok` |
| 6 | **Existing tool gateway?** | Org MCP broker / OpenAPI plugin host vs one-off FastAPI | Prefer the gateway if it already handles mTLS and identity; still use this repo’s library behind it |
| 7 | **Who owns triage policy?** (`P0` + KEV → page vs backlog) | LLM prompt; vuln-mgmt `triage` object in the contract | Policy-owned `triage` object later; do not bury SLA in the prompt |
| 8 | **Batch size and timeouts** | 5 / 25 / 100 CVEs per call | 25 max in schema; agent HTTP timeout ≥ `n × (VT_REQUEST_DELAY + 60s)` or smaller batches |
| 9 | **Windows service vs Linux container for Phase 2** | NSSM/Windows service on a jump box; Linux container on the allowed subnet | Whichever VLAN already reaches `webproxy` + VirusTotal. CA path and proxy URL change; code should not |
| 10 | **Hop-1 auth** | mTLS; IAP; JWT from agent platform; IP allowlist only | Workload identity (JWT or mTLS). IP allowlist is not enough |
| 11 | **Event bus (Pattern D)** | Now; after Phase 2; never | Never unless enrichment must run on every detection and a broker already exists |
| 12 | **Human CLI defaults** | Keep always-open HTML; change to `--no-open` by default | Keep today’s human default. Only agent mode (`--json`) turns the browser off |

Until 1–3 are answered, **ship Phase 1** on the workstation that already has proxy, `%USERPROFILE%\certs\corporate_trust_bundle.pem` (or `certs/corporate-ca.pem`), and `.env` working. That is the highest-value, lowest-risk move: the agent gets structured enrichment without relocating secrets or opening a new network surface.

The product is already in this repo — `GTIClient`, flattening, P0–P4, proxy/CA handling, and the HTML renderer. Agentic integration is a JSON contract, honest errors, and adapters. It is not a new enricher.
