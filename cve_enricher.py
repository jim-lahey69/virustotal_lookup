#!/usr/bin/env python3
"""
GTI / VirusTotal CVE Enricher
=============================

Enrich a list of CVE IDs using the Google Threat Intelligence (GTI)
Vulnerability Intelligence collections endpoint:

    GET /api/v3/collections/vulnerability--{cve-id-lowercase}

Requires a VirusTotal / GTI **Enterprise** or **Enterprise Plus** API key
with Vulnerability Intelligence privileges.

Configuration (preferred: project ``.env`` file — see ``.env.example``)
-----------------------------------------------------------------------
Copy ``.env.example`` to ``.env`` and fill in values. The script loads
``.env`` via python-dotenv at startup so you do **not** need to set
``$env:HTTP_PROXY`` / API key in every PowerShell session.

    VIRUSTOTAL_API_KEY   VirusTotal / GTI API key (required)
    VT_API_KEY           Alias for VIRUSTOTAL_API_KEY
    HTTP_PROXY           HTTP proxy URL (e.g. http://webproxy:8080)
    HTTPS_PROXY          HTTPS proxy URL (usually same as HTTP_PROXY)
    VT_HTTP_PROXY        Alias for HTTP_PROXY
    VT_HTTPS_PROXY       Alias for HTTPS_PROXY
    CORPORATE_CA_BUNDLE  Path to corporate root CA PEM/CRT for SSL inspection
    VT_REQUEST_DELAY     Inter-request delay in seconds (default: 1.0)

Usage
-----
    # After creating .env with key, proxy, and optional CA path:
    python cve_enricher.py --input cve_list.csv --output cve_enriched.csv --html report.html

Corporate SSL inspection
------------------------
Do **not** disable TLS verification. Place your org root CA at
``./certs/corporate-ca.pem`` (or set ``CORPORATE_CA_BUNDLE``) so
``requests`` can verify the MITM proxy chain. See SETUP.md / README.

HTML report
-----------
An HTML report is always written (default ``report.html``) and opened in
the default browser — including when enrichment fails (missing key, SSL
errors, network issues). The failure report includes a prominent error
section with the exception message.

Cleanup log (hygiene / documentation only — no functional change)
-----------------------------------------------------------------
Auditable notes from the maintainability pass. Runtime behavior of
``.env`` loading, proxy construction, CA-bundle resolution, ``GTIClient``,
HTML generation, and the always-open-report path is unchanged.

- Removed unused ``dataclasses.field`` import.
- Removed unused ``_dig()`` helper (never called; extraction uses ``_first``).
- Removed a no-op ``exploited_in_the_wild`` inference block that only ``pass``-ed.
- Removed an unreachable Critical→P0 branch in ``derive_priority_rating`` fallback
  (P0 for Critical already returns earlier in the official table).
- Deduplicated CVE-ID accumulation in ``load_cve_list`` via ``_accept_cve``.
- Expanded educational comments on corporate proxy/TLS, GTI client wiring,
  and why the HTML report is generated and launched even on failure.
"""

from __future__ import annotations

# --- Standard library ---
# argparse: CLI surface for operators who prefer flags over editing .env
# csv / html / json: input parsing and report serialization
# logging: operational visibility without printing secrets
# os / subprocess / webbrowser: env access and reliable browser open on Windows
# random / time: jittered backoff so concurrent clients do not thundering-herd the API
# traceback: captured into the HTML failure banner so SSL/proxy issues are visible offline
import argparse
import csv
import html
import json
import logging
import os
import random
import re
import subprocess
import sys
import time
import traceback
import webbrowser
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Optional, Union

# --- Third party ---
# requests: HTTP client; verify= path-or-True supports corporate MITM CAs
# dotenv: load project .env so PowerShell session variables are not required
# rich: progress bars and color cards on the terminal (stderr for logs)
import requests
from dotenv import load_dotenv
from rich import box
from rich.console import Console, Group
from rich.logging import RichHandler
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.table import Table
from rich.text import Text

# ---------------------------------------------------------------------------
# Configuration defaults
# ---------------------------------------------------------------------------
# Values may be overridden by .env, process environment, or CLI flags.
# Secrets are never hard-coded here — only safe defaults and path conventions.
# Anchoring to the script directory (not cwd) means operators can invoke
# ``python path\to\cve_enricher.py`` from any working directory and still
# find ``.env`` and ``certs/`` next to this file.
# ---------------------------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent
DEFAULT_ENV_FILE = PROJECT_ROOT / ".env"
# Conventional drop-location for the org SSL-inspection root CA.
# Used automatically *only if the file exists*; otherwise certifi/system trust.
# Operators who keep a personal bundle under their user profile
# (e.g. %USERPROFILE%\certs\corporate_trust_bundle.pem) should set
# CORPORATE_CA_BUNDLE in .env — that path is resolved via expanduser() below.
DEFAULT_CA_BUNDLE = PROJECT_ROOT / "certs" / "corporate-ca.pem"

DEFAULT_API_BASE = "https://www.virustotal.com/api/v3"
DEFAULT_INPUT = "cve_list.csv"
DEFAULT_OUTPUT = "cve_enriched.csv"
# HTML path is always used (report is written even when enrichment fails).
DEFAULT_HTML = "report.html"
DEFAULT_MAX_RETRIES = 5
DEFAULT_BACKOFF_BASE = 2.0  # seconds; exponential: base^attempt + jitter

# Canonical CVE ID shape used for validation after normalization.
CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

# GTI priority derivation treats these labels as "no known exploit availability".
# Values observed across GTI docs / UI wording variants.
NO_KNOWN_ALIASES = {"", "n/a", "none", "no known", "no_known", "unknown"}

# Fallback delay; actual value is resolved after .env load (see resolve_request_delay).
DEFAULT_DELAY = 1.0

# stdout for human-facing Rich cards; stderr for logs + progress so piping
# the process (or capturing stdout in a wrapper) does not mix log lines
# into a redirected report.
console = Console(stderr=False)
log_console = Console(stderr=True)


# ---------------------------------------------------------------------------
# Environment / config loading
# ---------------------------------------------------------------------------
# All secrets and proxy URLs should come from .env (or explicit CLI overrides).
# Why a project .env instead of PowerShell session variables:
#   - $env:HTTP_PROXY / $env:VIRUSTOTAL_API_KEY vanish when the window closes
#   - Locked-down desktops often forbid user-level environment changes
#   - .env is gitignored, lives with the project, and is loaded every run
# python-dotenv writes into os.environ, which later resolvers (API key,
# proxies, CA path, delay) all read. CLI flags still win over .env.
# ---------------------------------------------------------------------------


def load_project_dotenv(env_file: Optional[Path] = None) -> Optional[Path]:
    """
    Load secrets and proxy settings from a project ``.env`` file.

    Looks for ``.env`` next to this script first, then the current working
    directory. Existing process environment variables are **not** overridden
    (``override=False``), so CI/session exports still win when intentionally set.

    Returns the path that was loaded, or None if no ``.env`` was found.
    """
    # Search order: --env-file (if given), script-dir .env, then cwd .env
    # (cwd is skipped when it is the same inode/path as the script-dir file).
    candidates: list[Path] = []
    if env_file is not None:
        candidates.append(Path(env_file))
    candidates.append(DEFAULT_ENV_FILE)
    cwd_env = Path.cwd() / ".env"
    if cwd_env.resolve() != DEFAULT_ENV_FILE.resolve():
        candidates.append(cwd_env)

    for path in candidates:
        if path.is_file():
            # override=False: pre-set env (CI secrets, IT-pushed HTTP_PROXY)
            # takes precedence over values sitting in the file on disk.
            load_dotenv(dotenv_path=path, override=False)
            return path.resolve()

    # Last resort: python-dotenv walking parent directories (monorepo layouts).
    load_dotenv(override=False)
    return None


def resolve_request_delay(cli_value: Optional[float] = None) -> float:
    """
    Resolve inter-request delay: CLI > ``VT_REQUEST_DELAY`` > default.

    GTI rate-limits (HTTP 429) aggressively on Vulnerability Intelligence.
    A 1.0s pause is conservative for interactive analyst runs; bulk jobs
    can raise it via ``.env`` without touching the CLI.
    """
    if cli_value is not None:
        return float(cli_value)
    env_val = os.getenv("VT_REQUEST_DELAY")
    if env_val:
        try:
            return float(env_val)
        except ValueError:
            logging.warning("Invalid VT_REQUEST_DELAY=%r; using %s", env_val, DEFAULT_DELAY)
    return DEFAULT_DELAY


# Reject copy-paste placeholders so operators get a clear config error
# instead of a confusing 401 from VirusTotal.
_PLACEHOLDER_API_KEYS = frozenset(
    {
        "insert_key_here",
        "your-api-key",
        "your_key_here",
        "your-api-key-here",
        "changeme",
        "api_key",
        "apikey",
    }
)


def resolve_api_key(cli_value: Optional[str] = None) -> Optional[str]:
    """
    Resolve API key: CLI > VIRUSTOTAL_API_KEY > VT_API_KEY.

    ``VIRUSTOTAL_API_KEY`` is the preferred name in ``.env``.
    Returns None when unset or still a documented placeholder value so
    ``main()`` can fail with a config error (exit 2 + HTML banner) instead
    of sending a dummy key to VirusTotal and getting a confusing 401.

    Prefer ``.env`` over ``--api-key`` on shared workstations: CLI arguments
    persist in PowerShell history.
    """
    key = (
        (cli_value or "").strip()
        or (os.getenv("VIRUSTOTAL_API_KEY") or "").strip()
        or (os.getenv("VT_API_KEY") or "").strip()
    )
    if not key:
        return None
    if key.lower() in _PLACEHOLDER_API_KEYS:
        return None
    return key


def resolve_ssl_verify(
    ca_bundle: Optional[str] = None,
) -> Union[bool, str]:
    """
    Resolve TLS verification for ``requests``.

    Always verifies certificates — never returns ``False``.

    Why this exists (corporate SSL inspection)
    ------------------------------------------
    Most enterprise networks intercept HTTPS at a proxy (Zscaler, Netskope,
    Blue Coat, Palo Alto, etc.). The proxy presents a certificate signed by
    an **internal root CA** that is not in Python's certifi bundle. Without
    that CA, ``requests`` raises ``SSLError`` / ``CERTIFICATE_VERIFY_FAILED``.

    The supported fix is ``session.verify = "<path-to-pem>"``. Disabling
    verification (``verify=False``) is intentionally **not** offered: this
    tool talks to VirusTotal with an API key, and silently trusting any
    MITM would be a security defect. ``GTIClient`` also refuses ``False``.

    Why we prefer an explicit PEM (project or user-profile)
    -------------------------------------------------------
    - Reversible and auditable (does not mutate certifi).
    - Works even when the Python build does not use the Windows trust store.
    - ``Path.expanduser()`` maps ``~`` to the user profile (Windows:
      ``%USERPROFILE%``), so a personal bundle such as
      ``~/certs/corporate_trust_bundle.pem`` is a valid ``CORPORATE_CA_BUNDLE``.

    What happens if the bundle is missing
    -------------------------------------
    - If a path was **explicitly** configured (CLI / ``CORPORATE_CA_BUNDLE`` /
      ``REQUESTS_CA_BUNDLE`` / ``SSL_CERT_FILE``) and the file is not there,
      we **fail loud** with ``FileNotFoundError``. Silently falling back to
      certifi would just produce a harder-to-diagnose SSLError.
    - If nothing was configured, we look for the conventional project file
      ``certs/corporate-ca.pem`` and use it **only when it exists**.
    - Otherwise we return ``True`` (certifi / system trust). That is *not*
      "disable verification" — it is the default secure path for machines
      that are not behind SSL inspection (or whose CA is already in the
      system store). Operators can run without a corporate PEM on purpose.

    Resolution order:
      1. Explicit CLI / argument path (``ca_bundle`` / ``--ca-bundle``)
      2. ``CORPORATE_CA_BUNDLE`` from environment / ``.env``
      3. ``REQUESTS_CA_BUNDLE`` / ``SSL_CERT_FILE`` (standard Python/requests)
      4. Default path ``./certs/corporate-ca.pem`` if the file exists
      5. ``True`` — use certifi / system trust store

    Returns
    -------
    str
        Absolute path to a CA bundle PEM/CRT file.
    bool
        Always ``True`` when no custom bundle is configured.
    """
    candidates: list[str] = []
    if ca_bundle and str(ca_bundle).strip():
        candidates.append(str(ca_bundle).strip())
    env_ca = (os.getenv("CORPORATE_CA_BUNDLE") or "").strip()
    if env_ca:
        candidates.append(env_ca)
    # Honor standard Python/requests env vars used by many enterprise images
    # (IT sometimes sets REQUESTS_CA_BUNDLE machine-wide).
    for env_name in ("REQUESTS_CA_BUNDLE", "SSL_CERT_FILE"):
        val = (os.getenv(env_name) or "").strip()
        if val:
            candidates.append(val)

    for raw in candidates:
        # expanduser(): "~" and "~/certs/..." → %USERPROFILE% on Windows.
        path = Path(raw).expanduser()
        if not path.is_absolute():
            # Prefer project-root relative paths (how README/.env document them),
            # then fall back to the caller's working directory.
            project_relative = (PROJECT_ROOT / path).resolve()
            cwd_relative = (Path.cwd() / path).resolve()
            if project_relative.is_file():
                path = project_relative
            elif cwd_relative.is_file():
                path = cwd_relative
            else:
                # Keep the project-root resolution in the error message so
                # operators know where we looked.
                path = project_relative
        else:
            path = path.resolve()
        if path.is_file():
            # requests accepts a filesystem path string for verify=
            return str(path)
        # Explicit path was configured but missing — fail loud rather than
        # silently falling back (would surface as a less actionable SSLError).
        raise FileNotFoundError(
            f"CA bundle not found: {raw!r} (resolved to {path}). "
            "Export your corporate root CA to PEM/CRT and set CORPORATE_CA_BUNDLE, "
            f"or place it at {DEFAULT_CA_BUNDLE}. See SETUP.md."
        )

    # Convention path: use only when the operator has already dropped the file in.
    # Absence is *not* an error — many analysts run this off-network or on
    # machines whose Python already trusts the inspection CA via the OS store.
    if DEFAULT_CA_BUNDLE.is_file():
        return str(DEFAULT_CA_BUNDLE.resolve())

    # No corporate CA configured — rely on certifi / system trust (direct TLS).
    return True


def describe_ssl_verify(verify: Union[bool, str]) -> str:
    """Human-readable TLS mode for startup logs (never logs secret material).

    A path string means the corporate PEM is in use; ``True`` means we are
    on certifi/system trust. ``False`` cannot appear — ``GTIClient`` rejects it.
    """
    if isinstance(verify, str):
        return f"custom CA bundle → {verify}"
    return "default trust store (certifi / system)"


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------
# One flat record per CVE so CSV, Rich terminal cards, and the HTML report
# all share the same fields. Nested GTI JSON is normalized here so analysts
# (and downstream SIEM/ticketing) never have to walk the collections schema.
# String defaults are "N/A" / "False" so empty API fields still render
# consistently in every output format.
# ---------------------------------------------------------------------------


@dataclass
class CVERecord:
    """Flattened, decision-ready CVE enrichment record.

    ``status`` is ``ok`` on a successful fetch; otherwise a structured
    error kind (``not_found``, ``forbidden``, ``rate_limited``, ``error``)
    so the HTML/CSV still contain a row instead of dropping the CVE.
    """

    cve: str
    # ok | not_found | error | rate_limited | forbidden
    status: str = "ok"
    error_message: str = ""

    # Core prioritization (priority_rating is derived; priority_raw is API as-is)
    priority_rating: str = "N/A"  # P0–P4 (derived)
    priority_raw: str = "N/A"  # raw API field (may be bool / missing)
    risk_rating: str = "N/A"
    predicted_risk_rating: str = "N/A"
    risk_factors: str = "N/A"

    # Exploitation posture
    exploitation_state: str = "N/A"
    exploit_availability: str = "N/A"
    exploited_in_the_wild: str = "False"
    exploited_as_zero_day: str = "False"
    exploitation_consequence: str = "N/A"
    exploitation_vectors: str = "N/A"
    first_exploitation: str = "N/A"
    exploit_release_date: str = "N/A"

    # CISA Known Exploited Vulnerabilities catalog
    cisa_kev: str = "False"
    cisa_added_date: str = "N/A"
    cisa_due_date: str = "N/A"
    cisa_ransomware_use: str = "N/A"

    # Exploit Prediction Scoring System
    epss_score: str = "N/A"
    epss_percentile: str = "N/A"

    # CVSS v3.1
    cvss_v3_base: str = "N/A"
    cvss_v3_temporal: str = "N/A"
    cvss_v3_vector: str = "N/A"

    # CVSS v4.0
    cvss_v4_score: str = "N/A"
    cvss_v4_vector: str = "N/A"
    cvss_v4_exploit_maturity: str = "N/A"

    # CVSS v2 (supporting / legacy)
    cvss_v2_base: str = "N/A"
    cvss_v2_temporal: str = "N/A"
    cvss_v2_vector: str = "N/A"

    # Affected products (flattened from CPE ranges)
    affected_products: str = "N/A"
    affected_products_count: int = 0

    # Supporting context for triage notes and reports
    mve_id: str = "N/A"
    name: str = "N/A"
    description: str = "N/A"
    executive_summary: str = "N/A"
    analysis: str = "N/A"
    cwe_id: str = "N/A"
    cwe_title: str = "N/A"
    tags: str = "N/A"
    available_mitigation: str = "N/A"
    workarounds: str = "N/A"
    date_of_disclosure: str = "N/A"
    creation_date: str = "N/A"
    last_modification_date: str = "N/A"
    origin: str = "N/A"
    vt_url: str = "N/A"
    ioc_count: str = "N/A"

    # Truncated JSON bag for advanced consumers (SIEM, custom parsers)
    extra_json: str = ""


# Stable CSV column order — keep in sync with CVERecord fields used in write_csv.
# extra_json is intentionally omitted (it is a debug bag, not a spreadsheet column).
CSV_COLUMNS: list[str] = [
    "cve",
    "status",
    "error_message",
    "priority_rating",
    "priority_raw",
    "risk_rating",
    "predicted_risk_rating",
    "risk_factors",
    "exploitation_state",
    "exploit_availability",
    "exploited_in_the_wild",
    "exploited_as_zero_day",
    "exploitation_consequence",
    "exploitation_vectors",
    "first_exploitation",
    "exploit_release_date",
    "cisa_kev",
    "cisa_added_date",
    "cisa_due_date",
    "cisa_ransomware_use",
    "epss_score",
    "epss_percentile",
    "cvss_v3_base",
    "cvss_v3_temporal",
    "cvss_v3_vector",
    "cvss_v4_score",
    "cvss_v4_vector",
    "cvss_v4_exploit_maturity",
    "cvss_v2_base",
    "cvss_v2_temporal",
    "cvss_v2_vector",
    "affected_products_count",
    "affected_products",
    "mve_id",
    "name",
    "description",
    "executive_summary",
    "analysis",
    "cwe_id",
    "cwe_title",
    "tags",
    "available_mitigation",
    "workarounds",
    "date_of_disclosure",
    "creation_date",
    "last_modification_date",
    "origin",
    "ioc_count",
    "vt_url",
]


# ---------------------------------------------------------------------------
# Helpers — logging, display coercion, CVE ID normalization
# ---------------------------------------------------------------------------
# Small pure functions used by extraction, CSV, Rich, and HTML. Keeping
# display coercion in one place prevents "None" vs "N/A" vs "" drift
# across the three output formats.
# ---------------------------------------------------------------------------


def setup_logging(verbose: bool = False) -> None:
    """Configure Rich-backed logging on stderr (keeps stdout free for piping).

    Must run before any resolver logs (``.env`` loaded, proxy used, TLS mode)
    so operators can see those lines. ``-v`` flips DEBUG including dump-raw.
    """
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(console=log_console, rich_tracebacks=True, show_path=False)],
    )


def na(value: Any, default: str = "N/A") -> str:
    """Coerce API values to display-safe strings; treat None/empty as N/A.

    Bools become ``True``/``False`` (not ``1``/``0``) so CSV consumers and
    HTML badges share the same vocabulary. Lists are joined with ``; ``
    to stay on one CSV cell.
    """
    if value is None:
        return default
    if isinstance(value, bool):
        return "True" if value else "False"
    if isinstance(value, (list, tuple)):
        if not value:
            return default
        return "; ".join(str(v) for v in value if v is not None and str(v).strip() != "")
    if isinstance(value, float):
        # Enough precision for EPSS/CVSS without scientific notation noise
        return f"{value:.6f}".rstrip("0").rstrip(".") if value != 0 else "0"
    text = str(value).strip()
    return text if text else default


def fmt_ts(value: Any) -> str:
    """Format UTC unix timestamp (int/float) or ISO-ish string to ISO-8601 date.

    GTI mixes seconds, milliseconds, and already-formatted date strings
    (CISA KEV ``added_date``). The 10-billion heuristic treats large ints
    as milliseconds. Failures fall back to ``na()`` rather than crashing.
    """
    if value is None or value == "" or value is False:
        return "N/A"
    if isinstance(value, str):
        # Already a date string (e.g. first_seen_details value)
        return value if value.strip() else "N/A"
    try:
        ts = int(value)
        # Heuristic: values larger than ~year 2286 are likely milliseconds
        if ts > 10_000_000_000:
            ts //= 1000
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d")
    except (TypeError, ValueError, OSError, OverflowError):
        return na(value)


def normalize_cve(raw: str) -> Optional[str]:
    """Normalize a CVE ID to canonical uppercase form; return None if invalid.

    Accepts ``CVE-2021-44228``, ``cve-2021-44228``, ``CVE_2021_44228``, and
    a bare ``2021-44228``. The API id builder lowercases again; we store
    uppercase so CSV/HTML match how analysts write CVE IDs.
    """
    if not raw:
        return None
    cleaned = raw.strip().upper().replace(" ", "")
    # Tolerate underscore separators from some export tools
    cleaned = cleaned.replace("_", "-")
    if not cleaned.startswith("CVE-"):
        # Accept bare "2024-3400" and promote to CVE-YYYY-NNNN
        if re.match(r"^\d{4}-\d{4,}$", cleaned):
            cleaned = f"CVE-{cleaned}"
    if not CVE_PATTERN.match(cleaned):
        return None
    return cleaned


def cve_api_id(cve: str) -> str:
    """
    Build the GTI collections object id.

    API path requires lowercase: ``vulnerability--cve-yyyy-nnnnn``.
    The GUI URL uses the same object id, so HTML/CSV deep-links stay in sync
    with the GET we just performed.
    """
    return f"vulnerability--{cve.lower()}"


def _accept_cve(raw: str, cves: list[str], seen: set[str]) -> None:
    """Normalize, de-duplicate, and append a CVE ID, or log a skip.

    Shared by both headered and headerless CSV branches so first-seen
    order and the invalid-ID warning stay identical.
    """
    cve = normalize_cve(raw)
    if cve and cve not in seen:
        seen.add(cve)
        cves.append(cve)
    elif not cve:
        logging.warning("Skipping invalid CVE value: %r", raw)


def _norm_label(value: str) -> str:
    """Lowercase + collapse whitespace for fuzzy matching of GTI enum labels."""
    return re.sub(r"\s+", " ", (value or "").strip().lower())


def _is_no_known(value: str) -> bool:
    """True when exploit-availability wording means 'none / unknown'."""
    return _norm_label(value) in NO_KNOWN_ALIASES


# ---------------------------------------------------------------------------
# Priority derivation (GTI P0–P4 model)
# ---------------------------------------------------------------------------
#
# Source: https://gtidocs.virustotal.com/docs/vulnerability-report
#
# Inputs: Risk Rating, Exploitation State, Exploit Availability
#
# P0:
#   - Risk Critical (any)
#   - Risk High  + Exploitation State in {Wide, Confirmed, Reported}
#   - Risk Medium + Exploitation State == Wide
# P1:
#   - Risk High  + Exploitation State in {Suspected, No Known}
#                 + Exploit Availability != No Known
#   - Risk Medium + Exploitation State in {Confirmed, Reported, Suspected}
#   - Risk Low   + Exploitation State in {Wide, Confirmed}
# P2:
#   - Risk High  + Exploitation State == No Known + Exploit Availability == No Known
#   - Risk Medium + Exploitation State == No Known
#                 + Exploit Availability in {Trivial, Publicly Available,
#                                            Privately Held, Unverified}
#   - Risk Low   + Exploitation State in {Reported, Suspected}
# P3:
#   - Risk Medium + Exploitation State == No Known
#                 + Exploit Availability in {Interest Observed, No Known}
#   - Risk Low   + Exploitation State == No Known
#                 + Exploit Availability in {Trivial, Publicly Available,
#                                            Privately Held, Unverified}
# P4:
#   - Risk Low   + Exploitation State == No Known
#                 + Exploit Availability in {Interest Observed, No Known}
#
# Fallback: if fields are Unrated/N/A, attempt best-effort mapping; else "N/A".


def derive_priority_rating(
    risk_rating: str,
    exploitation_state: str,
    exploit_availability: str,
) -> str:
    """
    Derive GTI-style P0–P4 priority from risk + exploitation signals.

    The collections API exposes ``priority`` as a boolean; the P0–P4 badge in
    the GTI UI is a product of this combination table (documented above).
    """
    risk = _norm_label(risk_rating)
    state = _norm_label(exploitation_state)
    avail = _norm_label(exploit_availability)

    # Collapse missing / synonym labels so the decision table stays small
    if risk in {"n/a", "none", "unrated", ""}:
        risk = "unrated"
    if state in {"n/a", "none", ""}:
        state = "no known"
    if avail in {"n/a", "none", "unknown", ""}:
        avail = "no known"

    # Older filter wording "Known" ≈ publicly available exploit code
    if avail == "known":
        avail = "publicly available"

    # Pre-built sets for membership tests in the P0–P4 rules
    wide_confirmed_reported = {"wide", "confirmed", "reported"}
    suspected_no_known = {"suspected", "no known"}
    confirmed_reported_suspected = {"confirmed", "reported", "suspected"}
    wide_confirmed = {"wide", "confirmed"}
    reported_suspected = {"reported", "suspected"}
    exploit_code_present = {
        "trivial",
        "publicly available",
        "privately held",
        "unverified",
    }
    low_interest = {"interest observed", "no known"}

    # --- P0 (highest urgency) ---
    if risk == "critical":
        return "P0"
    if risk == "high" and state in wide_confirmed_reported:
        return "P0"
    if risk == "medium" and state == "wide":
        return "P0"

    # --- P1 ---
    if risk == "high" and state in suspected_no_known and not _is_no_known(avail):
        return "P1"
    if risk == "medium" and state in confirmed_reported_suspected:
        return "P1"
    if risk == "low" and state in wide_confirmed:
        return "P1"

    # --- P2 ---
    if risk == "high" and state == "no known" and _is_no_known(avail):
        return "P2"
    if risk == "medium" and state == "no known" and avail in exploit_code_present:
        return "P2"
    if risk == "low" and state in reported_suspected:
        return "P2"

    # --- P3 ---
    if risk == "medium" and state == "no known" and avail in low_interest:
        return "P3"
    if risk == "low" and state == "no known" and avail in exploit_code_present:
        return "P3"

    # --- P4 ---
    if risk == "low" and state == "no known" and avail in low_interest:
        return "P4"

    # Fallback heuristics when official table does not match (e.g. Unrated).
    # Critical already returned P0 above; it is not repeated here.
    if risk == "high":
        return "P1" if not _is_no_known(avail) or state in wide_confirmed_reported else "P2"
    if risk == "medium":
        return "P2"
    if risk == "low":
        return "P3"

    return "N/A"


# ---------------------------------------------------------------------------
# Input CSV
# ---------------------------------------------------------------------------
# Tolerates analyst-exported spreadsheets: Excel BOM, ``;`` / tab delimiters,
# optional headers, and a handful of common column names. Invalid IDs are
# skipped (with a warning) rather than aborting the whole run — a 200-row
# export with one bad cell should still enrich the rest.
# ---------------------------------------------------------------------------


def load_cve_list(path: Path) -> list[str]:
    """
    Load CVE IDs from CSV.

    Accepts:
      - Single-column file (header optional): CVE / cve_id / cveid / id
      - Multi-column file with a column named CVE, cve, cve_id, cveid, or id
      - Headerless single column of CVE values

    Returns a de-duplicated list in file order (first occurrence wins).
    """
    if not path.exists():
        raise FileNotFoundError(f"Input file not found: {path}")

    cves: list[str] = []
    seen: set[str] = set()

    # utf-8-sig strips a BOM that Excel often writes on Windows exports
    with path.open(newline="", encoding="utf-8-sig") as fh:
        sample = fh.read(4096)
        fh.seek(0)
        try:
            dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
        except csv.Error:
            dialect = csv.excel

        # Header vs data: first cell looks like a label, not a CVE ID
        fh.seek(0)
        first_line = fh.readline()
        fh.seek(0)
        has_header = bool(
            re.search(r"cve|id|identifier", first_line, re.IGNORECASE)
            and not CVE_PATTERN.search(first_line.split(",")[0].strip().strip('"'))
        )

        if has_header:
            reader = csv.DictReader(fh, dialect=dialect)
            # Map lowercased header names back to original field names so we
            # can accept "CVE", "cve_id", etc. without being case-sensitive.
            field_map = { (f or "").strip().lower(): f for f in (reader.fieldnames or []) }
            col = None
            for candidate in ("cve", "cve_id", "cveid", "cve-id", "id", "identifier", "vulnerability"):
                if candidate in field_map:
                    col = field_map[candidate]
                    break
            if col is None:
                # Unknown schema — use the leftmost column rather than failing
                if reader.fieldnames:
                    col = reader.fieldnames[0]
                else:
                    raise ValueError(f"No columns found in {path}")
            for row in reader:
                raw = (row.get(col) or "").strip()
                if not raw:
                    continue
                _accept_cve(raw, cves, seen)
        else:
            # Headerless: treat column 0 as the CVE list
            reader = csv.reader(fh, dialect=dialect)
            for row in reader:
                if not row:
                    continue
                raw = (row[0] or "").strip()
                if not raw or raw.lower() in {"cve", "cve_id", "id"}:
                    continue
                _accept_cve(raw, cves, seen)

    return cves


# ---------------------------------------------------------------------------
# API client
# ---------------------------------------------------------------------------
# Session-level proxy + CA bundle + API key; per-request throttle and retries.
#
# Construction contract (do not weaken):
#   - ``verify`` is a PEM path or True — never False
#   - proxies come from ``build_proxies()`` (``.env`` / CLI), applied on the
#     Session so every GET uses the corporate path
#   - the API key is sent as ``x-apikey`` (VirusTotal v3 convention)
#
# ``main()`` instantiates this *after* ``resolve_api_key`` / ``resolve_ssl_verify``
# / ``build_proxies``. The constructor re-checks key + TLS as defense in depth
# in case a future caller bypasses ``main()``.
# ---------------------------------------------------------------------------


class GTIClient:
    """Thin VirusTotal / GTI collections client with proxy + backoff support."""

    def __init__(
        self,
        api_key: str,
        *,
        base_url: str = DEFAULT_API_BASE,
        proxies: Optional[dict[str, str]] = None,
        verify: Union[bool, str] = True,
        timeout: float = 60.0,
        max_retries: int = DEFAULT_MAX_RETRIES,
        backoff_base: float = DEFAULT_BACKOFF_BASE,
        delay: float = DEFAULT_DELAY,
    ) -> None:
        """Bind API key, proxies, and TLS verify onto a shared ``requests.Session``."""
        # Defense in depth: placeholders should already be filtered by resolve_api_key.
        # Kept as an exact-match subset (not the lowercased frozenset) so this
        # constructor's rejection set stays identical to the previously validated
        # behavior if GTIClient is constructed outside main().
        if not api_key or api_key in {
            "INSERT_KEY_HERE",
            "your-api-key",
            "your_key_here",
            "changeme",
        }:
            raise ValueError(
                "API key missing or still a placeholder. "
                "Set VIRUSTOTAL_API_KEY in .env (or VT_API_KEY) or pass --api-key."
            )
        # Hard guard: never allow insecure TLS. Corporate MITM must be handled
        # with a CA bundle (resolve_ssl_verify), not by turning verification off.
        if verify is False:
            raise ValueError(
                "TLS verification cannot be disabled. Place the corporate root CA at "
                f"{DEFAULT_CA_BUNDLE} or set CORPORATE_CA_BUNDLE in .env. See SETUP.md."
            )
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.max_retries = max_retries
        self.backoff_base = backoff_base
        self.delay = delay
        self._last_request_at = 0.0

        # One Session reuses TCP/TLS connections (important behind a proxy) and
        # carries proxy + verify + headers for every GET in this run.
        self.session = requests.Session()
        self.session.headers.update(
            {
                "x-apikey": api_key,
                "accept": "application/json",
                "User-Agent": "gti-cve-enricher/1.0",
            }
        )
        # Explicit proxies from .env/CLI so behavior is deterministic even if the
        # process environment is incomplete (common on locked-down desktops).
        if proxies:
            self.session.proxies.update(proxies)
        # True = certifi/system trust; str path = corporate root CA for MITM inspection
        self.session.verify = verify
        logging.info("TLS verification: %s", describe_ssl_verify(verify))

    def _throttle(self) -> None:
        """Sleep just enough to honor the configured inter-request delay.

        Uses monotonic time so clock adjustments cannot skip the pause.
        ``delay <= 0`` disables throttling (tests / explicit operator choice).
        """
        if self.delay <= 0:
            return
        elapsed = time.monotonic() - self._last_request_at
        if elapsed < self.delay:
            time.sleep(self.delay - elapsed)

    def get_vulnerability(self, cve: str) -> tuple[Optional[dict[str, Any]], Optional[str], int]:
        """
        Fetch vulnerability collection for a CVE.

        Returns:
            (json_body | None, error_kind | None, http_status)
            error_kind in {None, 'not_found', 'forbidden', 'rate_limited', 'error'}

        401/403 are *not* retried: they almost always mean the key lacks
        Vulnerability Intelligence, and retrying would only burn quota.
        429 / 5xx / network (proxy, SSL, DNS) errors *are* retried with
        exponential backoff + jitter so concurrent analyst runs do not
        thundering-herd the API.
        """
        object_id = cve_api_id(cve)
        url = f"{self.base_url}/collections/{object_id}"

        for attempt in range(1, self.max_retries + 1):
            self._throttle()
            try:
                logging.debug("GET %s (attempt %d/%d)", url, attempt, self.max_retries)
                resp = self.session.get(url, timeout=self.timeout)
                self._last_request_at = time.monotonic()
            except requests.RequestException as exc:
                # Network/proxy/SSL failures — backoff then retry
                wait = self.backoff_base**attempt + random.uniform(0, 1)
                logging.warning(
                    "Network error for %s (attempt %d): %s — retrying in %.1fs",
                    cve,
                    attempt,
                    exc,
                    wait,
                )
                if attempt >= self.max_retries:
                    return None, "error", 0
                time.sleep(wait)
                continue

            if resp.status_code == 200:
                try:
                    return resp.json(), None, 200
                except ValueError:
                    return None, "error", 200

            if resp.status_code == 404:
                # CVE not in GTI collections (too new, unpublished, or out of coverage)
                body_preview = _safe_error_body(resp)
                logging.info("404 Not Found for %s — %s", cve, body_preview)
                return None, "not_found", 404

            if resp.status_code in (401, 403):
                # Almost always license/privilege rather than a bad CVE ID
                body_preview = _safe_error_body(resp)
                msg = (
                    f"HTTP {resp.status_code}: access denied for {cve}. "
                    "Vulnerability Intelligence requires a Google Threat Intelligence "
                    "(GTI) Enterprise or Enterprise Plus license. "
                    f"API detail: {body_preview}"
                )
                logging.error(msg)
                return None, "forbidden", resp.status_code

            if resp.status_code == 429:
                # Honor Retry-After when the API provides it; else exponential backoff
                retry_after = resp.headers.get("Retry-After")
                if retry_after and retry_after.isdigit():
                    wait = float(retry_after) + random.uniform(0, 1)
                else:
                    wait = self.backoff_base**attempt + random.uniform(0, 2)
                logging.warning(
                    "Rate limited (429) on %s — attempt %d/%d, sleeping %.1fs",
                    cve,
                    attempt,
                    self.max_retries,
                    wait,
                )
                if attempt >= self.max_retries:
                    return None, "rate_limited", 429
                time.sleep(wait)
                continue

            # Transient server faults: retry; other 4xx: surface as error
            body_preview = _safe_error_body(resp)
            if resp.status_code >= 500 and attempt < self.max_retries:
                wait = self.backoff_base**attempt + random.uniform(0, 1)
                logging.warning(
                    "Server error %s for %s — retrying in %.1fs (%s)",
                    resp.status_code,
                    cve,
                    wait,
                    body_preview,
                )
                time.sleep(wait)
                continue

            logging.error(
                "Error fetching %s: HTTP %s — %s",
                cve,
                resp.status_code,
                body_preview,
            )
            return None, "error", resp.status_code

        return None, "error", 0


def _safe_error_body(resp: requests.Response, limit: int = 300) -> str:
    """Extract a short, log-safe preview of an API error body.

    Truncated so 401 HTML error pages (from a proxy captive portal) do not
    flood the log. Never includes the API key (it is a request header, not
    a response body).
    """
    try:
        data = resp.json()
        if isinstance(data, dict):
            err = data.get("error") or data
            return json.dumps(err)[:limit]
        return str(data)[:limit]
    except Exception:
        return (resp.text or "")[:limit]


# ---------------------------------------------------------------------------
# Field extraction
# ---------------------------------------------------------------------------
# Maps the GTI vulnerability object schema into a flat CVERecord.
# Uses tolerant key lookup (``_first``) because field names have varied
# across API revisions — e.g. ``cvssv3_x`` vs ``cvssv3``. Never assume a
# nested key exists; a missing field becomes "N/A" rather than crashing
# the whole report.
# ---------------------------------------------------------------------------


def _first(*values: Any, default: Any = None) -> Any:
    """Return the first non-empty value (handles alternate API field names).

    Empty strings, empty lists/dicts, and None are skipped. Used throughout
    ``extract_record`` because GTI has renamed CVSS/exploitation keys across
    API revisions; we try documented names then legacy aliases.
    """
    for v in values:
        if v is None:
            continue
        if isinstance(v, str) and not v.strip():
            continue
        if isinstance(v, (list, dict)) and not v:
            continue
        return v
    return default


def _format_cpes(cpes: Any) -> tuple[str, int]:
    """Flatten CPE ranges into readable 'vendor / product version-range' strings.

    GTI stores affected products as start/end CPE objects with inclusive/
    exclusive relation flags. HTML later splits the joined string on ``|``.
    """
    if not isinstance(cpes, list) or not cpes:
        return "N/A", 0

    lines: list[str] = []
    for entry in cpes:
        if not isinstance(entry, dict):
            continue
        start = entry.get("start_cpe") or {}
        end = entry.get("end_cpe") or {}
        start_rel = entry.get("start_rel") or ""
        end_rel = entry.get("end_rel") or ""

        vendor = _first(start.get("vendor"), end.get("vendor"), default="")
        product = _first(start.get("product"), end.get("product"), default="")
        if not vendor and not product:
            # Fall back to full CPE URI when vendor/product parts are absent
            uri = _first(start.get("uri"), end.get("uri"), default="")
            if uri:
                lines.append(str(uri))
            continue

        start_ver = start.get("version") or ""
        end_ver = end.get("version") or ""
        range_bits: list[str] = []
        if start_ver:
            op = start_rel or ">="
            range_bits.append(f"{op} {start_ver}".strip())
        if end_ver:
            op = end_rel or "<="
            range_bits.append(f"{op} {end_ver}".strip())
        version_part = " and ".join(range_bits) if range_bits else "any"
        lines.append(f"{vendor} / {product} ({version_part})")

    # Deduplicate while preserving first-seen order
    unique: list[str] = []
    seen: set[str] = set()
    for line in lines:
        if line not in seen:
            seen.add(line)
            unique.append(line)

    if not unique:
        return "N/A", 0
    return " | ".join(unique), len(unique)


def extract_record(cve: str, payload: dict[str, Any]) -> CVERecord:
    """Map a GTI vulnerability collection response into a CVERecord.

    Called only on HTTP 200 with a JSON body. Malformed payloads still
    return a structured ``status="error"`` record so the HTML/CSV row
    exists and the always-open report is not empty for that CVE.
    """
    data = payload.get("data") if isinstance(payload, dict) else None
    if not isinstance(data, dict):
        return CVERecord(cve=cve, status="error", error_message="Malformed API response (no data)")

    attrs = data.get("attributes") or {}
    if not isinstance(attrs, dict):
        attrs = {}

    # --- CVSS (v2 / v3.x / v4.x; tolerate legacy key aliases) ---
    cvss = attrs.get("cvss") or {}
    # Documented keys: cvssv2_0, cvssv3_x, cvssv3_x_translated, cvssv4_x
    v3 = _first(
        cvss.get("cvssv3_x"),
        cvss.get("cvssv3_x_translated"),
        cvss.get("cvssv3"),
        cvss.get("v3"),
        default={},
    ) or {}
    v4 = _first(cvss.get("cvssv4_x"), cvss.get("cvssv4"), cvss.get("v4"), default={}) or {}
    v2 = _first(cvss.get("cvssv2_0"), cvss.get("cvssv2"), cvss.get("v2"), default={}) or {}

    v3_base = _first(v3.get("base_score"), v3.get("score"))
    v3_temporal = _first(v3.get("temporal_score"))
    v3_vector = _first(v3.get("vector"), v3.get("vector_string"))

    v4_score = _first(v4.get("score"), v4.get("base_score"))
    v4_vector = _first(v4.get("vector"), v4.get("vector_string"))
    v4_threat = v4.get("threat") if isinstance(v4.get("threat"), dict) else {}
    v4_maturity = _first(v4_threat.get("exploit_maturity"))

    v2_base = _first(v2.get("base_score"), v2.get("score"))
    v2_temporal = _first(v2.get("temporal_score"))
    v2_vector = _first(v2.get("vector"), v2.get("vector_string"))

    # --- EPSS ---
    epss = attrs.get("epss") if isinstance(attrs.get("epss"), dict) else {}
    epss_score = _first(epss.get("score"))
    epss_pct = _first(epss.get("percentile"))

    # --- Exploitation (fields may sit at top level or under attributes.exploitation) ---
    exploitation = attrs.get("exploitation") if isinstance(attrs.get("exploitation"), dict) else {}
    exploitation_state = _first(
        attrs.get("exploitation_state"),
        exploitation.get("exploitation_state"),
        default="N/A",
    )
    exploit_availability = _first(
        attrs.get("exploit_availability"),
        exploitation.get("exploit_availability"),
        default="N/A",
    )
    exploited_in_wild = _first(
        attrs.get("exploited_in_the_wild"),
        attrs.get("observed_in_the_wild"),
        exploitation.get("exploited_in_the_wild"),
        default=False,
    )
    exploited_zero_day = _first(
        attrs.get("exploited_as_zero_day"),
        attrs.get("zero_day"),
        exploitation.get("exploited_as_zero_day"),
        default=False,
    )

    # We do **not** infer exploited_in_the_wild from Exploitation State.
    # Wide/Confirmed often implies real-world use, but an explicit API
    # False/absent must be preserved so the report does not contradict GTI.

    # --- CISA KEV (presence of the object means "on the KEV list") ---
    kev = attrs.get("cisa_known_exploited")
    if isinstance(kev, dict) and kev:
        cisa_kev = True
        cisa_added = fmt_ts(kev.get("added_date"))
        cisa_due = fmt_ts(kev.get("due_date"))
        cisa_ransom = na(kev.get("ransomware_use"))
    else:
        cisa_kev = False
        cisa_added = "N/A"
        cisa_due = "N/A"
        cisa_ransom = "N/A"

    # --- Risk / priority ---
    # API documents priority as boolean; the GTI UI shows P0–P4 — we derive that.
    risk_rating = na(attrs.get("risk_rating"))
    predicted = na(attrs.get("predicted_risk_rating"))
    risk_factors = na(attrs.get("risk_factors"))
    priority_raw = attrs.get("priority")
    if isinstance(priority_raw, bool):
        priority_raw_str = "True" if priority_raw else "False"
    else:
        priority_raw_str = na(priority_raw)

    priority_rating = derive_priority_rating(
        risk_rating,
        str(exploitation_state),
        str(exploit_availability),
    )
    # Prefer an explicit P0–P4 string if the API ever supplies one
    if isinstance(priority_raw, str) and re.match(r"^P[0-4]$", priority_raw.strip(), re.I):
        priority_rating = priority_raw.strip().upper()

    # --- Products (CPE ranges) ---
    products_str, products_count = _format_cpes(attrs.get("cpes"))

    # --- CWE ---
    cwe = attrs.get("cwe") if isinstance(attrs.get("cwe"), dict) else {}

    # --- Counters (IoCs, etc.) ---
    counters = attrs.get("counters") if isinstance(attrs.get("counters"), dict) else {}

    # --- Narrative fields ---
    description = na(attrs.get("description"))
    executive = na(attrs.get("executive_summary"))
    analysis = na(attrs.get("analysis"))

    rec = CVERecord(
        cve=cve,
        status="ok",
        priority_rating=priority_rating,
        priority_raw=priority_raw_str,
        risk_rating=risk_rating,
        predicted_risk_rating=predicted,
        risk_factors=risk_factors,
        exploitation_state=na(exploitation_state),
        exploit_availability=na(exploit_availability),
        exploited_in_the_wild=na(exploited_in_wild, default="False"),
        exploited_as_zero_day=na(exploited_zero_day, default="False"),
        exploitation_consequence=na(attrs.get("exploitation_consequence")),
        exploitation_vectors=na(attrs.get("exploitation_vectors")),
        first_exploitation=fmt_ts(exploitation.get("first_exploitation")),
        exploit_release_date=fmt_ts(exploitation.get("exploit_release_date")),
        cisa_kev=na(cisa_kev, default="False"),
        cisa_added_date=cisa_added,
        cisa_due_date=cisa_due,
        cisa_ransomware_use=cisa_ransom,
        epss_score=na(epss_score),
        epss_percentile=na(epss_pct),
        cvss_v3_base=na(v3_base),
        cvss_v3_temporal=na(v3_temporal),
        cvss_v3_vector=na(v3_vector),
        cvss_v4_score=na(v4_score),
        cvss_v4_vector=na(v4_vector),
        cvss_v4_exploit_maturity=na(v4_maturity),
        cvss_v2_base=na(v2_base),
        cvss_v2_temporal=na(v2_temporal),
        cvss_v2_vector=na(v2_vector),
        affected_products=products_str,
        affected_products_count=products_count,
        mve_id=na(attrs.get("mve_id")),
        name=na(attrs.get("name"), default=cve),
        description=description,
        executive_summary=executive,
        analysis=analysis,
        cwe_id=na(cwe.get("id")),
        cwe_title=na(cwe.get("title")),
        tags=na(attrs.get("tags")),
        available_mitigation=na(attrs.get("available_mitigation")),
        workarounds=na(attrs.get("workarounds")),
        date_of_disclosure=fmt_ts(attrs.get("date_of_disclosure")),
        creation_date=fmt_ts(attrs.get("creation_date")),
        last_modification_date=fmt_ts(attrs.get("last_modification_date")),
        origin=na(attrs.get("origin")),
        ioc_count=na(counters.get("iocs")),
        vt_url=f"https://www.virustotal.com/gui/collection/{cve_api_id(cve)}",
    )

    # Compact raw fragments for advanced consumers (capped to keep CSV rows sane)
    extra = {
        "collection_id": data.get("id"),
        "collection_type": attrs.get("collection_type"),
        "risk_factors_list": attrs.get("risk_factors"),
        "available_mitigation_list": attrs.get("available_mitigation"),
        "workarounds_list": attrs.get("workarounds"),
        "cvss_raw": cvss,
        "epss_raw": epss,
        "cisa_known_exploited_raw": kev if isinstance(kev, dict) else None,
        "exploitation_raw": exploitation,
    }
    try:
        rec.extra_json = json.dumps(extra, default=str)[:4000]
    except (TypeError, ValueError):
        rec.extra_json = ""

    return rec


def error_record(cve: str, status: str, message: str) -> CVERecord:
    """Build a non-success CVERecord that still carries a deep-link to VirusTotal.

    Used for 404 / 401 / 429 / network errors and for CVEs skipped after an
    early-stop on forbidden. Keeping a row (instead of omitting the CVE)
    is what lets the HTML report remain a complete record of the input list.
    """
    return CVERecord(
        cve=cve,
        status=status,
        error_message=message,
        vt_url=f"https://www.virustotal.com/gui/collection/{cve_api_id(cve)}",
    )


# ---------------------------------------------------------------------------
# Output: CSV
# ---------------------------------------------------------------------------
# Flat columns for Excel / SIEM / ticketing export. Newlines inside
# narrative fields are collapsed so a description cannot split a row.
# Written only on a successful walk of the input list (including all-error
# rows). Config failures skip CSV and still produce HTML.
# ---------------------------------------------------------------------------


def write_csv(records: Iterable[CVERecord], path: Path) -> None:
    """Write enriched records using the stable CSV_COLUMNS order."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_COLUMNS, extrasaction="ignore")
        writer.writeheader()
        for rec in records:
            row = asdict(rec)
            # Collapse newlines so multi-line descriptions do not break CSV rows
            for key in ("description", "executive_summary", "analysis", "affected_products", "workarounds"):
                if key in row and isinstance(row[key], str):
                    row[key] = row[key].replace("\r", " ").replace("\n", " ").strip()
            writer.writerow({k: row.get(k, "") for k in CSV_COLUMNS})
    logging.info("Wrote CSV: %s", path)


# ---------------------------------------------------------------------------
# Output: Rich terminal cards
# ---------------------------------------------------------------------------
# Color-coded panels for interactive console review (optional via --no-rich).
# Priority colors mirror the HTML badges so an analyst who glances at the
# terminal sees the same P0–P4 language as in the browser report.
# ---------------------------------------------------------------------------


def _risk_style(risk: str) -> str:
    """Rich style for a risk rating or P0–P4 badge (aligned with HTML colors)."""
    r = _norm_label(risk)
    if r == "critical" or risk.upper() == "P0":
        return "bold white on dark_red"
    if r == "high" or risk.upper() == "P1":
        return "bold white on dark_orange3"
    if r == "medium" or risk.upper() == "P2":
        return "bold black on gold3"
    if r in {"low", "p3", "p4"} or risk.upper() in {"P3", "P4"}:
        return "bold white on dark_green"
    return "bold white on grey37"


def _priority_color(priority: str) -> str:
    """Border/label color for a P0–P4 badge; grey if unknown."""
    p = priority.upper()
    return {
        "P0": "dark_red",
        "P1": "dark_orange3",
        "P2": "gold3",
        "P3": "dark_green",
        "P4": "cyan",
    }.get(p, "grey50")


def _bool_badge(value: str, true_style: str = "bold red", false_style: str = "dim") -> Text:
    """Render True/False-ish API strings as a compact YES/no Rich span."""
    v = str(value).strip().lower()
    if v in {"true", "yes", "1"}:
        return Text("YES", style=true_style)
    if v in {"false", "no", "0"}:
        return Text("no", style=false_style)
    return Text(str(value), style="dim")


def render_rich_card(rec: CVERecord) -> Panel:
    """
    Build a color-coded Rich panel for one CVE.

    Error statuses get a simple red panel; successes show scores, exploitation,
    KEV, and a truncated summary suitable for terminal width.
    """
    if rec.status != "ok":
        title = Text.assemble(
            (rec.cve, "bold"),
            ("  "),
            (rec.status.upper(), "bold red"),
        )
        body = Text(rec.error_message or "No data", style="red")
        return Panel(body, title=title, border_style="red", box=box.ROUNDED)

    pri = rec.priority_rating or "N/A"
    risk = rec.risk_rating or "N/A"
    border = _priority_color(pri)

    # Priority / risk header strip
    header = Table.grid(padding=(0, 2))
    header.add_column(style="bold")
    header.add_column()
    header.add_row("Priority", Text(pri, style=f"bold {_priority_color(pri)}"))
    header.add_row("Risk Rating", Text(risk, style=_risk_style(risk)))
    header.add_row("Predicted Risk", rec.predicted_risk_rating)
    header.add_row("API priority field", rec.priority_raw)

    scores = Table(box=box.SIMPLE_HEAVY, show_header=True, header_style="bold cyan", expand=True)
    scores.add_column("Metric")
    scores.add_column("Value", justify="right")
    scores.add_column("Detail")
    scores.add_row("EPSS", rec.epss_score, f"percentile {rec.epss_percentile}")
    scores.add_row("CVSSv3.1 Base", rec.cvss_v3_base, rec.cvss_v3_vector)
    scores.add_row("CVSSv3.1 Temporal", rec.cvss_v3_temporal, "")
    scores.add_row("CVSSv4.0 BT", rec.cvss_v4_score, rec.cvss_v4_vector)
    scores.add_row("CVSSv4 Exploit Maturity", rec.cvss_v4_exploit_maturity, "")

    exploit = Table(box=box.SIMPLE, show_header=False, expand=True)
    exploit.add_column("K", style="bold")
    exploit.add_column("V")
    exploit.add_row("Exploitation State", Text(rec.exploitation_state, style="bold yellow"))
    exploit.add_row("Exploit Availability", rec.exploit_availability)
    exploit.add_row("Exploited in the Wild", _bool_badge(rec.exploited_in_the_wild))
    exploit.add_row("Exploited as Zero Day", _bool_badge(rec.exploited_as_zero_day))
    exploit.add_row("Consequence", rec.exploitation_consequence)
    exploit.add_row("Vectors", rec.exploitation_vectors)
    exploit.add_row("First Exploitation", rec.first_exploitation)
    exploit.add_row("Exploit Release", rec.exploit_release_date)

    kev = Table(box=box.SIMPLE, show_header=False, expand=True)
    kev.add_column("K", style="bold")
    kev.add_column("V")
    kev.add_row("CISA KEV", _bool_badge(rec.cisa_kev, true_style="bold white on red"))
    kev.add_row("Added", rec.cisa_added_date)
    kev.add_row("Due", rec.cisa_due_date)
    kev.add_row("Ransomware Use", rec.cisa_ransomware_use)

    products_preview = rec.affected_products
    if products_preview != "N/A" and len(products_preview) > 500:
        products_preview = products_preview[:500] + "…"

    meta = Table(box=box.SIMPLE, show_header=False, expand=True)
    meta.add_column("K", style="bold")
    meta.add_column("V")
    meta.add_row("MVE ID", rec.mve_id)
    meta.add_row("CWE", f"{rec.cwe_id} — {rec.cwe_title}" if rec.cwe_id != "N/A" else "N/A")
    meta.add_row("Disclosure", rec.date_of_disclosure)
    meta.add_row("Last Modified", rec.last_modification_date)
    meta.add_row("IoCs", rec.ioc_count)
    meta.add_row("Products", f"{rec.affected_products_count} entries")
    meta.add_row("Risk Factors", rec.risk_factors)
    meta.add_row("URL", rec.vt_url)

    summary_src = rec.executive_summary if rec.executive_summary != "N/A" else rec.description
    if summary_src != "N/A" and len(summary_src) > 600:
        summary_src = summary_src[:600] + "…"

    body = Group(
        header,
        Text(""),
        Text("Scores", style="bold underline"),
        scores,
        Text("Exploitation", style="bold underline"),
        exploit,
        Text("CISA KEV", style="bold underline"),
        kev,
        Text("Context", style="bold underline"),
        meta,
        Text(""),
        Text("Summary", style="bold underline"),
        Text(summary_src, style="italic"),
        Text(""),
        Text("Affected Products", style="bold underline"),
        Text(products_preview, style="dim"),
    )

    title = Text.assemble(
        (rec.cve, "bold white"),
        ("  "),
        (pri, f"bold {_priority_color(pri)}"),
        ("  "),
        (risk, _risk_style(risk)),
    )
    return Panel(body, title=title, border_style=border, box=box.DOUBLE_EDGE, padding=(1, 2))


def print_rich_report(records: list[CVERecord]) -> None:
    """Print a summary strip plus one Rich panel per CVE to the terminal."""
    console.print()
    console.rule("[bold]GTI CVE Enrichment Report[/bold]")
    # Aggregate priority / status counts for a one-line overview
    counts: dict[str, int] = {}
    for r in records:
        key = r.priority_rating if r.status == "ok" else r.status
        counts[key] = counts.get(key, 0) + 1
    summary = "  ".join(f"{k}={v}" for k, v in sorted(counts.items()))
    console.print(f"[dim]Total: {len(records)}  |  {summary}[/dim]\n")

    for rec in records:
        console.print(render_rich_card(rec))
        console.print()


# ---------------------------------------------------------------------------
# Output: HTML report
# ---------------------------------------------------------------------------
# Self-contained (inline CSS, no CDN) so it opens offline and behind
# corporate proxies that block external stylesheets. Dark theme matches
# the analyst-facing sample (e.g. CVE-2021-44228 Log4j).
#
# Invoked for success AND failure — operators always get a visual result.
# SSL/proxy/key errors are easier to screenshot and share as a formatted
# page than as a PowerShell traceback. See ``main()``: this renderer runs
# *outside* the enrichment try/except so config failures still produce a
# browsable page. ``--no-open`` skips the browser but still writes the file.
# ---------------------------------------------------------------------------


def _html_risk_class(risk_or_priority: str) -> str:
    """Map risk/priority labels to CSS badge class names.

    Shared by header chips and per-CVE badges so P0 and Critical always
    render with the same ``badge-critical`` color.
    """
    v = (risk_or_priority or "").strip().upper()
    if v in {"CRITICAL", "P0"}:
        return "critical"
    if v in {"HIGH", "P1"}:
        return "high"
    if v in {"MEDIUM", "P2"}:
        return "medium"
    if v in {"LOW", "P3", "P4"}:
        return "low"
    return "unknown"


def _html_escape(value: str) -> str:
    """Escape text for safe embedding in HTML attributes and body content."""
    return html.escape(value or "", quote=True)


def _html_bool(value: str) -> str:
    """Render a boolean-ish string as a colored YES/no badge."""
    v = str(value).strip().lower()
    if v in {"true", "yes", "1"}:
        return '<span class="badge badge-danger">YES</span>'
    if v in {"false", "no", "0"}:
        return '<span class="badge badge-muted">no</span>'
    return f'<span class="badge badge-muted">{_html_escape(str(value))}</span>'


def render_html_report(
    records: list[CVERecord],
    path: Path,
    title: str = "GTI CVE Enrichment Report",
    *,
    fatal_error: Optional[str] = None,
) -> None:
    """
    Write a self-contained HTML report with card layout and risk badges.

    Always produces a professional report. When ``fatal_error`` is set (or all
    records failed), a prominent run-level error section is included so the
    operator can diagnose SSL, proxy, API key, or network failures in-browser.

    ``fatal_error`` is the formatted exception from ``main()``'s outer
    handler (missing key, missing CA file, unreadable CSV, unexpected
    crash). Per-CVE failures live on their own error cards below the banner.
    """
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    ok = sum(1 for r in records if r.status == "ok")
    failed = len(records) - ok
    pri_counts: dict[str, int] = {}
    for r in records:
        if r.status == "ok":
            pri_counts[r.priority_rating] = pri_counts.get(r.priority_rating, 0) + 1

    # Run-level banner: config/SSL/network exceptions or "everything failed"
    fatal_section = ""
    if fatal_error:
        fatal_section = f"""
    <section class="fatal-banner" role="alert">
      <div class="fatal-title">Run failed</div>
      <p class="fatal-lead">
        Enrichment did not complete successfully. Details below. Partial CVE
        results (if any) still appear further down the page.
      </p>
      <pre class="fatal-detail">{_html_escape(fatal_error)}</pre>
    </section>
"""
    elif records and ok == 0:
        # Aggregate per-CVE errors when nothing succeeded
        sample_msgs = sorted(
            {
                (r.error_message or r.status).strip()
                for r in records
                if r.status != "ok" and (r.error_message or r.status)
            }
        )
        summary_text = "\n".join(f"• {m}" for m in sample_msgs[:12])
        if len(sample_msgs) > 12:
            summary_text += f"\n• …and {len(sample_msgs) - 12} more distinct error(s)"
        fatal_section = f"""
    <section class="fatal-banner" role="alert">
      <div class="fatal-title">No CVEs enriched successfully</div>
      <p class="fatal-lead">
        All {len(records)} CVE(s) failed or were skipped. Common causes: missing
        GTI Enterprise privileges (401/403), corporate proxy/SSL misconfiguration,
        or CVEs not present in GTI.
      </p>
      <pre class="fatal-detail">{_html_escape(summary_text or "See per-CVE cards below.")}</pre>
    </section>
"""
    elif not records and not fatal_error:
        fatal_section = """
    <section class="fatal-banner" role="alert">
      <div class="fatal-title">No results</div>
      <p class="fatal-lead">No CVE records were produced for this run.</p>
    </section>
"""

    # Build one card per CVE (error cards for non-ok statuses)
    cards: list[str] = []
    for rec in records:
        if rec.status != "ok":
            cards.append(
                f"""
<article class="card card-error">
  <header class="card-header">
    <h2>{_html_escape(rec.cve)}</h2>
    <span class="badge badge-unknown">{_html_escape(rec.status.upper())}</span>
  </header>
  <p class="error-msg">{_html_escape(rec.error_message or "No data")}</p>
  <p class="meta"><a href="{_html_escape(rec.vt_url)}" target="_blank" rel="noopener">VirusTotal</a></p>
</article>
"""
            )
            continue

        risk_cls = _html_risk_class(rec.risk_rating)
        pri_cls = _html_risk_class(rec.priority_rating)
        summary = rec.executive_summary if rec.executive_summary != "N/A" else rec.description
        if len(summary) > 900:
            summary = summary[:900] + "…"

        products_html = ""
        if rec.affected_products != "N/A":
            items = [p.strip() for p in rec.affected_products.split("|") if p.strip()]
            # Cap list length so huge CPE sets stay readable in the browser
            shown = items[:40]
            lis = "".join(f"<li>{_html_escape(i)}</li>" for i in shown)
            more = f"<li class='muted'>+{len(items) - 40} more…</li>" if len(items) > 40 else ""
            products_html = f"<ul class='product-list'>{lis}{more}</ul>"
        else:
            products_html = "<p class='muted'>N/A</p>"

        factors = (
            "".join(f"<li>{_html_escape(f.strip())}</li>" for f in rec.risk_factors.split(";") if f.strip())
            if rec.risk_factors != "N/A"
            else "<li class='muted'>N/A</li>"
        )

        cards.append(
            f"""
<article class="card risk-{risk_cls}">
  <header class="card-header">
    <div>
      <h2>{_html_escape(rec.cve)}</h2>
      <p class="subtitle">{_html_escape(rec.name if rec.name != rec.cve else "")}</p>
    </div>
    <div class="badges">
      <span class="badge badge-{pri_cls} badge-lg">{_html_escape(rec.priority_rating)}</span>
      <span class="badge badge-{risk_cls}">{_html_escape(rec.risk_rating)}</span>
    </div>
  </header>

  <section class="grid-3">
    <div class="metric">
      <div class="metric-label">EPSS</div>
      <div class="metric-value">{_html_escape(rec.epss_score)}</div>
      <div class="metric-sub">percentile {_html_escape(rec.epss_percentile)}</div>
    </div>
    <div class="metric">
      <div class="metric-label">CVSSv3.1 Base / Temporal</div>
      <div class="metric-value">{_html_escape(rec.cvss_v3_base)} <span class="muted">/ {_html_escape(rec.cvss_v3_temporal)}</span></div>
      <div class="metric-sub mono">{_html_escape(rec.cvss_v3_vector)}</div>
    </div>
    <div class="metric">
      <div class="metric-label">CVSSv4.0 BT</div>
      <div class="metric-value">{_html_escape(rec.cvss_v4_score)}</div>
      <div class="metric-sub mono">{_html_escape(rec.cvss_v4_vector)}</div>
    </div>
  </section>

  <section class="grid-2">
    <div>
      <h3>Exploitation</h3>
      <table class="kv">
        <tr><th>State</th><td><strong>{_html_escape(rec.exploitation_state)}</strong></td></tr>
        <tr><th>Availability</th><td>{_html_escape(rec.exploit_availability)}</td></tr>
        <tr><th>In the Wild</th><td>{_html_bool(rec.exploited_in_the_wild)}</td></tr>
        <tr><th>Zero Day</th><td>{_html_bool(rec.exploited_as_zero_day)}</td></tr>
        <tr><th>Consequence</th><td>{_html_escape(rec.exploitation_consequence)}</td></tr>
        <tr><th>Vectors</th><td>{_html_escape(rec.exploitation_vectors)}</td></tr>
        <tr><th>First Exploitation</th><td>{_html_escape(rec.first_exploitation)}</td></tr>
        <tr><th>Exploit Release</th><td>{_html_escape(rec.exploit_release_date)}</td></tr>
      </table>
    </div>
    <div>
      <h3>CISA KEV &amp; Context</h3>
      <table class="kv">
        <tr><th>CISA KEV</th><td>{_html_bool(rec.cisa_kev)}</td></tr>
        <tr><th>KEV Added</th><td>{_html_escape(rec.cisa_added_date)}</td></tr>
        <tr><th>KEV Due</th><td>{_html_escape(rec.cisa_due_date)}</td></tr>
        <tr><th>Ransomware</th><td>{_html_escape(rec.cisa_ransomware_use)}</td></tr>
        <tr><th>MVE ID</th><td>{_html_escape(rec.mve_id)}</td></tr>
        <tr><th>CWE</th><td>{_html_escape(rec.cwe_id)} — {_html_escape(rec.cwe_title)}</td></tr>
        <tr><th>Disclosure</th><td>{_html_escape(rec.date_of_disclosure)}</td></tr>
        <tr><th>Last Modified</th><td>{_html_escape(rec.last_modification_date)}</td></tr>
        <tr><th>IoCs</th><td>{_html_escape(rec.ioc_count)}</td></tr>
        <tr><th>API priority</th><td>{_html_escape(rec.priority_raw)}</td></tr>
      </table>
    </div>
  </section>

  <section>
    <h3>Risk Factors</h3>
    <ul class="factor-list">{factors}</ul>
  </section>

  <section>
    <h3>Summary</h3>
    <p class="summary">{_html_escape(summary)}</p>
  </section>

  <section>
    <h3>Affected Products <span class="muted">({rec.affected_products_count})</span></h3>
    {products_html}
  </section>

  <footer class="card-footer">
    <a href="{_html_escape(rec.vt_url)}" target="_blank" rel="noopener">Open in VirusTotal / GTI ↗</a>
    <span class="muted">Mitigations: {_html_escape(rec.available_mitigation)}</span>
  </footer>
</article>
"""
        )

    # Priority distribution chips shown in the page header
    pri_chips = "".join(
        f'<span class="chip badge-{_html_risk_class(k)}">{_html_escape(k)}: {v}</span>'
        for k, v in sorted(pri_counts.items())
    )

    # Full document is assembled as one string so the report has zero external
    # deps (no Google Fonts / CDN CSS — those often fail on corp networks).
    doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>{_html_escape(title)}</title>
<style>
  :root {{
    --bg: #0b1220;
    --surface: #121a2b;
    --surface-2: #1a2438;
    --text: #e8eefc;
    --muted: #8b9bb8;
    --border: #2a3754;
    --critical: #b91c1c;
    --critical-bg: #3f0d0d;
    --high: #c2410c;
    --high-bg: #3b1608;
    --medium: #ca8a04;
    --medium-bg: #3a2e08;
    --low: #15803d;
    --low-bg: #0c2a18;
    --unknown: #64748b;
    --accent: #38bdf8;
    --danger: #ef4444;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0;
    font-family: "Segoe UI", system-ui, -apple-system, sans-serif;
    background: radial-gradient(1200px 600px at 10% -10%, #1e293b 0%, var(--bg) 55%);
    color: var(--text);
    line-height: 1.5;
    min-height: 100vh;
  }}
  .wrap {{ max-width: 1100px; margin: 0 auto; padding: 2rem 1.25rem 4rem; }}
  header.page {{
    margin-bottom: 2rem;
    border-bottom: 1px solid var(--border);
    padding-bottom: 1.25rem;
  }}
  header.page h1 {{
    margin: 0 0 0.35rem;
    font-size: 1.75rem;
    letter-spacing: -0.02em;
  }}
  header.page .meta {{ color: var(--muted); font-size: 0.95rem; }}
  .chips {{ display: flex; flex-wrap: wrap; gap: 0.5rem; margin-top: 0.9rem; }}
  .chip {{
    display: inline-block;
    padding: 0.25rem 0.65rem;
    border-radius: 999px;
    font-size: 0.8rem;
    font-weight: 600;
    border: 1px solid var(--border);
    background: var(--surface-2);
  }}
  .card {{
    background: linear-gradient(180deg, var(--surface) 0%, #0f172a 100%);
    border: 1px solid var(--border);
    border-radius: 16px;
    padding: 1.25rem 1.35rem 1rem;
    margin-bottom: 1.25rem;
    box-shadow: 0 10px 30px rgba(0,0,0,0.25);
    border-left-width: 6px;
  }}
  .card.risk-critical {{ border-left-color: var(--critical); }}
  .card.risk-high {{ border-left-color: var(--high); }}
  .card.risk-medium {{ border-left-color: var(--medium); }}
  .card.risk-low {{ border-left-color: var(--low); }}
  .card.risk-unknown, .card-error {{ border-left-color: var(--unknown); }}
  .card-header {{
    display: flex;
    justify-content: space-between;
    gap: 1rem;
    align-items: flex-start;
    margin-bottom: 1rem;
  }}
  .card-header h2 {{
    margin: 0;
    font-size: 1.35rem;
    letter-spacing: -0.01em;
  }}
  .subtitle {{ margin: 0.2rem 0 0; color: var(--muted); font-size: 0.9rem; }}
  .badges {{ display: flex; flex-wrap: wrap; gap: 0.4rem; justify-content: flex-end; }}
  .badge {{
    display: inline-block;
    padding: 0.2rem 0.55rem;
    border-radius: 8px;
    font-size: 0.75rem;
    font-weight: 700;
    letter-spacing: 0.03em;
    text-transform: uppercase;
  }}
  .badge-lg {{ font-size: 0.9rem; padding: 0.35rem 0.7rem; }}
  .badge-critical {{ background: var(--critical); color: #fff; }}
  .badge-high {{ background: var(--high); color: #fff; }}
  .badge-medium {{ background: var(--medium); color: #1a1a1a; }}
  .badge-low {{ background: var(--low); color: #fff; }}
  .badge-unknown {{ background: var(--unknown); color: #fff; }}
  .badge-danger {{ background: var(--danger); color: #fff; }}
  .badge-muted {{ background: #334155; color: #cbd5e1; }}
  h3 {{
    margin: 1rem 0 0.5rem;
    font-size: 0.95rem;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    color: var(--accent);
  }}
  .grid-3 {{
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 0.75rem;
  }}
  .grid-2 {{
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 1rem;
  }}
  @media (max-width: 800px) {{
    .grid-3, .grid-2 {{ grid-template-columns: 1fr; }}
    .card-header {{ flex-direction: column; }}
    .badges {{ justify-content: flex-start; }}
  }}
  .metric {{
    background: var(--surface-2);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 0.75rem 0.9rem;
  }}
  .metric-label {{ font-size: 0.75rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.05em; }}
  .metric-value {{ font-size: 1.25rem; font-weight: 700; margin-top: 0.15rem; }}
  .metric-sub {{ font-size: 0.78rem; color: var(--muted); margin-top: 0.2rem; word-break: break-all; }}
  .mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }}
  table.kv {{ width: 100%; border-collapse: collapse; font-size: 0.9rem; }}
  table.kv th {{
    text-align: left;
    color: var(--muted);
    font-weight: 600;
    width: 42%;
    padding: 0.3rem 0.4rem 0.3rem 0;
    vertical-align: top;
  }}
  table.kv td {{ padding: 0.3rem 0; vertical-align: top; }}
  .summary {{ color: #dbe7ff; font-size: 0.95rem; }}
  .product-list, .factor-list {{
    margin: 0;
    padding-left: 1.1rem;
    columns: 2;
    gap: 1.5rem;
    font-size: 0.88rem;
  }}
  @media (max-width: 700px) {{
    .product-list, .factor-list {{ columns: 1; }}
  }}
  .product-list li, .factor-list li {{ margin-bottom: 0.25rem; break-inside: avoid; }}
  .muted {{ color: var(--muted); }}
  .card-footer {{
    display: flex;
    justify-content: space-between;
    gap: 1rem;
    flex-wrap: wrap;
    border-top: 1px solid var(--border);
    margin-top: 1rem;
    padding-top: 0.75rem;
    font-size: 0.85rem;
  }}
  a {{ color: var(--accent); text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}
  .error-msg {{ color: #fca5a5; }}
  .fatal-banner {{
    background: linear-gradient(135deg, #3f0d0d 0%, #1c0a0a 60%, #121a2b 100%);
    border: 1px solid #b91c1c;
    border-left: 6px solid #ef4444;
    border-radius: 16px;
    padding: 1.25rem 1.35rem;
    margin-bottom: 1.5rem;
    box-shadow: 0 12px 32px rgba(185, 28, 28, 0.25);
  }}
  .fatal-title {{
    font-size: 1.2rem;
    font-weight: 800;
    color: #fecaca;
    margin-bottom: 0.4rem;
    letter-spacing: -0.01em;
  }}
  .fatal-lead {{
    color: #fca5a5;
    margin: 0 0 0.85rem;
    font-size: 0.95rem;
  }}
  .fatal-detail {{
    margin: 0;
    padding: 0.9rem 1rem;
    background: #0b0f18;
    border: 1px solid #7f1d1d;
    border-radius: 10px;
    color: #fee2e2;
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    font-size: 0.82rem;
    white-space: pre-wrap;
    word-break: break-word;
    max-height: 28rem;
    overflow: auto;
  }}
  footer.page {{
    margin-top: 2rem;
    color: var(--muted);
    font-size: 0.8rem;
    border-top: 1px solid var(--border);
    padding-top: 1rem;
  }}
</style>
</head>
<body>
  <div class="wrap">
    <header class="page">
      <h1>{_html_escape(title)}</h1>
      <div class="meta">
        Generated {generated} · {len(records)} CVE(s) · {ok} enriched successfully
        · {failed} failed/skipped
        {" · <strong style='color:#fca5a5'>RUN ERROR</strong>" if fatal_error else ""}
      </div>
      <div class="chips">{pri_chips or '<span class="chip">No successful enrichments</span>'}</div>
    </header>
    {fatal_section}
    {"".join(cards) if cards else '<p class="muted">No per-CVE cards to display.</p>'}
    <footer class="page">
      Data source: Google Threat Intelligence / VirusTotal Vulnerability collections API
      (<code>/api/v3/collections/vulnerability--&lt;cve&gt;</code>).
      Priority (P0–P4) is derived from Risk Rating + Exploitation State + Exploit Availability
      per GTI vulnerability report guidance. Requires GTI Enterprise / Enterprise Plus.
      This report is always generated and opened after each run, including failures.
    </footer>
  </div>
</body>
</html>
"""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(doc, encoding="utf-8")
    logging.info("Wrote HTML report: %s", path)


def open_report_in_browser(path: Path) -> None:
    """
    Open the HTML report in the default browser (prefer a new window/tab).

    Uses ``webbrowser`` first; on Windows falls back to ``os.startfile`` /
    ``cmd /c start`` if needed so the report still surfaces after a failed run.

    Why we open even on failure
    ---------------------------
    Analysts running this from a locked-down Windows desktop often miss
    stderr in a flashing console window. A browser tab is the reliable
    place to read SSL/proxy/key errors, screenshot them, and attach them
    to a ticket. ``--no-open`` exists only for CI/automation; the file is
    still written by ``render_html_report``.

    Failures here are logged, never raised — a browser-helper error must
    not mask a successful enrichment (or replace the real exit code).
    """
    resolved = path.resolve()
    if not resolved.is_file():
        logging.warning("Cannot open report — file missing: %s", resolved)
        return

    uri = resolved.as_uri()
    logging.info("Opening HTML report in browser: %s", resolved)

    try:
        # new=1 asks for a new window; autoraise brings the browser forward
        opened = webbrowser.open(uri, new=1, autoraise=True)
        if opened:
            return
    except Exception as exc:  # noqa: BLE001 — best-effort UI helper
        logging.debug("webbrowser.open failed: %s", exc)

    # Windows-reliable fallbacks when webbrowser is misconfigured or restricted
    if sys.platform == "win32":
        try:
            os.startfile(str(resolved))  # type: ignore[attr-defined]
            return
        except Exception as exc:  # noqa: BLE001
            logging.debug("os.startfile failed: %s", exc)
        try:
            # Empty title argument after "start" is required when the path is quoted
            subprocess.run(
                ["cmd", "/c", "start", "", str(resolved)],
                check=False,
                shell=False,
            )
            return
        except Exception as exc:  # noqa: BLE001
            logging.warning("Failed to open report via cmd start: %s", exc)
            return

    logging.warning(
        "Could not open the report automatically. Open manually: %s", resolved
    )


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------
# Wire config → client → enrich loop → CSV / Rich / always-on HTML.
#
# Order in ``main()`` is load-bearing:
#   1. argparse  (so --env-file / -v exist)
#   2. logging
#   3. load_project_dotenv  → os.environ
#   4. resolve API key, input CSV, proxies, CA bundle
#   5. GTIClient(...)  with those resolved values
#   6. enrich + CSV + optional Rich
#   7. ALWAYS render HTML and (unless --no-open) launch the browser
# Step 7 lives outside the enrichment try so missing keys, missing CA
# files, and SSL errors still produce a browsable failure page.
# ---------------------------------------------------------------------------


def build_proxies(
    http_proxy: Optional[str],
    https_proxy: Optional[str],
) -> Optional[dict[str, str]]:
    """
    Build a requests proxies dict from CLI flags and environment / ``.env``.

    Resolution order per scheme: CLI → VT_* alias → HTTP(S)_PROXY → lowercase.
    Values typically come from the project ``.env`` (loaded at startup) so
    operators do not re-export proxies in every PowerShell session.

    Corporate networks almost always require an HTTP proxy for outbound
    HTTPS (the proxy URL itself uses ``http://``, even for HTTPS targets).
    If only one scheme is configured we mirror it onto the other so
    VirusTotal is not accidentally reached direct and blocked.
    """
    http_p = (
        http_proxy
        or os.getenv("VT_HTTP_PROXY")
        or os.getenv("HTTP_PROXY")
        or os.getenv("http_proxy")
    )
    https_p = (
        https_proxy
        or os.getenv("VT_HTTPS_PROXY")
        or os.getenv("HTTPS_PROXY")
        or os.getenv("https_proxy")
    )
    proxies: dict[str, str] = {}
    if http_p:
        proxies["http"] = http_p.strip()
    if https_p:
        proxies["https"] = https_p.strip()
    # Corporate proxies are almost always one HTTP endpoint for both schemes;
    # mirror a single configured value so HTTPS traffic is not sent direct
    # (direct would fail or bypass inspection and look like a policy violation).
    if "http" in proxies and "https" not in proxies:
        proxies["https"] = proxies["http"]
    elif "https" in proxies and "http" not in proxies:
        proxies["http"] = proxies["https"]
    return proxies or None


def _format_fatal_error(exc: BaseException) -> str:
    """Human-readable exception + short traceback for the HTML error panel.

    Kept off the console by default (full text is DEBUG / ``-v``) so a
    missing CA file is one clear line in the terminal and the detail lives
    in the report that we always open.
    """
    tb = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
    # Cap size so the HTML stays readable in constrained browser windows
    if len(tb) > 8000:
        tb = tb[:8000] + "\n… [traceback truncated]"
    return f"{type(exc).__name__}: {exc}\n\n{tb}"


def enrich_cves(
    client: GTIClient,
    cves: list[str],
    *,
    stop_on_forbidden: bool = True,
) -> list[CVERecord]:
    """
    Query each CVE and collect success or structured error records.

    On 401/403, optionally stop early and mark remaining CVEs as skipped so
    we do not burn rate budget against a key without VI privileges.
    Remaining IDs still get error rows so the HTML report is a complete
    accounting of the input list, not a silent truncation.

    Progress renders on stderr (``log_console``) so stdout stays usable
    if an operator pipes the process.
    """
    records: list[CVERecord] = []
    total = len(cves)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=log_console,
        transient=False,
    ) as progress:
        task = progress.add_task("Enriching CVEs…", total=total)
        for idx, cve in enumerate(cves, start=1):
            progress.update(task, description=f"[{idx}/{total}] {cve}")
            logging.info("(%d/%d) Querying %s → %s", idx, total, cve, cve_api_id(cve))

            body, err, status = client.get_vulnerability(cve)
            if err is None and body is not None:
                rec = extract_record(cve, body)
                records.append(rec)
                logging.info(
                    "  → %s | risk=%s | priority=%s | EPSS=%s | KEV=%s",
                    cve,
                    rec.risk_rating,
                    rec.priority_rating,
                    rec.epss_score,
                    rec.cisa_kev,
                )
            elif err == "not_found":
                records.append(
                    error_record(
                        cve,
                        "not_found",
                        "Vulnerability not found in GTI collections (404). "
                        "It may be too new, unpublished, or outside GTI coverage.",
                    )
                )
            elif err == "forbidden":
                records.append(
                    error_record(
                        cve,
                        "forbidden",
                        "Access denied (401/403). GTI Vulnerability Intelligence requires "
                        "Enterprise or Enterprise Plus. Verify API key privileges.",
                    )
                )
                if stop_on_forbidden:
                    logging.error(
                        "Stopping early: API key lacks Vulnerability Intelligence privilege. "
                        "Remaining CVEs will not be queried."
                    )
                    # Mark remaining as skipped so the HTML/CSV still list every
                    # input CVE (complete accounting) without further API calls.
                    for rest in cves[idx:]:
                        records.append(
                            error_record(
                                rest,
                                "forbidden",
                                "Skipped: earlier request returned 401/403 (privilege missing).",
                            )
                        )
                    progress.update(task, completed=total)
                    break
            elif err == "rate_limited":
                records.append(
                    error_record(
                        cve,
                        "rate_limited",
                        "Exceeded rate limit after retries (HTTP 429). Try a higher --delay.",
                    )
                )
            else:
                records.append(
                    error_record(
                        cve,
                        "error",
                        f"Request failed (HTTP {status or 'n/a'}).",
                    )
                )
            progress.advance(task)

    return records


def build_arg_parser() -> argparse.ArgumentParser:
    """Define CLI flags; defaults favor .env for secrets and network settings.

    Flags are overrides, not the primary config surface. ``--html`` always
    has a path (default ``report.html``) because the report is always written.
    ``--no-open`` is the only way to skip the browser, and it does not skip
    the write.
    """
    p = argparse.ArgumentParser(
        prog="cve_enricher.py",
        description=(
            "Enrich CVE IDs via Google Threat Intelligence / VirusTotal "
            "vulnerability collections (Enterprise required). "
            "Config: project .env (API key, proxies, CORPORATE_CA_BUNDLE). "
            "HTML report is always written and opened, including on failure."
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("-i", "--input", default=DEFAULT_INPUT, help="Input CSV of CVE IDs")
    p.add_argument("-o", "--output", default=DEFAULT_OUTPUT, help="Output enriched CSV path")
    p.add_argument(
        "--html",
        default=DEFAULT_HTML,
        metavar="PATH",
        help="Self-contained HTML report path (always written and opened)",
    )
    p.add_argument(
        "--no-open",
        action="store_true",
        help="Do not open the HTML report in a browser (report is still written)",
    )
    p.add_argument(
        "--no-rich",
        action="store_true",
        help="Skip Rich terminal cards (still logs progress)",
    )
    p.add_argument(
        "--api-key",
        default=None,
        help="VirusTotal/GTI API key (prefer VIRUSTOTAL_API_KEY in .env)",
    )
    p.add_argument(
        "--http-proxy",
        default=None,
        help="HTTP proxy URL (or HTTP_PROXY / VT_HTTP_PROXY in .env)",
    )
    p.add_argument(
        "--https-proxy",
        default=None,
        help="HTTPS proxy URL (or HTTPS_PROXY / VT_HTTPS_PROXY in .env)",
    )
    p.add_argument(
        "--ca-bundle",
        default=None,
        metavar="PATH",
        help=(
            "Corporate root CA PEM/CRT for SSL inspection "
            f"(or CORPORATE_CA_BUNDLE; default file {DEFAULT_CA_BUNDLE.name} under certs/)"
        ),
    )
    p.add_argument(
        "--delay",
        type=float,
        default=None,
        help=f"Seconds between API requests (default: VT_REQUEST_DELAY or {DEFAULT_DELAY})",
    )
    p.add_argument(
        "--max-retries",
        type=int,
        default=DEFAULT_MAX_RETRIES,
        help="Max retries on 429 / 5xx / network errors",
    )
    p.add_argument(
        "--continue-on-forbidden",
        action="store_true",
        help="Do not stop the run when 401/403 is returned",
    )
    p.add_argument("-v", "--verbose", action="store_true", help="Debug logging")
    p.add_argument(
        "--dump-raw",
        metavar="DIR",
        default=None,
        help="Optional directory to save raw JSON responses per CVE",
    )
    p.add_argument(
        "--env-file",
        default=None,
        metavar="PATH",
        help="Path to .env file (default: .env next to this script)",
    )
    return p


def main(argv: Optional[list[str]] = None) -> int:
    """
    Run enrichment end-to-end.

    Guarantees: after parse + logging setup, an HTML report is always generated
    and opened (unless ``--no-open``), even when the run fails with a missing
    key, SSL error, bad input, or unexpected exception.

    Exit codes (unchanged): 0 = at least one success; 1 = no successes /
    runtime error; 2 = config/input/CA; 3 = privilege (401/403) and zero
    successes.
    """
    # Parse CLI first so --env-file / -v apply before any other work.
    args = build_arg_parser().parse_args(argv)
    setup_logging(verbose=args.verbose)

    # Load .env early: populates os.environ for key, proxy, and CA resolution
    # used by resolve_api_key / build_proxies / resolve_ssl_verify below.
    env_path = load_project_dotenv(Path(args.env_file) if args.env_file else None)
    if env_path:
        logging.info("Loaded configuration from %s", env_path)
    else:
        logging.info(
            "No .env file found (looked for %s). Using process environment / CLI only.",
            DEFAULT_ENV_FILE,
        )

    # Shared state for the always-on report path (success or failure).
    # Initialized *before* the try so the finally-equivalent HTML block
    # can render an empty-records failure page if we never get that far.
    html_path = Path(args.html)
    records: list[CVERecord] = []
    fatal_error: Optional[str] = None
    exit_code = 0
    output_path = Path(args.output)

    try:
        # --- Resolve secrets and inputs ---
        api_key = resolve_api_key(args.api_key)
        if not api_key:
            raise RuntimeError(
                "No API key. Set VIRUSTOTAL_API_KEY (or VT_API_KEY) in the project "
                ".env file, or pass --api-key. See .env.example and SETUP.md."
            )

        input_path = Path(args.input)
        try:
            cves = load_cve_list(input_path)
        except (OSError, ValueError) as exc:
            raise RuntimeError(f"Failed to read input: {exc}") from exc

        if not cves:
            raise RuntimeError(f"No valid CVE IDs found in {input_path}")

        logging.info("Loaded %d unique CVE(s) from %s", len(cves), input_path)

        # --- Network: proxy + TLS trust ---
        # Proxies and CA bundle are applied on the Session inside GTIClient.
        # Redact user:password@ in logs if operators put creds in the proxy URL.
        proxies = build_proxies(args.http_proxy, args.https_proxy)
        if proxies:
            safe_proxies = {
                k: re.sub(r"://([^:/@]+):([^@]+)@", r"://\1:***@", v)
                for k, v in proxies.items()
            }
            logging.info("Using proxies: %s", safe_proxies)
        else:
            logging.info("No HTTP(S) proxy configured (direct connection).")

        # Wrap FileNotFoundError so the HTML banner and exit-code 2 matcher
        # see a RuntimeError whose message still contains "CA bundle".
        try:
            verify = resolve_ssl_verify(args.ca_bundle)
        except FileNotFoundError as exc:
            raise RuntimeError(str(exc)) from exc

        delay = resolve_request_delay(args.delay)

        # GTIClient re-validates key + verify=False; wrap ValueError the same
        # way so the always-open HTML path (not a traceback-only crash) owns it.
        try:
            client = GTIClient(
                api_key=api_key,
                proxies=proxies,
                verify=verify,
                delay=delay,
                max_retries=args.max_retries,
            )
        except ValueError as exc:
            raise RuntimeError(str(exc)) from exc

        # Optional: wrap the GET to persist raw JSON for offline debugging
        # (schema drift, ticket attachments). Does not change enrichment
        # results — dump happens after a successful parse of the body.
        dump_dir = Path(args.dump_raw) if args.dump_raw else None
        if dump_dir:
            dump_dir.mkdir(parents=True, exist_ok=True)
            original_get = client.get_vulnerability

            def get_with_dump(
                cve: str,
            ) -> tuple[Optional[dict[str, Any]], Optional[str], int]:
                body, err, status = original_get(cve)
                if body is not None:
                    out = dump_dir / f"{cve.upper()}.json"
                    out.write_text(json.dumps(body, indent=2), encoding="utf-8")
                    logging.debug("Dumped raw JSON → %s", out)
                return body, err, status

            client.get_vulnerability = get_with_dump  # type: ignore[method-assign]

        # --- Enrich + export ---
        records = enrich_cves(
            client,
            cves,
            stop_on_forbidden=not args.continue_on_forbidden,
        )

        write_csv(records, output_path)

        if not args.no_rich:
            print_rich_report(records)
        else:
            # Compact one-line summary when Rich panels are disabled
            for rec in records:
                logging.info(
                    "%s | status=%s | priority=%s | risk=%s | epss=%s | kev=%s",
                    rec.cve,
                    rec.status,
                    rec.priority_rating,
                    rec.risk_rating,
                    rec.epss_score,
                    rec.cisa_kev,
                )

        ok = sum(1 for r in records if r.status == "ok")
        failed = len(records) - ok
        logging.info(
            "Done. Enriched=%d  Failed/Skipped=%d  CSV=%s",
            ok,
            failed,
            output_path,
        )

        # Exit semantics: 3 = privilege total failure; 1 = no successes; 0 = ok
        if any(r.status == "forbidden" for r in records) and ok == 0:
            exit_code = 3
        elif ok == 0:
            exit_code = 1
        else:
            exit_code = 0

    except Exception as exc:  # noqa: BLE001 — capture for HTML failure report
        # Do not re-raise: we still write/open the HTML report below.
        # That is the always-open guarantee — a missing key or SSL failure
        # must not exit before the operator gets a browsable error page.
        fatal_error = _format_fatal_error(exc)
        logging.error("%s", exc)
        if args.verbose:
            logging.debug("%s", fatal_error)
        log_console.print(f"[bold red]Error:[/bold red] {exc}")
        # Prefer exit 2 for config/input problems; 1 for other runtime failures
        msg = str(exc).lower()
        if any(
            needle in msg
            for needle in (
                "api key",
                "no valid cve",
                "failed to read input",
                "ca bundle",
                "placeholder",
            )
        ):
            exit_code = 2
        else:
            exit_code = 1

    # ------------------------------------------------------------------
    # Always write + open HTML report (success, partial, or total failure).
    #
    # This block intentionally sits *outside* the main try so config/SSL/key
    # failures still produce a browsable error page. ``records`` may be empty
    # and ``fatal_error`` set; ``render_html_report`` handles both.
    # ``--no-open`` skips the browser only — the file is still written.
    # A failure *here* is logged and can flip a 0 exit to 1, but never
    # swallows the original enrichment exit code if it was already non-zero.
    # ------------------------------------------------------------------
    try:
        title = "GTI CVE Enrichment Report"
        if fatal_error:
            title = "GTI CVE Enrichment Report — FAILED"
        render_html_report(
            records,
            html_path,
            title=title,
            fatal_error=fatal_error,
        )
        logging.info("HTML report: %s", html_path.resolve())
        if not args.no_open:
            open_report_in_browser(html_path)
    except Exception as report_exc:  # noqa: BLE001
        logging.error("Failed to write/open HTML report: %s", report_exc)
        if exit_code == 0:
            exit_code = 1

    return exit_code


if __name__ == "__main__":
    # Standard CLI entry: propagate process exit code to the shell.
    sys.exit(main())
