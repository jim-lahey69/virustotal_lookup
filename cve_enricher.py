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
    python cve_enricher.py --input CVE-2026-12345
    python cve_enricher.py -i cve_list.csv --output cve_enriched.csv --html report.html

Corporate SSL inspection
------------------------
Do **not** disable TLS verification. Place your org root CA at
``./certs/corporate-ca.pem`` (or set ``CORPORATE_CA_BUNDLE``) so
``requests`` can verify the MITM proxy chain. See SETUP.md / README.

HTML report
-----------
Single-CVE runs write the primary HTML report (default ``report.html``) and
companion IOC report (default ``ioc_report.html``). Multi-CVE runs write one
``CVE-..._report.html`` / ``CVE-..._iocs.html`` pair per input record, open the
first primary report automatically, and offer a lightweight numbered selector
for additional reports. Failure reports include a prominent error section.

Report architecture
-------------------
API responses are normalized once into ``CVERecord`` objects. The primary
report, companion IOC report, CSV, terminal cards, and inline SVG visualization
all consume those records; report rendering never repeats an enrichment query.
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
import ipaddress
import json
import logging
import os
import random
import re
import subprocess
import sys
import time
import traceback
import urllib.parse
import webbrowser
from dataclasses import asdict, dataclass, field
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
DEFAULT_IOC_HTML = "ioc_report.html"
DEFAULT_MAX_RETRIES = 5
DEFAULT_BACKOFF_BASE = 2.0  # seconds; exponential: base^attempt + jitter

# Canonical CVE ID shape used for validation after normalization.
CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

# GTI priority derivation treats these labels as "no known exploit availability".
# Values observed across GTI docs / UI wording variants.
NO_KNOWN_ALIASES = {"no known", "no_known", "no-known", "noknown"}

# Official Exploitation State labels and numeric levels (GTI docs).
# Missing / unrecognized API values display as "Unknown" — never coerced to "No Known".
EXPLOITATION_STATE_LEVELS: dict[int, str] = {
    0: "No Known",
    1: "Suspected",
    2: "Reported",
    3: "Confirmed",
    4: "Wide",
}
EXPLOITATION_STATE_ALIASES: dict[str, int] = {
    "no known": 0,
    "no_known": 0,
    "no-known": 0,
    "noknown": 0,
    "suspected": 1,
    "reported": 2,
    "confirmed": 3,
    "wide": 4,
}

# The public Vulnerability API exposes labels for the three priority axes, not
# an image or separate numeric visualization fields. These centralized maps
# convert those documented ordinal labels to the 0-4 scale used by GTI's
# Priority Visualization. Both visible labels and SVG positions are populated
# from the normalized CVERecord fields produced with these maps.
RISK_RATING_LEVELS: dict[int, str] = {
    0: "Unrated",
    1: "Low",
    2: "Medium",
    3: "High",
    4: "Critical",
}
RISK_RATING_ALIASES: dict[str, int] = {
    "none": 0,
    "unrated": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}
EXPLOIT_AVAILABILITY_LEVELS: dict[int, str] = {
    0: "No Known",
    1: "Interest Observed",
    2: "Unverified",
    3: "Privately Held",
    4: "Publicly Available",
}
EXPLOIT_AVAILABILITY_ALIASES: dict[str, int] = {
    "none": 0,
    "no known": 0,
    "no_known": 0,
    "no-known": 0,
    "noknown": 0,
    "interest observed": 1,
    "unverified": 2,
    "privately held": 3,
    "known": 4,
    "publicly available": 4,
    # Trivial exploitation is at least as accessible as public exploit code;
    # the official graphic has no level above 4, so both occupy its endpoint.
    "trivial": 4,
}
WILD_COLLECTION_TAGS = frozenset(
    {
        "observed in the wild",
        "observed_in_the_wild",
        "exploited in the wild",
        "exploited_in_the_wild",
        "in the wild",
        "in_the_wild",
        "cisa exploited",
        "cisa_exploited",
        "cisa kev",
        "cisa_kev",
    }
)

# The collection relationship endpoint supports a maximum page size of 40.
# Every object returned on that page is retained and rendered in the separate
# IOC report; nothing is truncated again by the presentation layer.
IOC_PAGE_SIZE = 40
# Compatibility alias for external callers that imported the old name.
IOC_DISPLAY_CAP = IOC_PAGE_SIZE
IOC_RELATIONSHIPS: tuple[str, ...] = ("files", "urls", "domains", "ip_addresses")

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

    # Convention paths: use only when the operator has already dropped the file in.
    # Absence is *not* an error — many analysts run this off-network or on
    # machines whose Python already trusts the inspection CA via the OS store.
    # Corporate desktops often keep a personal bundle under the user profile
    # (%USERPROFILE%\certs\corporate_trust_bundle.pem on Windows).
    user_profile_bundle = Path.home() / "certs" / "corporate_trust_bundle.pem"
    if user_profile_bundle.is_file():
        return str(user_profile_bundle.resolve())
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
# String defaults are "N/A" / "Unknown" so empty API fields still render
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
    risk_rating_level: str = "N/A"  # 0–4 visualization level
    predicted_risk_rating: str = "N/A"
    risk_factors: str = "N/A"

    # Exploitation posture
    exploitation_state: str = "Unknown"
    exploitation_state_level: str = "N/A"  # 0–4 or N/A when Unknown
    exploit_availability: str = "N/A"
    exploit_availability_level: str = "N/A"  # 0–4 visualization level
    exploited_in_the_wild: str = "Unknown"
    exploited_in_the_wild_status: str = "not_returned"
    exploited_in_the_wild_sources: str = ""  # debug: authoritative field/filter source
    exploited_in_the_wild_explicit: str = "N/A"  # raw explicit field if present
    exploited_as_zero_day: str = "Unknown"
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
    ioc_status: str = "not_returned"
    ioc_error: str = ""
    # Actual IoC objects from the relationship fetch. Totals come from counters.
    ioc_files_total: int = 0
    ioc_urls_total: int = 0
    ioc_domains_total: int = 0
    ioc_ip_addresses_total: int = 0
    ioc_files: list[dict[str, str]] = field(default_factory=list)
    ioc_urls: list[dict[str, str]] = field(default_factory=list)
    ioc_domains: list[dict[str, str]] = field(default_factory=list)
    ioc_ip_addresses: list[dict[str, str]] = field(default_factory=list)

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
    "exploited_in_the_wild_status",
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
    "ioc_status",
    "ioc_error",
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


def validate_input_cve(raw: str) -> str:
    """Normalize and validate a single ``--input`` CVE identifier.

    Strips surrounding whitespace, uppercases, then requires ``CVE_PATTERN``.
    Unlike ``normalize_cve()``, this does not promote bare ``YYYY-NNNN`` IDs
    or rewrite underscores — ``--input`` is a strict one-CVE entry point.
    """
    normalized = (raw or "").strip().upper()
    if "," in (raw or "") or not CVE_PATTERN.match(normalized):
        raise ValueError(
            f"Invalid CVE identifier for --input: {raw!r}. "
            "Provide exactly one ID matching CVE-YYYY-NNNN "
            "(example: CVE-2026-12345)."
        )
    return normalized


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


def _as_nonneg_int(value: Any, default: int = 0) -> int:
    """Best-effort non-negative int for IoC counters (missing → default)."""
    if value is None or value is False:
        return default
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return default


def normalize_exploitation_state(value: Any) -> tuple[Optional[int], str]:
    """Map GTI ``exploitation_state`` strings to ``(level, canonical label)``.

    Official values and levels (GTI Vulnerability Intelligence docs)::

        0 = No Known
        1 = Suspected
        2 = Reported
        3 = Confirmed
        4 = Wide

    Unknown or missing values return ``(None, "Unknown")``. They are **not**
    coerced to ``No Known`` — that label means GTI has assessed the landscape
    and is unaware of exploitation, which is different from "field absent".
    """
    if value is None:
        return None, "Unknown"
    text = str(value).strip()
    if not text:
        return None, "Unknown"
    key = _norm_label(text).replace("_", " ").replace("-", " ")
    key_compact = key.replace(" ", "")
    if key in EXPLOITATION_STATE_ALIASES:
        level = EXPLOITATION_STATE_ALIASES[key]
        return level, EXPLOITATION_STATE_LEVELS[level]
    if key_compact in EXPLOITATION_STATE_ALIASES:
        level = EXPLOITATION_STATE_ALIASES[key_compact]
        return level, EXPLOITATION_STATE_LEVELS[level]
    if key.isdigit():
        num = int(key)
        if num in EXPLOITATION_STATE_LEVELS:
            return num, EXPLOITATION_STATE_LEVELS[num]
    return None, "Unknown"


def normalize_risk_rating(value: Any) -> tuple[Optional[int], str]:
    """Return the canonical Risk Rating label and its visualization level.

    GTI documents the ordered labels ``Unrated``, ``Low``, ``Medium``,
    ``High``, and ``Critical``. The local visualization places these at 0-4.
    Missing values remain unavailable rather than being treated as Unrated.
    """
    if value is None:
        return None, "N/A"
    text = str(value).strip()
    if not text:
        return None, "N/A"
    key = _norm_label(text).replace("_", " ").replace("-", " ")
    if key.isdigit() and int(key) in RISK_RATING_LEVELS:
        level = int(key)
        return level, RISK_RATING_LEVELS[level]
    level = RISK_RATING_ALIASES.get(key)
    if level is None:
        return None, text
    return level, RISK_RATING_LEVELS[level]


def normalize_exploit_availability(value: Any) -> tuple[Optional[int], str]:
    """Return canonical Exploit Availability text and its 0-4 graph level.

    The API returns categorical labels while the GTI graphic has five points.
    ``Publicly Available``, legacy ``Known``, and ``Trivial`` share level 4;
    their distinct display labels are retained because they carry useful
    analyst meaning even though the graph has no higher position.
    """
    if value is None:
        return None, "N/A"
    text = str(value).strip()
    if not text:
        return None, "N/A"
    key = _norm_label(text).replace("_", " ").replace("-", " ")
    if key.isdigit() and int(key) in EXPLOIT_AVAILABILITY_LEVELS:
        level = int(key)
        return level, EXPLOIT_AVAILABILITY_LEVELS[level]
    level = EXPLOIT_AVAILABILITY_ALIASES.get(key)
    if level is None:
        return None, text
    label = {
        "none": "No Known",
        "no known": "No Known",
        "noknown": "No Known",
        "interest observed": "Interest Observed",
        "unverified": "Unverified",
        "privately held": "Privately Held",
        "known": "Publicly Available",
        "publicly available": "Publicly Available",
        "trivial": "Trivial",
    }.get(key, EXPLOIT_AVAILABILITY_LEVELS[level])
    return level, label


def _truthy_flag(value: Any) -> bool:
    """True for boolean/string values that mean yes/true."""
    if value is True:
        return True
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return value == 1
    if isinstance(value, str):
        return _norm_label(value) in {"true", "yes", "y", "1"}
    return False


def _falsey_flag(value: Any) -> bool:
    """True for boolean/string values that mean no/false (explicit, not missing)."""
    if value is False:
        return True
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return value == 0
    if isinstance(value, str):
        return _norm_label(value) in {"false", "no", "n", "0"}
    return False


def _walk_wild_keys(obj: Any, prefix: str = "") -> list[tuple[str, Any]]:
    """Collect keys whose names look like in-the-wild / observed-wild flags."""
    hits: list[tuple[str, Any]] = []
    if isinstance(obj, dict):
        for key, val in obj.items():
            path = f"{prefix}{key}" if not prefix else f"{prefix}.{key}"
            key_l = str(key).lower()
            if "wild" in key_l or key_l in {
                "observed_in_the_wild",
                "exploited_in_the_wild",
                "in_the_wild",
            }:
                hits.append((path, val))
            if isinstance(val, (dict, list)):
                hits.extend(_walk_wild_keys(val, path))
    elif isinstance(obj, list):
        for idx, item in enumerate(obj[:20]):
            if isinstance(item, (dict, list)):
                hits.extend(_walk_wild_keys(item, f"{prefix}[{idx}]"))
    return hits


def _tag_list(tags: Any) -> list[str]:
    if isinstance(tags, str):
        return [t.strip() for t in re.split(r"[;,]", tags) if t.strip()]
    if isinstance(tags, (list, tuple)):
        return [str(t).strip() for t in tags if t is not None and str(t).strip()]
    return []


def derive_exploited_in_the_wild(
    attrs: dict[str, Any],
    *,
    exploitation: Optional[dict[str, Any]] = None,
    tags: Any = None,
) -> tuple[str, list[str], str]:
    """Normalize an explicit in-the-wild value from a vulnerability object.

    The published Vulnerability object does not document an
    ``exploited_in_the_wild`` attribute. The documented API representation of
    the GUI flag is membership in the ``Observed In The Wild`` vulnerability
    filter, queried separately by :meth:`GTIClient.get_observed_in_the_wild`.

    This helper accepts explicit fields if an API revision supplies one and an
    exact ``Observed In The Wild`` tag if it is present in the object. It does
    **not** infer the flag from Exploitation State, CISA KEV, exploit
    availability, or any other semantically related metric.

    When no explicit value is present, the result is ``"Unknown"`` rather
    than ``"False"``. Absence of an undocumented property is not evidence of
    a negative result.

    Returns
    -------
    (display, sources, explicit)
        display: ``"True"`` / ``"False"`` / ``"Unknown"``
        sources: labels of explicit values that determined the result
        explicit: raw explicit field value if one was present, else ``"N/A"``
    """
    exploitation = exploitation if isinstance(exploitation, dict) else {}
    positive_sources: list[str] = []
    negative_sources: list[str] = []
    explicit_raw = "N/A"

    explicit_candidates = [
        ("attributes.exploited_in_the_wild", attrs.get("exploited_in_the_wild")),
        ("attributes.observed_in_the_wild", attrs.get("observed_in_the_wild")),
        ("attributes.exploited_in_wild", attrs.get("exploited_in_wild")),
        ("exploitation.exploited_in_the_wild", exploitation.get("exploited_in_the_wild")),
        ("exploitation.observed_in_the_wild", exploitation.get("observed_in_the_wild")),
        ("exploitation.in_the_wild", exploitation.get("in_the_wild")),
    ]
    for label, val in explicit_candidates:
        if val is None or val == "":
            continue
        if explicit_raw == "N/A":
            explicit_raw = na(val)
        if _truthy_flag(val):
            positive_sources.append(f"{label}={val!r}")
        elif _falsey_flag(val):
            negative_sources.append(f"{label}={val!r}")

    # Nested exploitation / attributes keys that mention "wild"
    seen_paths = {
        s.split("=")[0]
        for s in positive_sources + negative_sources
    }
    for path, val in _walk_wild_keys({"attributes": attrs, "exploitation": exploitation}):
        short = path
        if short in seen_paths:
            continue
        if val is None or val == "":
            continue
        if explicit_raw == "N/A" and not isinstance(val, (dict, list)):
            explicit_raw = na(val)
        if _truthy_flag(val):
            positive_sources.append(f"{path}={val!r}")
            seen_paths.add(short)
        elif _falsey_flag(val):
            negative_sources.append(f"{path}={val!r}")
            seen_paths.add(short)

    for tag in _tag_list(tags):
        if _norm_label(tag) in WILD_COLLECTION_TAGS:
            positive_sources.append(f"tag={tag}")

    if positive_sources:
        display = "True"
        sources = positive_sources
    elif negative_sources:
        display = "False"
        sources = negative_sources
    else:
        display = "Unknown"
        sources = []

    # Deduplicate while preserving order
    uniq: list[str] = []
    seen: set[str] = set()
    for item in sources:
        if item not in seen:
            seen.add(item)
            uniq.append(item)
    return display, uniq, explicit_raw


def parse_observed_in_the_wild_response(cve: str, payload: dict[str, Any]) -> bool:
    """Return exact CVE membership from an Observed In The Wild filter response.

    A successful empty list is an authoritative negative. A malformed response
    raises ``ValueError`` so callers can preserve ``Unknown`` rather than
    silently converting a parsing problem into ``False``.
    """
    if not isinstance(payload, dict) or not isinstance(payload.get("data"), list):
        raise ValueError("Observed In The Wild response has no data list")

    expected_id = cve_api_id(cve).lower()
    expected_cve = cve.upper()
    for item in payload["data"]:
        if not isinstance(item, dict):
            continue
        if str(item.get("id") or "").lower() == expected_id:
            return True
        attrs = item.get("attributes") if isinstance(item.get("attributes"), dict) else {}
        if str(attrs.get("cve_id") or "").upper() == expected_cve:
            return True
    return False


def apply_observed_in_the_wild_result(
    rec: CVERecord,
    value: Optional[bool],
    *,
    error: Optional[str] = None,
    http_status: int = 0,
) -> None:
    """Apply the authoritative filter result without collapsing errors to No."""
    if error is not None or value is None:
        rec.exploited_in_the_wild_status = "lookup_failed"
        if rec.exploited_in_the_wild not in {"True", "False"}:
            rec.exploited_in_the_wild = "Unknown"
        logging.warning(
            "Observed In The Wild lookup unavailable for %s (status=%s, err=%s)",
            rec.cve,
            http_status,
            error or "unknown",
        )
        return

    rec.exploited_in_the_wild = "True" if value else "False"
    rec.exploited_in_the_wild_status = "filter_returned"
    filter_source = f'vulnerability_filter="Observed In The Wild"={value}'
    existing = [s for s in rec.exploited_in_the_wild_sources.split("; ") if s]
    rec.exploited_in_the_wild_sources = "; ".join([filter_source, *existing])


def exploitation_debug_snapshot(attrs: dict[str, Any]) -> dict[str, Any]:
    """Small dict of exploitation-related keys for DEBUG logs (never HTML)."""
    exploitation = attrs.get("exploitation") if isinstance(attrs.get("exploitation"), dict) else {}
    kev = attrs.get("cisa_known_exploited")
    snap: dict[str, Any] = {
        "exploitation_state": attrs.get("exploitation_state"),
        "exploit_availability": attrs.get("exploit_availability"),
        "exploitation_keys": sorted(exploitation.keys()) if exploitation else [],
        "exploitation_nested": {
            k: exploitation.get(k)
            for k in (
                "exploitation_state",
                "exploit_availability",
                "exploited_in_the_wild",
                "observed_in_the_wild",
                "in_the_wild",
                "first_exploitation",
                "exploit_release_date",
            )
            if k in exploitation
        },
        "explicit_exploited_in_the_wild": attrs.get("exploited_in_the_wild"),
        "explicit_observed_in_the_wild": attrs.get("observed_in_the_wild"),
        "cisa_known_exploited_present": bool(isinstance(kev, dict) and kev),
        "tags": attrs.get("tags"),
        "wild_key_hits": [
            {"path": p, "value": v}
            for p, v in _walk_wild_keys(attrs)
            if not isinstance(v, (dict, list))
        ],
        "attr_keys_matching_exploit": sorted(
            k for k in attrs.keys() if "exploit" in str(k).lower() or "wild" in str(k).lower()
        ),
    }
    return snap


def log_exploitation_debug(cve: str, attrs: dict[str, Any]) -> None:
    """DEBUG-only dump of exploitation keys. Never written into the HTML report."""
    if not logging.getLogger().isEnabledFor(logging.DEBUG):
        return
    try:
        snap = exploitation_debug_snapshot(attrs)
        logging.debug("Exploitation source keys for %s: %s", cve, json.dumps(snap, default=str)[:4000])
    except (TypeError, ValueError):
        logging.debug("Exploitation source keys for %s: <unserializable>", cve)


# ---------------------------------------------------------------------------
# IoC relationship parsing
# ---------------------------------------------------------------------------
# ``counters.iocs`` / ``files_count`` are *counts only*. Actual indicators
# live on collection relationships: files, urls, domains, ip_addresses.
# ---------------------------------------------------------------------------


def parse_relationship_iocs(
    relationship: str,
    payload: Optional[dict[str, Any]],
) -> list[dict[str, str]]:
    """Flatten a GTI relationship response into display-ready IOC dictionaries.

    Malformed top-level data is a parsing failure, not an empty IOC result.
    """
    if not isinstance(payload, dict):
        raise ValueError(f"{relationship} relationship response is not an object")
    rows = payload.get("data")
    if not isinstance(rows, list):
        raise ValueError(f"{relationship} relationship response has no data list")
    parsed: list[dict[str, str]] = []
    seen: set[str] = set()
    for obj in rows:
        if not isinstance(obj, dict) or obj.get("error"):
            continue
        item = _parse_one_ioc(relationship, obj)
        if not item:
            continue
        identity = (item.get("display") or item.get("id") or "").strip()
        # Domain and file hashes are case-insensitive; URL paths can be
        # case-sensitive, so preserve their exact identity for deduplication.
        dedupe_key = identity if relationship.lower() == "urls" else identity.casefold()
        if not dedupe_key or dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        parsed.append(item)
    return parsed


def _parse_one_ioc(relationship: str, obj: dict[str, Any]) -> Optional[dict[str, str]]:
    attrs = obj.get("attributes") if isinstance(obj.get("attributes"), dict) else {}
    obj_id = str(obj.get("id") or "").strip()
    rel = relationship.lower()
    if rel == "files":
        sha256 = str(attrs.get("sha256") or obj_id)
        if not sha256:
            return None
        sha1 = str(attrs.get("sha1") or "")
        md5 = str(attrs.get("md5") or "")
        name = str(attrs.get("meaningful_name") or "")
        if not name:
            names = attrs.get("names") if isinstance(attrs.get("names"), list) else []
            name = str(names[0]) if names else ""
        ftype = str(attrs.get("type_description") or attrs.get("type_tag") or "")
        return {
            "id": sha256,
            "sha256": sha256,
            "sha1": sha1,
            "md5": md5,
            "name": name,
            "type": ftype,
            "display": sha256,
            "vt_url": f"https://www.virustotal.com/gui/file/{sha256}",
        }
    if rel == "urls":
        url = str(attrs.get("url") or attrs.get("last_final_url") or "")
        display = url or obj_id
        if not display:
            return None
        vt_id = obj_id
        return {
            "id": obj_id,
            "url": url,
            "display": display,
            "vt_url": f"https://www.virustotal.com/gui/url/{vt_id}" if vt_id else "",
        }
    if rel == "domains":
        domain = str(attrs.get("id") or obj_id)
        if not domain:
            return None
        return {
            "id": domain,
            "display": domain,
            "vt_url": f"https://www.virustotal.com/gui/domain/{domain}",
        }
    if rel in {"ip_addresses", "ip_address"}:
        ip = str(attrs.get("ip_address") or attrs.get("id") or obj_id)
        if not ip:
            return None
        return {
            "id": ip,
            "display": ip,
            "vt_url": f"https://www.virustotal.com/gui/ip-address/{ip}",
        }
    return None


def ioc_counter_breakdown(attrs: dict[str, Any]) -> dict[str, int]:
    """Read per-type IoC totals from ``counters`` (preferred) or collection counts."""
    counters = attrs.get("counters") if isinstance(attrs.get("counters"), dict) else {}
    files_n = _as_nonneg_int(_first(counters.get("files"), attrs.get("files_count"), default=0))
    urls_n = _as_nonneg_int(_first(counters.get("urls"), attrs.get("urls_count"), default=0))
    domains_n = _as_nonneg_int(_first(counters.get("domains"), attrs.get("domains_count"), default=0))
    ips_n = _as_nonneg_int(
        _first(counters.get("ip_addresses"), attrs.get("ip_addresses_count"), default=0)
    )
    total = _as_nonneg_int(_first(counters.get("iocs"), default=files_n + urls_n + domains_n + ips_n))
    return {
        "files": files_n,
        "urls": urls_n,
        "domains": domains_n,
        "ip_addresses": ips_n,
        "iocs": total,
    }


def ioc_counter_status(attrs: dict[str, Any], counts: dict[str, int]) -> str:
    """Classify IOC counters as pending, explicit none, or not returned."""
    counters = attrs.get("counters") if isinstance(attrs.get("counters"), dict) else {}
    current_keys = {"iocs", "files", "urls", "domains", "ip_addresses"}
    legacy_keys = {"files_count", "urls_count", "domains_count", "ip_addresses_count"}
    counters_returned = bool(current_keys.intersection(counters)) or bool(
        legacy_keys.intersection(attrs)
    )
    if not counters_returned:
        return "not_returned"
    if counts["iocs"] == 0 and not any(counts[key] for key in IOC_RELATIONSHIPS):
        return "none"
    return "pending"


def attach_iocs(client: "GTIClient", rec: CVERecord, payload: dict[str, Any]) -> None:
    """Fetch relationship IoCs when GTI reports a non-zero count.

    Uses the same session (proxy, CA bundle, throttle, retries) as the
    collection GET. Relationship failures do not fail the CVE record, but are
    retained in ``ioc_status`` / ``ioc_error`` and rendered distinctly from an
    explicit zero count.
    """
    data = payload.get("data") if isinstance(payload, dict) else None
    attrs = (data.get("attributes") if isinstance(data, dict) else None) or {}
    if not isinstance(attrs, dict):
        attrs = {}
    counts = ioc_counter_breakdown(attrs)
    rec.ioc_files_total = counts["files"]
    rec.ioc_urls_total = counts["urls"]
    rec.ioc_domains_total = counts["domains"]
    rec.ioc_ip_addresses_total = counts["ip_addresses"]
    counter_status = ioc_counter_status(attrs, counts)
    if counter_status == "not_returned":
        rec.ioc_status = "not_returned"
        return
    if rec.ioc_count in {"N/A", ""}:
        rec.ioc_count = str(counts["iocs"])
    if counter_status == "none":
        rec.ioc_status = "none"
        return

    wanted: list[str] = [rel for rel in IOC_RELATIONSHIPS if counts.get(rel, 0) > 0]
    if not wanted and counts["iocs"] > 0:
        # Breakdown missing; probe all types and omit empty results later.
        wanted = list(IOC_RELATIONSHIPS)

    field_by_rel = {
        "files": "ioc_files",
        "urls": "ioc_urls",
        "domains": "ioc_domains",
        "ip_addresses": "ioc_ip_addresses",
    }
    failures: list[str] = []
    successes = 0
    for rel in wanted:
        body, err, status = client.get_relationship(rec.cve, rel, limit=IOC_PAGE_SIZE)
        if err or not isinstance(body, dict):
            logging.warning(
                "Could not list %s IoCs for %s (status=%s, err=%s)",
                rel,
                rec.cve,
                status,
                err,
            )
            failures.append(f"{rel}: request failed (HTTP {status or 'n/a'}, {err or 'error'})")
            continue
        try:
            items = parse_relationship_iocs(rel, body)
        except (TypeError, ValueError) as exc:
            logging.warning("Could not parse %s IOCs for %s: %s", rel, rec.cve, exc)
            failures.append(f"{rel}: response parsing failed")
            continue
        successes += 1
        pagination_error = str(body.get("_pagination_error") or "").strip()
        if pagination_error:
            failures.append(f"{rel}: {pagination_error}")
        setattr(rec, field_by_rel[rel], items)
        meta = body.get("meta") if isinstance(body.get("meta"), dict) else {}
        meta_count = _as_nonneg_int(meta.get("count"))
        total_attr = f"ioc_{rel}_total" if rel != "ip_addresses" else "ioc_ip_addresses_total"
        current_total = getattr(rec, total_attr)
        if meta_count > current_total:
            setattr(rec, total_attr, meta_count)
        logging.debug("Fetched %d %s IoC(s) for %s (total=%s)", len(items), rel, rec.cve, getattr(rec, total_attr))

    collected_count = _ioc_record_count(rec)
    reported_count = max(
        counts["iocs"],
        sum(counts[relationship] for relationship in IOC_RELATIONSHIPS),
    )
    if collected_count < reported_count and not failures:
        failures.append(
            f"VirusTotal reported {reported_count} IOC(s), but the relationship "
            f"endpoints returned {collected_count} unique renderable record(s)"
        )
    logging.debug(
        "Collected %d unique IOC record(s) for %s (VirusTotal reported %d)",
        collected_count,
        rec.cve,
        reported_count,
    )

    if failures:
        rec.ioc_status = "partial" if successes else "error"
        rec.ioc_error = "; ".join(failures)
    else:
        rec.ioc_status = "complete"


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
    if state in {"n/a", "none", "unknown", ""}:
        state = "unknown"
    if avail in {"n/a", "none", "unknown", ""}:
        avail = "unknown"

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
    # Every remaining published P0-P4 rule requires a known Exploitation State.
    # Do not convert a missing field into the semantically different "No Known".
    if state == "unknown":
        return "N/A"
    if risk == "high" and state in wide_confirmed_reported:
        return "P0"
    if risk == "medium" and state == "wide":
        return "P0"

    # These rules do not depend on exploit availability and remain valid when
    # that separate API field is absent.
    if risk == "medium" and state in confirmed_reported_suspected:
        return "P1"
    if risk == "low" and state in wide_confirmed:
        return "P1"
    if risk == "low" and state in reported_suspected:
        return "P2"
    if avail == "unknown":
        return "N/A"

    # --- P1 ---
    if risk == "high" and state in suspected_no_known and not _is_no_known(avail):
        return "P1"

    # --- P2 ---
    if risk == "high" and state == "no known" and _is_no_known(avail):
        return "P2"
    if risk == "medium" and state == "no known" and avail in exploit_code_present:
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

    def _get_json(self, url: str, *, context: str) -> tuple[Optional[dict[str, Any]], Optional[str], int]:
        """
        GET ``url`` with the same throttle / retry / proxy / CA-bundle behavior
        used for vulnerability collection fetches.

        Returns:
            (json_body | None, error_kind | None, http_status)
            error_kind in {None, 'not_found', 'forbidden', 'rate_limited',
            'proxy_error', 'tls_error', 'timeout', 'network_error',
            'parse_error', 'error'}

        401/403 are *not* retried: they almost always mean the key lacks
        Vulnerability Intelligence, and retrying would only burn quota.
        429 / 5xx / network (proxy, SSL, DNS) errors *are* retried with
        exponential backoff + jitter so concurrent analyst runs do not
        thundering-herd the API.
        """
        for attempt in range(1, self.max_retries + 1):
            self._throttle()
            try:
                logging.debug("GET %s (attempt %d/%d)", url, attempt, self.max_retries)
                resp = self.session.get(url, timeout=self.timeout)
                self._last_request_at = time.monotonic()
            except requests.RequestException as exc:
                # Network/proxy/SSL failures — backoff then retry
                if isinstance(exc, requests.exceptions.ProxyError):
                    error_kind = "proxy_error"
                elif isinstance(exc, requests.exceptions.SSLError):
                    error_kind = "tls_error"
                elif isinstance(exc, requests.exceptions.Timeout):
                    error_kind = "timeout"
                else:
                    error_kind = "network_error"
                if attempt >= self.max_retries:
                    logging.error(
                        "Network error for %s after %d attempt(s): %s",
                        context,
                        attempt,
                        exc,
                    )
                    return None, error_kind, 0
                wait = self.backoff_base**attempt + random.uniform(0, 1)
                logging.warning(
                    "Network error for %s (attempt %d): %s — retrying in %.1fs",
                    context,
                    attempt,
                    exc,
                    wait,
                )
                time.sleep(wait)
                continue

            if resp.status_code == 200:
                try:
                    return resp.json(), None, 200
                except ValueError:
                    return None, "parse_error", 200

            if resp.status_code == 404:
                # CVE not in GTI collections (too new, unpublished, or out of coverage)
                body_preview = _safe_error_body(resp)
                logging.info("404 Not Found for %s — %s", context, body_preview)
                return None, "not_found", 404

            if resp.status_code in (401, 403):
                # Almost always license/privilege rather than a bad CVE ID
                body_preview = _safe_error_body(resp)
                msg = (
                    f"HTTP {resp.status_code}: access denied for {context}. "
                    "Vulnerability Intelligence requires a Google Threat Intelligence "
                    "(GTI) Enterprise or Enterprise Plus license. "
                    f"API detail: {body_preview}"
                )
                logging.error(msg)
                return None, "forbidden", resp.status_code

            if resp.status_code == 429:
                # Honor Retry-After when the API provides it; else exponential backoff
                if attempt >= self.max_retries:
                    logging.error(
                        "Rate limit persisted for %s after %d attempt(s)",
                        context,
                        attempt,
                    )
                    return None, "rate_limited", 429
                retry_after = resp.headers.get("Retry-After")
                if retry_after and retry_after.isdigit():
                    wait = float(retry_after) + random.uniform(0, 1)
                else:
                    wait = self.backoff_base**attempt + random.uniform(0, 2)
                logging.warning(
                    "Rate limited (429) on %s — attempt %d/%d, sleeping %.1fs",
                    context,
                    attempt,
                    self.max_retries,
                    wait,
                )
                time.sleep(wait)
                continue

            # Transient server faults: retry; other 4xx: surface as error
            body_preview = _safe_error_body(resp)
            if resp.status_code >= 500 and attempt < self.max_retries:
                wait = self.backoff_base**attempt + random.uniform(0, 1)
                logging.warning(
                    "Server error %s for %s — retrying in %.1fs (%s)",
                    resp.status_code,
                    context,
                    wait,
                    body_preview,
                )
                time.sleep(wait)
                continue

            logging.error(
                "Error fetching %s: HTTP %s — %s",
                context,
                resp.status_code,
                body_preview,
            )
            return None, "error", resp.status_code

        return None, "error", 0

    def get_vulnerability(self, cve: str) -> tuple[Optional[dict[str, Any]], Optional[str], int]:
        """Fetch the vulnerability collection object for a CVE."""
        object_id = cve_api_id(cve)
        url = f"{self.base_url}/collections/{object_id}"
        return self._get_json(url, context=cve)

    def get_observed_in_the_wild(
        self,
        cve: str,
    ) -> tuple[Optional[bool], Optional[str], int]:
        """Query the API's documented ``Observed In The Wild`` filter.

        The GUI field is not a documented Vulnerability object attribute. An
        exact filtered search supplies an authoritative boolean while keeping
        a request or parsing failure distinguishable as ``None``.
        """
        filter_text = (
            f'collection_type:vulnerability name:{cve} '
            'vulnerability_filter:"Observed In The Wild"'
        )
        query = urllib.parse.urlencode({"filter": filter_text, "limit": 1})
        url = f"{self.base_url}/collections?{query}"
        body, err, status = self._get_json(
            url,
            context=f"{cve} Observed In The Wild filter",
        )
        if err is not None or body is None:
            return None, err or "error", status
        try:
            return parse_observed_in_the_wild_response(cve, body), None, status
        except (TypeError, ValueError) as exc:
            logging.warning("Could not parse Observed In The Wild result for %s: %s", cve, exc)
            return None, "parse_error", status

    def get_relationship(
        self,
        cve: str,
        relationship: str,
        *,
        limit: int = IOC_PAGE_SIZE,
    ) -> tuple[Optional[dict[str, Any]], Optional[str], int]:
        """Fetch a collection relationship (files / urls / domains / ip_addresses).

        Full related objects (not descriptors-only) so file names, hashes, and
        URL strings are available for the IOC report. Supported ``links.next``
        pagination is followed so all returned objects are retained. Every page
        uses the same TLS/proxy/retry path as ``get_vulnerability``.
        """
        object_id = cve_api_id(cve)
        rel = relationship.strip().strip("/")
        url = f"{self.base_url}/collections/{object_id}/{rel}?limit={int(limit)}"
        expected = urllib.parse.urlparse(url)
        rows: list[Any] = []
        total = 0
        seen_urls: set[str] = set()
        next_url: Optional[str] = url

        while next_url:
            if next_url in seen_urls:
                return {
                    "data": rows,
                    "meta": {"count": max(total, len(rows))},
                    "_pagination_error": "VirusTotal returned a repeated pagination URL",
                }, None, 200
            seen_urls.add(next_url)

            body, err, status = self._get_json(next_url, context=f"{cve}/{rel}")
            if err or not isinstance(body, dict):
                if rows:
                    return {
                        "data": rows,
                        "meta": {"count": max(total, len(rows))},
                        "_pagination_error": (
                            f"pagination request failed (HTTP {status or 'n/a'}, {err or 'error'})"
                        ),
                    }, None, 200
                return body, err, status

            page_rows = body.get("data")
            if not isinstance(page_rows, list):
                if rows:
                    return {
                        "data": rows,
                        "meta": {"count": max(total, len(rows))},
                        "_pagination_error": "paginated response had no data list",
                    }, None, 200
                return body, None, status
            rows.extend(page_rows)
            meta = body.get("meta") if isinstance(body.get("meta"), dict) else {}
            total = max(total, _as_nonneg_int(meta.get("count")), len(rows))
            links = body.get("links") if isinstance(body.get("links"), dict) else {}
            candidate = str(links.get("next") or "").strip()
            if not candidate:
                next_url = None
                continue

            candidate = urllib.parse.urljoin(next_url, candidate)
            parsed = urllib.parse.urlparse(candidate)
            # A pagination URL comes from API data but is sent with x-apikey;
            # constrain it to the exact configured origin and relationship path.
            if (
                parsed.scheme.casefold() != expected.scheme.casefold()
                or parsed.netloc.casefold() != expected.netloc.casefold()
                or parsed.path != expected.path
            ):
                return {
                    "data": rows,
                    "meta": {"count": max(total, len(rows))},
                    "_pagination_error": "VirusTotal returned an unsafe pagination URL",
                }, None, 200
            next_url = candidate

        return {"data": rows, "meta": {"count": max(total, len(rows))}}, None, 200


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
    exploitation_state_raw = _first(
        attrs.get("exploitation_state"),
        exploitation.get("exploitation_state"),
        default=None,
    )
    state_level, state_label = normalize_exploitation_state(exploitation_state_raw)
    exploit_availability_raw = _first(
        attrs.get("exploit_availability"),
        exploitation.get("exploit_availability"),
        default=None,
    )
    availability_level, exploit_availability = normalize_exploit_availability(
        exploit_availability_raw
    )
    exploited_zero_day = _first(
        attrs.get("exploited_as_zero_day"),
        attrs.get("zero_day"),
        exploitation.get("exploited_as_zero_day"),
        default=None,
    )

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

    # The documented API source for the GUI flag is a separate vulnerability
    # filter query. Preserve any explicit object value here, otherwise Unknown;
    # enrich_cves() applies the authoritative filter result afterward.
    log_exploitation_debug(cve, attrs)
    exploited_in_wild, wild_sources, wild_explicit = derive_exploited_in_the_wild(
        attrs,
        exploitation=exploitation,
        tags=attrs.get("tags"),
    )
    wild_status = "object_returned" if wild_sources else "not_returned"

    # --- Risk / priority ---
    # API documents priority as boolean; the GTI UI shows P0–P4 — we derive that.
    risk_level, risk_rating = normalize_risk_rating(attrs.get("risk_rating"))
    predicted = na(attrs.get("predicted_risk_rating"))
    risk_factors = na(attrs.get("risk_factors"))
    priority_raw = attrs.get("priority")
    if isinstance(priority_raw, bool):
        priority_raw_str = "True" if priority_raw else "False"
    else:
        priority_raw_str = na(priority_raw)

    priority_rating = derive_priority_rating(
        risk_rating,
        state_label,
        exploit_availability,
    )
    # Prefer an explicit P0–P4 string if the API ever supplies one
    if isinstance(priority_raw, str) and re.match(r"^P[0-4]$", priority_raw.strip(), re.I):
        priority_rating = priority_raw.strip().upper()

    # --- Products (CPE ranges) ---
    products_str, products_count = _format_cpes(attrs.get("cpes"))

    # --- CWE ---
    cwe = attrs.get("cwe") if isinstance(attrs.get("cwe"), dict) else {}

    # --- Counters (IoCs, etc.) — counts only; objects come from relationships ---
    ioc_counts = ioc_counter_breakdown(attrs)
    ioc_status = ioc_counter_status(attrs, ioc_counts)

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
        risk_rating_level="N/A" if risk_level is None else str(risk_level),
        predicted_risk_rating=predicted,
        risk_factors=risk_factors,
        exploitation_state=state_label,
        exploitation_state_level="N/A" if state_level is None else str(state_level),
        exploit_availability=exploit_availability,
        exploit_availability_level=(
            "N/A" if availability_level is None else str(availability_level)
        ),
        exploited_in_the_wild=exploited_in_wild,
        exploited_in_the_wild_status=wild_status,
        exploited_in_the_wild_sources="; ".join(wild_sources),
        exploited_in_the_wild_explicit=wild_explicit,
        exploited_as_zero_day=na(exploited_zero_day, default="Unknown"),
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
        ioc_count="N/A" if ioc_status == "not_returned" else str(ioc_counts["iocs"]),
        ioc_status=ioc_status,
        ioc_files_total=ioc_counts["files"],
        ioc_urls_total=ioc_counts["urls"],
        ioc_domains_total=ioc_counts["domains"],
        ioc_ip_addresses_total=ioc_counts["ip_addresses"],
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
        "exploited_in_the_wild_normalized": exploited_in_wild,
        "exploited_in_the_wild_status": wild_status,
        "exploited_in_the_wild_sources": wild_sources,
        "ioc_status": ioc_status,
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


def _ioc_anchor_id(cve: str) -> str:
    """Create a stable, attribute-safe anchor for a CVE's IOC section."""
    cleaned = re.sub(r"[^A-Za-z0-9_.:-]+", "-", str(cve).strip().upper()).strip("-")
    return cleaned or "IOC"


def default_ioc_report_path(primary_path: Path) -> Path:
    """Place the run's IOC report beside the primary report."""
    candidate = primary_path.with_name(DEFAULT_IOC_HTML)
    if candidate.resolve() == primary_path.resolve():
        candidate = primary_path.with_name(f"{primary_path.stem}_ioc_report.html")
    return candidate


def _report_targets(
    records: list[CVERecord],
    primary_path: Path,
    ioc_path: Path,
) -> list[tuple[list[CVERecord], Path, Path]]:
    """Map records to report files, retaining legacy paths for zero/one CVE."""
    if len(records) <= 1:
        return [(records, primary_path, ioc_path)]

    targets: list[tuple[list[CVERecord], Path, Path]] = []
    for rec in records:
        safe_cve = _ioc_anchor_id(rec.cve)
        targets.append(
            (
                [rec],
                primary_path.with_name(f"{safe_cve}_report.html"),
                ioc_path.with_name(f"{safe_cve}_iocs.html"),
            )
        )
    return targets


def _relative_report_href(source_path: Path, target_path: Path) -> str:
    """Return a URL-encoded relative link suitable for local ``file://`` use."""
    try:
        relative = os.path.relpath(target_path.resolve(), start=source_path.parent.resolve())
    except ValueError as exc:
        raise ValueError("Primary and IOC reports must be written on the same drive") from exc
    return urllib.parse.quote(Path(relative).as_posix(), safe="/._-~")


def _html_bool(value: str) -> str:
    """Render a boolean-ish string as a colored YES/no badge."""
    v = str(value).strip().lower()
    if v in {"true", "yes", "1"}:
        return '<span class="badge badge-danger">YES</span>'
    if v in {"false", "no", "0"}:
        return '<span class="badge badge-muted">no</span>'
    return f'<span class="badge badge-muted">{_html_escape(str(value))}</span>'


EXPLOITATION_STATE_DEFINITION = (
    "Indicates our knowledge of the current exploitation landscape, and whether "
    "a vulnerability is known or suspected to be exploited."
)
EXPLOITATION_STATE_LEGEND = (
    "0 = No known | 1 = Suspected | 2 = Reported | 3 = Confirmed | 4 = Wide"
)
PRIORITY_VIZ_CAPTION = (
    "Vulnerability severity visualization is based on (1) its potential impact, "
    "(2) whether a functional exploit exists and is accessible to potential attackers, "
    "(3) whether it is being actively used by attackers in real-world attacks."
)


def _html_info_icon(tooltip_text: str, *, aria_label: str) -> str:
    """Self-contained info icon with title + CSS hover/focus tooltip (no JS framework)."""
    title = _html_escape(tooltip_text)
    # Preserve line breaks inside the CSS tooltip bubble.
    body = "<br/>".join(_html_escape(line) if line else "&nbsp;" for line in tooltip_text.split("\n"))
    return (
        f'<span class="info-tip" tabindex="0" title="{title}" '
        f'role="img" aria-label="{_html_escape(aria_label)}">'
        f'<span class="info-tip-mark" aria-hidden="true">i</span>'
        f'<span class="info-tip-bubble">{body}</span>'
        f"</span>"
    )


def _html_exploit_state_class(state: str) -> str:
    key = _norm_label(state).replace(" ", "")
    return {
        "wide": "wide",
        "confirmed": "confirmed",
        "reported": "reported",
        "suspected": "suspected",
        "noknown": "noknown",
        "unknown": "unknown",
    }.get(key, "unknown")


def _priority_level(value: str) -> Optional[int]:
    """Parse a normalized record level without coercing missing data to zero."""
    try:
        level = int(value)
    except (TypeError, ValueError):
        return None
    return level if 0 <= level <= 4 else None


def _svg_axis_point(
    origin: tuple[float, float],
    endpoint: tuple[float, float],
    level: int,
) -> tuple[float, float]:
    fraction = level / 4
    return (
        origin[0] + (endpoint[0] - origin[0]) * fraction,
        origin[1] + (endpoint[1] - origin[1]) * fraction,
    )


def _html_priority_svg(rec: CVERecord) -> str:
    """Render the three normalized GTI metrics as an offline inline SVG."""
    origin = (250.0, 220.0)
    axes = {
        "risk": ((250.0, 54.0), _priority_level(rec.risk_rating_level)),
        "availability": ((75.0, 321.0), _priority_level(rec.exploit_availability_level)),
        "state": ((425.0, 321.0), _priority_level(rec.exploitation_state_level)),
    }

    axis_lines = []
    tick_labels = []
    value_markers = []
    points: list[tuple[float, float]] = []
    for axis_name, (endpoint, level) in axes.items():
        axis_lines.append(
            f'<line class="priority-axis" x1="{origin[0]:g}" y1="{origin[1]:g}" '
            f'x2="{endpoint[0]:g}" y2="{endpoint[1]:g}"/>'
        )
        for tick in range(1, 5):
            tx, ty = _svg_axis_point(origin, endpoint, tick)
            if axis_name == "risk":
                label_x, label_y, anchor = tx + 12, ty + 5, "start"
            elif axis_name == "availability":
                label_x, label_y, anchor = tx - 6, ty + 5, "end"
            else:
                label_x, label_y, anchor = tx + 6, ty + 5, "start"
            tick_labels.append(
                f'<text class="priority-tick" x="{label_x:g}" y="{label_y:g}" '
                f'text-anchor="{anchor}">{tick}</text>'
            )
        if level is not None:
            px, py = _svg_axis_point(origin, endpoint, level)
            points.append((px, py))
            value_markers.append(
                f'<circle class="priority-marker" cx="{px:g}" cy="{py:g}" r="8" '
                f'data-axis="{axis_name}" data-level="{level}"/>'
            )

    polygon = ""
    if len(points) == 3:
        point_text = " ".join(f"{x:g},{y:g}" for x, y in points)
        polygon = f'<polygon class="priority-shape" points="{point_text}"/>'

    accessible = _html_escape(
        "Priority metrics: "
        f"Risk Rating {rec.risk_rating} level {rec.risk_rating_level}; "
        f"Exploit Availability {rec.exploit_availability} level "
        f"{rec.exploit_availability_level}; Exploitation State "
        f"{rec.exploitation_state} level {rec.exploitation_state_level}."
    )
    return f"""
      <svg class="priority-chart" viewBox="0 0 500 380" role="img" aria-labelledby="priority-title-{_ioc_anchor_id(rec.cve)}">
        <title id="priority-title-{_ioc_anchor_id(rec.cve)}">{accessible}</title>
        <g>{''.join(axis_lines)}</g>
        {polygon}
        <g>{''.join(tick_labels)}</g>
        <g>{''.join(value_markers)}</g>
        <circle class="priority-origin" cx="250" cy="220" r="4"/>
        <text class="priority-axis-label" x="250" y="24" text-anchor="middle">Risk Rating</text>
        <text class="priority-axis-label" x="12" y="368" text-anchor="start">Exploit Availability</text>
        <text class="priority-axis-label" x="488" y="368" text-anchor="end">Exploitation State</text>
      </svg>
"""


def _html_priority_viz(rec: CVERecord) -> str:
    """Dynamic Y-axis visualization plus the three GTI priority inputs."""
    pri_cls = _html_risk_class(rec.priority_rating)
    cvss_bits = []
    if rec.cvss_v3_base != "N/A":
        cvss_bits.append(f"CVSSv3.1 {_html_escape(rec.cvss_v3_base)}")
    if rec.cvss_v4_score != "N/A":
        cvss_bits.append(f"CVSSv4 {_html_escape(rec.cvss_v4_score)}")
    cvss_line = " · ".join(cvss_bits) if cvss_bits else "N/A"
    tip = _html_info_icon(PRIORITY_VIZ_CAPTION, aria_label="Priority visualization criteria")
    return f"""
  <section class="priority-viz" aria-label="Priority visualization">
    <div class="priority-viz-head">
      <h3>Priority visualization {tip}</h3>
      <span class="badge badge-{pri_cls} badge-lg">{_html_escape(rec.priority_rating)}</span>
    </div>
    <p class="priority-viz-caption">{_html_escape(PRIORITY_VIZ_CAPTION)}</p>
    <div class="priority-viz-body">
      <div class="priority-chart-wrap">{_html_priority_svg(rec)}</div>
      <div class="priority-inputs">
        <div class="priority-input">
          <div class="metric-label">1 · Potential impact</div>
          <div class="metric-value-sm">{_html_escape(rec.risk_rating)}</div>
          <div class="metric-sub">Risk rating level {_html_escape(rec.risk_rating_level)}
            · Predicted {_html_escape(rec.predicted_risk_rating)}
            · {cvss_line}</div>
        </div>
        <div class="priority-input">
          <div class="metric-label">2 · Exploit accessibility</div>
          <div class="metric-value-sm">{_html_escape(rec.exploit_availability)}</div>
          <div class="metric-sub">Exploit Availability level {_html_escape(rec.exploit_availability_level)}</div>
        </div>
        <div class="priority-input">
          <div class="metric-label">3 · Real-world use</div>
          <div class="metric-value-sm">{_html_escape(rec.exploitation_state)}
            · {_html_bool(rec.exploited_in_the_wild)}</div>
          <div class="metric-sub">Exploitation State level {_html_escape(rec.exploitation_state_level)}</div>
        </div>
      </div>
    </div>
  </section>
"""


def _html_wild_status_note(rec: CVERecord) -> str:
    """Explain unavailable lookups and any object/filter disagreement."""
    if rec.exploited_in_the_wild_status == "lookup_failed":
        return (
            '<div class="debug-note">Observed In The Wild lookup failed; '
            "the result remains Unknown unless an explicit object value was returned.</div>"
        )
    if rec.exploited_in_the_wild_status == "not_returned":
        return (
            '<div class="debug-note">Not returned by the vulnerability object; '
            "the Observed In The Wild filter was not queried.</div>"
        )

    explicit = (rec.exploited_in_the_wild_explicit or "N/A").strip()
    filtered = rec.exploited_in_the_wild
    if rec.exploited_in_the_wild_status != "filter_returned" or explicit in {"N/A", ""}:
        return ""
    explicit_yes = explicit.lower() in {"true", "yes", "1"}
    filtered_yes = str(filtered).lower() in {"true", "yes", "1"}
    if explicit_yes == filtered_yes:
        return ""
    sources = rec.exploited_in_the_wild_sources or "(none)"
    return (
        f'<div class="debug-note">Observed In The Wild filter: {"Yes" if filtered_yes else "No"} · '
        f"explicit field: {_html_escape(explicit)} · source fields: {_html_escape(sources)}</div>"
    )


def _html_ioc_link(item: dict[str, str]) -> str:
    display = _html_escape(item.get("display") or item.get("id") or "")
    href = (item.get("vt_url") or "").strip()
    parsed = urllib.parse.urlparse(href)
    if (
        parsed.scheme == "https"
        and parsed.hostname
        and parsed.hostname.casefold() in {"virustotal.com", "www.virustotal.com"}
    ):
        return f'<a class="mono" href="{_html_escape(href)}" target="_blank" rel="noopener noreferrer">{display}</a>'
    return f'<span class="mono">{display}</span>'


def _ioc_record_count(rec: CVERecord) -> int:
    """Return the number of unique IOC records available to the renderer."""
    return sum(
        len(items)
        for items in (
            rec.ioc_files,
            rec.ioc_urls,
            rec.ioc_domains,
            rec.ioc_ip_addresses,
        )
    )


def _html_ioc_table(
    title: str,
    items: list[dict[str, str]],
    total: int,
    *,
    kind: str,
) -> str:
    if not items and total <= 0:
        return ""
    shown = items
    rendered_count = len(shown)
    if not shown:
        return (
            f"<h4>{_html_escape(title)} <span class='muted'>(0)</span></h4>"
            f"<p class='muted'>Count reported by GTI, but no objects were returned for this type.</p>"
        )
    if kind == "files":
        head = "<tr><th>IOC Type</th><th>IOC Value</th><th>SHA-1 / MD5</th><th>Context</th></tr>"
        body_rows = []
        for it in shown:
            hashes = " / ".join(h for h in (it.get("sha1") or "", it.get("md5") or "") if h)
            name = it.get("name") or ""
            ftype = it.get("type") or ""
            name_type = " · ".join(p for p in (name, ftype) if p) or "—"
            body_rows.append(
                '<tr class="ioc-record">'
                "<td>SHA-256</td>"
                f"<td>{_html_ioc_link(it)}</td>"
                f"<td class='mono muted'>{_html_escape(hashes) if hashes else '—'}</td>"
                f"<td>{_html_escape(name_type)}</td>"
                "</tr>"
            )
        body = "".join(body_rows)
    else:
        type_label = {
            "urls": "URL",
            "domains": "Domain",
            "ipv4": "IPv4 address",
            "ipv6": "IPv6 address",
            "other": "Unclassified",
        }.get(kind, "Indicator")
        head = "<tr><th>IOC Type</th><th>IOC Value</th></tr>"
        body = "".join(
            f'<tr class="ioc-record"><td>{_html_escape(type_label)}</td><td>{_html_ioc_link(it)}</td></tr>'
            for it in shown
        )
    more_line = ""
    if total and total != rendered_count:
        more_line = (
            f"<p class='muted ioc-more'>VirusTotal reports {total} object(s); "
            f"the API returned {rendered_count} unique renderable record(s) for this run.</p>"
        )
    return f"""
    <h4>{_html_escape(title)} <span class="muted">({rendered_count})</span></h4>
    <div class="ioc-wrap">
      <table class="ioc"><thead>{head}</thead><tbody>{body}</tbody></table>
    </div>
    {more_line}
"""


def _partition_ip_iocs(
    items: list[dict[str, str]],
) -> tuple[list[dict[str, str]], list[dict[str, str]], list[dict[str, str]]]:
    """Classify returned IP relationship objects deterministically."""
    ipv4: list[dict[str, str]] = []
    ipv6: list[dict[str, str]] = []
    other: list[dict[str, str]] = []
    for item in items:
        value = (item.get("display") or item.get("id") or "").strip()
        try:
            parsed = ipaddress.ip_address(value)
        except ValueError:
            other.append(item)
        else:
            (ipv4 if parsed.version == 4 else ipv6).append(item)
    return ipv4, ipv6, other


def _html_ioc_detail_section(rec: CVERecord) -> str:
    """Render IOC objects while preserving none/absent/error distinctions."""
    rendered_count = _ioc_record_count(rec)
    heading = (
        'Indicators of Compromise: '
        f'<span class="ioc-count">{rendered_count}</span>'
    )
    ipv4, ipv6, other_ips = _partition_ip_iocs(rec.ioc_ip_addresses)
    blocks = [
        _html_ioc_table("Files", rec.ioc_files, rec.ioc_files_total, kind="files"),
        _html_ioc_table("URLs", rec.ioc_urls, rec.ioc_urls_total, kind="urls"),
        _html_ioc_table("Domains", rec.ioc_domains, rec.ioc_domains_total, kind="domains"),
        _html_ioc_table("IPv4 addresses", ipv4, len(ipv4), kind="ipv4"),
        _html_ioc_table("IPv6 addresses", ipv6, len(ipv6), kind="ipv6"),
        _html_ioc_table("Other / unclassified", other_ips, len(other_ips), kind="other"),
    ]
    nonempty = [b for b in blocks if b]
    status_note = ""
    if rec.ioc_status in {"partial", "error"}:
        detail = rec.ioc_error or "VirusTotal did not return the requested IOC relationships."
        status_note = (
            '<p class="ioc-error" role="alert">IOC retrieval failed or was incomplete: '
            f"{_html_escape(detail)}</p>"
        )
    if nonempty:
        return f"""
  <section class="iocs">
    <h3>{heading}</h3>
    {status_note}
    {"".join(nonempty)}
  </section>
"""
    if rec.ioc_status in {"partial", "error"}:
        return f"""
  <section class="iocs">
    <h3>{heading}</h3>
    {status_note}
  </section>
"""
    if rec.ioc_status == "not_returned":
        return f"""
  <section class="iocs">
    <h3>{heading}</h3>
    <p class="muted">IOC availability was not returned by VirusTotal.</p>
  </section>
"""
    reported = rec.ioc_files_total + rec.ioc_urls_total + rec.ioc_domains_total + rec.ioc_ip_addresses_total
    if reported <= 0:
        try:
            reported = int(rec.ioc_count) if rec.ioc_count not in {"N/A", ""} else 0
        except (TypeError, ValueError):
            reported = 0
    if reported > 0:
        return f"""
  <section class="iocs">
    <h3>{heading}</h3>
    <p class="muted">VirusTotal reports {reported} associated IOC(s), but no relationship objects were returned.</p>
  </section>
"""
    return f"""
  <section class="iocs">
    <h3>{heading}</h3>
    <p class="muted">No associated IOCs returned by VirusTotal.</p>
  </section>
"""


def _html_ioc_summary(rec: CVERecord, report_href: str) -> str:
    """Render only status/count and a deep-link; IOC payloads stay out of the main report."""
    anchor = urllib.parse.quote(_ioc_anchor_id(rec.cve), safe="-._~")
    href = f"{report_href}#{anchor}"
    if rec.ioc_status == "none":
        status = "No associated IOCs returned by VirusTotal."
    elif rec.ioc_status == "not_returned":
        status = "IOC availability was not returned by VirusTotal."
    elif rec.ioc_status in {"partial", "error"}:
        status = "IOC retrieval failed or was incomplete; see the IOC report for details."
    else:
        count = str(_ioc_record_count(rec))
        status = f"{count} associated indicator(s)."
    return f"""
  <section class="iocs ioc-summary">
    <h3>Indicators of Compromise</h3>
    <p>{_html_escape(status)}</p>
    <a class="ioc-report-link" href="{_html_escape(href)}" target="_blank" rel="noopener noreferrer">View IOC Report ↗</a>
  </section>
"""


def render_ioc_report(
    records: list[CVERecord],
    path: Path,
    title: str = "GTI IOC Report",
    *,
    primary_report_path: Optional[Path] = None,
    fatal_error: Optional[str] = None,
) -> None:
    """Write one standalone IOC report containing an anchored section per CVE."""
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    primary_path = primary_report_path or path.with_name(DEFAULT_HTML)
    primary_href = _relative_report_href(path, primary_path)
    expected_rendered_count = sum(
        _ioc_record_count(rec) for rec in records if rec.status == "ok"
    )

    nav_links: list[str] = []
    sections: list[str] = []
    for rec in records:
        anchor = _ioc_anchor_id(rec.cve)
        encoded_anchor = urllib.parse.quote(anchor, safe="-._~")
        nav_links.append(
            f'<a class="chip" href="#{_html_escape(encoded_anchor)}">{_html_escape(rec.cve)}</a>'
        )
        if rec.status != "ok":
            content = (
                '<p class="ioc-error" role="alert">IOC data is unavailable because '
                f'enrichment failed: {_html_escape(rec.error_message or rec.status)}</p>'
            )
        else:
            content = _html_ioc_detail_section(rec)
        sections.append(
            f"""
    <article class="card" id="{_html_escape(anchor)}">
      <header class="card-header">
        <div><div class="eyebrow">CVE Identifier</div><h2>{_html_escape(rec.cve)}</h2></div>
        <a href="{_html_escape(primary_href)}" rel="noopener">Back to primary report</a>
      </header>
      {content}
    </article>
"""
        )

    fatal_section = ""
    if fatal_error:
        fatal_section = f"""
    <section class="fatal-banner" role="alert">
      <h2>Run failed</h2>
      <p>The IOC report was still generated so the run has a complete audit trail.</p>
      <pre>{_html_escape(fatal_error)}</pre>
    </section>
"""
    empty = '<p class="muted">No CVE records were produced for this run.</p>'
    doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>{_html_escape(title)}</title>
<style>
  :root {{
    --bg: #0b1220; --surface: #121a2b; --surface-2: #1a2438;
    --text: #e8eefc; --muted: #8b9bb8; --border: #2a3754;
    --accent: #38bdf8; --danger: #ef4444;
  }}
  * {{ box-sizing: border-box; }}
  html {{ scroll-behavior: smooth; }}
  body {{
    margin: 0; min-height: 100vh; color: var(--text); line-height: 1.5;
    font-family: "Segoe UI", system-ui, -apple-system, sans-serif;
    background: radial-gradient(1200px 600px at 10% -10%, #1e293b 0%, var(--bg) 55%);
  }}
  .wrap {{ max-width: 1100px; margin: 0 auto; padding: 2rem 1.25rem 4rem; }}
  .page-header {{ border-bottom: 1px solid var(--border); margin-bottom: 1.5rem; padding-bottom: 1rem; }}
  h1 {{ margin: 0 0 0.35rem; font-size: 1.75rem; }}
  h2 {{ margin: 0; font-size: 1.3rem; }}
  h3 {{ margin: 1rem 0 0.5rem; color: var(--accent); font-size: 0.95rem; letter-spacing: 0.06em; text-transform: uppercase; }}
  h4 {{ margin: 0.9rem 0 0.4rem; font-size: 0.9rem; color: #dbeafe; }}
  a {{ color: var(--accent); text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}
  .muted {{ color: var(--muted); }}
  .meta {{ color: var(--muted); font-size: 0.9rem; }}
  .eyebrow {{ color: var(--muted); font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.08em; }}
  .nav {{ display: flex; flex-wrap: wrap; gap: 0.45rem; margin-top: 0.9rem; }}
  .chip {{ padding: 0.25rem 0.6rem; border: 1px solid var(--border); border-radius: 999px; background: var(--surface-2); font-size: 0.8rem; }}
  .card {{
    scroll-margin-top: 1rem; margin-bottom: 1.25rem; padding: 1.2rem 1.3rem;
    border: 1px solid var(--border); border-left: 5px solid var(--accent);
    border-radius: 14px; background: linear-gradient(180deg, var(--surface), #0f172a);
    box-shadow: 0 10px 30px rgba(0,0,0,0.25);
  }}
  .card-header {{ display: flex; justify-content: space-between; align-items: flex-start; gap: 1rem; }}
  .iocs > h3 {{ margin-top: 1.1rem; }}
  .ioc-wrap {{ overflow-x: auto; border: 1px solid var(--border); border-radius: 10px; background: #0d1628; }}
  table.ioc {{ width: 100%; border-collapse: collapse; font-size: 0.84rem; }}
  table.ioc th {{ padding: 0.45rem 0.55rem; text-align: left; color: var(--muted); border-bottom: 1px solid var(--border); }}
  table.ioc td {{ padding: 0.45rem 0.55rem; vertical-align: top; border-bottom: 1px solid #1e293b; word-break: break-all; }}
  table.ioc tr:last-child td {{ border-bottom: 0; }}
  .mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; user-select: text; }}
  .ioc-more {{ margin: 0.45rem 0; font-size: 0.8rem; }}
  .ioc-error, .fatal-banner {{ color: #fecaca; background: #3f0d0d; border: 1px solid #7f1d1d; border-radius: 10px; padding: 0.7rem 0.85rem; }}
  .fatal-banner {{ margin-bottom: 1.25rem; }}
  .fatal-banner pre {{ white-space: pre-wrap; word-break: break-word; font-size: 0.78rem; }}
  footer {{ margin-top: 2rem; padding-top: 1rem; border-top: 1px solid var(--border); color: var(--muted); font-size: 0.8rem; }}
  @media (max-width: 700px) {{ .card-header {{ flex-direction: column; }} }}
</style>
</head>
<body>
  <main class="wrap">
    <header class="page-header">
      <h1>{_html_escape(title)}</h1>
      <div class="meta">Generated {generated} · {len(records)} CVE(s) · Indicators of Compromise: {expected_rendered_count}</div>
      <div class="nav">{''.join(nav_links)}</div>
    </header>
    {fatal_section}
    {''.join(sections) if sections else empty}
    <footer>
      IOC objects were collected during the same enrichment run as the primary report.
      Values are shown in full and grouped only by their VirusTotal relationship type.
    </footer>
  </main>
</body>
</html>
"""
    actual_rendered_count = doc.count('class="ioc-record"')
    if actual_rendered_count != expected_rendered_count:
        raise RuntimeError(
            "IOC report rendering mismatch: "
            f"received {expected_rendered_count} record(s), rendered {actual_rendered_count}"
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(doc, encoding="utf-8")
    logging.info("Wrote IOC report: %s", path)


def render_html_report(
    records: list[CVERecord],
    path: Path,
    title: str = "GTI CVE Enrichment Report",
    *,
    fatal_error: Optional[str] = None,
    ioc_report_path: Optional[Path] = None,
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
    resolved_ioc_path = ioc_report_path or default_ioc_report_path(path)
    ioc_report_href = _relative_report_href(path, resolved_ioc_path)
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
  {_html_ioc_summary(rec, ioc_report_href)}
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

        state_tip_text = f"{EXPLOITATION_STATE_DEFINITION}\n\n{EXPLOITATION_STATE_LEGEND}"
        state_icon = _html_info_icon(
            state_tip_text,
            aria_label=EXPLOITATION_STATE_DEFINITION,
        )
        state_cls = _html_exploit_state_class(rec.exploitation_state)
        level_bit = (
            f'<span class="muted"> (level { _html_escape(rec.exploitation_state_level)})</span>'
            if rec.exploitation_state_level not in {"N/A", ""}
            else ""
        )
        wild_note = _html_wild_status_note(rec)
        ioc_section = _html_ioc_summary(rec, ioc_report_href)
        priority_viz = _html_priority_viz(rec)

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

  {priority_viz}

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
        <tr>
          <th>Exploitation State {state_icon}</th>
          <td>
            <strong class="exploit-state exploit-{state_cls}">{_html_escape(rec.exploitation_state)}</strong>{level_bit}
            <div class="metric-sub">{_html_escape(EXPLOITATION_STATE_LEGEND)}</div>
          </td>
        </tr>
        <tr><th>Exploit Availability</th><td>{_html_escape(rec.exploit_availability)}</td></tr>
        <tr><th>Exploited in the Wild</th><td>{_html_bool(rec.exploited_in_the_wild)}{wild_note}</td></tr>
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
        <tr><th>CWE</th><td>{_html_escape(rec.cwe_id)} — {_html_escape(rec.cwe_title)}</td></tr>
        <tr><th>Disclosure</th><td>{_html_escape(rec.date_of_disclosure)}</td></tr>
        <tr><th>Last Modified</th><td>{_html_escape(rec.last_modification_date)}</td></tr>
        <tr><th>IoCs</th><td>{_html_escape(rec.ioc_count)}</td></tr>
        <tr><th>API priority</th><td>{_html_escape(rec.priority_raw)}</td></tr>
        <tr><th>VT collection</th><td><a href="{_html_escape(rec.vt_url)}" target="_blank" rel="noopener">Open in VirusTotal</a></td></tr>
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

  {ioc_section}

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
  .info-tip {{
    position: relative;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 1.05rem;
    height: 1.05rem;
    margin-left: 0.25rem;
    vertical-align: middle;
    cursor: help;
    outline: none;
  }}
  .info-tip-mark {{
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 1.05rem;
    height: 1.05rem;
    border-radius: 50%;
    border: 1px solid var(--accent);
    color: var(--accent);
    font-size: 0.68rem;
    font-weight: 800;
    font-style: italic;
    line-height: 1;
    background: #0c1929;
  }}
  .info-tip-bubble {{
    display: none;
    position: absolute;
    z-index: 30;
    left: 0;
    top: calc(100% + 8px);
    width: 22rem;
    max-width: min(22rem, 75vw);
    padding: 0.7rem 0.85rem;
    background: #0b0f18;
    border: 1px solid var(--border);
    border-radius: 10px;
    color: var(--text);
    font-size: 0.78rem;
    font-weight: 400;
    text-transform: none;
    letter-spacing: 0;
    line-height: 1.45;
    box-shadow: 0 12px 32px rgba(0,0,0,0.45);
    white-space: normal;
  }}
  .info-tip:hover .info-tip-bubble,
  .info-tip:focus .info-tip-bubble,
  .info-tip:focus-within .info-tip-bubble {{
    display: block;
  }}
  .exploit-state.exploit-wide {{ color: #f87171; }}
  .exploit-state.exploit-confirmed {{ color: #fb923c; }}
  .exploit-state.exploit-reported {{ color: #fbbf24; }}
  .exploit-state.exploit-suspected {{ color: #93c5fd; }}
  .exploit-state.exploit-noknown,
  .exploit-state.exploit-unknown {{ color: var(--muted); }}
  .priority-viz {{
    background: var(--surface-2);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 0.85rem 1rem 1rem;
    margin-bottom: 1rem;
  }}
  .priority-viz-head {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 0.75rem;
  }}
  .priority-viz-head h3 {{ margin: 0; }}
  .priority-viz-caption {{
    color: var(--muted);
    font-size: 0.82rem;
    margin: 0.55rem 0 0.8rem;
  }}
  .priority-viz-body {{
    display: grid;
    grid-template-columns: minmax(320px, 1.25fr) minmax(260px, 0.75fr);
    gap: 1rem;
    align-items: center;
  }}
  .priority-chart-wrap {{
    min-width: 0;
    background: #111b30;
    border: 1px solid #334361;
    border-radius: 10px;
    padding: 0.35rem;
  }}
  .priority-chart {{ display: block; width: 100%; height: auto; max-height: 26rem; }}
  .priority-axis {{ stroke: #435777; stroke-width: 7; stroke-linecap: square; }}
  .priority-shape {{
    fill: rgba(255, 93, 83, 0.13);
    stroke: #ff5d53;
    stroke-width: 6;
    stroke-linejoin: round;
  }}
  .priority-marker {{ fill: #ff5d53; stroke: #ffd2cf; stroke-width: 1.5; }}
  .priority-origin {{ fill: #435777; }}
  .priority-tick {{ fill: #d8e1f1; font-size: 17px; }}
  .priority-axis-label {{ fill: #f4f7ff; font-size: 20px; font-weight: 500; }}
  .priority-inputs {{
    display: grid;
    grid-template-columns: 1fr;
    gap: 0.65rem;
  }}
  .priority-input {{
    background: #0f172a;
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 0.65rem 0.75rem;
  }}
  .metric-value-sm {{
    font-size: 1.02rem;
    font-weight: 700;
    margin-top: 0.2rem;
  }}
  @media (max-width: 800px) {{
    .priority-viz-body {{ grid-template-columns: 1fr; }}
  }}
  .debug-note {{
    margin-top: 0.35rem;
    font-size: 0.75rem;
    color: #fcd34d;
  }}
  table.ioc {{
    width: 100%;
    border-collapse: collapse;
    font-size: 0.82rem;
  }}
  table.ioc th {{
    text-align: left;
    color: var(--muted);
    font-weight: 600;
    padding: 0.35rem 0.5rem;
    border-bottom: 1px solid var(--border);
  }}
  table.ioc td {{
    padding: 0.35rem 0.5rem;
    border-bottom: 1px solid #1e293b;
    vertical-align: top;
    word-break: break-all;
  }}
  .ioc-wrap {{
    overflow-x: auto;
    border: 1px solid var(--border);
    border-radius: 10px;
    background: #0f172a;
  }}
  h4 {{
    margin: 0.85rem 0 0.4rem;
    font-size: 0.88rem;
    color: var(--text);
  }}
  .ioc-more {{ margin: 0.4rem 0 0.2rem; font-size: 0.8rem; }}
  .ioc-error {{
    color: #fecaca;
    background: #3f0d0d;
    border: 1px solid #7f1d1d;
    border-radius: 8px;
    padding: 0.55rem 0.7rem;
  }}
  .ioc-summary {{
    border-top: 1px solid var(--border);
    margin-top: 1rem;
    padding-top: 0.15rem;
  }}
  .ioc-summary p {{ margin: 0.2rem 0 0.55rem; color: var(--muted); }}
  .ioc-report-link {{
    display: inline-flex;
    align-items: center;
    border: 1px solid #0ea5e9;
    border-radius: 8px;
    padding: 0.42rem 0.7rem;
    background: #082f49;
    font-weight: 700;
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


def select_report_to_open(reports: list[tuple[str, Path]]) -> None:
    """Let an analyst open any additional per-CVE reports in input order."""
    if len(reports) <= 1:
        return

    print("\nAvailable CVE reports:\n")
    for index, (cve, _) in enumerate(reports, start=1):
        print(f"{index}: {cve}")

    while True:
        try:
            selection = input(
                "\nSelect a report to open by number, or press Enter to exit: "
            ).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return

        if not selection:
            return
        try:
            selected_index = int(selection)
        except ValueError:
            selected_index = 0

        if not 1 <= selected_index <= len(reports):
            print(f"Invalid selection. Enter a number between 1 and {len(reports)}.")
            continue

        cve, report_path = reports[selected_index - 1]
        print(f"Opening report for {cve}...")
        open_report_in_browser(report_path)


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------
# Wire config → client → enrich loop → CSV / Rich / always-on HTML.
#
# Order in ``main()`` is load-bearing:
#   1. argparse  (so --env-file / -v exist)
#   2. logging
#   3. load_project_dotenv  → os.environ
#   4. resolve API key, --input CVE or input CSV, proxies, CA bundle
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
                observed, wild_err, wild_http_status = client.get_observed_in_the_wild(cve)
                apply_observed_in_the_wild_result(
                    rec,
                    observed,
                    error=wild_err,
                    http_status=wild_http_status,
                )
                try:
                    attach_iocs(client, rec, body)
                except Exception as ioc_exc:  # noqa: BLE001 — IoC list is optional
                    rec.ioc_status = "error"
                    rec.ioc_error = "Unexpected IOC processing failure"
                    logging.warning(
                        "IOC processing failed for %s (%s)",
                        cve,
                        type(ioc_exc).__name__,
                    )
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
            elif err == "proxy_error":
                records.append(
                    error_record(
                        cve,
                        "proxy_error",
                        "Proxy connection failed after retries. Verify the configured "
                        "HTTP(S) proxy URL and credentials.",
                    )
                )
            elif err == "tls_error":
                records.append(
                    error_record(
                        cve,
                        "tls_error",
                        "TLS verification failed after retries. Configure the corporate "
                        "CA bundle; TLS verification cannot be disabled.",
                    )
                )
            elif err == "timeout":
                records.append(
                    error_record(
                        cve,
                        "timeout",
                        "VirusTotal request timed out after retries. Check network and "
                        "proxy connectivity.",
                    )
                )
            elif err == "network_error":
                records.append(
                    error_record(
                        cve,
                        "network_error",
                        "Network error after retries. Check DNS, firewall, and proxy "
                        "connectivity.",
                    )
                )
            elif err == "parse_error":
                records.append(
                    error_record(
                        cve,
                        "parse_error",
                        f"VirusTotal returned an unreadable JSON response "
                        f"(HTTP {status or 'n/a'}).",
                    )
                )
            else:
                records.append(
                    error_record(
                        cve,
                        "error",
                        f"VirusTotal API request failed (HTTP {status or 'n/a'}).",
                    )
                )
            progress.advance(task)

    return records


class _StoreOnceAction(argparse.Action):
    """Store one option value and reject ambiguous duplicate occurrences."""

    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: Any,
        option_string: Optional[str] = None,
    ) -> None:
        if getattr(namespace, self.dest, None) is not None:
            parser.error(f"{option_string or self.dest} may only be specified once")
        setattr(namespace, self.dest, values)


def build_arg_parser() -> argparse.ArgumentParser:
    """Define CLI flags; defaults favor .env for secrets and network settings.

    Flags are overrides, not the primary config surface. ``--html`` always
    has a path (default ``report.html``); on multi-CVE runs its directory is
    used for the individual ``CVE-..._report.html`` files.
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
    # --input is the supported single-CVE entry point for local and agent/CLI use.
    p.add_argument(
        "--input",
        action=_StoreOnceAction,
        default=None,
        metavar="CVE",
        help="Single CVE identifier to enrich (example: CVE-2026-12345)",
    )
    p.add_argument(
        "-i",
        dest="cve_file",
        default=DEFAULT_INPUT,
        metavar="FILE",
        help="Input CSV of CVE IDs (ignored when --input is set)",
    )
    p.add_argument("-o", "--output", default=DEFAULT_OUTPUT, help="Output enriched CSV path")
    p.add_argument(
        "--html",
        default=DEFAULT_HTML,
        metavar="PATH",
        help=(
            "Self-contained HTML report path; multi-CVE runs write "
            "CVE-..._report.html files in its directory"
        ),
    )
    p.add_argument(
        "--ioc-html",
        default=None,
        metavar="PATH",
        help=(
            "IOC HTML report path; multi-CVE runs write CVE-..._iocs.html "
            "files in its directory (default: beside --html)"
        ),
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

    Guarantees: after parse + logging setup, primary and IOC HTML reports are
    always generated, even when the run fails with a missing key, SSL error,
    bad input, or unexpected exception. Multi-CVE runs generate one pair per
    record. The first primary report opens automatically and a numbered selector
    can open more reports (unless ``--no-open``).

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
    ioc_path = Path(args.ioc_html) if args.ioc_html else default_ioc_report_path(html_path)
    report_path_error: Optional[str] = None
    if ioc_path.resolve() == html_path.resolve():
        report_path_error = "--ioc-html must be different from --html"
        # Keep the always-written failure artifacts distinct even for bad input.
        ioc_path = default_ioc_report_path(html_path)
    records: list[CVERecord] = []
    fatal_error: Optional[str] = None
    exit_code = 0
    output_path = Path(args.output)

    try:
        if report_path_error:
            raise RuntimeError(report_path_error)
        # --- Resolve CVE targets, then secrets ---
        # --input (single CVE) wins over the CSV from -i / default cve_list.csv.
        if args.input is not None:
            try:
                cves = [validate_input_cve(args.input)]
            except ValueError as exc:
                raise RuntimeError(str(exc)) from exc
            logging.info(
                "Using --input CVE %s (CSV from -i ignored)",
                cves[0],
            )
        else:
            input_path = Path(args.cve_file)
            try:
                cves = load_cve_list(input_path)
            except (OSError, ValueError) as exc:
                raise RuntimeError(f"Failed to read input: {exc}") from exc

            if not cves:
                raise RuntimeError(f"No valid CVE IDs found in {input_path}")

            logging.info("Loaded %d unique CVE(s) from %s", len(cves), input_path)

        api_key = resolve_api_key(args.api_key)
        if not api_key:
            raise RuntimeError(
                "No API key. Set VIRUSTOTAL_API_KEY (or VT_API_KEY) in the project "
                ".env file, or pass --api-key. See .env.example and SETUP.md."
            )

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
                "invalid cve",
                "failed to read input",
                "ca bundle",
                "placeholder",
                "--ioc-html",
            )
        ):
            exit_code = 2
        else:
            exit_code = 1

    # ------------------------------------------------------------------
    # Always write HTML reports (success, partial, or total failure). Multi-CVE
    # runs get one primary/IOC pair per CVE; zero/single-CVE runs retain the
    # configured legacy paths. IOC reports open only from their primary report.
    #
    # This block intentionally sits *outside* the main try so config/SSL/key
    # failures still produce a browsable error page. ``records`` may be empty
    # and ``fatal_error`` set; ``render_html_report`` handles both.
    # ``--no-open`` skips the browser only — the file is still written.
    # A failure *here* is logged and can flip a 0 exit to 1, but never
    # swallows the original enrichment exit code if it was already non-zero.
    # ------------------------------------------------------------------
    report_failed = False
    written_primary_reports: list[tuple[str, Path]] = []
    fallback_primary_path: Optional[Path] = None
    targets = _report_targets(records, html_path, ioc_path)
    for target_records, target_primary_path, target_ioc_path in targets:
        cve_label = target_records[0].cve if target_records else ""
        ioc_title = "GTI IOC Report"
        primary_title = "GTI CVE Enrichment Report"
        if len(records) > 1:
            ioc_title = f"{ioc_title} — {cve_label}"
            primary_title = f"{primary_title} — {cve_label}"
        if fatal_error:
            ioc_title = f"{ioc_title} — FAILED"
            primary_title = f"{primary_title} — FAILED"

        try:
            render_ioc_report(
                target_records,
                target_ioc_path,
                title=ioc_title,
                primary_report_path=target_primary_path,
                fatal_error=fatal_error,
            )
            logging.info("IOC report: %s", target_ioc_path.resolve())
        except Exception as report_exc:  # noqa: BLE001
            report_failed = True
            logging.error("Failed to write IOC report for %s: %s", cve_label or "run", report_exc)

        try:
            render_html_report(
                target_records,
                target_primary_path,
                title=primary_title,
                fatal_error=fatal_error,
                ioc_report_path=target_ioc_path,
            )
            logging.info("HTML report: %s", target_primary_path.resolve())
            if target_records:
                written_primary_reports.append((cve_label, target_primary_path))
            else:
                fallback_primary_path = target_primary_path
        except Exception as report_exc:  # noqa: BLE001
            report_failed = True
            logging.error(
                "Failed to write primary HTML report for %s: %s",
                cve_label or "run",
                report_exc,
            )

    if not args.no_open:
        if written_primary_reports:
            open_report_in_browser(written_primary_reports[0][1])
            if len(written_primary_reports) > 1:
                select_report_to_open(written_primary_reports)
        elif fallback_primary_path is not None:
            open_report_in_browser(fallback_primary_path)
    if report_failed and exit_code == 0:
        exit_code = 1

    return exit_code


if __name__ == "__main__":
    # Standard CLI entry: propagate process exit code to the shell.
    sys.exit(main())
