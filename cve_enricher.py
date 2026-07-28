#!/usr/bin/env python3
"""
GTI / VirusTotal CVE Enricher
=============================

Enrich a list of CVE IDs using the Google Threat Intelligence (GTI)
Vulnerability Intelligence collections endpoint:

    GET /api/v3/collections/vulnerability--{cve-id-lowercase}

Requires a VirusTotal / GTI **Enterprise** or **Enterprise Plus** API key
with Vulnerability Intelligence privileges.

Usage
-----
    export VT_API_KEY="your-api-key"
    # Optional corporate proxy:
    export HTTP_PROXY="http://proxy.example.com:8080"
    export HTTPS_PROXY="http://proxy.example.com:8080"
    # Optional: disable TLS verification (not recommended)
    export VT_VERIFY_SSL="false"

    python cve_enricher.py --input cve_list.csv --output cve_enriched.csv --html report.html

Environment / config
--------------------
    VT_API_KEY          VirusTotal / GTI API key (required)
    HTTP_PROXY          HTTP proxy URL
    HTTPS_PROXY         HTTPS proxy URL
    VT_HTTP_PROXY       Alias for HTTP_PROXY (script-specific)
    VT_HTTPS_PROXY      Alias for HTTPS_PROXY (script-specific)
    VT_VERIFY_SSL       "true" (default) or "false"
    VT_REQUEST_DELAY    Default inter-request delay in seconds (default: 1.0)
"""

from __future__ import annotations

import argparse
import csv
import html
import json
import logging
import os
import random
import re
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Optional

import requests
import urllib3
from rich import box
from rich.console import Console, Group
from rich.logging import RichHandler
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.table import Table
from rich.text import Text

# ---------------------------------------------------------------------------
# Configuration (override via env vars or CLI; never hard-code secrets)
# ---------------------------------------------------------------------------

DEFAULT_API_BASE = "https://www.virustotal.com/api/v3"
DEFAULT_INPUT = "cve_list.csv"
DEFAULT_OUTPUT = "cve_enriched.csv"
DEFAULT_DELAY = float(os.getenv("VT_REQUEST_DELAY", "1.0"))
DEFAULT_MAX_RETRIES = 5
DEFAULT_BACKOFF_BASE = 2.0  # seconds; exponential: base^attempt + jitter

CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

# GTI priority derivation uses these normalized labels.
# Exploit availability values observed in GTI docs / UI.
NO_KNOWN_ALIASES = {"", "n/a", "none", "no known", "no_known", "unknown"}

console = Console(stderr=False)
log_console = Console(stderr=True)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class CVERecord:
    """Flattened, decision-ready CVE enrichment record."""

    cve: str
    status: str = "ok"  # ok | not_found | error | rate_limited | forbidden
    error_message: str = ""

    # Core prioritization
    priority_rating: str = "N/A"  # P0–P4 (derived)
    priority_raw: str = "N/A"  # raw API field (may be bool / missing)
    risk_rating: str = "N/A"
    predicted_risk_rating: str = "N/A"
    risk_factors: str = "N/A"

    # Exploitation
    exploitation_state: str = "N/A"
    exploit_availability: str = "N/A"
    exploited_in_the_wild: str = "False"
    exploited_as_zero_day: str = "False"
    exploitation_consequence: str = "N/A"
    exploitation_vectors: str = "N/A"
    first_exploitation: str = "N/A"
    exploit_release_date: str = "N/A"

    # CISA KEV
    cisa_kev: str = "False"
    cisa_added_date: str = "N/A"
    cisa_due_date: str = "N/A"
    cisa_ransomware_use: str = "N/A"

    # EPSS
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

    # CVSS v2 (supporting)
    cvss_v2_base: str = "N/A"
    cvss_v2_temporal: str = "N/A"
    cvss_v2_vector: str = "N/A"

    # Products
    affected_products: str = "N/A"
    affected_products_count: int = 0

    # Supporting context
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

    # Preserve interesting nested bits for advanced consumers
    extra_json: str = ""


# CSV column order (stable, analyst-friendly)
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
# Helpers
# ---------------------------------------------------------------------------


def setup_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(console=log_console, rich_tracebacks=True, show_path=False)],
    )


def na(value: Any, default: str = "N/A") -> str:
    """Coerce API values to display-safe strings; treat None/empty as N/A."""
    if value is None:
        return default
    if isinstance(value, bool):
        return "True" if value else "False"
    if isinstance(value, (list, tuple)):
        if not value:
            return default
        return "; ".join(str(v) for v in value if v is not None and str(v).strip() != "")
    if isinstance(value, float):
        # Keep enough precision for EPSS/CVSS without scientific noise
        return f"{value:.6f}".rstrip("0").rstrip(".") if value != 0 else "0"
    text = str(value).strip()
    return text if text else default


def fmt_ts(value: Any) -> str:
    """Format UTC unix timestamp (int/float) or ISO-ish string to ISO-8601 date."""
    if value is None or value == "" or value is False:
        return "N/A"
    if isinstance(value, str):
        # Already a date string (e.g. first_seen_details value)
        return value if value.strip() else "N/A"
    try:
        ts = int(value)
        # Heuristic: millisecond timestamps
        if ts > 10_000_000_000:
            ts //= 1000
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d")
    except (TypeError, ValueError, OSError, OverflowError):
        return na(value)


def normalize_cve(raw: str) -> Optional[str]:
    """Normalize a CVE ID to canonical uppercase form; return None if invalid."""
    if not raw:
        return None
    cleaned = raw.strip().upper().replace(" ", "")
    # Tolerate missing hyphen variants slightly
    cleaned = cleaned.replace("_", "-")
    if not cleaned.startswith("CVE-"):
        if re.match(r"^\d{4}-\d{4,}$", cleaned):
            cleaned = f"CVE-{cleaned}"
    if not CVE_PATTERN.match(cleaned):
        return None
    return cleaned


def cve_api_id(cve: str) -> str:
    """Build the collections object id: vulnerability--cve-yyyy-nnnnn (lowercase)."""
    return f"vulnerability--{cve.lower()}"


def _norm_label(value: str) -> str:
    return re.sub(r"\s+", " ", (value or "").strip().lower())


def _is_no_known(value: str) -> bool:
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
    """Derive GTI-style P0–P4 priority from risk + exploitation signals."""
    risk = _norm_label(risk_rating)
    state = _norm_label(exploitation_state)
    avail = _norm_label(exploit_availability)

    # Normalize common aliases
    if risk in {"n/a", "none", "unrated", ""}:
        risk = "unrated"
    if state in {"n/a", "none", ""}:
        state = "no known"
    if avail in {"n/a", "none", "unknown", ""}:
        avail = "no known"

    # Map "Known" (older filter wording) toward public availability for matching
    if avail == "known":
        avail = "publicly available"

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

    # --- P0 ---
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

    # Fallback heuristics when official table does not match (e.g. Unrated)
    if risk == "high":
        return "P1" if not _is_no_known(avail) or state in wide_confirmed_reported else "P2"
    if risk == "medium":
        return "P2"
    if risk == "low":
        return "P3"
    if risk == "critical":
        return "P0"

    return "N/A"


# ---------------------------------------------------------------------------
# Input CSV
# ---------------------------------------------------------------------------


def load_cve_list(path: Path) -> list[str]:
    """
    Load CVE IDs from CSV.

    Accepts:
      - Single-column file (header optional): CVE / cve_id / cveid / id
      - Multi-column file with a column named CVE, cve, cve_id, cveid, or id
      - Headerless single column of CVE values
    """
    if not path.exists():
        raise FileNotFoundError(f"Input file not found: {path}")

    cves: list[str] = []
    seen: set[str] = set()

    with path.open(newline="", encoding="utf-8-sig") as fh:
        sample = fh.read(4096)
        fh.seek(0)
        try:
            dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
        except csv.Error:
            dialect = csv.excel

        # Detect header
        fh.seek(0)
        first_line = fh.readline()
        fh.seek(0)
        has_header = bool(
            re.search(r"cve|id|identifier", first_line, re.IGNORECASE)
            and not CVE_PATTERN.search(first_line.split(",")[0].strip().strip('"'))
        )

        if has_header:
            reader = csv.DictReader(fh, dialect=dialect)
            # Normalize header keys
            field_map = { (f or "").strip().lower(): f for f in (reader.fieldnames or []) }
            col = None
            for candidate in ("cve", "cve_id", "cveid", "cve-id", "id", "identifier", "vulnerability"):
                if candidate in field_map:
                    col = field_map[candidate]
                    break
            if col is None:
                # Fall back to first column
                if reader.fieldnames:
                    col = reader.fieldnames[0]
                else:
                    raise ValueError(f"No columns found in {path}")
            for row in reader:
                raw = (row.get(col) or "").strip()
                if not raw:
                    continue
                cve = normalize_cve(raw)
                if cve and cve not in seen:
                    seen.add(cve)
                    cves.append(cve)
                elif not cve:
                    logging.warning("Skipping invalid CVE value: %r", raw)
        else:
            reader = csv.reader(fh, dialect=dialect)
            for row in reader:
                if not row:
                    continue
                raw = (row[0] or "").strip()
                if not raw or raw.lower() in {"cve", "cve_id", "id"}:
                    continue
                cve = normalize_cve(raw)
                if cve and cve not in seen:
                    seen.add(cve)
                    cves.append(cve)
                elif not cve:
                    logging.warning("Skipping invalid CVE value: %r", raw)

    return cves


# ---------------------------------------------------------------------------
# API client
# ---------------------------------------------------------------------------


class GTIClient:
    """Thin VirusTotal / GTI collections client with proxy + backoff support."""

    def __init__(
        self,
        api_key: str,
        *,
        base_url: str = DEFAULT_API_BASE,
        proxies: Optional[dict[str, str]] = None,
        verify_ssl: bool = True,
        timeout: float = 60.0,
        max_retries: int = DEFAULT_MAX_RETRIES,
        backoff_base: float = DEFAULT_BACKOFF_BASE,
        delay: float = DEFAULT_DELAY,
    ) -> None:
        if not api_key or api_key in {"INSERT_KEY_HERE", "your-api-key", "changeme"}:
            raise ValueError(
                "API key missing. Set VT_API_KEY environment variable or pass --api-key."
            )
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.max_retries = max_retries
        self.backoff_base = backoff_base
        self.delay = delay
        self._last_request_at = 0.0

        self.session = requests.Session()
        self.session.headers.update(
            {
                "x-apikey": api_key,
                "accept": "application/json",
                "User-Agent": "gti-cve-enricher/1.0",
            }
        )
        if proxies:
            self.session.proxies.update(proxies)
        self.session.verify = verify_ssl
        if not verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            logging.warning("TLS certificate verification is DISABLED (verify=False).")

    def _throttle(self) -> None:
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
                body_preview = _safe_error_body(resp)
                logging.info("404 Not Found for %s — %s", cve, body_preview)
                return None, "not_found", 404

            if resp.status_code in (401, 403):
                body_preview = _safe_error_body(resp)
                # Privilege / license messaging
                msg = (
                    f"HTTP {resp.status_code}: access denied for {cve}. "
                    "Vulnerability Intelligence requires a Google Threat Intelligence "
                    "(GTI) Enterprise or Enterprise Plus license. "
                    f"API detail: {body_preview}"
                )
                logging.error(msg)
                return None, "forbidden", resp.status_code

            if resp.status_code == 429:
                # Prefer Retry-After header when present
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

            # Other 5xx / unexpected
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
    try:
        data = resp.json()
        if isinstance(data, dict):
            err = data.get("error") or data
            return json.dumps(err)[:limit]
        return str(data)[:limit]
    except Exception:
        return (resp.text or "")[:limit]


# ---------------------------------------------------------------------------
# Field extraction (mapped to real GTI vulnerability object schema)
# ---------------------------------------------------------------------------


def _dig(d: Any, *keys: str, default: Any = None) -> Any:
    cur = d
    for k in keys:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(k, default)
        if cur is default:
            return default
    return cur


def _first(*values: Any, default: Any = None) -> Any:
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
    """Flatten CPE ranges into readable 'vendor / product version-range' strings."""
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
            # Fall back to URI
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

    # Deduplicate while preserving order
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
    """Map a GTI vulnerability collection response into a CVERecord."""
    data = payload.get("data") if isinstance(payload, dict) else None
    if not isinstance(data, dict):
        return CVERecord(cve=cve, status="error", error_message="Malformed API response (no data)")

    attrs = data.get("attributes") or {}
    if not isinstance(attrs, dict):
        attrs = {}

    # --- CVSS ---
    cvss = attrs.get("cvss") or {}
    # Documented keys: cvssv2_0, cvssv3_x, cvssv3_x_translated, cvssv4_x
    # Also tolerate legacy/alternate shapes (v3, cvssv3, etc.)
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

    # --- Exploitation (top-level + nested dict) ---
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

    # Derive wild exploitation from state when boolean field absent
    if exploited_in_wild is False or exploited_in_wild is None:
        if _norm_label(str(exploitation_state)) in {"wide", "confirmed"}:
            # Confirmed/Wide implies observed exploitation; keep explicit bool if present
            pass

    # --- CISA KEV ---
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
    risk_rating = na(attrs.get("risk_rating"))
    predicted = na(attrs.get("predicted_risk_rating"))
    risk_factors = na(attrs.get("risk_factors"))
    priority_raw = attrs.get("priority")
    # API docs list priority as boolean; UI uses P0–P4 (derived)
    if isinstance(priority_raw, bool):
        priority_raw_str = "True" if priority_raw else "False"
    else:
        priority_raw_str = na(priority_raw)

    priority_rating = derive_priority_rating(
        risk_rating,
        str(exploitation_state),
        str(exploit_availability),
    )
    # If API ever returns an explicit P0–P4 string, prefer it
    if isinstance(priority_raw, str) and re.match(r"^P[0-4]$", priority_raw.strip(), re.I):
        priority_rating = priority_raw.strip().upper()

    # --- Products ---
    products_str, products_count = _format_cpes(attrs.get("cpes"))

    # --- CWE ---
    cwe = attrs.get("cwe") if isinstance(attrs.get("cwe"), dict) else {}

    # --- Counters ---
    counters = attrs.get("counters") if isinstance(attrs.get("counters"), dict) else {}

    # --- Description (truncate very long text for CSV usability; full in extra) ---
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

    # Compact extra payload for advanced use (risk factors raw, tags, etc.)
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
    return CVERecord(
        cve=cve,
        status=status,
        error_message=message,
        vt_url=f"https://www.virustotal.com/gui/collection/{cve_api_id(cve)}",
    )


# ---------------------------------------------------------------------------
# Output: CSV
# ---------------------------------------------------------------------------


def write_csv(records: Iterable[CVERecord], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_COLUMNS, extrasaction="ignore")
        writer.writeheader()
        for rec in records:
            row = asdict(rec)
            # CSV-safe: collapse newlines in long text fields
            for key in ("description", "executive_summary", "analysis", "affected_products", "workarounds"):
                if key in row and isinstance(row[key], str):
                    row[key] = row[key].replace("\r", " ").replace("\n", " ").strip()
            writer.writerow({k: row.get(k, "") for k in CSV_COLUMNS})
    logging.info("Wrote CSV: %s", path)


# ---------------------------------------------------------------------------
# Output: Rich terminal cards
# ---------------------------------------------------------------------------


def _risk_style(risk: str) -> str:
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
    p = priority.upper()
    return {
        "P0": "dark_red",
        "P1": "dark_orange3",
        "P2": "gold3",
        "P3": "dark_green",
        "P4": "cyan",
    }.get(p, "grey50")


def _bool_badge(value: str, true_style: str = "bold red", false_style: str = "dim") -> Text:
    v = str(value).strip().lower()
    if v in {"true", "yes", "1"}:
        return Text("YES", style=true_style)
    if v in {"false", "no", "0"}:
        return Text("no", style=false_style)
    return Text(str(value), style="dim")


def render_rich_card(rec: CVERecord) -> Panel:
    """Build a color-coded Rich panel for one CVE."""
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
    console.print()
    console.rule("[bold]GTI CVE Enrichment Report[/bold]")
    # Summary strip
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


def _html_risk_class(risk_or_priority: str) -> str:
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
    return html.escape(value or "", quote=True)


def _html_bool(value: str) -> str:
    v = str(value).strip().lower()
    if v in {"true", "yes", "1"}:
        return '<span class="badge badge-danger">YES</span>'
    if v in {"false", "no", "0"}:
        return '<span class="badge badge-muted">no</span>'
    return f'<span class="badge badge-muted">{_html_escape(str(value))}</span>'


def render_html_report(records: list[CVERecord], path: Path, title: str = "GTI CVE Enrichment Report") -> None:
    """Write a self-contained HTML report with card layout and risk badges."""
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    ok = sum(1 for r in records if r.status == "ok")
    pri_counts: dict[str, int] = {}
    for r in records:
        if r.status == "ok":
            pri_counts[r.priority_rating] = pri_counts.get(r.priority_rating, 0) + 1

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
            # Cap displayed products for readability
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

    pri_chips = "".join(
        f'<span class="chip badge-{_html_risk_class(k)}">{_html_escape(k)}: {v}</span>'
        for k, v in sorted(pri_counts.items())
    )

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
      </div>
      <div class="chips">{pri_chips or '<span class="chip">No successful enrichments</span>'}</div>
    </header>
    {"".join(cards)}
    <footer class="page">
      Data source: Google Threat Intelligence / VirusTotal Vulnerability collections API
      (<code>/api/v3/collections/vulnerability--&lt;cve&gt;</code>).
      Priority (P0–P4) is derived from Risk Rating + Exploitation State + Exploit Availability
      per GTI vulnerability report guidance. Requires GTI Enterprise / Enterprise Plus.
    </footer>
  </div>
</body>
</html>
"""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(doc, encoding="utf-8")
    logging.info("Wrote HTML report: %s", path)


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


def build_proxies(
    http_proxy: Optional[str],
    https_proxy: Optional[str],
) -> Optional[dict[str, str]]:
    http_p = http_proxy or os.getenv("VT_HTTP_PROXY") or os.getenv("HTTP_PROXY") or os.getenv("http_proxy")
    https_p = https_proxy or os.getenv("VT_HTTPS_PROXY") or os.getenv("HTTPS_PROXY") or os.getenv("https_proxy")
    proxies: dict[str, str] = {}
    if http_p:
        proxies["http"] = http_p
    if https_p:
        proxies["https"] = https_p
    return proxies or None


def parse_verify_ssl(cli_value: Optional[str]) -> bool:
    if cli_value is not None:
        return cli_value.lower() in {"1", "true", "yes", "on"}
    env = os.getenv("VT_VERIFY_SSL", "true").lower()
    return env in {"1", "true", "yes", "on"}


def enrich_cves(
    client: GTIClient,
    cves: list[str],
    *,
    stop_on_forbidden: bool = True,
) -> list[CVERecord]:
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
                    # Mark remaining as skipped
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
    p = argparse.ArgumentParser(
        prog="cve_enricher.py",
        description=(
            "Enrich CVE IDs via Google Threat Intelligence / VirusTotal "
            "vulnerability collections (Enterprise required)."
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("-i", "--input", default=DEFAULT_INPUT, help="Input CSV of CVE IDs")
    p.add_argument("-o", "--output", default=DEFAULT_OUTPUT, help="Output enriched CSV path")
    p.add_argument("--html", default=None, metavar="PATH", help="Write self-contained HTML report")
    p.add_argument(
        "--no-rich",
        action="store_true",
        help="Skip Rich terminal cards (still logs progress)",
    )
    p.add_argument(
        "--api-key",
        default=None,
        help="VirusTotal/GTI API key (prefer VT_API_KEY env var)",
    )
    p.add_argument(
        "--http-proxy",
        default=None,
        help="HTTP proxy URL (or set HTTP_PROXY / VT_HTTP_PROXY)",
    )
    p.add_argument(
        "--https-proxy",
        default=None,
        help="HTTPS proxy URL (or set HTTPS_PROXY / VT_HTTPS_PROXY)",
    )
    p.add_argument(
        "--verify-ssl",
        default=None,
        choices=["true", "false"],
        help="Verify TLS certificates (default from VT_VERIFY_SSL or true)",
    )
    p.add_argument(
        "--delay",
        type=float,
        default=DEFAULT_DELAY,
        help="Seconds to wait between API requests",
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
    return p


def main(argv: Optional[list[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)
    setup_logging(verbose=args.verbose)

    api_key = args.api_key or os.getenv("VT_API_KEY") or os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key:
        log_console.print(
            "[bold red]Error:[/bold red] No API key. Set [cyan]VT_API_KEY[/cyan] "
            "or pass [cyan]--api-key[/cyan]."
        )
        return 2

    input_path = Path(args.input)
    output_path = Path(args.output)

    try:
        cves = load_cve_list(input_path)
    except (OSError, ValueError) as exc:
        logging.error("Failed to read input: %s", exc)
        return 2

    if not cves:
        logging.error("No valid CVE IDs found in %s", input_path)
        return 2

    logging.info("Loaded %d unique CVE(s) from %s", len(cves), input_path)

    proxies = build_proxies(args.http_proxy, args.https_proxy)
    if proxies:
        logging.info("Using proxies: %s", {k: v for k, v in proxies.items()})

    verify_ssl = parse_verify_ssl(args.verify_ssl)

    try:
        client = GTIClient(
            api_key=api_key,
            proxies=proxies,
            verify_ssl=verify_ssl,
            delay=args.delay,
            max_retries=args.max_retries,
        )
    except ValueError as exc:
        logging.error("%s", exc)
        return 2

    # Optional raw dump wrapper
    dump_dir = Path(args.dump_raw) if args.dump_raw else None
    if dump_dir:
        dump_dir.mkdir(parents=True, exist_ok=True)
        original_get = client.get_vulnerability

        def get_with_dump(cve: str) -> tuple[Optional[dict[str, Any]], Optional[str], int]:
            body, err, status = original_get(cve)
            if body is not None:
                out = dump_dir / f"{cve.upper()}.json"
                out.write_text(json.dumps(body, indent=2), encoding="utf-8")
                logging.debug("Dumped raw JSON → %s", out)
            return body, err, status

        client.get_vulnerability = get_with_dump  # type: ignore[method-assign]

    records = enrich_cves(
        client,
        cves,
        stop_on_forbidden=not args.continue_on_forbidden,
    )

    write_csv(records, output_path)

    if args.html:
        render_html_report(records, Path(args.html))

    if not args.no_rich:
        print_rich_report(records)
    else:
        # Compact text summary
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
    logging.info("Done. Enriched=%d  Failed/Skipped=%d  CSV=%s", ok, failed, output_path)
    if args.html:
        logging.info("HTML report: %s", args.html)

    # Exit code: 0 if at least one success, 1 if all failed, 3 if privilege issue
    if any(r.status == "forbidden" for r in records) and ok == 0:
        return 3
    if ok == 0:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
