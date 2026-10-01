"""Deterministic internal vulnerability-priority scoring.

The functions in this module are intentionally independent of VirusTotal
transport and report rendering.  Callers provide normalized or raw enrichment
values, and receive an auditable 0-100 assessment plus a P0-P3 classification.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Any, Optional


SEVERITY_WEIGHT = 40.0
ACTIVE_EXPLOITATION_WEIGHT = 25.0
EXPLOITATION_PROBABILITY_WEIGHT = 15.0
EXPLOIT_MATURITY_WEIGHT = 10.0
EXPLOIT_AUTOMATABILITY_WEIGHT = 10.0

PRIORITY_THRESHOLDS: tuple[tuple[float, str], ...] = (
    (90.0, "P0"),
    (70.0, "P1"),
    (50.0, "P2"),
    (0.0, "P3"),
)

MATURITY_NONE = "NONE"
MATURITY_POC = "POC"
MATURITY_PUBLIC_OR_ATTACKED = "PUBLIC_OR_ATTACKED"

# The requirement does not assign a tier to percentiles from 76 through 79.
# That gap is deliberately isolated here and uses the conservative adjacent
# (50th-75th) tier until policy supplies a different value.
EPSS_PERCENTILE_BANDS: tuple[tuple[float, float, str], ...] = (
    (95.0, 1.0, "95th percentile or higher"),
    (80.0, 0.66, "80th-94th percentile"),
    (76.0, 0.33, "76th-79th percentile (conservative fallback)"),
    (50.0, 0.33, "50th-75th percentile"),
    (0.0, 0.0, "below 50th percentile"),
)


@dataclass(frozen=True)
class ScoredCriterion:
    """One normalized score component and its source explanation."""

    points: float
    normalized_value: str
    details: tuple[str, ...] = ()
    source_available: bool = True
    source: str = ""


@dataclass(frozen=True)
class PriorityAssessment:
    """Complete internal priority calculation."""

    vulnerability_severity: ScoredCriterion
    active_exploitation: ScoredCriterion
    exploitation_probability: ScoredCriterion
    exploit_maturity: ScoredCriterion
    exploit_automatability: ScoredCriterion
    total_score: float
    priority_rating: str


def _finite_float(value: Any) -> Optional[float]:
    """Return a finite float, rejecting booleans and malformed values."""
    if value is None or isinstance(value, bool):
        return None
    try:
        parsed = float(str(value).strip())
    except (TypeError, ValueError):
        return None
    return parsed if math.isfinite(parsed) else None


def normalize_evidence_flag(value: Any) -> Optional[bool]:
    """Normalize a security-intelligence flag while preserving unavailable data."""
    if value is True:
        return True
    if value is False:
        return False
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if value == 1:
            return True
        if value == 0:
            return False
        return None
    if not isinstance(value, str):
        return None
    label = re.sub(r"[\s_-]+", " ", value.strip().casefold())
    if label in {
        "true",
        "yes",
        "y",
        "1",
        "known",
        "available",
        "associated",
        "present",
        "confirmed",
    }:
        return True
    if label in {
        "false",
        "no",
        "n",
        "0",
        "none",
        "not known",
        "unavailable",
        "not available",
        "not associated",
        "absent",
    }:
        return False
    return None


def calculate_vulnerability_severity(
    cvss_v4_score: Any,
    cvss_v3_score: Any,
) -> ScoredCriterion:
    """Score CVSS v4 first, falling back to CVSS v3.1 (maximum 40 points)."""
    for version, raw_score in (("4.0", cvss_v4_score), ("3.1", cvss_v3_score)):
        base_score = _finite_float(raw_score)
        if base_score is not None and 0.0 <= base_score <= 10.0:
            points = (base_score / 10.0) * SEVERITY_WEIGHT
            return ScoredCriterion(
                points=points,
                normalized_value=f"CVSS {version} {base_score:g}",
                details=(f"CVSS {version} base score selected",),
                source=f"CVSS {version}",
            )
    return ScoredCriterion(
        points=0.0,
        normalized_value="Unavailable",
        details=("No valid CVSS v4.0 or v3.1 base score",),
        source_available=False,
    )


def _flag_label(value: Optional[bool]) -> str:
    if value is True:
        return "Yes"
    if value is False:
        return "No"
    return "Unavailable"


def calculate_active_exploitation(
    cisa_kev: Any,
    ransomware_available: Any,
    malware_kit_available: Any,
) -> ScoredCriterion:
    """Score the inclusive OR of KEV, ransomware, and malware-kit evidence."""
    normalized = (
        ("CISA KEV", normalize_evidence_flag(cisa_kev)),
        ("Ransomware association", normalize_evidence_flag(ransomware_available)),
        ("Malware-kit association", normalize_evidence_flag(malware_kit_available)),
    )
    positives = tuple(label for label, value in normalized if value is True)
    details = tuple(f"{label}: {_flag_label(value)}" for label, value in normalized)
    active = bool(positives)
    return ScoredCriterion(
        points=ACTIVE_EXPLOITATION_WEIGHT if active else 0.0,
        normalized_value="Yes" if active else "No",
        details=positives + details,
        source_available=any(value is not None for _, value in normalized),
    )


def normalize_epss_percentile(value: Any) -> Optional[float]:
    """Return EPSS percentile on a 0-100 scale.

    VirusTotal supplies EPSS percentiles as fractions (0-1). Values above one
    are accepted as already-percent values for reusable callers and tests.
    """
    percentile = _finite_float(value)
    if percentile is None or percentile < 0.0:
        return None
    if percentile <= 1.0:
        percentile *= 100.0
    if percentile > 100.0:
        return None
    return percentile


def calculate_exploitation_probability(epss_percentile: Any) -> ScoredCriterion:
    """Score EPSS percentile using the centrally defined policy bands."""
    percentile = normalize_epss_percentile(epss_percentile)
    if percentile is None:
        return ScoredCriterion(
            points=0.0,
            normalized_value="Unavailable",
            details=("No valid EPSS percentile",),
            source_available=False,
        )
    for minimum, fraction, label in EPSS_PERCENTILE_BANDS:
        if percentile >= minimum:
            return ScoredCriterion(
                points=EXPLOITATION_PROBABILITY_WEIGHT * fraction,
                normalized_value=f"{percentile:g}th percentile",
                details=(label,),
            )
    raise AssertionError("EPSS band configuration does not cover zero")


def normalize_exploit_maturity(value: Any) -> Optional[str]:
    """Normalize CVSS/VT maturity wording to the three internal states."""
    if value is None:
        return None
    label = re.sub(r"[\s_-]+", " ", str(value).strip().casefold())
    compact = label.replace(" ", "")
    if not label or label in {"n/a", "na", "unknown", "not defined", "x"}:
        return None
    if label in {
        "none",
        "unreported",
        "not available",
        "no known",
        "interest observed",
        "unverified",
        "privately held",
        "u",
    }:
        return MATURITY_NONE
    if label in {
        "p",
        "poc",
        "proof of concept",
        "proof-of-concept",
        "proof of concept code",
        "functional",
    } or compact in {"proofofconcept", "proofofconceptcode"}:
        return MATURITY_POC
    if label in {
        "a",
        "attacked",
        "public",
        "publicly available",
        "known",
        "trivial",
        "reported",
        "confirmed",
        "wide",
        "weaponized",
    }:
        return MATURITY_PUBLIC_OR_ATTACKED
    return None


def calculate_exploit_maturity(
    cvss_v4_maturity: Any,
    exploit_availability: Any = None,
    exploitation_state: Any = None,
) -> ScoredCriterion:
    """Select the highest maturity supported by existing VT enrichment."""
    candidates = (
        ("CVSS v4 exploit maturity", cvss_v4_maturity),
        ("VirusTotal exploit availability", exploit_availability),
        ("VirusTotal exploitation state", exploitation_state),
    )
    ranked = {
        MATURITY_NONE: 0,
        MATURITY_POC: 1,
        MATURITY_PUBLIC_OR_ATTACKED: 2,
    }
    recognized: list[tuple[str, str]] = []
    for source, value in candidates:
        normalized = normalize_exploit_maturity(value)
        if normalized is not None:
            recognized.append((source, normalized))
    if not recognized:
        return ScoredCriterion(
            points=0.0,
            normalized_value=MATURITY_NONE,
            details=("No recognized exploit-maturity evidence",),
            source_available=False,
        )
    source, maturity = max(recognized, key=lambda item: ranked[item[1]])
    points = {
        MATURITY_NONE: 0.0,
        MATURITY_POC: EXPLOIT_MATURITY_WEIGHT * 0.5,
        MATURITY_PUBLIC_OR_ATTACKED: EXPLOIT_MATURITY_WEIGHT,
    }[maturity]
    return ScoredCriterion(
        points=points,
        normalized_value=maturity,
        details=(f"Selected from {source}",),
        source=source,
    )


def parse_cvss_vector(vector: Any, *, version: str) -> Optional[dict[str, str]]:
    """Parse a CVSS vector into metric/value pairs, rejecting malformed input."""
    if not isinstance(vector, str):
        return None
    parts = vector.strip().split("/")
    if not parts or parts[0].upper() != f"CVSS:{version}":
        return None
    metrics: dict[str, str] = {}
    for component in parts[1:]:
        if component.count(":") != 1:
            return None
        metric, value = (part.strip().upper() for part in component.split(":", 1))
        if not metric or not value or metric in metrics:
            return None
        metrics[metric] = value
    return metrics


def calculate_exploit_automatability(
    cvss_v4_vector: Any,
    *,
    cvss_v4_available: bool,
) -> ScoredCriterion:
    """Score only an explicitly parsed CVSS v4 ``AU:Y`` metric."""
    if not cvss_v4_available:
        return ScoredCriterion(
            points=0.0,
            normalized_value="No",
            details=("CVSS v4.0 unavailable; CVSS v3.1 has no AU metric",),
            source_available=False,
        )
    metrics = parse_cvss_vector(cvss_v4_vector, version="4.0")
    if metrics is None:
        return ScoredCriterion(
            points=0.0,
            normalized_value="No",
            details=("CVSS v4.0 vector missing or malformed",),
            source_available=False,
        )
    automatability = metrics.get("AU") == "Y"
    au_value = metrics.get("AU")
    detail = f"AU:{au_value}" if au_value else "AU metric unavailable"
    return ScoredCriterion(
        points=EXPLOIT_AUTOMATABILITY_WEIGHT if automatability else 0.0,
        normalized_value="Yes" if automatability else "No",
        details=(detail,),
        source_available=au_value is not None,
    )


def classify_priority(score: Any) -> str:
    """Classify a clamped score using the non-overlapping P0-P3 thresholds."""
    numeric = _finite_float(score)
    bounded = min(100.0, max(0.0, numeric if numeric is not None else 0.0))
    for minimum, rating in PRIORITY_THRESHOLDS:
        if bounded >= minimum:
            return rating
    raise AssertionError("Priority threshold configuration does not cover zero")


def calculate_internal_priority(
    *,
    cvss_v4_score: Any = None,
    cvss_v3_score: Any = None,
    cvss_v4_vector: Any = None,
    cisa_kev: Any = None,
    ransomware_available: Any = None,
    malware_kit_available: Any = None,
    epss_percentile: Any = None,
    cvss_v4_maturity: Any = None,
    exploit_availability: Any = None,
    exploitation_state: Any = None,
) -> PriorityAssessment:
    """Calculate all five criteria, a bounded total, and final rating."""
    severity = calculate_vulnerability_severity(cvss_v4_score, cvss_v3_score)
    active = calculate_active_exploitation(
        cisa_kev,
        ransomware_available,
        malware_kit_available,
    )
    probability = calculate_exploitation_probability(epss_percentile)
    parsed_v4 = parse_cvss_vector(cvss_v4_vector, version="4.0")
    maturity_input = cvss_v4_maturity
    if normalize_exploit_maturity(maturity_input) is None and parsed_v4 is not None:
        maturity_input = parsed_v4.get("E")
    maturity = calculate_exploit_maturity(
        maturity_input,
        exploit_availability,
        exploitation_state,
    )
    v4_available = (
        calculate_vulnerability_severity(cvss_v4_score, None).source_available
        or parsed_v4 is not None
    )
    automatability = calculate_exploit_automatability(
        cvss_v4_vector,
        cvss_v4_available=v4_available,
    )
    total = min(
        100.0,
        max(
            0.0,
            severity.points
            + active.points
            + probability.points
            + maturity.points
            + automatability.points,
        ),
    )
    return PriorityAssessment(
        vulnerability_severity=severity,
        active_exploitation=active,
        exploitation_probability=probability,
        exploit_maturity=maturity,
        exploit_automatability=automatability,
        total_score=total,
        priority_rating=classify_priority(total),
    )
