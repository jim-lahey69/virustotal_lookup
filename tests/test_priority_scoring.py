"""Unit and integration coverage for the internal 0-100 priority engine."""

from __future__ import annotations

import csv
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import cve_enricher as ce  # noqa: E402
import priority_scoring as ps  # noqa: E402


class VulnerabilitySeverityTests(unittest.TestCase):
    def test_cvss_v4_is_preferred(self) -> None:
        result = ps.calculate_vulnerability_severity(9.0, 10.0)
        self.assertEqual((result.points, result.normalized_value), (36.0, "CVSS 4.0 9"))
        self.assertEqual(result.source, "CVSS 4.0")

    def test_cvss_v31_is_fallback(self) -> None:
        result = ps.calculate_vulnerability_severity(None, 7.5)
        self.assertEqual((result.points, result.normalized_value), (30.0, "CVSS 3.1 7.5"))
        self.assertEqual(result.source, "CVSS 3.1")

    def test_maximum_cvss_is_40(self) -> None:
        self.assertEqual(ps.calculate_vulnerability_severity(10.0, None).points, 40.0)

    def test_missing_cvss_scores_zero(self) -> None:
        result = ps.calculate_vulnerability_severity(None, None)
        self.assertEqual(result.points, 0.0)
        self.assertFalse(result.source_available)


class ActiveExploitationTests(unittest.TestCase):
    def assert_active(self, kev=None, ransomware=None, malware_kit=None) -> None:
        result = ps.calculate_active_exploitation(kev, ransomware, malware_kit)
        self.assertEqual((result.normalized_value, result.points), ("Yes", 25.0))

    def test_cisa_kev_only(self) -> None:
        self.assert_active(kev=True, ransomware=False, malware_kit=False)

    def test_ransomware_only(self) -> None:
        self.assert_active(kev=False, ransomware="Known", malware_kit=False)

    def test_malware_kit_only(self) -> None:
        self.assert_active(kev=False, ransomware=False, malware_kit=True)

    def test_multiple_positive_indicators(self) -> None:
        result = ps.calculate_active_exploitation(True, True, True)
        self.assertEqual(result.points, 25.0)
        self.assertIn("CISA KEV", result.details)
        self.assertIn("Ransomware association", result.details)

    def test_no_positive_indicators(self) -> None:
        result = ps.calculate_active_exploitation(False, False, None)
        self.assertEqual((result.normalized_value, result.points), ("No", 0.0))
        self.assertIn("Malware-kit association: Unavailable", result.details)


class ExploitationProbabilityTests(unittest.TestCase):
    def assert_points(self, percentile, expected: float) -> None:
        self.assertAlmostEqual(
            ps.calculate_exploitation_probability(percentile).points,
            expected,
        )

    def test_below_50(self) -> None:
        self.assert_points(49.99, 0.0)

    def test_exactly_50(self) -> None:
        self.assert_points(50, 4.95)

    def test_exactly_75(self) -> None:
        self.assert_points(75, 4.95)

    def test_76_to_79_uses_explicit_conservative_fallback(self) -> None:
        for percentile in (76, 77, 78, 79, 79.99):
            with self.subTest(percentile=percentile):
                result = ps.calculate_exploitation_probability(percentile)
                self.assertEqual(result.points, 4.95)
                self.assertIn("conservative fallback", result.details[0])

    def test_exactly_80(self) -> None:
        self.assert_points(80, 9.9)

    def test_exactly_94(self) -> None:
        self.assert_points(94, 9.9)

    def test_exactly_95(self) -> None:
        self.assert_points(95, 15.0)

    def test_exactly_100(self) -> None:
        self.assert_points(100, 15.0)

    def test_fractional_api_percentile_is_scaled(self) -> None:
        result = ps.calculate_exploitation_probability(0.97)
        self.assertEqual((result.points, result.normalized_value), (15.0, "97th percentile"))

    def test_missing_epss(self) -> None:
        result = ps.calculate_exploitation_probability(None)
        self.assertEqual(result.points, 0.0)
        self.assertFalse(result.source_available)


class ExploitMaturityTests(unittest.TestCase):
    def test_none(self) -> None:
        result = ps.calculate_exploit_maturity("None")
        self.assertEqual((result.normalized_value, result.points), (ps.MATURITY_NONE, 0.0))

    def test_poc(self) -> None:
        result = ps.calculate_exploit_maturity("Proof of Concept")
        self.assertEqual((result.normalized_value, result.points), (ps.MATURITY_POC, 5.0))

    def test_public(self) -> None:
        result = ps.calculate_exploit_maturity("Public")
        self.assertEqual(
            (result.normalized_value, result.points),
            (ps.MATURITY_PUBLIC_OR_ATTACKED, 10.0),
        )

    def test_attacked(self) -> None:
        result = ps.calculate_exploit_maturity("Attacked")
        self.assertEqual(
            (result.normalized_value, result.points),
            (ps.MATURITY_PUBLIC_OR_ATTACKED, 10.0),
        )

    def test_missing_value(self) -> None:
        result = ps.calculate_exploit_maturity(None)
        self.assertEqual((result.normalized_value, result.points), (ps.MATURITY_NONE, 0.0))
        self.assertFalse(result.source_available)

    def test_existing_vt_exploit_availability_can_supply_maturity(self) -> None:
        result = ps.calculate_exploit_maturity(None, "Publicly Available", "Unknown")
        self.assertEqual(result.points, 10.0)
        self.assertIn("VirusTotal exploit availability", result.details[0])

    def test_cvss_v4_vector_e_metric_supplies_maturity(self) -> None:
        result = ps.calculate_internal_priority(
            cvss_v4_score=5.0,
            cvss_v4_vector="CVSS:4.0/AV:N/AC:L/E:P/AU:N",
        )
        self.assertEqual(result.exploit_maturity.normalized_value, ps.MATURITY_POC)
        self.assertEqual(result.exploit_maturity.points, 5.0)


class ExploitAutomatabilityTests(unittest.TestCase):
    def test_cvss_v4_au_yes(self) -> None:
        result = ps.calculate_exploit_automatability(
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/AU:Y",
            cvss_v4_available=True,
        )
        self.assertEqual((result.normalized_value, result.points), ("Yes", 10.0))

    def test_cvss_v4_au_no(self) -> None:
        result = ps.calculate_exploit_automatability(
            "CVSS:4.0/AV:N/AU:N",
            cvss_v4_available=True,
        )
        self.assertEqual((result.normalized_value, result.points), ("No", 0.0))

    def test_cvss_v4_without_au(self) -> None:
        result = ps.calculate_exploit_automatability(
            "CVSS:4.0/AV:N/AC:L",
            cvss_v4_available=True,
        )
        self.assertEqual(result.points, 0.0)
        self.assertIn("AU metric unavailable", result.details)

    def test_malformed_vector(self) -> None:
        result = ps.calculate_exploit_automatability(
            "CVSS:4.0/AV:N/broken/AU:Y",
            cvss_v4_available=True,
        )
        self.assertEqual(result.points, 0.0)
        self.assertFalse(result.source_available)

    def test_cvss_v31_only_does_not_infer_au(self) -> None:
        result = ps.calculate_exploit_automatability(
            "CVSS:3.1/AV:N/AC:L/AU:Y",
            cvss_v4_available=False,
        )
        self.assertEqual(result.points, 0.0)
        self.assertIn("CVSS v3.1 has no AU metric", result.details[0])


class PriorityThresholdTests(unittest.TestCase):
    def test_every_boundary(self) -> None:
        expected = {
            49.99: "P3",
            50: "P2",
            69.99: "P2",
            70: "P1",
            89.99: "P1",
            90: "P0",
            100: "P0",
        }
        for score, rating in expected.items():
            with self.subTest(score=score):
                self.assertEqual(ps.classify_priority(score), rating)

    def test_out_of_range_values_are_bounded(self) -> None:
        self.assertEqual(ps.classify_priority(-50), "P3")
        self.assertEqual(ps.classify_priority(900), "P0")
        self.assertEqual(ps.classify_priority("malformed"), "P3")


class CompletePriorityScenarioTests(unittest.TestCase):
    def test_full_p0_scenario(self) -> None:
        result = ps.calculate_internal_priority(
            cvss_v4_score=9.8,
            cvss_v4_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/AU:Y",
            cisa_kev=True,
            ransomware_available=False,
            malware_kit_available=False,
            epss_percentile=0.97,
            cvss_v4_maturity="Attacked",
        )
        self.assertAlmostEqual(result.total_score, 99.2)
        self.assertEqual(result.priority_rating, "P0")

    def test_v31_conservative_scenario(self) -> None:
        result = ps.calculate_internal_priority(
            cvss_v3_score=5.0,
            cisa_kev=False,
            ransomware_available=False,
            malware_kit_available=False,
            epss_percentile=75,
            cvss_v4_maturity="PoC",
        )
        self.assertAlmostEqual(result.total_score, 29.95)
        self.assertEqual(result.priority_rating, "P3")

    def test_public_exploit_p2_scenario(self) -> None:
        result = ps.calculate_internal_priority(
            cvss_v3_score=8.8,
            cisa_kev=False,
            epss_percentile=0.90,
            exploit_availability="Publicly Available",
        )
        self.assertAlmostEqual(result.total_score, 55.1)
        self.assertEqual(result.priority_rating, "P2")


class PriorityPipelineIntegrationTests(unittest.TestCase):
    def test_failed_lookup_is_not_misclassified_as_p3(self) -> None:
        rec = ce.error_record("CVE-2026-89999", "not_found", "missing")
        self.assertEqual(rec.priority_rating, "N/A")

    def test_native_vt_priority_cannot_override_internal_result(self) -> None:
        rec = ce.extract_record(
            "CVE-2026-90000",
            {"data": {"attributes": {"priority": "P0"}}},
        )
        self.assertEqual(rec.vt_priority_raw, "P0")
        self.assertEqual((rec.priority_score, rec.priority_rating), (0.0, "P3"))

    def test_report_contains_a_mathematically_consistent_breakdown(self) -> None:
        rec = ce.extract_record(
            "CVE-2026-90001",
            {
                "data": {
                    "attributes": {
                        "priority": "P3",
                        "cisa_known_exploited": {"added_date": 1},
                        "epss": {"percentile": 0.97},
                        "cvss": {
                            "cvssv4_x": {
                                "score": 9.8,
                                "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/AU:Y",
                                "threat": {"exploit_maturity": "Attacked"},
                            }
                        },
                    }
                }
            },
        )
        component_sum = sum(
            (
                rec.vulnerability_severity_score,
                rec.active_exploitation_score,
                rec.exploitation_probability_score,
                rec.exploit_maturity_score,
                rec.exploit_automatability_score,
            )
        )
        self.assertAlmostEqual(rec.priority_score, component_sum)
        self.assertEqual((rec.priority_score, rec.priority_rating), (99.2, "P0"))
        self.assertEqual(rec.vulnerability_severity_cvss_version, "CVSS 4.0")
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "report.html"
            ce.render_html_report([rec], path)
            report = path.read_text(encoding="utf-8")
        self.assertIn("Internal Priority Score", report)
        self.assertIn("99.2 <span>/ 100</span>", report)
        self.assertIn("Vulnerability Severity", report)
        self.assertIn("Exploit Automatability", report)
        self.assertIn("VirusTotal priority (comparison only; not used)</th><td>P3", report)

    def test_csv_exports_internal_components_and_labeled_vt_value(self) -> None:
        rec = ce.extract_record(
            "CVE-2026-90002",
            {"data": {"attributes": {"priority": True}}},
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "out.csv"
            ce.write_csv([rec], path)
            with path.open(newline="", encoding="utf-8") as handle:
                row = next(csv.DictReader(handle))
        self.assertEqual(row["priority_rating"], "P3")
        self.assertEqual(row["priority_score"], "0.0")
        self.assertEqual(row["vt_priority_raw"], "True")
        self.assertIn("active_exploitation_score", row)

    def test_explicit_association_signals_rescore_active_exploitation(self) -> None:
        rec = ce.extract_record(
            "CVE-2026-90003",
            {"data": {"attributes": {"cvss": {"cvssv3_x": {"base_score": 10}}}}},
        )
        self.assertEqual((rec.priority_score, rec.priority_rating), (40.0, "P3"))
        rec.supporting_intelligence = [
            ce.AssociationEntity(
                "malware-family--one",
                "malware-family",
                "Example ransomware family",
                tags=["ransomware"],
            )
        ]
        ce.apply_association_priority_signals(rec)
        self.assertEqual(rec.ransomware_available, "True")
        self.assertEqual((rec.priority_score, rec.priority_rating), (65.0, "P2"))


if __name__ == "__main__":
    unittest.main()
