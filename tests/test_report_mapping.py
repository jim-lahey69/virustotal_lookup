"""Regression tests for GTI report normalization and HTML rendering."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from dataclasses import fields
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import cve_enricher as ce  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def _html_for(rec: ce.CVERecord) -> str:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "report.html"
        ce.render_html_report([rec], path)
        return path.read_text(encoding="utf-8")


class ExploitationStateTests(unittest.TestCase):
    def test_all_official_labels_and_levels(self) -> None:
        expected = {
            0: "No Known",
            1: "Suspected",
            2: "Reported",
            3: "Confirmed",
            4: "Wide",
        }
        for level, label in expected.items():
            self.assertEqual(ce.normalize_exploitation_state(level), (level, label))
            self.assertEqual(ce.normalize_exploitation_state(label), (level, label))

    def test_aliases(self) -> None:
        self.assertEqual(ce.normalize_exploitation_state("wide")[1], "Wide")
        self.assertEqual(ce.normalize_exploitation_state("CONFIRMED")[1], "Confirmed")
        self.assertEqual(ce.normalize_exploitation_state("no_known")[1], "No Known")

    def test_missing_and_unexpected_are_unknown(self) -> None:
        for value in (None, "", "N/A", "unexpected", 5, -1):
            self.assertEqual(ce.normalize_exploitation_state(value), (None, "Unknown"))
        rec = ce.extract_record("CVE-1900-0001", {"data": {"attributes": {}}})
        self.assertEqual(rec.exploitation_state, "Unknown")


class ExploitedInTheWildTests(unittest.TestCase):
    def test_cve_2026_34621_filter_match_is_yes_in_html(self) -> None:
        payload = _load("cve-2026-34621.json")
        rec = ce.extract_record("CVE-2026-34621", payload)

        # A Confirmed state alone is not substituted for the separate GUI flag.
        self.assertEqual(rec.exploitation_state, "Confirmed")
        self.assertEqual(rec.exploited_in_the_wild, "Unknown")

        observed = ce.parse_observed_in_the_wild_response(
            "CVE-2026-34621",
            _load("cve-2026-34621-observed-in-wild.json"),
        )
        self.assertTrue(observed)
        ce.apply_observed_in_the_wild_result(rec, observed, http_status=200)
        self.assertEqual(rec.exploited_in_the_wild, "True")
        self.assertEqual(rec.exploited_in_the_wild_status, "filter_returned")

        html = _html_for(rec)
        self.assertIn("Exploited in the Wild", html)
        self.assertIn("badge-danger\">YES", html)

    def test_successful_empty_filter_is_no(self) -> None:
        observed = ce.parse_observed_in_the_wild_response(
            "CVE-1900-0002",
            {"data": [], "meta": {"count": 0}},
        )
        self.assertFalse(observed)
        rec = ce.extract_record(
            "CVE-1900-0002",
            {"data": {"attributes": {"exploitation_state": "No Known"}}},
        )
        ce.apply_observed_in_the_wild_result(rec, observed, http_status=200)
        self.assertEqual(rec.exploited_in_the_wild, "False")
        self.assertIn(
            'Exploited in the Wild</th><td><span class="badge badge-muted">no</span>',
            _html_for(rec),
        )

    def test_missing_object_property_is_unknown_not_no(self) -> None:
        rec = ce.extract_record(
            "CVE-1900-0003",
            {
                "data": {
                    "attributes": {
                        "exploitation_state": "Wide",
                        "cisa_known_exploited": {"added_date": 1},
                    }
                }
            },
        )
        self.assertEqual(rec.exploited_in_the_wild, "Unknown")
        self.assertEqual(rec.exploited_in_the_wild_status, "not_returned")

    def test_explicit_boolean_values_are_preserved(self) -> None:
        yes, yes_sources, yes_raw = ce.derive_exploited_in_the_wild(
            {"exploited_in_the_wild": True}
        )
        no, no_sources, no_raw = ce.derive_exploited_in_the_wild(
            {"exploited_in_the_wild": False}
        )
        self.assertEqual((yes, yes_raw), ("True", "True"))
        self.assertEqual((no, no_raw), ("False", "False"))
        self.assertTrue(yes_sources)
        self.assertTrue(no_sources)

    def test_lookup_failure_stays_unknown(self) -> None:
        rec = ce.extract_record("CVE-1900-0004", {"data": {"attributes": {}}})
        ce.apply_observed_in_the_wild_result(
            rec,
            None,
            error="rate_limited",
            http_status=429,
        )
        self.assertEqual(rec.exploited_in_the_wild, "Unknown")
        self.assertEqual(rec.exploited_in_the_wild_status, "lookup_failed")
        html = _html_for(rec)
        self.assertIn("Observed In The Wild lookup failed", html)
        self.assertNotIn("lookup failed; the result remains No", html)

    def test_filter_result_wins_over_conflicting_object_value(self) -> None:
        rec = ce.extract_record(
            "CVE-1900-0005",
            {"data": {"attributes": {"exploited_in_the_wild": False}}},
        )
        ce.apply_observed_in_the_wild_result(rec, True, http_status=200)
        self.assertEqual(rec.exploited_in_the_wild, "True")
        html = _html_for(rec)
        self.assertIn("Observed In The Wild filter: Yes", html)
        self.assertIn("explicit field: False", html)

    def test_malformed_filter_response_is_not_a_negative(self) -> None:
        with self.assertRaises(ValueError):
            ce.parse_observed_in_the_wild_response("CVE-1900-0006", {"meta": {}})

    def test_enrichment_pipeline_applies_filter_result(self) -> None:
        class _Stub:
            def __init__(self) -> None:
                self.observed_calls: list[str] = []

            def get_vulnerability(self, cve: str):
                return _load("cve-2026-34621.json"), None, 200

            def get_observed_in_the_wild(self, cve: str):
                self.observed_calls.append(cve)
                value = ce.parse_observed_in_the_wild_response(
                    cve,
                    _load("cve-2026-34621-observed-in-wild.json"),
                )
                return value, None, 200

            def get_relationship(self, cve: str, relationship: str, *, limit: int = 25):
                if relationship == "files":
                    return _load("relationship-files.json"), None, 200
                return {"data": [], "meta": {"count": 1}}, None, 200

        stub = _Stub()
        records = ce.enrich_cves(stub, ["CVE-2026-34621"])  # type: ignore[arg-type]
        self.assertEqual(stub.observed_calls, ["CVE-2026-34621"])
        self.assertEqual(records[0].exploited_in_the_wild, "True")
        self.assertIn("badge-danger\">YES", _html_for(records[0]))

    def test_client_uses_documented_filter_query(self) -> None:
        client = ce.GTIClient("test-key", delay=0, max_retries=1)
        captured: dict[str, str] = {}

        def _fake_get(url: str, *, context: str):
            captured["url"] = url
            captured["context"] = context
            return _load("cve-2026-34621-observed-in-wild.json"), None, 200

        client._get_json = _fake_get  # type: ignore[method-assign]
        value, error, status = client.get_observed_in_the_wild("CVE-2026-34621")
        self.assertEqual((value, error, status), (True, None, 200))
        self.assertIn("vulnerability_filter%3A%22Observed+In+The+Wild%22", captured["url"])
        self.assertIn("name%3ACVE-2026-34621", captured["url"])


class CanonicalIdentifierTests(unittest.TestCase):
    def test_cve_is_the_only_vulnerability_identifier_field(self) -> None:
        identifier_fields = {
            item.name
            for item in fields(ce.CVERecord)
            if item.name == "cve" or item.name.endswith("_id")
        }
        self.assertEqual(identifier_fields, {"cve", "cwe_id"})
        self.assertEqual(ce.CSV_COLUMNS[0], "cve")

    def test_unrelated_api_alias_is_not_rendered(self) -> None:
        payload = _load("cve-2026-34621.json")
        payload["data"]["attributes"]["legacy_identifier"] = "LEGACY-DO-NOT-RENDER"
        rec = ce.extract_record("CVE-2026-34621", payload)
        html = _html_for(rec)
        self.assertIn("CVE-2026-34621", html)
        self.assertNotIn("LEGACY-DO-NOT-RENDER", html)


class HtmlFeatureTests(unittest.TestCase):
    def test_exploitation_state_info_icon_and_visible_legend(self) -> None:
        rec = ce.extract_record("CVE-2026-34621", _load("cve-2026-34621.json"))
        html = _html_for(rec)
        self.assertIn("info-tip", html)
        self.assertIn(
            "Indicates our knowledge of the current exploitation landscape, and whether a vulnerability is known or suspected to be exploited.",
            html,
        )
        self.assertIn(
            "0 = No known | 1 = Suspected | 2 = Reported | 3 = Confirmed | 4 = Wide",
            html,
        )
        self.assertIn("exploit-confirmed", html)

    def test_priority_visualization_and_raw_value(self) -> None:
        rec = ce.extract_record("CVE-2021-44228", _load("cve-2021-44228.json"))
        html = _html_for(rec)
        self.assertIn("Priority visualization", html)
        self.assertIn("Potential impact", html)
        self.assertIn("Exploit accessibility", html)
        self.assertIn("Real-world use", html)
        self.assertIn(
            "Vulnerability severity visualization is based on (1) its potential impact",
            html,
        )
        self.assertEqual(rec.priority_raw, "True")
        self.assertIn("<th>API priority</th><td>True</td>", html)
        self.assertEqual(rec.priority_rating, "P0")

    def test_missing_state_does_not_create_priority(self) -> None:
        self.assertEqual(
            ce.derive_priority_rating("High", "Unknown", "Publicly Available"),
            "N/A",
        )
        self.assertEqual(
            ce.derive_priority_rating("High", "No Known", "Unknown"),
            "N/A",
        )

    def test_api_text_is_html_escaped(self) -> None:
        payload = {"data": {"attributes": {"description": "<script>alert(1)</script>"}}}
        html = _html_for(ce.extract_record("CVE-1900-0007", payload))
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", html)
        self.assertNotIn("<script>alert(1)</script>", html)


class IocReportingTests(unittest.TestCase):
    def test_ioc_section_lists_actual_indicators(self) -> None:
        rec = ce.extract_record("CVE-2021-44228", _load("cve-2021-44228.json"))
        rec.ioc_files = ce.parse_relationship_iocs("files", _load("relationship-files.json"))
        rec.ioc_urls = [
            {
                "id": "urlid1",
                "display": "http://evil.example/log4j",
                "vt_url": "https://www.virustotal.com/gui/url/urlid1",
            }
        ]
        rec.ioc_urls_total = 2
        rec.ioc_files_total = 18
        rec.ioc_status = "complete"
        html = _html_for(rec)
        self.assertIn("Indicators of Compromise", html)
        self.assertIn("exploit.jar", html)
        self.assertIn("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", html)
        self.assertIn("http://evil.example/log4j", html)
        self.assertIn("and 16 more", html)
        self.assertNotIn("IP addresses", html)
        self.assertNotIn("Domains", html)

    def test_explicit_zero_iocs_has_clear_message(self) -> None:
        rec = ce.extract_record(
            "CVE-1900-0008",
            {"data": {"attributes": {"counters": {"iocs": 0}}}},
        )
        self.assertEqual(rec.ioc_status, "none")
        html = _html_for(rec)
        self.assertIn("No associated IOCs returned by VirusTotal.", html)

    def test_absent_ioc_property_is_not_reported_as_none(self) -> None:
        rec = ce.extract_record("CVE-1900-0009", {"data": {"attributes": {}}})
        self.assertEqual(rec.ioc_status, "not_returned")
        html = _html_for(rec)
        self.assertIn("IOC availability was not returned by VirusTotal.", html)
        self.assertNotIn("No associated IOCs returned by VirusTotal.", html)

    def test_ioc_retrieval_failure_is_distinct(self) -> None:
        class _Stub:
            def get_relationship(self, cve: str, relationship: str, *, limit: int = 25):
                return None, "error", 503

        payload = {"data": {"attributes": {"counters": {"iocs": 1, "files": 1}}}}
        rec = ce.extract_record("CVE-1900-0010", payload)
        ce.attach_iocs(_Stub(), rec, payload)  # type: ignore[arg-type]
        self.assertEqual(rec.ioc_status, "error")
        html = _html_for(rec)
        self.assertIn("IOC retrieval failed or was incomplete", html)
        self.assertNotIn("No associated IOCs returned by VirusTotal.", html)

    def test_ioc_parsing_failure_is_distinct(self) -> None:
        class _Stub:
            def get_relationship(self, cve: str, relationship: str, *, limit: int = 25):
                return {"meta": {"count": 1}}, None, 200

        payload = {"data": {"attributes": {"counters": {"iocs": 1, "files": 1}}}}
        rec = ce.extract_record("CVE-1900-0011", payload)
        ce.attach_iocs(_Stub(), rec, payload)  # type: ignore[arg-type]
        self.assertEqual(rec.ioc_status, "error")
        self.assertIn("response parsing failed", rec.ioc_error)
        self.assertNotIn("No associated IOCs", _html_for(rec))

    def test_ioc_cap_and_parse(self) -> None:
        payload = {
            "data": [
                {
                    "type": "file",
                    "id": f"{i:064x}",
                    "attributes": {"sha256": f"{i:064x}"},
                }
                for i in range(30)
            ]
        }
        items = ce.parse_relationship_iocs("files", payload)
        self.assertEqual(len(items), ce.IOC_DISPLAY_CAP)
        rec = ce.CVERecord(
            cve="CVE-1900-0012",
            status="ok",
            ioc_files=items,
            ioc_files_total=40,
            ioc_count="40",
            ioc_status="complete",
        )
        html = _html_for(rec)
        self.assertIn("and 15 more", html)
        self.assertIn("showing 25 of 40", html)


class AttachIocsTests(unittest.TestCase):
    def test_fetches_only_types_with_counts(self) -> None:
        class _Stub:
            def __init__(self) -> None:
                self.called: list[tuple[str, str, int]] = []

            def get_relationship(self, cve: str, relationship: str, *, limit: int = 25):
                self.called.append((cve, relationship, limit))
                if relationship == "files":
                    return _load("relationship-files.json"), None, 200
                return {"data": [], "meta": {"count": 1}}, None, 200

        payload = _load("cve-2026-34621.json")
        rec = ce.extract_record("CVE-2026-34621", payload)
        stub = _Stub()
        ce.attach_iocs(stub, rec, payload)  # type: ignore[arg-type]
        self.assertEqual([call[1] for call in stub.called], ["files", "urls"])
        self.assertEqual(len(rec.ioc_files), 2)
        self.assertEqual(rec.ioc_files[0]["name"], "exploit.jar")
        self.assertEqual(rec.ioc_status, "complete")


class IocParserTests(unittest.TestCase):
    def test_parse_files_urls_domains_ips(self) -> None:
        files = ce.parse_relationship_iocs("files", _load("relationship-files.json"))
        self.assertEqual(files[0]["name"], "exploit.jar")
        self.assertTrue(files[0]["vt_url"].endswith(files[0]["sha256"]))

        urls = ce.parse_relationship_iocs(
            "urls",
            {"data": [{"type": "url", "id": "abc", "attributes": {"url": "https://evil.test/x"}}]},
        )
        self.assertEqual(urls[0]["display"], "https://evil.test/x")

        domains = ce.parse_relationship_iocs(
            "domains",
            {"data": [{"type": "domain", "id": "evil.test"}]},
        )
        self.assertEqual(domains[0]["display"], "evil.test")

        ips = ce.parse_relationship_iocs(
            "ip_addresses",
            {"data": [{"type": "ip_address", "id": "203.0.113.9"}]},
        )
        self.assertEqual(ips[0]["display"], "203.0.113.9")


if __name__ == "__main__":
    unittest.main()
