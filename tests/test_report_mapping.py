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


def _reports_for(records: list[ce.CVERecord]) -> tuple[str, str]:
    with tempfile.TemporaryDirectory() as tmp:
        primary = Path(tmp) / "report.html"
        ioc = Path(tmp) / "ioc_report.html"
        ce.render_ioc_report(records, ioc, primary_report_path=primary)
        ce.render_html_report(records, primary, ioc_report_path=ioc)
        return (
            primary.read_text(encoding="utf-8"),
            ioc.read_text(encoding="utf-8"),
        )


def _ioc_row_count(report: str) -> int:
    return report.count('class="ioc-record"')


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


class PriorityMetricNormalizationTests(unittest.TestCase):
    def test_risk_rating_levels(self) -> None:
        expected = {
            "Unrated": 0,
            "Low": 1,
            "Medium": 2,
            "High": 3,
            "Critical": 4,
        }
        for label, level in expected.items():
            self.assertEqual(ce.normalize_risk_rating(label), (level, label))

    def test_exploit_availability_levels(self) -> None:
        expected = {
            "No Known": 0,
            "Interest Observed": 1,
            "Unverified": 2,
            "Privately Held": 3,
            "Publicly Available": 4,
            "Trivial": 4,
        }
        for label, level in expected.items():
            self.assertEqual(ce.normalize_exploit_availability(label), (level, label))
        self.assertEqual(
            ce.normalize_exploit_availability("Known"),
            (4, "Publicly Available"),
        )

    def test_missing_metrics_are_not_coerced_to_zero(self) -> None:
        self.assertEqual(ce.normalize_risk_rating(None), (None, "N/A"))
        self.assertEqual(ce.normalize_exploit_availability(None), (None, "N/A"))


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
        self.assertIn('<svg class="priority-chart"', html)
        self.assertIn('data-axis="risk" data-level="4"', html)
        self.assertIn('data-axis="availability" data-level="4"', html)
        self.assertIn('data-axis="state" data-level="4"', html)
        self.assertIn('<polygon class="priority-shape"', html)
        self.assertIn(
            "Vulnerability severity visualization is based on (1) its potential impact",
            html,
        )
        self.assertEqual(rec.priority_raw, "True")
        self.assertIn("<th>API priority</th><td>True</td>", html)
        self.assertEqual(rec.priority_rating, "P0")

    def test_priority_svg_changes_with_normalized_values(self) -> None:
        low_signal = ce.extract_record(
            "CVE-1900-0042",
            {
                "data": {
                    "attributes": {
                        "risk_rating": "High",
                        "exploit_availability": "No Known",
                        "exploitation_state": "No Known",
                    }
                }
            },
        )
        high_signal = ce.extract_record("CVE-2021-44228", _load("cve-2021-44228.json"))
        low_html = _html_for(low_signal)
        high_html = _html_for(high_signal)
        self.assertEqual(
            (
                low_signal.risk_rating_level,
                low_signal.exploit_availability_level,
                low_signal.exploitation_state_level,
            ),
            ("3", "0", "0"),
        )
        self.assertIn('data-axis="risk" data-level="3"', low_html)
        self.assertIn('data-axis="availability" data-level="0"', low_html)
        self.assertIn('data-axis="state" data-level="0"', low_html)
        self.assertNotEqual(
            low_html.split('<polygon class="priority-shape"', 1)[1].split("/>", 1)[0],
            high_html.split('<polygon class="priority-shape"', 1)[1].split("/>", 1)[0],
        )

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
    def test_ioc_payload_is_only_in_separate_report(self) -> None:
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
        primary, ioc = _reports_for([rec])
        self.assertIn("Indicators of Compromise", primary)
        self.assertIn('href="ioc_report.html#CVE-2021-44228"', primary)
        self.assertIn('target="_blank" rel="noopener noreferrer"', primary)
        self.assertNotIn("exploit.jar", primary)
        self.assertNotIn("http://evil.example/log4j", primary)
        self.assertIn('id="CVE-2021-44228"', ioc)
        self.assertIn("exploit.jar", ioc)
        self.assertIn("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ioc)
        self.assertIn("http://evil.example/log4j", ioc)
        self.assertIn("IOC Type", ioc)
        self.assertIn("IOC Value", ioc)
        self.assertIn("Indicators of Compromise: <span class=\"ioc-count\">3</span>", ioc)
        self.assertEqual(_ioc_row_count(ioc), 3)

    def test_explicit_zero_iocs_has_clear_message(self) -> None:
        rec = ce.extract_record(
            "CVE-1900-0008",
            {"data": {"attributes": {"counters": {"iocs": 0}}}},
        )
        self.assertEqual(rec.ioc_status, "none")
        primary, ioc = _reports_for([rec])
        self.assertIn("No associated IOCs returned by VirusTotal.", primary)
        self.assertIn("No associated IOCs returned by VirusTotal.", ioc)
        self.assertIn('href="ioc_report.html#CVE-1900-0008"', primary)
        self.assertIn("Indicators of Compromise: <span class=\"ioc-count\">0</span>", ioc)
        self.assertEqual(_ioc_row_count(ioc), 0)

    def test_one_ioc_count_matches_one_rendered_row(self) -> None:
        value = "only.example"
        rec = ce.CVERecord(
            cve="CVE-1900-0001",
            ioc_status="complete",
            ioc_count="1",
            ioc_domains_total=1,
            ioc_domains=[{"id": value, "display": value}],
        )
        _, ioc = _reports_for([rec])
        self.assertIn("Indicators of Compromise: <span class=\"ioc-count\">1</span>", ioc)
        self.assertEqual(_ioc_row_count(ioc), 1)
        self.assertEqual(ioc.count(value), 1)

    def test_log4j_twenty_iocs_are_all_rendered(self) -> None:
        file_rows = [
            {
                "type": "file",
                "id": f"{index:064x}",
                "attributes": {"sha256": f"{index:064x}"},
            }
            for index in range(18)
        ]
        url_rows = [
            {
                "type": "url",
                "id": f"url-{index}",
                "attributes": {"url": f"https://ioc.example/log4j/{index}"},
            }
            for index in range(2)
        ]

        class _Stub:
            def get_relationship(self, cve: str, relationship: str, *, limit: int = 40):
                rows = file_rows if relationship == "files" else url_rows
                return {"data": rows, "meta": {"count": len(rows)}}, None, 200

        payload = _load("cve-2021-44228.json")
        rec = ce.extract_record("CVE-2021-44228", payload)
        ce.attach_iocs(_Stub(), rec, payload)  # type: ignore[arg-type]
        _, ioc = _reports_for([rec])
        self.assertEqual(rec.ioc_status, "complete")
        self.assertEqual(ce._ioc_record_count(rec), 20)
        self.assertIn("Indicators of Compromise: <span class=\"ioc-count\">20</span>", ioc)
        self.assertEqual(_ioc_row_count(ioc), 20)
        for item in rec.ioc_files + rec.ioc_urls:
            self.assertIn(item["display"], ioc)

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

    def test_every_returned_ioc_is_retained(self) -> None:
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
        self.assertEqual(len(items), 30)
        rec = ce.CVERecord(
            cve="CVE-1900-0012",
            status="ok",
            ioc_files=items,
            ioc_files_total=40,
            ioc_count="40",
            ioc_status="complete",
        )
        primary, ioc = _reports_for([rec])
        self.assertNotIn(f"{29:064x}", primary)
        self.assertIn(f"{29:064x}", ioc)
        self.assertIn("the API returned 30 unique renderable record(s) for this run", ioc)
        self.assertIn("Indicators of Compromise: <span class=\"ioc-count\">30</span>", ioc)
        self.assertEqual(_ioc_row_count(ioc), 30)

    def test_one_hundred_iocs_are_not_sliced_or_hidden(self) -> None:
        domains = [
            {"id": f"ioc-{index}.example", "display": f"ioc-{index}.example"}
            for index in range(100)
        ]
        rec = ce.CVERecord(
            cve="CVE-1900-0100",
            ioc_status="complete",
            ioc_count="100",
            ioc_domains_total=100,
            ioc_domains=domains,
        )
        _, ioc = _reports_for([rec])
        self.assertIn("Indicators of Compromise: <span class=\"ioc-count\">100</span>", ioc)
        self.assertEqual(_ioc_row_count(ioc), 100)
        self.assertIn("ioc-99.example", ioc)

    def test_multiple_cves_deep_link_to_their_own_sections(self) -> None:
        records = []
        for number, value in ((21, "one.example"), (22, "two.example"), (23, "three.example")):
            rec = ce.CVERecord(
                cve=f"CVE-2026-100{number}",
                ioc_status="complete",
                ioc_count="1",
                ioc_domains_total=1,
                ioc_domains=[{"id": value, "display": value}],
            )
            records.append(rec)
        primary, ioc = _reports_for(records)
        for rec in records:
            self.assertIn(f'href="ioc_report.html#{rec.cve}"', primary)
            self.assertEqual(ioc.count(f'id="{rec.cve}"'), 1)
        for value in ("one.example", "two.example", "three.example"):
            self.assertEqual(ioc.count(value), 1)

    def test_ioc_values_and_anchor_are_html_safe(self) -> None:
        rec = ce.CVERecord(
            cve='CVE-2026-9999"><script>',
            ioc_status="complete",
            ioc_count="1",
            ioc_urls_total=1,
            ioc_urls=[
                {
                    "id": "bad",
                    "display": '<img src=x onerror="alert(1)">&',
                    "vt_url": "javascript:alert(1)",
                }
            ],
        )
        primary, ioc = _reports_for([rec])
        self.assertNotIn("<script>", primary)
        self.assertNotIn("<img src=x", ioc)
        self.assertNotIn('href="javascript:', ioc)
        self.assertIn("&lt;img src=x onerror=&quot;alert(1)&quot;&gt;&amp;", ioc)

    def test_duplicate_indicators_are_removed(self) -> None:
        payload = {
            "data": [
                {"type": "domain", "id": "Example.test"},
                {"type": "domain", "id": "example.test"},
            ]
        }
        items = ce.parse_relationship_iocs("domains", payload)
        self.assertEqual(len(items), 1)

    def test_ipv4_and_ipv6_are_classified(self) -> None:
        rec = ce.CVERecord(
            cve="CVE-2026-20000",
            ioc_status="complete",
            ioc_count="2",
            ioc_ip_addresses_total=2,
            ioc_ip_addresses=[
                {"id": "203.0.113.9", "display": "203.0.113.9"},
                {"id": "2001:db8::1", "display": "2001:db8::1"},
            ],
        )
        _, ioc = _reports_for([rec])
        self.assertIn("IPv4 addresses", ioc)
        self.assertIn("IPv6 addresses", ioc)

    def test_custom_report_locations_use_encoded_relative_links(self) -> None:
        rec = ce.CVERecord(cve="CVE-2026-30000", ioc_status="none", ioc_count="0")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            primary = root / "reports" / "primary report.html"
            ioc = root / "indicators" / "run iocs.html"
            ce.render_ioc_report([rec], ioc, primary_report_path=primary)
            ce.render_html_report([rec], primary, ioc_report_path=ioc)
            primary_html = primary.read_text(encoding="utf-8")
            ioc_html = ioc.read_text(encoding="utf-8")
        self.assertIn('../indicators/run%20iocs.html#CVE-2026-30000', primary_html)
        self.assertIn('../reports/primary%20report.html', ioc_html)

    def test_reports_have_no_external_rendering_dependencies(self) -> None:
        rec = ce.CVERecord(cve="CVE-2026-30001", ioc_status="none", ioc_count="0")
        primary, ioc = _reports_for([rec])
        for report in (primary, ioc):
            self.assertNotIn("<script", report.lower())
            self.assertNotIn("<link", report.lower())
        self.assertIn("<svg", primary)


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
        self.assertEqual(rec.ioc_status, "partial")
        self.assertIn("reported 3 IOC(s)", rec.ioc_error)


class IocPaginationTests(unittest.TestCase):
    def test_relationship_fetch_follows_supported_next_links(self) -> None:
        client = ce.GTIClient("test-key", delay=0, max_retries=1)
        calls: list[str] = []

        def _fake_get(url: str, *, context: str):
            calls.append(url)
            if len(calls) == 1:
                return (
                    {
                        "data": [{"type": "domain", "id": "one.example"}],
                        "meta": {"count": 2},
                        "links": {
                            "next": (
                                "https://www.virustotal.com/api/v3/collections/"
                                "vulnerability--cve-2026-40000/domains?cursor=next&limit=40"
                            )
                        },
                    },
                    None,
                    200,
                )
            return (
                {"data": [{"type": "domain", "id": "two.example"}], "meta": {"count": 2}},
                None,
                200,
            )

        client._get_json = _fake_get  # type: ignore[method-assign]
        body, error, status = client.get_relationship("CVE-2026-40000", "domains")
        self.assertEqual((error, status), (None, 200))
        self.assertEqual(len(calls), 2)
        self.assertEqual([row["id"] for row in body["data"]], ["one.example", "two.example"])

    def test_relationship_fetch_collects_one_hundred_objects_across_pages(self) -> None:
        client = ce.GTIClient("test-key", delay=0, max_retries=1)
        calls: list[str] = []

        def _fake_get(url: str, *, context: str):
            page = len(calls)
            calls.append(url)
            start, stop = ((0, 40), (40, 80), (80, 100))[page]
            body = {
                "data": [
                    {"type": "domain", "id": f"ioc-{index}.example"}
                    for index in range(start, stop)
                ],
                "meta": {"count": 100},
            }
            if page < 2:
                body["links"] = {
                    "next": (
                        "https://www.virustotal.com/api/v3/collections/"
                        "vulnerability--cve-2026-40100/domains"
                        f"?cursor=page{page + 2}&limit=40"
                    )
                }
            return body, None, 200

        client._get_json = _fake_get  # type: ignore[method-assign]
        body, error, status = client.get_relationship("CVE-2026-40100", "domains")
        self.assertEqual((error, status), (None, 200))
        self.assertEqual(len(calls), 3)
        self.assertEqual(len(body["data"]), 100)
        self.assertEqual(body["data"][-1]["id"], "ioc-99.example")

    def test_relationship_fetch_rejects_cross_origin_next_link(self) -> None:
        client = ce.GTIClient("test-key", delay=0, max_retries=1)
        calls: list[str] = []

        def _fake_get(url: str, *, context: str):
            calls.append(url)
            return (
                {
                    "data": [{"type": "domain", "id": "safe.example"}],
                    "meta": {"count": 2},
                    "links": {"next": "https://attacker.invalid/collect?cursor=secret"},
                },
                None,
                200,
            )

        client._get_json = _fake_get  # type: ignore[method-assign]
        body, error, status = client.get_relationship("CVE-2026-40001", "domains")
        self.assertEqual((error, status), (None, 200))
        self.assertEqual(len(calls), 1)
        self.assertIn("unsafe pagination URL", body["_pagination_error"])


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
