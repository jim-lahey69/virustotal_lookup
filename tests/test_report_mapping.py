"""Regression tests for GTI report mapping (in-the-wild, MVE, IoCs, state, priority viz)."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
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
    def test_official_levels(self) -> None:
        expected = {
            "No Known": 0,
            "Suspected": 1,
            "Reported": 2,
            "Confirmed": 3,
            "Wide": 4,
        }
        for label, level in expected.items():
            got_level, got_label = ce.normalize_exploitation_state(label)
            self.assertEqual(got_level, level)
            self.assertEqual(got_label, label)

    def test_aliases_and_numeric(self) -> None:
        self.assertEqual(ce.normalize_exploitation_state("wide")[1], "Wide")
        self.assertEqual(ce.normalize_exploitation_state("CONFIRMED")[1], "Confirmed")
        self.assertEqual(ce.normalize_exploitation_state("no_known")[1], "No Known")
        self.assertEqual(ce.normalize_exploitation_state(4)[1], "Wide")

    def test_missing_is_unknown_not_no_known(self) -> None:
        self.assertEqual(ce.normalize_exploitation_state(None), (None, "Unknown"))
        self.assertEqual(ce.normalize_exploitation_state(""), (None, "Unknown"))
        self.assertEqual(ce.normalize_exploitation_state("N/A"), (None, "Unknown"))
        rec = ce.extract_record("CVE-1900-0001", {"data": {"attributes": {}}})
        self.assertEqual(rec.exploitation_state, "Unknown")
        self.assertNotEqual(rec.exploitation_state, "No Known")


class ExploitedInTheWildTests(unittest.TestCase):
    def test_cve_2026_34621_fixture_is_yes(self) -> None:
        """Mandatory fixture: GUI Yes, no attributes.exploited_in_the_wild key."""
        payload = _load("cve-2026-34621.json")
        attrs = payload["data"]["attributes"]
        self.assertNotIn("exploited_in_the_wild", attrs)
        rec = ce.extract_record("CVE-2026-34621", payload)
        self.assertEqual(rec.exploited_in_the_wild, "True")
        self.assertIn("exploitation_state=Confirmed", rec.exploited_in_the_wild_sources)
        html = _html_for(rec)
        self.assertIn("badge-danger", html)
        self.assertIn("YES", html)
        # Must not render the muted "no" badge for this CVE.
        self.assertNotRegex(
            html,
            r"Exploited in the Wild</th>\s*<td><span class=\"badge badge-muted\">no</span>",
        )

    def test_cve_2021_44228_log4j_is_yes(self) -> None:
        payload = _load("cve-2021-44228.json")
        rec = ce.extract_record("CVE-2021-44228", payload)
        self.assertEqual(rec.exploitation_state, "Wide")
        self.assertEqual(rec.exploited_in_the_wild, "True")
        html = _html_for(rec)
        self.assertIn("YES", html)
        self.assertNotRegex(
            html,
            r"Exploited in the Wild</th>\s*<td><span class=\"badge badge-muted\">no</span>",
        )

    def test_no_signals_is_no(self) -> None:
        payload = {
            "data": {
                "attributes": {
                    "exploitation_state": "No Known",
                    "exploit_availability": "No Known",
                    "tags": [],
                }
            }
        }
        rec = ce.extract_record("CVE-1900-0002", payload)
        self.assertEqual(rec.exploited_in_the_wild, "False")

    def test_explicit_true_wins_even_if_state_is_no_known(self) -> None:
        display, sources, explicit = ce.derive_exploited_in_the_wild(
            {"exploited_in_the_wild": True, "exploitation_state": "No Known"},
            exploitation_state="No Known",
        )
        self.assertEqual(display, "True")
        self.assertTrue(any("exploited_in_the_wild" in s for s in sources))
        self.assertEqual(explicit, "True")

    def test_confirmed_is_never_mapped_to_no(self) -> None:
        display, sources, _ = ce.derive_exploited_in_the_wild(
            {"exploitation_state": "Confirmed"},
            exploitation_state="Confirmed",
            cisa_kev=False,
        )
        self.assertEqual(display, "True")
        self.assertIn("exploitation_state=Confirmed", sources)

    def test_wide_is_never_mapped_to_no(self) -> None:
        display, _, _ = ce.derive_exploited_in_the_wild(
            {"exploitation_state": "Wide"},
            exploitation_state="Wide",
            cisa_kev=False,
        )
        self.assertEqual(display, "True")

    def test_missing_kev_does_not_veto_gti_wild_state(self) -> None:
        display, sources, _ = ce.derive_exploited_in_the_wild(
            {"exploitation_state": "Wide"},
            exploitation_state="Wide",
            cisa_kev=False,
        )
        self.assertEqual(display, "True")
        self.assertNotIn("cisa_known_exploited", sources)

    def test_cisa_kev_alone_is_yes(self) -> None:
        display, sources, _ = ce.derive_exploited_in_the_wild(
            {"exploitation_state": "Reported"},
            exploitation_state="Reported",
            cisa_kev=True,
        )
        self.assertEqual(display, "True")
        self.assertIn("cisa_known_exploited", sources)

    def test_observed_in_the_wild_tag(self) -> None:
        display, sources, _ = ce.derive_exploited_in_the_wild(
            {"exploitation_state": "Suspected", "tags": ["Observed In The Wild"]},
            exploitation_state="Suspected",
            tags=["Observed In The Wild"],
        )
        self.assertEqual(display, "True")
        self.assertTrue(any("tag=" in s for s in sources))

    def test_explicit_false_plus_wide_shows_conflict_note(self) -> None:
        rec = ce.extract_record(
            "CVE-1900-0003",
            {
                "data": {
                    "attributes": {
                        "exploitation_state": "Wide",
                        "exploited_in_the_wild": False,
                    }
                }
            },
        )
        self.assertEqual(rec.exploited_in_the_wild, "True")
        html = _html_for(rec)
        self.assertIn("API derived: Yes", html)
        self.assertIn("explicit field:", html)
        self.assertIn("source fields:", html)


class MveRemovalTests(unittest.TestCase):
    def test_html_does_not_show_mve(self) -> None:
        rec = ce.extract_record("CVE-2021-44228", _load("cve-2021-44228.json"))
        self.assertEqual(rec.mve_id, "MVE-2021-10855")  # still extracted internally
        html = _html_for(rec)
        self.assertNotIn("MVE ID", html)
        self.assertNotIn("MVE-2021-10855", html)
        rec2 = ce.extract_record("CVE-2026-34621", _load("cve-2026-34621.json"))
        html2 = _html_for(rec2)
        self.assertNotIn("MVE-2026-99999", html2)
        self.assertNotIn("MVE ID", html2)


class HtmlFeatureTests(unittest.TestCase):
    def test_exploitation_state_info_icon_and_legend(self) -> None:
        rec = ce.extract_record("CVE-2026-34621", _load("cve-2026-34621.json"))
        html = _html_for(rec)
        self.assertIn("info-tip", html)
        self.assertIn(
            "Indicates our knowledge of the current exploitation landscape, and whether a vulnerability is known or suspected to be exploited.",
            html,
        )
        self.assertIn("0 = No Known", html)
        self.assertIn("1 = Suspected", html)
        self.assertIn("2 = Reported", html)
        self.assertIn("3 = Confirmed", html)
        self.assertIn("4 = Wide", html)
        self.assertIn("exploit-confirmed", html)

    def test_priority_visualization_block(self) -> None:
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
        self.assertIn("P0", html)

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
        html = _html_for(rec)
        self.assertIn("Indicators of Compromise", html)
        self.assertIn("exploit.jar", html)
        self.assertIn("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", html)
        self.assertIn("http://evil.example/log4j", html)
        self.assertIn("and 16 more", html)
        self.assertNotIn("IP addresses", html)  # zero → omitted
        self.assertNotIn("Domains", html)

    def test_no_iocs_muted_message(self) -> None:
        rec = ce.extract_record(
            "CVE-1900-0004",
            {"data": {"attributes": {"exploitation_state": "No Known"}}},
        )
        html = _html_for(rec)
        self.assertIn("No associated IoCs returned by GTI.", html)

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
        rec = ce.CVERecord(cve="CVE-1900-0005", status="ok", ioc_files=items, ioc_files_total=40)
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
                return {"data": []}, None, 200

        rec = ce.extract_record("CVE-2026-34621", _load("cve-2026-34621.json"))
        stub = _Stub()
        ce.attach_iocs(stub, rec, _load("cve-2026-34621.json"))  # type: ignore[arg-type]
        rels = [c[1] for c in stub.called]
        self.assertEqual(rels, ["files", "urls"])  # domains/ips counts are 0
        self.assertEqual(len(rec.ioc_files), 2)
        self.assertEqual(rec.ioc_files[0]["name"], "exploit.jar")


class IocParserTests(unittest.TestCase):
    def test_parse_files_urls_domains_ips(self) -> None:
        files = ce.parse_relationship_iocs("files", _load("relationship-files.json"))
        self.assertEqual(files[0]["name"], "exploit.jar")
        self.assertTrue(files[0]["vt_url"].endswith(files[0]["sha256"]))
        urls = ce.parse_relationship_iocs(
            "urls",
            {
                "data": [
                    {
                        "type": "url",
                        "id": "abc",
                        "attributes": {"url": "https://evil.test/x"},
                    }
                ]
            },
        )
        self.assertEqual(urls[0]["display"], "https://evil.test/x")
        domains = ce.parse_relationship_iocs(
            "domains", {"data": [{"type": "domain", "id": "evil.test"}]}
        )
        self.assertEqual(domains[0]["display"], "evil.test")
        ips = ce.parse_relationship_iocs(
            "ip_addresses", {"data": [{"type": "ip_address", "id": "203.0.113.9"}]}
        )
        self.assertEqual(ips[0]["display"], "203.0.113.9")


if __name__ == "__main__":
    unittest.main()
