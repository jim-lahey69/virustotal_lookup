"""Association retrieval, normalization, attack-chain integrity, and report tests."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import cve_enricher as ce


ASSOCIATIONS_PAYLOAD = {
    "data": [
        {
            "type": "collection",
            "id": "threat-actor--actor-1",
            "attributes": {
                "collection_type": "threat-actor",
                "name": "Example Actor",
                "description": "Observed actor context",
                "origin": "Google Threat Intelligence",
                "alt_names": ["Actor Alias"],
                "tags": ["espionage"],
                "creation_date": 1704067200,
            },
            "links": {
                "self": "https://www.virustotal.com/api/v3/collections/threat-actor--actor-1"
            },
        },
        {
            "type": "collection",
            "id": "campaign--campaign-1",
            "attributes": {
                "collection_type": "campaign",
                "name": "Example Campaign",
                "campaign_type": "Multitarget Campaign",
                "first_seen_details": [{"value": "2025-01-02T00:00:00Z"}],
                "malware_roles": [{"value": "Backdoor"}],
            },
        },
        {
            "type": "collection",
            "id": "malware--malware-1",
            "attributes": {
                "collection_type": "malware-family",
                "name": "Example Malware",
            },
        },
        {
            "type": "collection",
            "id": "vulnerability--cve-2025-9999",
            "attributes": {
                "collection_type": "vulnerability",
                "name": "Unrelated vulnerability",
            },
        },
    ],
    "meta": {"count": 4},
}

TECHNIQUES_PAYLOAD = {
    "data": [
        {
            "type": "attack_technique",
            "id": "T1190",
            "attributes": {
                "name": "Exploit Public-Facing Application",
                "link": "https://attack.mitre.org/techniques/T1190/",
            },
        },
        {
            "type": "attack_technique",
            "id": "T1059.001",
            "attributes": {"name": "PowerShell"},
        },
    ],
    "meta": {"count": 2},
}

TACTICS = {
    "T1190": {
        "data": [
            {
                "type": "attack_tactic",
                "id": "TA0001",
                "attributes": {
                    "name": "Initial Access",
                    "link": "https://attack.mitre.org/tactics/TA0001/",
                },
            }
        ]
    },
    "T1059.001": {
        "data": [
            {
                "type": "attack_tactic",
                "id": "TA0002",
                "attributes": {"name": "Execution"},
            }
        ]
    },
}


class AssociationParserTests(unittest.TestCase):
    def test_filters_and_normalizes_relevant_threat_objects(self) -> None:
        groups = ce.parse_associations(ASSOCIATIONS_PAYLOAD)
        self.assertEqual([item.name for item in groups["threat_actors"]], ["Example Actor"])
        self.assertEqual([item.name for item in groups["campaigns"]], ["Example Campaign"])
        self.assertEqual(
            [item.name for item in groups["supporting_intelligence"]],
            ["Example Malware"],
        )
        self.assertEqual(groups["threat_actors"][0].origin, "Google Threat Intelligence")
        self.assertIn("Campaign type: Multitarget Campaign", groups["campaigns"][0].classifications)

    def test_tcodes_are_attack_technique_ids_not_an_assumed_field(self) -> None:
        techniques = ce.parse_attack_techniques(TECHNIQUES_PAYLOAD)
        self.assertEqual([item.technique_id for item in techniques], ["T1190", "T1059.001"])
        self.assertEqual(techniques[0].relationship, "attack_techniques")

    def test_malformed_payloads_are_not_treated_as_empty(self) -> None:
        with self.assertRaises(ValueError):
            ce.parse_associations({"meta": {"count": 0}})
        with self.assertRaises(ValueError):
            ce.parse_attack_techniques({"data": {}})


class AssociationAttachmentTests(unittest.TestCase):
    class Client:
        def __init__(self, associations=ASSOCIATIONS_PAYLOAD, techniques=TECHNIQUES_PAYLOAD):
            self.associations = associations
            self.techniques = techniques
            self.calls: list[tuple[str, str]] = []

        def get_collection_relationship(self, cve: str, relationship: str, *, limit: int = 40):
            self.calls.append((cve, relationship))
            payload = self.associations if relationship == "associations" else self.techniques
            return payload, None, 200

        def get_attack_technique_tactics(self, technique_id: str, *, limit: int = 40):
            return TACTICS.get(technique_id, {"data": []}), None, 200

    def test_builds_mapped_chain_from_direct_techniques_and_tactics(self) -> None:
        rec = ce.CVERecord(cve="CVE-2026-10000", status="ok")
        client = self.Client()
        ce.attach_associations(client, rec)  # type: ignore[arg-type]

        self.assertEqual(rec.association_status, "complete")
        self.assertEqual([stage.stage_id for stage in rec.attack_chain], ["TA0001", "TA0002"])
        self.assertTrue(all(stage.evidence_type == "Analytical Mapping" for stage in rec.attack_chain))
        self.assertIn("not an observed intrusion chronology", rec.attack_chain_note)
        self.assertEqual(
            client.calls,
            [
                ("CVE-2026-10000", "associations"),
                ("CVE-2026-10000", "attack_techniques"),
            ],
        )

    def test_no_associations_and_no_techniques_is_a_clean_no_data_state(self) -> None:
        rec = ce.CVERecord(cve="CVE-2026-10001", status="ok")
        ce.attach_associations(
            self.Client(associations={"data": []}, techniques={"data": []}),
            rec,
        )  # type: ignore[arg-type]
        self.assertEqual(rec.association_status, "none")
        self.assertEqual(rec.attack_chain, [])
        self.assertIn("Insufficient VirusTotal intelligence", rec.attack_chain_note)

    def test_actor_without_attack_evidence_does_not_fabricate_a_chain(self) -> None:
        rec = ce.CVERecord(cve="CVE-2026-10002", status="ok")
        ce.attach_associations(
            self.Client(associations=ASSOCIATIONS_PAYLOAD, techniques={"data": []}),
            rec,
        )  # type: ignore[arg-type]
        self.assertEqual(len(rec.threat_actors), 1)
        self.assertEqual(rec.attack_chain, [])
        self.assertIn("Insufficient VirusTotal intelligence", rec.attack_chain_note)

    def test_api_failure_is_partial_and_retains_available_techniques(self) -> None:
        class PartialClient(self.Client):
            def get_collection_relationship(self, cve: str, relationship: str, *, limit: int = 40):
                if relationship == "associations":
                    return None, "rate_limited", 429
                return TECHNIQUES_PAYLOAD, None, 200

        rec = ce.CVERecord(cve="CVE-2026-10003", status="ok")
        ce.attach_associations(PartialClient(), rec)  # type: ignore[arg-type]
        self.assertEqual(rec.association_status, "partial")
        self.assertEqual(len(rec.attack_chain), 2)
        self.assertIn("HTTP 429", rec.association_error)


class AssociationPaginationTests(unittest.TestCase):
    def test_collects_all_associations_across_pages(self) -> None:
        client = ce.GTIClient("test-key", delay=0, max_retries=1)
        calls: list[str] = []

        def fake_get(url: str, *, context: str):
            calls.append(url)
            if len(calls) == 1:
                return {
                    "data": [{"type": "collection", "id": "threat-actor--one"}],
                    "meta": {"count": 2},
                    "links": {
                        "next": (
                            "https://www.virustotal.com/api/v3/collections/"
                            "vulnerability--cve-2026-10004/associations?cursor=next&limit=40"
                        )
                    },
                }, None, 200
            return {
                "data": [{"type": "collection", "id": "campaign--two"}],
                "meta": {"count": 2},
            }, None, 200

        client._get_json = fake_get  # type: ignore[method-assign]
        body, error, status = client.get_collection_relationship(
            "CVE-2026-10004", "associations"
        )
        self.assertEqual((error, status), (None, 200))
        self.assertEqual(len(calls), 2)
        self.assertEqual([row["id"] for row in body["data"]], ["threat-actor--one", "campaign--two"])


class AssociationReportTests(unittest.TestCase):
    def _render(self, records: list[ce.CVERecord]) -> tuple[str, str]:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            primary = root / "report.html"
            ioc = root / "ioc_report.html"
            associations = root / "associations_report.html"
            ce.render_ioc_report(records, ioc, primary_report_path=primary)
            ce.render_associations_report(
                records,
                associations,
                primary_report_path=primary,
                ioc_report_path=ioc,
            )
            ce.render_html_report(
                records,
                primary,
                ioc_report_path=ioc,
                associations_report_path=associations,
            )
            return primary.read_text(encoding="utf-8"), associations.read_text(encoding="utf-8")

    def test_report_distinguishes_observed_data_from_mapping(self) -> None:
        rec = ce.CVERecord(cve="CVE-2026-10005", status="ok", ioc_status="none")
        ce.attach_associations(AssociationAttachmentTests.Client(), rec)  # type: ignore[arg-type]
        primary, associations = self._render([rec])

        self.assertIn('href="associations_report.html#CVE-2026-10005"', primary)
        self.assertIn("Associated Threat Actors", associations)
        self.assertIn("Example Actor", associations)
        self.assertIn("Example Campaign", associations)
        self.assertIn("Example Malware", associations)
        self.assertIn("T1190", associations)
        self.assertIn("Evidence type", associations)
        self.assertIn("Analytical Mapping", associations)
        self.assertIn("not an observed intrusion chronology", associations)
        self.assertIn("CVE-level co-association does not prove technique-level attribution", associations)

    def test_no_data_and_insufficient_chain_messages_are_explicit(self) -> None:
        rec = ce.CVERecord(cve="CVE-2026-10006", status="ok", association_status="none")
        rec.attack_chain_note = (
            "Insufficient VirusTotal intelligence is available to construct a defensible "
            "attack chain for this vulnerability."
        )
        _, associations = self._render([rec])
        self.assertIn(
            "No threat actor or campaign associations were returned by VirusTotal for this vulnerability.",
            associations,
        )
        self.assertIn("Insufficient VirusTotal intelligence", associations)

    def test_multiple_cve_state_is_isolated(self) -> None:
        first = ce.CVERecord(
            cve="CVE-2026-10007",
            status="ok",
            association_status="complete",
            threat_actors=[
                ce.AssociationEntity("threat-actor--one", "threat-actor", "Only First")
            ],
        )
        second = ce.CVERecord(cve="CVE-2026-10008", status="ok", association_status="none")
        _, associations = self._render([first, second])
        first_section = associations.split('id="CVE-2026-10007"', 1)[1].split(
            'id="CVE-2026-10008"', 1
        )[0]
        second_section = associations.split('id="CVE-2026-10008"', 1)[1]
        self.assertIn("Only First", first_section)
        self.assertNotIn("Only First", second_section)

    def test_api_values_are_html_escaped(self) -> None:
        rec = ce.CVERecord(
            cve="CVE-2026-10009",
            status="ok",
            association_status="complete",
            threat_actors=[
                ce.AssociationEntity(
                    "threat-actor--x",
                    "threat-actor",
                    "<script>alert(1)</script>",
                    vt_url="javascript:alert(1)",
                )
            ],
        )
        _, associations = self._render([rec])
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", associations)
        self.assertNotIn("<script>alert(1)</script>", associations)
        self.assertNotIn('href="javascript:', associations)


if __name__ == "__main__":
    unittest.main()
