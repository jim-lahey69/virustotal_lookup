"""CLI regression tests for the strict single-CVE ``--input`` workflow."""

from __future__ import annotations

import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import cve_enricher as ce  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _success_record(cve: str) -> ce.CVERecord:
    return ce.extract_record(
        cve,
        {"data": {"attributes": {"name": cve, "description": "Test record"}}},
    )


class InputValidationTests(unittest.TestCase):
    def test_valid_identifier_is_accepted(self) -> None:
        self.assertEqual(ce.validate_input_cve("CVE-2026-12345"), "CVE-2026-12345")

    def test_lowercase_and_surrounding_whitespace_are_normalized(self) -> None:
        self.assertEqual(
            ce.validate_input_cve("  cve-2026-12345  "),
            "CVE-2026-12345",
        )

    def test_more_than_four_numeric_digits_are_accepted(self) -> None:
        self.assertEqual(
            ce.validate_input_cve("CVE-2026-123456"),
            "CVE-2026-123456",
        )

    def test_malformed_identifiers_are_rejected(self) -> None:
        invalid_values = (
            "TEST-2026-12345",
            "CVE-2026-ABC",
            "test",
            "CVE12345",
            "CVE-26-12345",
            "CVE-2026-",
            "",
            "CVE-2026- 12345",
            "CVE_2026_12345",
            "2026-12345",
            "CVE-2026-12345,CVE-2026-23456",
        )
        for value in invalid_values:
            with self.subTest(value=value), self.assertRaises(ValueError):
                ce.validate_input_cve(value)


class InputParserTests(unittest.TestCase):
    def test_help_documents_single_cve_input(self) -> None:
        help_text = ce.build_arg_parser().format_help()
        self.assertIn("--input CVE", help_text)
        self.assertIn("Single CVE identifier to enrich", help_text)
        self.assertIn("--ioc-html PATH", help_text)

    def test_missing_input_value_is_a_parser_error(self) -> None:
        stderr = io.StringIO()
        with redirect_stderr(stderr), self.assertRaises(SystemExit) as caught:
            ce.build_arg_parser().parse_args(["--input"])
        self.assertEqual(caught.exception.code, 2)
        self.assertIn("expected one argument", stderr.getvalue())

    def test_extra_positional_cve_is_a_parser_error(self) -> None:
        stderr = io.StringIO()
        with redirect_stderr(stderr), self.assertRaises(SystemExit) as caught:
            ce.build_arg_parser().parse_args(
                ["--input", "CVE-2026-12345", "CVE-2026-23456"]
            )
        self.assertEqual(caught.exception.code, 2)
        self.assertIn("unrecognized arguments", stderr.getvalue())

    def test_duplicate_input_flags_are_rejected(self) -> None:
        stderr = io.StringIO()
        with redirect_stderr(stderr), self.assertRaises(SystemExit) as caught:
            ce.build_arg_parser().parse_args(
                [
                    "--input",
                    "CVE-2026-12345",
                    "--input",
                    "CVE-2026-23456",
                ]
            )
        self.assertEqual(caught.exception.code, 2)
        self.assertIn("--input may only be specified once", stderr.getvalue())


class ClientErrorClassificationTests(unittest.TestCase):
    def test_transport_failures_keep_specific_error_kinds(self) -> None:
        cases = (
            (ce.requests.exceptions.ProxyError("proxy failed"), "proxy_error"),
            (ce.requests.exceptions.SSLError("certificate failed"), "tls_error"),
            (ce.requests.exceptions.Timeout("request timed out"), "timeout"),
            (ce.requests.exceptions.ConnectionError("connection failed"), "network_error"),
        )
        for exception, expected_kind in cases:
            with self.subTest(expected_kind=expected_kind):
                client = ce.GTIClient("test-api-key", delay=0.0, max_retries=1)
                with patch.object(client.session, "get", side_effect=exception):
                    body, error_kind, status = client.get_vulnerability(
                        "CVE-2026-12345"
                    )
                self.assertIsNone(body)
                self.assertEqual(error_kind, expected_kind)
                self.assertEqual(status, 0)

    def test_invalid_success_response_json_is_a_parse_error(self) -> None:
        class InvalidJsonResponse:
            status_code = 200

            @staticmethod
            def json():
                raise ValueError("invalid JSON")

        client = ce.GTIClient("test-api-key", delay=0.0, max_retries=1)
        with patch.object(client.session, "get", return_value=InvalidJsonResponse()):
            body, error_kind, status = client.get_vulnerability("CVE-2026-12345")

        self.assertIsNone(body)
        self.assertEqual(error_kind, "parse_error")
        self.assertEqual(status, 200)


class InputMainTests(unittest.TestCase):
    def test_successful_fixture_run_writes_linked_reports(self) -> None:
        cve = "CVE-2021-44228"
        vulnerability = json.loads(
            (FIXTURES / "cve-2021-44228.json").read_text(encoding="utf-8")
        )
        related_files = json.loads(
            (FIXTURES / "relationship-files.json").read_text(encoding="utf-8")
        )

        class FixtureClient:
            def get_vulnerability(self, requested_cve: str):
                self.assert_cve = requested_cve
                return vulnerability, None, 200

            def get_observed_in_the_wild(self, requested_cve: str):
                return True, None, 200

            def get_relationship(self, requested_cve: str, relationship: str, *, limit: int = 40):
                if relationship == "files":
                    return related_files, None, 200
                if relationship == "urls":
                    return {
                        "data": [
                            {
                                "type": "url",
                                "id": "fixture-url-id",
                                "attributes": {"url": "https://ioc.example/exploit"},
                            }
                        ],
                        "meta": {"count": 1},
                    }, None, 200
                return {"data": [], "meta": {"count": 0}}, None, 200

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            output = root / "result.csv"
            primary = root / "report.html"
            ioc = root / "ioc_report.html"
            with (
                patch.object(ce, "load_project_dotenv", return_value=None),
                patch.object(ce, "resolve_api_key", return_value="test-api-key"),
                patch.object(ce, "build_proxies", return_value=None),
                patch.object(ce, "resolve_ssl_verify", return_value=True),
                patch.object(ce, "resolve_request_delay", return_value=0.0),
                patch.object(ce, "GTIClient", return_value=FixtureClient()),
            ):
                exit_code = ce.main(
                    [
                        "--input",
                        cve,
                        "--output",
                        str(output),
                        "--html",
                        str(primary),
                        "--ioc-html",
                        str(ioc),
                        "--no-open",
                        "--no-rich",
                    ]
                )
            primary_html = primary.read_text(encoding="utf-8")
            ioc_html = ioc.read_text(encoding="utf-8")

        self.assertEqual(exit_code, 0)
        self.assertIn('<svg class="priority-chart"', primary_html)
        self.assertIn(f'href="ioc_report.html#{cve}"', primary_html)
        self.assertNotIn("exploit.jar", primary_html)
        self.assertIn(f'id="{cve}"', ioc_html)
        self.assertIn("exploit.jar", ioc_html)
        self.assertIn("https://ioc.example/exploit", ioc_html)

    def test_valid_input_reaches_existing_pipeline_exactly_once(self) -> None:
        cve = "CVE-2026-12345"
        record = _success_record(cve)
        client = object()

        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "result.csv"
            html = Path(tmp) / "report.html"
            with (
                patch.object(ce, "load_project_dotenv", return_value=None),
                patch.object(ce, "resolve_api_key", return_value="test-api-key"),
                patch.object(ce, "build_proxies", return_value=None),
                patch.object(ce, "resolve_ssl_verify", return_value=True),
                patch.object(ce, "resolve_request_delay", return_value=0.0),
                patch.object(ce, "GTIClient", return_value=client),
                patch.object(ce, "load_cve_list") as load_cve_list,
                patch.object(ce, "enrich_cves", return_value=[record]) as enrich,
                patch.object(ce, "write_csv") as write_csv,
                patch.object(ce, "print_rich_report"),
                patch.object(ce, "render_ioc_report") as render_ioc,
                patch.object(ce, "render_html_report") as render_html,
                patch.object(ce, "open_report_in_browser") as open_browser,
            ):
                exit_code = ce.main(
                    [
                        "--input",
                        cve,
                        "--output",
                        str(output),
                        "--html",
                        str(html),
                        "--no-open",
                    ]
                )

        self.assertEqual(exit_code, 0)
        load_cve_list.assert_not_called()
        enrich.assert_called_once_with(client, [cve], stop_on_forbidden=True)
        write_csv.assert_called_once_with([record], output)
        self.assertEqual(render_ioc.call_args.args[:2], ([record], html.with_name("ioc_report.html")))
        self.assertEqual(render_html.call_args.args[:2], ([record], html))
        self.assertEqual(render_html.call_args.kwargs["ioc_report_path"], html.with_name("ioc_report.html"))
        open_browser.assert_not_called()

    def test_lowercase_input_is_canonical_before_pipeline_call(self) -> None:
        cve = "CVE-2026-12345"
        record = _success_record(cve)

        with tempfile.TemporaryDirectory() as tmp:
            with (
                patch.object(ce, "load_project_dotenv", return_value=None),
                patch.object(ce, "resolve_api_key", return_value="test-api-key"),
                patch.object(ce, "build_proxies", return_value=None),
                patch.object(ce, "resolve_ssl_verify", return_value=True),
                patch.object(ce, "resolve_request_delay", return_value=0.0),
                patch.object(ce, "GTIClient", return_value=object()),
                patch.object(ce, "enrich_cves", return_value=[record]) as enrich,
                patch.object(ce, "write_csv"),
                patch.object(ce, "print_rich_report"),
                patch.object(ce, "render_ioc_report"),
                patch.object(ce, "render_html_report"),
            ):
                exit_code = ce.main(
                    [
                        "--input",
                        " cve-2026-12345 ",
                        "--html",
                        str(Path(tmp) / "report.html"),
                        "--no-open",
                    ]
                )

        self.assertEqual(exit_code, 0)
        self.assertEqual(enrich.call_args.args[1], [cve])

    def test_invalid_input_fails_before_api_or_pipeline_initialization(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with (
                patch.object(ce, "load_project_dotenv", return_value=None),
                patch.object(ce, "resolve_api_key") as resolve_key,
                patch.object(ce, "GTIClient") as client_class,
                patch.object(ce, "enrich_cves") as enrich,
                patch.object(ce, "write_csv") as write_csv,
                patch.object(ce, "render_ioc_report") as render_ioc,
                patch.object(ce, "render_html_report") as render_html,
            ):
                exit_code = ce.main(
                    [
                        "--input",
                        "CVE-2026-ABC",
                        "--html",
                        str(Path(tmp) / "report.html"),
                        "--no-open",
                    ]
                )

        self.assertEqual(exit_code, 2)
        resolve_key.assert_not_called()
        client_class.assert_not_called()
        enrich.assert_not_called()
        write_csv.assert_not_called()
        render_ioc.assert_called_once()
        self.assertEqual(
            render_html.call_args.kwargs["title"],
            "GTI CVE Enrichment Report — FAILED",
        )
        self.assertIn("Invalid CVE identifier", render_html.call_args.kwargs["fatal_error"])

    def test_api_failure_returns_nonzero_and_renders_failed_record(self) -> None:
        cve = "CVE-2026-12345"

        class FailingClient:
            def __init__(self) -> None:
                self.calls: list[str] = []

            def get_vulnerability(self, requested_cve: str):
                self.calls.append(requested_cve)
                return None, "network_error", 0

        client = FailingClient()
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "result.csv"
            html = Path(tmp) / "report.html"
            with (
                patch.object(ce, "load_project_dotenv", return_value=None),
                patch.object(ce, "resolve_api_key", return_value="test-api-key"),
                patch.object(ce, "build_proxies", return_value=None),
                patch.object(ce, "resolve_ssl_verify", return_value=True),
                patch.object(ce, "resolve_request_delay", return_value=0.0),
                patch.object(ce, "GTIClient", return_value=client),
            ):
                exit_code = ce.main(
                    [
                        "--input",
                        cve,
                        "--output",
                        str(output),
                        "--html",
                        str(html),
                        "--no-open",
                        "--no-rich",
                    ]
                )

            html_text = html.read_text(encoding="utf-8")
            ioc_text = html.with_name("ioc_report.html").read_text(encoding="utf-8")

        self.assertEqual(exit_code, 1)
        self.assertEqual(client.calls, [cve])
        self.assertIn(cve, html_text)
        self.assertIn("0 enriched successfully", html_text)
        self.assertIn("Network error", html_text)
        self.assertIn(f'ioc_report.html#{cve}', html_text)
        self.assertIn(cve, ioc_text)
        self.assertIn("enrichment failed", ioc_text)

    def test_report_generation_failure_changes_success_exit_to_failure(self) -> None:
        cve = "CVE-2026-12345"
        record = _success_record(cve)

        with tempfile.TemporaryDirectory() as tmp:
            with (
                patch.object(ce, "load_project_dotenv", return_value=None),
                patch.object(ce, "resolve_api_key", return_value="test-api-key"),
                patch.object(ce, "build_proxies", return_value=None),
                patch.object(ce, "resolve_ssl_verify", return_value=True),
                patch.object(ce, "resolve_request_delay", return_value=0.0),
                patch.object(ce, "GTIClient", return_value=object()),
                patch.object(ce, "enrich_cves", return_value=[record]),
                patch.object(ce, "write_csv"),
                patch.object(ce, "print_rich_report"),
                patch.object(ce, "render_ioc_report"),
                patch.object(
                    ce,
                    "render_html_report",
                    side_effect=OSError("report write failed"),
                ),
            ):
                exit_code = ce.main(
                    [
                        "--input",
                        cve,
                        "--html",
                        str(Path(tmp) / "report.html"),
                        "--no-open",
                    ]
                )

        self.assertEqual(exit_code, 1)

    def test_only_primary_report_is_opened(self) -> None:
        cve = "CVE-2026-12345"
        record = _success_record(cve)
        with tempfile.TemporaryDirectory() as tmp:
            html = Path(tmp) / "report.html"
            with (
                patch.object(ce, "load_project_dotenv", return_value=None),
                patch.object(ce, "resolve_api_key", return_value="test-api-key"),
                patch.object(ce, "build_proxies", return_value=None),
                patch.object(ce, "resolve_ssl_verify", return_value=True),
                patch.object(ce, "resolve_request_delay", return_value=0.0),
                patch.object(ce, "GTIClient", return_value=object()),
                patch.object(ce, "enrich_cves", return_value=[record]),
                patch.object(ce, "write_csv"),
                patch.object(ce, "print_rich_report"),
                patch.object(ce, "render_ioc_report"),
                patch.object(ce, "render_html_report"),
                patch.object(ce, "open_report_in_browser") as open_browser,
            ):
                exit_code = ce.main(["--input", cve, "--html", str(html)])

        self.assertEqual(exit_code, 0)
        open_browser.assert_called_once_with(html)

    def test_cve_propagates_into_generated_html(self) -> None:
        cve = "CVE-2026-12345"
        with tempfile.TemporaryDirectory() as tmp:
            html = Path(tmp) / "report.html"
            ce.render_html_report([_success_record(cve)], html)
            html_text = html.read_text(encoding="utf-8")

        self.assertIn(cve, html_text)
        self.assertIn(f"vulnerability--{cve.lower()}", html_text)


if __name__ == "__main__":
    unittest.main()
