"""Report ownership, safe cleanup, and the interactive review lifecycle."""

from __future__ import annotations

import io
import json
import sys
import tempfile
import unittest
from contextlib import ExitStack, contextmanager, redirect_stdout
from pathlib import Path
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import cve_enricher as ce  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures"


class ReportCleanupTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.generated: set[Path] = set()

    def generate_pair(self, cve: str = "CVE-2021-44228") -> tuple[Path, Path]:
        record = ce.extract_record(cve, {"data": {"attributes": {"name": cve}}})
        primary = self.root / f"{cve}_report.html"
        ioc = self.root / f"{cve}_iocs.html"
        ce.render_ioc_report(
            [record], ioc, primary_report_path=primary,
            generated_report_files=self.generated,
        )
        ce.render_html_report(
            [record], primary, ioc_report_path=ioc,
            generated_report_files=self.generated,
        )
        self.assertTrue(primary.is_file())
        self.assertTrue(ioc.is_file())
        return primary, ioc

    def test_single_cve_pair_is_tracked_and_removed(self) -> None:
        paths = self.generate_pair()
        self.assertEqual(self.generated, set(paths))
        ce.cleanup_generated_reports(self.generated)
        self.assertTrue(all(not path.exists() for path in paths))

    def test_multiple_cves_leave_static_and_previous_reports_untouched(self) -> None:
        untouched = [self.root / "template.html", self.root / "CVE-2020-1234_report.html"]
        for path in untouched:
            path.write_text("preserve this HTML", encoding="utf-8")
        paths = []
        for cve in ("CVE-2021-44228", "CVE-2023-12345", "CVE-2024-56789"):
            paths.extend(self.generate_pair(cve))
        self.assertEqual(len(self.generated), 6)
        self.assertEqual(self.generated, set(paths))
        ce.cleanup_generated_reports(self.generated)
        self.assertTrue(all(not path.exists() for path in paths))
        for path in untouched:
            self.assertEqual(path.read_text(encoding="utf-8"), "preserve this HTML")

    def test_missing_generated_file_does_not_stop_cleanup(self) -> None:
        primary, ioc = self.generate_pair()
        primary.unlink()
        ce.cleanup_generated_reports(self.generated)
        self.assertFalse(ioc.exists())
        ce.cleanup_generated_reports(self.generated)  # Safe to retry.

    def test_locked_file_warns_and_cleanup_continues(self) -> None:
        self.generate_pair()
        locked, removable = sorted(self.generated)
        original_unlink = Path.unlink

        def unlink(path: Path, *args, **kwargs) -> None:
            if path == locked:
                raise PermissionError("file is locked")
            original_unlink(path, *args, **kwargs)

        with patch.object(Path, "unlink", unlink), self.assertLogs(level="WARNING") as logs:
            ce.cleanup_generated_reports(self.generated)
        self.assertTrue(locked.exists())
        self.assertFalse(removable.exists())
        self.assertIn(str(locked), "\n".join(logs.output))
        self.assertIn("file is locked", "\n".join(logs.output))

    def test_removal_between_exists_and_unlink_is_harmless(self) -> None:
        self.generate_pair()
        original_unlink = Path.unlink

        def concurrent_unlink(path: Path) -> None:
            original_unlink(path)
            raise FileNotFoundError(str(path))

        with patch.object(Path, "unlink", concurrent_unlink):
            ce.cleanup_generated_reports(self.generated)
        self.assertTrue(all(not path.exists() for path in self.generated))

    def test_partial_write_is_registered_for_later_cleanup(self) -> None:
        path = self.root / "partial.html"
        original_open = Path.open

        @contextmanager
        def failing_open(path: Path, *args, **kwargs):
            with original_open(path, *args, **kwargs) as file:
                def fail_write(doc: str) -> None:
                    file.write(doc[:12])
                    raise OSError("disk full")

                yield Mock(write=fail_write)

        with patch.object(Path, "open", failing_open), self.assertRaisesRegex(OSError, "disk full"):
            ce.render_html_report([], path, generated_report_files=self.generated)
        self.assertEqual(self.generated, {path})
        self.assertTrue(path.is_file())
        ce.cleanup_generated_reports(self.generated)
        self.assertFalse(path.exists())

    def test_failed_open_does_not_register_or_delete_existing_file(self) -> None:
        path = self.root / "existing.html"
        path.write_text("untouched", encoding="utf-8")
        with (
            patch.object(Path, "open", side_effect=PermissionError("cannot open")),
            self.assertRaises(PermissionError),
        ):
            ce.render_html_report([], path, generated_report_files=self.generated)
        self.assertEqual(self.generated, set())
        ce.cleanup_generated_reports(self.generated)
        self.assertEqual(path.read_text(encoding="utf-8"), "untouched")


class FixtureClient:
    """Offline API boundary; main still performs input, enrichment and exports."""

    def get_vulnerability(self, cve: str):
        return json.loads((FIXTURES / "cve-2021-44228.json").read_text(encoding="utf-8")), None, 200

    def get_observed_in_the_wild(self, cve: str):
        return True, None, 200

    def get_relationship(self, cve: str, relationship: str, *, limit: int = 40):
        if relationship == "files":
            return json.loads((FIXTURES / "relationship-files.json").read_text(encoding="utf-8")), None, 200
        if relationship == "urls":
            return {
                "data": [{"type": "url", "id": "fixture-url", "attributes": {"url": "https://ioc.example/exploit"}}],
                "meta": {"count": 1},
            }, None, 200
        return {"data": [], "meta": {"count": 0}}, None, 200


class ReportSessionTests(unittest.TestCase):
    def setUp(self) -> None:
        stack = ExitStack()
        self.addCleanup(stack.close)
        self.root = Path(stack.enter_context(tempfile.TemporaryDirectory()))
        self.static = self.root / "static.html"
        self.static.write_text("static page", encoding="utf-8")
        self.primary = self.root / "report.html"
        self.ioc = self.root / "ioc_report.html"
        self.csv = self.root / "result.csv"
        self.args = ["--input", "CVE-2021-44228", "--html", str(self.primary),
                     "--output", str(self.csv), "--no-rich"]
        for name, value in (
            ("load_project_dotenv", None), ("resolve_api_key", "test-api-key"),
            ("build_proxies", None), ("resolve_ssl_verify", True),
            ("resolve_request_delay", 0.0), ("GTIClient", FixtureClient()),
        ):
            stack.enter_context(patch.object(ce, name, return_value=value))
        self.open_browser = stack.enter_context(patch.object(ce, "open_report_in_browser"))
        self.cleanup = stack.enter_context(patch.object(ce, "cleanup_generated_reports", wraps=ce.cleanup_generated_reports))
        stack.enter_context(redirect_stdout(io.StringIO()))

    def assert_linked_pair(self, cve: str, primary: Path, ioc: Path) -> None:
        primary_html = primary.read_text(encoding="utf-8")
        ioc_html = ioc.read_text(encoding="utf-8")
        self.assertIn(f'href="{ce._relative_report_href(primary, ioc)}#{cve}"', primary_html)
        self.assertIn(f'id="{cve}"', ioc_html)
        self.assertIn(f'href="{ce._relative_report_href(ioc, primary)}"', ioc_html)
        self.assertIn('<svg class="priority-chart"', primary_html)
        self.assertIn("exploit.jar", ioc_html)
        self.assertIn("https://ioc.example/exploit", ioc_html)

    def test_single_cve_stays_available_until_enter(self) -> None:
        responses = iter(["still reviewing", ""])

        def review(prompt: str) -> str:
            self.assertIn("Press Enter to exit and remove generated HTML reports", prompt)
            self.cleanup.assert_not_called()
            self.assert_linked_pair("CVE-2021-44228", self.primary, self.ioc)
            self.open_browser.assert_called_once_with(self.primary)
            return next(responses)

        with patch("builtins.input", side_effect=review) as read_input:
            self.assertEqual(ce.main(self.args), 0)
        self.assertEqual(read_input.call_count, 2)
        self.cleanup.assert_called_once_with({self.primary, self.ioc})
        self.assertFalse(self.primary.exists())
        self.assertFalse(self.ioc.exists())
        self.assertTrue(self.csv.exists())
        self.assertEqual(self.static.read_text(encoding="utf-8"), "static page")

    def test_csv_selection_keeps_all_pairs_until_enter(self) -> None:
        cves = ["CVE-2021-44228", "CVE-2023-12345", "CVE-2024-56789"]
        source = self.root / "input.csv"
        source.write_text("CVE\n" + "\n".join(cves), encoding="utf-8")
        paths = [(self.root / f"{cve}_report.html", self.root / f"{cve}_iocs.html") for cve in cves]
        responses = iter(["2", "3", ""])

        def review(prompt: str) -> str:
            self.assertIn("remove generated HTML reports", prompt)
            self.cleanup.assert_not_called()
            for cve, (primary, ioc) in zip(cves, paths):
                self.assert_linked_pair(cve, primary, ioc)
            return next(responses)

        with patch("builtins.input", side_effect=review):
            self.assertEqual(ce.main(["-i", str(source)] + self.args[2:]), 0)
        generated = {path for pair in paths for path in pair}
        self.cleanup.assert_called_once_with(generated)
        self.assertEqual([call.args[0] for call in self.open_browser.call_args_list], [pair[0] for pair in paths])
        self.assertTrue(all(not path.exists() for path in generated))
        self.assertEqual(set(self.root.glob("*.html")), {self.static})

    def test_no_open_still_waits_for_manual_review(self) -> None:
        def review(prompt: str) -> str:
            self.assertNotIn("Select a report", prompt)
            self.assert_linked_pair("CVE-2021-44228", self.primary, self.ioc)
            self.cleanup.assert_not_called()
            return ""

        with patch("builtins.input", side_effect=review):
            self.assertEqual(ce.main(self.args + ["--no-open"]), 0)
        self.open_browser.assert_not_called()
        self.assertFalse(self.primary.exists())
        self.assertFalse(self.ioc.exists())

    def test_eof_and_interrupt_preserve_reports(self) -> None:
        for end_input in (EOFError, KeyboardInterrupt):
            with self.subTest(end_input=end_input), patch("builtins.input", side_effect=end_input):
                self.assertEqual(ce.main(self.args), 0)
            self.assertTrue(self.primary.is_file())
            self.assertTrue(self.ioc.is_file())
        self.cleanup.assert_not_called()

    def test_custom_report_directories_are_tracked(self) -> None:
        primary = self.root / "primary pages" / "custom.html"
        ioc = self.root / "ioc pages" / "indicators.html"

        def review(prompt: str) -> str:
            self.assert_linked_pair("CVE-2021-44228", primary, ioc)
            return ""

        with patch("builtins.input", side_effect=review):
            self.assertEqual(ce.main(self.args + ["--html", str(primary), "--ioc-html", str(ioc)]), 0)
        self.cleanup.assert_called_once_with({primary, ioc})
        self.assertFalse(primary.exists())
        self.assertFalse(ioc.exists())

    def test_either_report_generation_failure_keeps_other_tracked(self) -> None:
        for renderer, generated in (("render_ioc_report", self.primary), ("render_html_report", self.ioc)):
            def review(prompt: str) -> str:
                self.assertTrue(generated.is_file())
                return ""

            with (
                self.subTest(renderer=renderer),
                patch.object(ce, renderer, side_effect=OSError("render failed")),
                patch("builtins.input", side_effect=review),
            ):
                self.assertEqual(ce.main(self.args), 1)
            self.assertEqual(self.cleanup.call_args.args[0], {generated})
            self.assertFalse(generated.exists())

    def test_configuration_failure_reports_are_reviewed_then_removed(self) -> None:
        def review(prompt: str) -> str:
            self.assertIn("No API key", self.primary.read_text(encoding="utf-8"))
            self.assertTrue(self.ioc.is_file())
            self.cleanup.assert_not_called()
            return ""

        with patch.object(ce, "resolve_api_key", return_value=None), patch("builtins.input", side_effect=review):
            self.assertEqual(ce.main(self.args), 2)
        self.assertFalse(self.primary.exists())
        self.assertFalse(self.ioc.exists())


if __name__ == "__main__":
    unittest.main()
