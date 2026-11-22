"""The PDF report: the print layout of the page, finding a browser, and writing the file."""
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from aibom_engine import pdf, report
from aibom_engine.source import SourceError

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_ui import PACKAGES  # noqa: E402  (the same small set of packages and advisories)

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")


def item(name, role="used", **kw):
    base = {"name": name, "kind": "model", "tier": "declared", "role": role, "aliases": [], "found_by": ["context"], "maker": "OpenAI",
            "mode": "chat", "reason": "", "evidence": [{"file": "src/app.py", "line": 3, "use": "live", "snippet": "model='%s'" % name, "category": "code"}]}
    base.update(kw)
    return base


ITEMS = [item("gpt-4o"), item("gpt-4o-mini", role="listed")]
META = {"packages": PACKAGES, "warnings": []}


class PrintLayout(unittest.TestCase):
    def setUp(self):
        self.patch = mock.patch("aibom_engine.findings.database.load_db", return_value={"vulnerabilities": {}})
        self.page = report.build_html(ITEMS, "demo", "owner/repo", None, META, pdf=True, today="2026-11-11")
        self.normal = report.build_html(ITEMS, "demo", "owner/repo", None, META)

    def test_there_is_a_cover_with_what_was_scanned_and_with_which_version(self):
        self.assertIn("<section class='cover'>", self.page)
        for needle in ("AI bill of materials", "2026-11-11", "owner/repo", "aibom 0.", "AI packages the project depends on, with 6 known vulnerabilities (1 more in 1 packages that are only in a lockfile)"):
            self.assertIn(needle, self.page)
        self.assertNotIn("<section class='cover'>", self.normal)

    def test_the_page_setup_is_a_landscape_a4_with_page_numbers(self):
        self.assertIn("@page{size:A4 landscape", self.page)
        self.assertIn('counter(page)', self.page)
        self.assertNotIn("@page", self.normal)

    def test_nothing_in_a_pdf_needs_a_click_or_a_script(self):
        self.assertNotIn("<script", self.page)
        self.assertNotIn("<nav", self.page)
        self.assertNotIn("id='q'", self.page)
        self.assertEqual(self.page.count("<details"), self.page.count("<details open"))
        self.assertGreater(self.page.count("<details open"), 0)

    def test_words_that_only_make_sense_on_a_screen_are_gone(self):
        self.assertNotIn("click to see the line", self.page)
        self.assertIn("details.more>summary{display:none}", self.page)  # an opened fold needs no "show 3 more" label

    def test_the_packages_and_vulnerabilities_come_before_the_model_tables(self):
        # One order for the page and the PDF: summary, findings, AI packages and their vulnerabilities, then the models.
        for page in (self.page, self.normal):
            self.assertLess(page.index("id='flags'"), page.index("<h2>AI packages</h2>"))
            self.assertLess(page.index("<h2>AI packages</h2>"), page.index("Used directly in the code"))

    def test_the_long_lists_are_counted_and_point_to_the_files_that_hold_them(self):
        self.assertIn("1 more model names are written in the code only inside big tables", self.page)
        self.assertIn("models.csv", self.page)

    def test_the_fix_plan_is_still_in_the_pdf(self):
        with mock.patch("aibom_engine.report.fix_plan_rows", return_value=[{"package": "alpha", "version": "1.0.0", "worst": "high", "target": "2.0.0",
                                                                           "total": 3, "clears": 3, "remaining": [], "warning": ""}]):
            page = report.build_html(ITEMS, "demo", meta=META, pdf=True)
        self.assertIn("<h3>Fix plan</h3>", page)
        self.assertLess(page.index("<h3>Fix plan</h3>"), page.index("Used directly in the code"))


class FindBrowser(unittest.TestCase):
    def test_the_environment_names_a_browser_explicitly(self):
        with tempfile.NamedTemporaryFile(suffix=".exe") as f, mock.patch.dict(os.environ, {"AIBOM_BROWSER": f.name}):
            self.assertEqual(pdf.find_browser(), f.name)
        with mock.patch.dict(os.environ, {"AIBOM_BROWSER": "no-such-browser-here"}):
            self.assertIsNone(pdf.find_browser())

    def test_no_browser_says_how_to_get_the_pdf_by_hand(self):
        with mock.patch.object(pdf, "find_browser", return_value=None):
            with self.assertRaises(SourceError) as e:
                pdf.print_to_pdf("<p>x</p>", os.path.join(tempfile.gettempdir(), "x.pdf"))
        self.assertIn("Print, Save as PDF", str(e.exception))
        self.assertIn("AIBOM_BROWSER", str(e.exception))


class WritingTheFile(unittest.TestCase):
    def fake_browser(self, write=True, content=b"%PDF-1.4\n" + b"x" * 2000):
        calls = []

        def run(cmd, **kw):
            calls.append(cmd)
            if write:
                target = next(a for a in cmd if a.startswith("--print-to-pdf=")).split("=", 1)[1]
                with open(target, "wb") as f:
                    f.write(content)
            return subprocess.CompletedProcess(cmd, 0, "", "")
        return run, calls

    def test_the_browser_is_asked_for_a_headless_print_without_headers(self):
        run, calls = self.fake_browser()
        with tempfile.TemporaryDirectory() as tmp, mock.patch("subprocess.run", run):
            out = pdf.print_to_pdf("<p>hello</p>", os.path.join(tmp, "sub", "r.pdf"), browser="chrome")
            self.assertTrue(os.path.isfile(out))
        cmd = calls[0]
        for flag in ("--headless=new", "--no-pdf-header-footer"):
            self.assertIn(flag, cmd)
        self.assertTrue(any(a.startswith("file:///") and a.endswith("report.html") for a in cmd))

    def test_a_browser_that_writes_nothing_or_not_a_pdf_is_reported_not_trusted(self):
        for kw in ({"write": False}, {"content": b"<html>not a pdf, but longer than a thousand bytes" + b"x" * 2000}, {"content": b"%PDF-"}):
            run, _ = self.fake_browser(**kw)
            with tempfile.TemporaryDirectory() as tmp, mock.patch("subprocess.run", run):
                with self.assertRaises(SourceError, msg=str(kw)[:40]):
                    pdf.print_to_pdf("<p>x</p>", os.path.join(tmp, "r.pdf"), browser="chrome")

    def test_an_old_file_is_not_mistaken_for_the_new_one(self):
        run, _ = self.fake_browser(write=False)
        with tempfile.TemporaryDirectory() as tmp, mock.patch("subprocess.run", run):
            old = os.path.join(tmp, "r.pdf")
            with open(old, "wb") as f:
                f.write(b"%PDF-1.4\n" + b"y" * 2000)
            with self.assertRaises(SourceError):
                pdf.print_to_pdf("<p>x</p>", old, browser="chrome")

    def test_a_timeout_is_a_plain_message(self):
        def slow(cmd, **kw):
            raise subprocess.TimeoutExpired(cmd, 1)
        with tempfile.TemporaryDirectory() as tmp, mock.patch("subprocess.run", slow):
            with self.assertRaises(SourceError) as e:
                pdf.print_to_pdf("<p>x</p>", os.path.join(tmp, "r.pdf"), browser="chrome", timeout=1)
        self.assertIn("did not finish", str(e.exception))


@unittest.skipUnless(pdf.find_browser(), "needs Chrome, Edge or Chromium")
class RealBrowser(unittest.TestCase):
    def test_a_scan_becomes_a_real_pdf_from_the_command_line(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "run")
            scan = subprocess.run([sys.executable, "-m", "aibom_engine", "scan", os.path.join(ROOT, "tests", "fixtures", "review-app"), "--out", out, "--quiet"],
                                  cwd=ROOT, capture_output=True, text=True, timeout=300)
            self.assertEqual(scan.returncode, 0, scan.stderr)
            target = os.path.join(tmp, "named.pdf")
            done = subprocess.run([sys.executable, "-m", "aibom_engine", "report", out, "--pdf", "--output", target], cwd=ROOT, capture_output=True, text=True, timeout=300)
            self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
            with open(target, "rb") as f:
                data = f.read()
            self.assertTrue(data.startswith(b"%PDF-"))
            self.assertGreater(len(data), 5000)
            self.assertIn("pdf:", done.stdout)


if __name__ == "__main__":
    unittest.main()
