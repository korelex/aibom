import csv
import os
import tempfile
import unittest

from aibom_engine.pipeline import run

ROOT = os.path.join(os.path.dirname(__file__), "..")
APP = os.path.join(ROOT, "tests", "fixtures", "review-app")


class ReviewAppRiskReport(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.out = cls.tmp.name
        cls.result = run(APP, cls.out, app="review-app")

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def read(self, name):
        with open(os.path.join(self.out, name), encoding="utf-8-sig", errors="replace") as handle:
            return handle.read()

    def rows(self):
        return list(csv.DictReader(self.read("models.csv").splitlines()))

    def test_csv_has_lifecycle_and_license_columns(self):
        rows = self.rows()
        self.assertTrue({"status", "pinned", "deprecation_date", "replacement", "license", "license_restricted"} <= set(rows[0]))
        claude = next(r for r in rows if "claude-3-5-sonnet-20240620" in r["model"])
        self.assertEqual(claude["status"], "deprecated")
        self.assertEqual(claude["replacement"], "claude-sonnet-4-5")
        self.assertEqual(claude["deprecation_date"], "2025-10-22")
        self.assertEqual(claude["license"], "proprietary")
        self.assertEqual(claude["license_restricted"], "no")
        self.assertEqual(claude["pinned"], "yes")

    def test_floating_alias_is_visible(self):
        rows = self.rows()
        gpt4o = next(r for r in rows if r["model"] == "gpt-4o")
        self.assertEqual(gpt4o["pinned"], "no")

    def test_markdown_and_html_show_the_same_facts(self):
        markdown = self.read("report.md")
        page = self.read("report.html")
        for text in (markdown, page):
            self.assertIn("claude-3-5-sonnet-20240620", text)
            self.assertIn("deprecated", text)
            self.assertIn("claude-sonnet-4-5", text)
        self.assertIn("Risks", page)
        for label in ("Deprecated or retired", "Floating aliases", "Restricted licenses", "Unknown licenses"):
            self.assertIn(label, page)

    def test_docs_and_tests_are_left_out(self):
        names = {r["model"] for r in self.rows() if r["role"] != "left out"}
        self.assertNotIn("gpt-3.5-turbo", names)
        self.assertNotIn("gpt-4-turbo", names)


if __name__ == "__main__":
    unittest.main()
