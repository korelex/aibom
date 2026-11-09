"""The review app (tests/fixtures/review-app) through the whole pipeline: what each human output and the AI-BOM say.

Expected values were checked against the provider's own page (see lifecycle_source_url in the output).
The scan date is fixed because status is worked out from dates.
"""
import csv
import json
import os
import re
import tempfile
import unittest
from unittest import mock

from aibom_engine.pipeline import run

ROOT = os.path.join(os.path.dirname(__file__), "..")
APP = os.path.join(ROOT, "tests", "fixtures", "review-app")
TODAY = "2026-11-09"


class ReviewAppRiskReport(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.patch = mock.patch.dict(os.environ, {"AIBOM_TODAY": TODAY})
        cls.patch.start()
        cls.tmp = tempfile.TemporaryDirectory()
        cls.out = cls.tmp.name
        cls.result = run(APP, cls.out, app="review-app")

    @classmethod
    def tearDownClass(cls):
        cls.patch.stop()
        cls.tmp.cleanup()

    def read(self, name, out=None):
        with open(os.path.join(out or self.out, name), encoding="utf-8-sig", errors="replace") as handle:
            return handle.read()

    def rows(self):
        return list(csv.DictReader(self.read("models.csv").splitlines()))

    def row(self, model):
        return next(r for r in self.rows() if r["model"] == model)

    def test_the_bom_is_valid_cyclonedx(self):
        self.assertTrue(self.result["valid"], self.result["error"])

    def test_csv_has_lifecycle_and_license_columns(self):
        header = set(self.rows()[0])
        self.assertTrue({"status", "pinned", "floating_alias", "deprecation_date", "retirement_date", "replacement", "lifecycle_source",
                         "license", "license_restricted"} <= header)

    def test_a_retired_model_is_shown_as_retired_with_its_dates_and_replacement(self):
        # claude-3-5-sonnet-20240620: deprecated 2025-08-13, retired 2025-10-28, replacement claude-sonnet-5-5.
        claude = self.row("claude-3-5-sonnet-20240620")
        self.assertEqual(claude["status"], "retired")
        self.assertEqual(claude["deprecation_date"], "2025-08-13")
        self.assertEqual(claude["retirement_date"], "2025-10-28")
        self.assertEqual(claude["replacement"], "claude-sonnet-5-5")
        self.assertTrue(claude["lifecycle_source"].startswith("https://platform.claude.com/"))
        self.assertEqual((claude["pinned"], claude["floating_alias"]), ("yes", "no"))
        self.assertEqual((claude["license"], claude["license_restricted"]), ("proprietary", "no"))

    def test_llama2_license_is_conditional(self):
        rows = self.rows()
        llama = next(r for r in rows if "llama-2-7b" in r["model"].lower())
        self.assertEqual(llama["license"], "llama2")
        self.assertIn("Llama 2", llama["license_name"])
        self.assertEqual(llama["license_commercial_use"], "conditional")

    def test_all_three_human_outputs_agree_about_the_retired_model(self):
        markdown, page = self.read("report.md"), self.read("report.html")
        for text in (markdown, page):
            for needle in ("claude-3-5-sonnet-20240620", "retired", "2025-10-28", "claude-sonnet-5-5"):
                self.assertIn(needle, text, needle)
            # it must not be described as merely "deprecated" any more
            self.assertNotRegex(text, r"claude-3-5-sonnet-20240620[^\n]*\| deprecated \|")

    def test_floating_alias_is_flagged_only_where_a_snapshot_exists_to_pin(self):
        self.assertEqual(self.row("gpt-4o")["floating_alias"], "yes")
        self.assertEqual(self.row("gpt-4o-mini")["floating_alias"], "yes")
        self.assertEqual(self.row("text-embedding-3-small")["floating_alias"], "no")  # no dated snapshot exists
        self.assertEqual(self.row("claude-3-5-sonnet-20240620")["floating_alias"], "no")

    def test_hugging_face_repos_are_not_floating_aliases(self):
        self.assertEqual(self.row("meta-llama/Llama-2-7b-hf")["floating_alias"], "no")
        markdown = self.read("report.md")
        self.assertRegex(markdown, r"- Floating aliases[^\n]*: 2 \(gpt-4o, gpt-4o-mini\)")
        self.assertRegex(markdown, r"- Hugging Face models[^\n]*: 1 \(meta-llama/Llama-2-7b-hf\)")

    def test_untracked_models_say_so_instead_of_claiming_to_be_active(self):
        # No sourced record exists for text-embedding-3-small, so it is "not tracked", never "active".
        self.assertEqual(self.row("text-embedding-3-small")["status"], "unknown")
        markdown = self.read("report.md")
        self.assertRegex(markdown, r"\| text-embedding-3-small \|[^\n]*\| not tracked \|")
        self.assertIn("Not tracked", markdown)  # the explanation under the Risks block
        self.assertNotRegex(markdown, r"\| text-embedding-3-small \|[^\n]*\| active \|")

    def test_gpt_4o_is_deprecated_and_floating(self):
        # OpenAI announced on 2026-10-14 that gpt-4o (2024-08-06, 2024-11-20) shuts down on 2027-01-14.
        gpt = self.row("gpt-4o")
        self.assertEqual((gpt["status"], gpt["deprecation_date"], gpt["retirement_date"]), ("deprecated", "2026-10-14", "2027-01-14"))
        self.assertEqual((gpt["pinned"], gpt["floating_alias"]), ("no", "yes"))
        self.assertRegex(self.read("report.md"), r"- Deprecated \(retirement scheduled, still works\): 2 \(gpt-4o, gpt-4o-mini\)")

    def test_risks_block_has_every_label_in_markdown_and_html(self):
        markdown, page = self.read("report.md"), self.read("report.html")
        for label in ("Retired (API calls fail)", "Deprecated (retirement scheduled", "Floating aliases", "Hugging Face models",
                      "Restricted licenses", "Unknown licenses"):
            self.assertIn(label, markdown, label)
            self.assertIn(label, page, label)
        risks = re.search(r"<div class='risks'>.*?</div>", page, re.S).group(0)
        self.assertRegex(risks, r"Retired \(API calls fail\):</b> 1 &mdash; claude-3-5-sonnet-20240620")

    def test_bom_carries_the_lifecycle_facts(self):
        bom = json.loads(self.read("aibom.cdx.json"))
        comp = next(c for c in bom["components"] if c["name"] == "claude-3-5-sonnet-20240620")
        props = {p["name"]: p["value"] for p in comp["properties"]}
        self.assertEqual(props["aibom-engine:status"], "retired")
        self.assertEqual(props["aibom-engine:retirement-date"], "2025-10-28")
        self.assertEqual(props["aibom-engine:deprecation-date"], "2025-08-13")
        self.assertEqual(props["aibom-engine:replacement"], "claude-sonnet-5-5")
        self.assertEqual(props["aibom-engine:floating-alias"], "false")
        gpt = next(c for c in bom["components"] if c["name"] == "gpt-4o")
        self.assertEqual({p["name"]: p["value"] for p in gpt["properties"]}["aibom-engine:floating-alias"], "true")

    def test_output_is_the_same_on_every_run(self):
        with tempfile.TemporaryDirectory() as second:
            run(APP, second, app="review-app")
            for name in ("aibom.cdx.json", "report.md", "models.csv", "report.html"):
                self.assertEqual(self.read(name), self.read(name, second), name)

    def test_docs_and_tests_are_left_out(self):
        names = {r["model"] for r in self.rows() if r["role"] != "left out"}
        self.assertNotIn("gpt-3.5-turbo", names)
        self.assertNotIn("gpt-4-turbo", names)


class PlatformNote(unittest.TestCase):
    def test_bedrock_ids_carry_the_platform_footnote(self):
        with tempfile.TemporaryDirectory() as src, tempfile.TemporaryDirectory() as out, mock.patch.dict(os.environ, {"AIBOM_TODAY": TODAY}):
            with open(os.path.join(src, "app.py"), "w", encoding="utf-8") as fh:
                fh.write('MODEL = "anthropic.claude-3-5-sonnet-20240620-v1:0"\n')
            run(src, out, app="bedrock-app")
            with open(os.path.join(out, "report.md"), encoding="utf-8") as fh:
                markdown = fh.read()
        self.assertIn("retired*", markdown)
        self.assertIn("Amazon Bedrock, Azure and Google Vertex AI set their own", markdown)


if __name__ == "__main__":
    unittest.main()
