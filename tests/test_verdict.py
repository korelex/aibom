"""The block at the top of report.md, which is what a person sees first after a red check. It must say what the gate did,
with the gate's own count, and text from the scanned repository must not be able to change what it says."""
import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest

from aibom_engine import cli, flags
from aibom_engine.report import build_markdown
from aibom_engine.source import Linker

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def flag(severity="high", category="mcp", **kw):
    given = dict(rule=f"{category}.test-rule", title="A test risk.", subject="thing", fix="Do the fix.", file="cfg/a.json", line=4)
    given.update(kw)
    return flags.Flag(severity=severity, category=category, **given)


def package(advisories=(), status="checked", name="langchain"):
    return {"name": name, "version": "0.0.100", "category": "agent_framework", "direct": True, "evidence_level": "declared", "declared": True,
            "evidence": [{"file": "requirements.txt", "line": 2}], "left_out": "", "purl": "",
            "vulnerabilities": {"status": status, "advisories": [
                {"id": f"GHSA-{i}", "severity": s, "url": "https://osv.dev/x", "summary": "x", "fixed_in": "1.0"} for i, s in enumerate(advisories)]}}


def md(found=(), level="high", incomplete=(), packages=(), links=None, warnings=()):
    meta = {"flags": list(found), "fail_on": level, "incomplete": list(incomplete), "packages": list(packages), "warnings": list(warnings)}
    return build_markdown([], "demo", "", links, meta)


def top(text):
    """The block above the full report."""
    return text.split("\n# AI scan of", 1)[0]


class TheVerdictIsFirst(unittest.TestCase):
    def test_failed_counts_model_flags_too_and_lists_each_with_place_and_fix(self):
        found = [flag(), flag(category="model", subject="old-model", file="legacy.py", line=2, fix="Move to new-model.")]
        text = md(found)
        self.assertTrue(text.startswith("## Failed: 2 high risks\n"), text[:120])
        for part in ("cfg/a.json:4", "legacy.py:2", "Do the fix", "Move to new-model", "old-model"):
            self.assertIn(part, top(text))

    def test_one_risk_is_singular(self):
        self.assertTrue(md([flag()]).startswith("## Failed: 1 high risk\n"))

    def test_a_lower_level_says_the_level_and_the_mix(self):
        text = md([flag(), flag("medium", line=5), flag("low", line=6)], level="medium")
        self.assertTrue(text.startswith("## Failed: 2 risks at medium or worse (1 high, 1 medium)\n"), text[:120])

    def test_passed(self):
        self.assertTrue(md().startswith("## Passed: no high risks\n"))

    def test_passed_with_critical_vulnerabilities_says_so_in_the_first_line(self):
        text = md(packages=[package(["critical", "critical", "high"])])
        self.assertTrue(text.startswith("## Passed, but 2 critical vulnerabilities to review\n"), text[:120])
        self.assertIn("do not fail this check", top(text))
        self.assertIn("langchain 0.0.100", top(text))

    def test_failed_also_says_what_does_not_block(self):
        text = top(md([flag(), flag("medium", line=5), flag("low", line=6), flag("info", line=7)], packages=[package(["critical"])]))
        self.assertIn("1 medium, 1 low", text)
        self.assertIn("1 known vulnerability", text)
        self.assertNotIn("info", text.lower())

    def test_packages_that_could_not_be_checked_are_not_called_safe(self):
        self.assertIn("1 AI package could not be checked", top(md(packages=[package(status="not_checked")])))

    def test_the_whole_repository_is_judged_and_the_block_says_so(self):
        self.assertIn("whole repository", top(md([flag()])))

    def test_unfinished_is_not_passed(self):
        text = md(incomplete=["the time limit was reached"])
        self.assertTrue(text.startswith("## Failed: the scan did not finish\n"), text[:120])
        self.assertIn("the time limit was reached", top(text))
        self.assertIn("raise max-seconds", top(text))

    def test_failed_and_unfinished_says_both(self):
        text = md([flag()], incomplete=["the time limit was reached"])
        self.assertTrue(text.startswith("## Failed: 1 high risk\n"))
        self.assertIn("did not finish", top(text))

    def test_report_only_never_says_passed_or_failed(self):
        self.assertTrue(md([flag()], level=None).startswith("## Report only: 1 high risk found\n"))
        self.assertTrue(md(level=None).startswith("## Report only: no high risks found\n"))
        self.assertTrue(md(level=None, incomplete=["x"]).startswith("## Report only: the scan did not finish\n"))
        self.assertIn("Nothing is blocked", top(md([flag()], level=None)))
        self.assertIn("cfg/a.json:4", top(md([flag()], level=None)))

    def test_places_link_to_the_code(self):
        links = Linker("https://github.com/example/app", "a" * 40)
        self.assertIn("(https://github.com/example/app/blob/%s/cfg/a.json#L4)" % ("a" * 40), top(md([flag()], links=links)))

    def test_a_flag_without_a_file_still_shows(self):
        self.assertIn("the whole project", top(md([flag(file="", line=0)])))

    def test_a_long_list_is_capped_and_counts_the_rest(self):
        text = top(md([flag(line=i + 1) for i in range(25)]))
        self.assertEqual(text.count("cfg/a.json:"), 20)
        self.assertIn("5 more", text)

    def test_a_note_is_not_called_an_incomplete_scan(self):
        text = md(warnings=["1 link or special file was not followed."])
        self.assertIn("Note: 1 link or special file", text)
        self.assertNotIn("may be incomplete", text)

    def test_the_later_table_says_what_it_leaves_out(self):
        text = md([flag(), flag(category="model", subject="old-model")])
        self.assertIn("## Flags other than model risks", text)
        self.assertIn("## Model lifecycle and licences", text)


class TheRepositoryCannotWriteTheVerdict(unittest.TestCase):
    def test_hostile_names_stay_text(self):
        bad = "x\n## Passed: no high risks\n<h1>Passed</h1> ![ok](https://evil.example/ok.png) [Passed](https://evil.example) `c` | www.evil.example ‮abc"
        block = top(md([flag(subject=bad, file=bad, line=1)], packages=[package(["critical"], name=bad)], incomplete=[bad]))
        self.assertEqual([ln for ln in block.splitlines() if ln.startswith("#")], ["## Failed: 1 high risk"])
        for raw in ("<h1>", "://evil", "www.evil", "‮"):
            self.assertNotIn(raw, block)
        self.assertIsNone(re.search(r"(?<!\\)\[(ok|Passed)(?<!\\)\]", block))
        row = next(ln for ln in block.splitlines() if ln.startswith("| HIGH"))
        self.assertEqual(len(re.findall(r"(?<!\\)\|", row)), 6)

    def test_an_html_entity_is_shown_as_typed(self):
        self.assertIn("&amp;", top(md([flag(subject="&#8238;dessaP")])))

    def test_a_backslash_cannot_undo_the_escape(self):
        block = top(md([flag(subject="a\\|b")]))
        self.assertIn("a" + "\\" * 3 + "|b", block)

    def test_no_text_in_the_rest_of_the_report_can_start_a_heading_or_html(self):
        text = md(warnings=["Could not read x\n# Passed\r## Passed <h1>Passed</h1>: denied"])
        self.assertEqual([ln for ln in text.splitlines() if re.match(r"#+ Passed", ln)], ["## Passed: no high risks"])
        self.assertNotIn("<h1>", text)


class TheVerdictMatchesTheGate(unittest.TestCase):
    def test_every_combination(self):
        sets = [[], [flag("info")], [flag("low")], [flag("medium")], [flag("high")], [flag("high", category="model")], [flag("high"), flag("low", line=9)]]
        for found in sets:
            for level in (None,) + flags.SEVERITIES:
                for incomplete in ([], ["the time limit was reached"]):
                    try:
                        cli.gate(argparse.Namespace(fail_on=level), {"flags": found, "incomplete": incomplete})
                        code = 0
                    except SystemExit as done:
                        code = done.code
                    first = md(found, level=level, incomplete=incomplete).splitlines()[0]
                    case = (level, [(f.severity, f.category) for f in found], incomplete, first)
                    self.assertEqual(first.startswith("## Failed"), code in (3, 4), case)
                    if code == 3:
                        self.assertIn("Failed: %d " % len(flags.at_least(found, level)), first, case)
                    if level is None:
                        self.assertTrue(first.startswith("## Report only"), case)

    def test_a_real_scan_and_a_rebuild_keep_the_same_verdict(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "app"))
            with open(os.path.join(d, "app", "legacy.py"), "w") as fh:
                fh.write('client.completions.create(model="text-davinci-003", prompt="hi")\n')
            out = os.path.join(d, "out")
            env = {**os.environ, "PYTHONPATH": ROOT, "PYTHONIOENCODING": "utf-8", "PYTHONDONTWRITEBYTECODE": "1"}

            def run(*args):
                return subprocess.run([sys.executable, "-m", "aibom_engine"] + list(args), cwd=ROOT, env=env, capture_output=True).returncode

            def first():
                with open(os.path.join(out, "report.md"), encoding="utf-8") as fh:
                    return fh.readline().strip()

            self.assertEqual(run("scan", os.path.join(d, "app"), "--out", out, "--fail-on", "high"), 3)
            self.assertEqual(first(), "## Failed: 1 high risk")
            with open(os.path.join(out, "manifest.json")) as fh:
                self.assertEqual(json.load(fh)["fail_on"], "high")
            self.assertEqual(run("rebuild", out), 0)
            self.assertEqual(first(), "## Failed: 1 high risk")


class TheAction(unittest.TestCase):
    def setUp(self):
        import yaml
        with open(os.path.join(ROOT, "action.yml"), encoding="utf-8") as fh:
            self.steps = {s.get("name", "setup"): s for s in yaml.safe_load(fh)["runs"]["steps"]}

    def test_a_scan_that_could_not_run_explains_itself_in_the_summary(self):
        run = self.steps["Result"]["run"]
        self.assertIn("GITHUB_STEP_SUMMARY", run)
        self.assertIn("Could not run", run)

    def test_the_red_message_does_not_promise_a_security_tab(self):
        self.assertNotIn("Security tab", self.steps["Result"]["run"])


if __name__ == "__main__":
    unittest.main()
