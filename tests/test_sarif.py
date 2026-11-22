"""SARIF output: the risk flags of a scan in the format GitHub code scanning reads."""
import json
import os
import subprocess
import sys
import tempfile
import unittest

from aibom_engine import flags as F
from aibom_engine import sarif

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP = os.path.join(ROOT, "tests", "fixtures", "review-app")
ENV = {**os.environ, "AIBOM_TODAY": "2026-11-09", "PYTHONDONTWRITEBYTECODE": "1"}


def flag(rule="secret.api-key", severity="high", file="src/a.py", line=3, **kw):
    return F.Flag(rule, severity, category=kw.pop("category", "secret"), title=kw.pop("title", "A key is written in the code."), subject=kw.pop("subject", "OpenAI"),
                  fix=kw.pop("fix", "Rotate the key."), file=file, line=line, **kw)


class Shape(unittest.TestCase):
    def test_one_rule_per_rule_id_and_one_result_per_flag(self):
        doc, skipped = sarif.build([flag(), flag(line=9), flag("mcp.shell-command", "medium", ".mcp.json", 4, category="mcp")])
        run = doc["runs"][0]
        self.assertEqual((doc["version"], skipped), ("2.1.0", 0))
        self.assertEqual([r["id"] for r in run["tool"]["driver"]["rules"]], ["mcp.shell-command", "secret.api-key"])
        self.assertEqual(len(run["results"]), 3)
        for r in run["results"]:
            self.assertEqual(run["tool"]["driver"]["rules"][r["ruleIndex"]]["id"], r["ruleId"])

    def test_levels_and_the_severity_github_ranks_by(self):
        doc, _ = sarif.build([flag(severity="low", file="tests/t.py"), flag(severity="high"), flag("model.floating-alias", "info", "a.py", 1, category="model")])
        run = doc["runs"][0]
        rules = {r["id"]: r for r in run["tool"]["driver"]["rules"]}
        self.assertEqual(rules["secret.api-key"]["properties"]["security-severity"], "8.0")        # the worst seen for the rule
        self.assertEqual(rules["model.floating-alias"]["properties"]["security-severity"], "1.0")
        self.assertEqual(sorted(r["level"] for r in run["results"]), ["error", "note", "note"])

    def test_the_place_is_the_file_and_line_and_a_whole_file_has_no_line(self):
        doc, _ = sarif.build([flag(file="src/my app.py", line=7), flag(file="models/m.pkl", line=0, rule="model-file.dangerous-call", category="model-file")])
        locs = {r["ruleId"]: r["locations"][0]["physicalLocation"] for r in doc["runs"][0]["results"]}
        self.assertEqual(locs["secret.api-key"], {"artifactLocation": {"uri": "src/my%20app.py"}, "region": {"startLine": 7}})
        self.assertEqual(locs["model-file.dangerous-call"], {"artifactLocation": {"uri": "models/m.pkl"}})

    def test_a_prefix_puts_the_paths_under_the_scanned_folder(self):
        for prefix, want in (("", "src/a.py"), (".", "src/a.py"), ("./", "src/a.py"), ("services/api", "services/api/src/a.py"), ("services/api/", "services/api/src/a.py"),
                             ("./services", "services/src/a.py"), ("services\\api", "services/api/src/a.py")):
            doc, _ = sarif.build([flag()], prefix)
            self.assertEqual(doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"], want, prefix)

    def test_a_flag_about_no_file_is_left_out_and_counted(self):
        doc, skipped = sarif.build([flag(), flag(file="", line=0, rule="model.retired", category="model")])
        self.assertEqual((len(doc["runs"][0]["results"]), skipped), (1, 1))

    def test_the_message_holds_the_title_detail_and_fix(self):
        doc, _ = sarif.build([flag(detail="It is in src/a.py.")])
        self.assertEqual(doc["runs"][0]["results"][0]["message"]["text"], "A key is written in the code. It is in src/a.py. Fix: Rotate the key.")

    def test_no_flags_is_a_valid_empty_run(self):
        doc, skipped = sarif.build([])
        self.assertEqual((doc["runs"][0]["results"], doc["runs"][0]["tool"]["driver"]["rules"], skipped), ([], [], 0))

    def test_the_same_flags_give_the_same_bytes(self):
        with tempfile.TemporaryDirectory() as d:
            a, b = os.path.join(d, "a.sarif"), os.path.join(d, "b.sarif")
            sarif.write(a, [flag(), flag("mcp.shell-command", "medium", ".mcp.json", 4, category="mcp")])
            sarif.write(b, [flag("mcp.shell-command", "medium", ".mcp.json", 4, category="mcp"), flag()])
            with open(a, "rb") as fa, open(b, "rb") as fb:
                self.assertEqual(fa.read(), fb.read())

    def test_no_secret_reaches_the_file(self):
        key = "sk-ant-api03-" + "Zq8Lr2Xv" * 11 + "AA"
        doc, _ = sarif.build([flag(title=f"key {key}", detail=f"value {key}")])
        self.assertNotIn(key, json.dumps(doc))


class FromAScan(unittest.TestCase):
    def test_a_scan_writes_aibom_sarif_and_the_command_rewrites_it_with_a_prefix(self):
        with tempfile.TemporaryDirectory() as out:
            r = subprocess.run([sys.executable, "-m", "aibom_engine", "--plain", "scan", APP, "--out", out], cwd=ROOT, capture_output=True, text=True, env=ENV)
            self.assertEqual(r.returncode, 0, r.stderr)
            with open(os.path.join(out, "flags.json"), encoding="utf-8") as fh:
                flags = json.load(fh)["flags"]
            with open(os.path.join(out, "aibom.sarif"), encoding="utf-8") as fh:
                doc = json.load(fh)
            self.assertEqual(len(doc["runs"][0]["results"]), sum(1 for f in flags if f["file"]))
            self.assertEqual({r["ruleId"] for r in doc["runs"][0]["results"]}, {f["rule"] for f in flags if f["file"]})
            r = subprocess.run([sys.executable, "-m", "aibom_engine", "sarif", out, "--prefix", "tests/fixtures/review-app"], cwd=ROOT, capture_output=True, text=True, env=ENV)
            self.assertEqual(r.returncode, 0, r.stderr)
            with open(os.path.join(out, "aibom.sarif"), encoding="utf-8") as fh:
                uris = {x["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for x in json.load(fh)["runs"][0]["results"]}
            self.assertTrue(uris and all(u.startswith("tests/fixtures/review-app/") for u in uris), uris)
            for u in uris:
                self.assertTrue(os.path.exists(os.path.join(ROOT, *u.split("/"))), u)     # every path points at a real file

    def test_the_command_refuses_a_folder_that_is_not_a_scan(self):
        with tempfile.TemporaryDirectory() as d:
            r = subprocess.run([sys.executable, "-m", "aibom_engine", "sarif", d], cwd=ROOT, capture_output=True, text=True, env=ENV)
            self.assertEqual(r.returncode, 2)
            self.assertIn("not a finished scan", r.stderr)


if __name__ == "__main__":
    unittest.main()
