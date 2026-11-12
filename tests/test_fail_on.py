"""--fail-on (M3.6): a scan can stop a build when it finds a risk flag at a chosen severity or worse."""
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP = os.path.join(ROOT, "tests", "fixtures", "review-app")      # it has high, medium and low flags
ENV = {**os.environ, "AIBOM_TODAY": "2026-11-09", "PYTHONDONTWRITEBYTECODE": "1"}


def scan(*extra, app=APP):
    with tempfile.TemporaryDirectory() as out:
        return subprocess.run([sys.executable, "-m", "aibom_engine", "--plain", "scan", app, "--out", out] + list(extra), cwd=ROOT, capture_output=True, text=True, env=ENV)


class FailOn(unittest.TestCase):
    def test_without_the_option_a_scan_with_flags_succeeds(self):
        self.assertEqual(scan().returncode, 0)

    def test_a_flag_at_or_above_the_level_fails_the_scan_with_code_3(self):
        for level in ("info", "low", "medium", "high"):
            r = scan("--fail-on", level)
            self.assertEqual(r.returncode, 3, (level, r.stderr))
            self.assertIn("Failed:", r.stderr)
            self.assertIn("or worse", r.stderr)

    def test_the_results_are_still_written_when_the_gate_fails(self):
        with tempfile.TemporaryDirectory() as out:
            r = subprocess.run([sys.executable, "-m", "aibom_engine", "--plain", "scan", APP, "--out", out, "--fail-on", "high"], cwd=ROOT, capture_output=True, text=True, env=ENV)
            self.assertEqual(r.returncode, 3)
            self.assertTrue(os.path.exists(os.path.join(out, "flags.json")))
            self.assertTrue(os.path.exists(os.path.join(out, "aibom.cdx.json")))

    def test_a_folder_without_flags_passes_every_level(self):
        with tempfile.TemporaryDirectory() as app:
            with open(os.path.join(app, "a.py"), "w", encoding="utf-8") as fh:
                fh.write("x = 1\n")
            for level in ("info", "low", "medium", "high"):
                self.assertEqual(scan("--fail-on", level, app=app).returncode, 0, level)

    def test_a_level_that_does_not_exist_is_refused_before_scanning(self):
        r = scan("--fail-on", "critical")
        self.assertEqual(r.returncode, 2)
        self.assertIn("invalid choice", r.stderr)

    def test_a_scan_that_cannot_run_is_not_the_same_code_as_a_failed_gate(self):
        r = scan("--fail-on", "high", app=os.path.join(ROOT, "no-such-folder"))
        self.assertEqual(r.returncode, 2)

    def test_the_gate_counts_only_flags_at_the_level_or_worse(self):
        from aibom_engine import flags as F
        flags = [F.Flag("a.b", "low", title="t", category="c", subject="s", fix="f"), F.Flag("a.c", "info", title="t", category="c", subject="s", fix="f")]
        self.assertEqual(len(F.at_least(flags, "low")), 1)
        self.assertEqual(len(F.at_least(flags, "medium")), 0)


if __name__ == "__main__":
    unittest.main()
