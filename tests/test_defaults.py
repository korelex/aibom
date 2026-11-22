"""The time limit of a scan is one number, used everywhere a scan can start."""
import inspect
import os
import re
import unittest

import aibom_engine
from aibom_engine import cli, credentials, interactive, mcp, modelfiles, pipeline, remote_code

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TimeLimit(unittest.TestCase):
    def test_it_is_600_seconds(self):
        # 120 was too short for a large repository freshly downloaded on Windows, where the antivirus checks each new file the
        # first time it is read (found on a real scan: four minutes of reading for a scan that itself takes 45 seconds).
        self.assertEqual(aibom_engine.MAX_SECONDS, 600)

    def test_the_command_the_menu_and_the_scan_all_use_it(self):
        self.assertEqual(inspect.signature(pipeline.run).parameters["max_seconds"].default, aibom_engine.MAX_SECONDS)
        import subprocess
        import sys
        shown = subprocess.run([sys.executable, "-m", "aibom_engine", "scan", "--help"], cwd=ROOT, capture_output=True, text=True,
                               env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1", "COLUMNS": "200"})
        self.assertIn("(default 600)", re.sub(r"\s+", " ", shown.stdout))
        source = inspect.getsource(cli)
        self.assertIn('"--max-seconds", type=int, default=MAX_SECONDS', source)
        self.assertIn("max_seconds=MAX_SECONDS", inspect.getsource(interactive))
        for module in (credentials, mcp, modelfiles, remote_code):          # each detector's own fallback, when called without a deadline
            self.assertIn("time.time() + MAX_SECONDS", inspect.getsource(module), module.__name__)
            self.assertNotRegex(inspect.getsource(module), r"time\.time\(\) \+ 120\b")

    def test_the_action_and_the_docs_say_the_same(self):
        with open(os.path.join(ROOT, "action.yml"), encoding="utf-8") as fh:
            self.assertRegex(fh.read(), r'max-seconds:\n    description: [^\n]+\n    default: "600"')
        with open(os.path.join(ROOT, "README.md"), encoding="utf-8") as fh:
            self.assertIn("| `--max-seconds N` | 600 |", fh.read())
        with open(os.path.join(ROOT, "docs", "running-in-your-infra.md"), encoding="utf-8") as fh:
            self.assertIn("| `max-seconds` | `600` |", fh.read())


if __name__ == "__main__":
    unittest.main()
