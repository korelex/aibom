import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, ROOT)
from aibom_engine import source, verify  # noqa: E402
from aibom_engine.finders import context, dictionary  # noqa: E402
from aibom_engine.finding import Finding  # noqa: E402
from aibom_engine.merge import MAX_EVIDENCE, merge  # noqa: E402
from aibom_engine.pipeline import run  # noqa: E402
from aibom_engine.report import build_html, build_markdown  # noqa: E402
from aibom_engine.triage import FileInfo  # noqa: E402


def write(root, rel, text):
    p = os.path.join(root, rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        f.write(text)


class Links(unittest.TestCase):
    def test_github_forms(self):
        for a in ("https://github.com/o/r", "github.com/o/r", "https://github.com/o/r.git", "https://github.com/o/r/", "git@github.com:o/r.git"):
            s = source.parse(a)
            self.assertEqual((s["kind"], s["name"]), ("git", "r"), a)

    def test_owner_repo_shorthand(self):
        self.assertEqual(source.parse("vercel/ai-chatbot")["url"], "https://github.com/vercel/ai-chatbot")

    def test_branch_and_folder(self):
        s = source.parse("https://github.com/o/r/tree/dev/src/app")
        self.assertEqual((s["branch"], s["subpath"]), ("dev", "src/app"))

    def test_local_folder(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(source.parse(d)["kind"], "local")

    def test_nonsense_gives_a_helpful_message(self):
        with self.assertRaises(source.SourceError) as cm:
            source.parse("not a thing")
        self.assertIn("https://github.com/owner/repo", str(cm.exception))

    def test_error_messages_are_plain(self):
        self.assertIn("private", source.friendly_git_error("fatal: repository 'x' not found", "u"))
        self.assertIn("internet", source.friendly_git_error("fatal: unable to access: Could not resolve host: github.com", "u"))
        self.assertIn("branch", source.friendly_git_error("fatal: Remote branch zzz not found in upstream origin", "u"))
        self.assertIn("could not download", source.friendly_git_error("weird failure", "u"))


@unittest.skipUnless(shutil.which("git"), "git is not installed")
class Download(unittest.TestCase):
    def make_repo(self, d):
        write(d, "app/config.py", 'MODEL = "gpt-4o-mini"\n')
        env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@t", GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@t")
        for cmd in (["init", "-q"], ["add", "."], ["commit", "-q", "-m", "x"]):
            subprocess.run(["git", "-C", d] + cmd, check=True, env=env, capture_output=True)

    def test_download_and_cleanup(self):
        with tempfile.TemporaryDirectory() as d:
            self.make_repo(d)
            url = "file://" + d.replace(os.sep, "/")
            src = source.parse(url)
            root, tmp = source.fetch(src)
            try:
                self.assertTrue(os.path.exists(os.path.join(root, "app", "config.py")))
            finally:
                source.cleanup(tmp)
            self.assertFalse(os.path.exists(tmp))

    def test_missing_folder_in_repo(self):
        with tempfile.TemporaryDirectory() as d:
            self.make_repo(d)
            src = source.parse("file://" + d.replace(os.sep, "/"))
            src["subpath"] = "no/such/folder"
            with self.assertRaises(source.SourceError):
                source.fetch(src)

    def test_unreachable_repo_is_a_friendly_error(self):
        src = source.parse("file:///definitely/not/here")
        with self.assertRaises(source.SourceError) as cm:
            source.fetch(src)
        self.assertNotIn("Traceback", str(cm.exception))


class Roles(unittest.TestCase):
    def item(self, name, file, line):
        return {"name": name, "tier": "declared", "reason": "", "evidence": [{"file": file, "line": line, "use": "live", "category": "code"}]}

    def test_long_table_is_listed_and_direct_use_is_used(self):
        items = [self.item(f"gpt-{i}", "limits.py", 10 + i) for i in range(9)]
        direct = self.item("gpt-0", "limits.py", 10)
        direct["evidence"].append({"file": "config.py", "line": 5, "use": "live", "category": "code"})
        items[0] = direct
        verify.assign_roles(items)
        self.assertEqual(items[0]["role"], "used")
        self.assertTrue(all(i["role"] == "listed" for i in items[1:]))

    def test_a_catalog_file_is_listed_even_when_entries_are_far_apart(self):
        items = [self.item(f"model-{i}", "profiles.py", 10 + i * 80) for i in range(25)]
        verify.assign_roles(items)
        self.assertTrue(all(i["role"] == "listed" for i in items))

    def test_short_list_is_used(self):
        items = [self.item(f"claude-{i}", "config.py", 10 + i) for i in range(3)]
        verify.assign_roles(items)
        self.assertTrue(all(i["role"] == "used" for i in items))

    def test_rejected_has_no_role(self):
        it = self.item("gpt-4", "a.py", 1)
        it["tier"] = "rejected"
        verify.assign_roles([it])
        self.assertEqual(it["role"], "")


class Limits(unittest.TestCase):
    def test_deadline_in_the_past_stops_both_finders(self):
        with tempfile.TemporaryDirectory() as d:
            write(d, "a.py", 'MODEL = "gpt-4o"\n')
            files = [FileInfo("a.py", "code", 10)]
            late = time.time() - 5
            self.assertEqual(dictionary.run(d, files, deadline=late), [])
            self.assertEqual(context.run(d, files, deadline=late), [])
            self.assertTrue(dictionary.run(d, files))

    def test_evidence_is_capped_for_names_that_appear_thousands_of_times(self):
        fs = [Finding("t", "model", "gpt-4", f"f{i % 50}.py", i + 1, "", "code", "x") for i in range(MAX_EVIDENCE + 500)]
        item = merge(fs)[0]
        self.assertEqual(len(item["evidence"]), MAX_EVIDENCE)
        self.assertEqual(item["evidence_total"], MAX_EVIDENCE + 500)


class EndToEnd(unittest.TestCase):
    def test_small_app(self):
        with tempfile.TemporaryDirectory() as d, tempfile.TemporaryDirectory() as out:
            write(d, "app/config.py", 'DEFAULT_MODEL = "gpt-4o-mini"\n# old: "gpt-4.1-nano"\nprint("calling gpt-4 now")\n')
            write(d, "README.md", "We also tried gpt-3.5-turbo here.\n")
            logs = []
            r = run(d, out, app="demo", source="a test", log=logs.append)
            self.assertTrue(r["valid"])
            self.assertEqual((r["items"], r["used"]), (1, 1))
            self.assertEqual(r["rejected"], 3)
            self.assertTrue(any("Checking" in m for m in logs))
            for f in ("aibom.cdx.json", "report.html", "report.md", "manifest.json"):
                self.assertTrue(os.path.exists(os.path.join(out, f)), f)

    def test_app_without_models_says_why(self):
        with tempfile.TemporaryDirectory() as d, tempfile.TemporaryDirectory() as out:
            write(d, "main.py", "print('hello')\n")
            r = run(d, out, app="empty")
            self.assertEqual(r["items"], 0)
            with open(os.path.join(out, "report.md"), encoding="utf-8") as f:
                text = f.read()
            self.assertIn("No AI model names were found", text)
            self.assertIn("run", text)

    def test_cli_scan_prints_a_summary_and_exits_zero(self):
        with tempfile.TemporaryDirectory() as d, tempfile.TemporaryDirectory() as out:
            write(d, "a.py", 'MODEL = "gpt-4o"\n')
            r = subprocess.run([sys.executable, "-m", "aibom_engine", "scan", d, "--out", out, "--quiet"], cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn("1    models used directly in the code", r.stdout)

    def test_cli_bad_source_is_a_friendly_message_not_a_traceback(self):
        r = subprocess.run([sys.executable, "-m", "aibom_engine", "scan", "not a thing"], cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(r.returncode, 2)
        self.assertIn("Problem:", r.stderr)
        self.assertNotIn("Traceback", r.stderr)


if __name__ == "__main__":
    unittest.main()
