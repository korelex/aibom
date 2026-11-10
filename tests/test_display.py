import csv
import io
import os
import re
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, ROOT)
from aibom_engine import display  # noqa: E402
from aibom_engine.pipeline import run  # noqa: E402
from aibom_engine.report import build_csv, build_html, build_markdown, intro  # noqa: E402
from aibom_engine.source import Linker  # noqa: E402


def item(name, tier="declared", role="used", file="a.py", line=1, maker="OpenAI", mode="chat", use="live", reason="", evidence=None):
    ev = evidence or [{"file": file, "line": line, "use": use, "category": "code", "snippet": f'MODEL = "{name}"'}]
    return {"name": name, "aliases": [], "tier": tier, "role": role, "maker": maker, "mode": mode, "reason": reason, "evidence": ev, "places": {"live": len(ev), "other": 0}}


def write(root, rel, text):
    p = os.path.join(root, rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        f.write(text)


class Spellings(unittest.TestCase):
    def test_same_model_same_key(self):
        keys = {display.key_of(n) for n in ("gpt-4o", "openai-gpt-4o", "openai/gpt-4o", "azure/gpt-4o", "OpenAI:GPT-4o")}
        self.assertEqual(keys, {"gpt-4o"})
        self.assertEqual(display.key_of("gpt-35-turbo"), display.key_of("gpt-3.5-turbo"))

    def test_different_models_stay_apart(self):
        self.assertNotEqual(display.key_of("gpt-4o"), display.key_of("gpt-4o-mini"))
        self.assertNotEqual(display.key_of("gemini-pro"), display.key_of("pro"))

    def test_rows_merge_spellings_and_keep_the_plain_one(self):
        rows = display.build_rows([item("openai-gpt-4o", file="a.py"), item("gpt-4o", file="b.py"), item("claude-3-opus", maker="Anthropic")])
        self.assertEqual(len(rows["used"]), 2)
        gpt = next(r for r in rows["used"] if "gpt" in r["name"])
        self.assertEqual(gpt["name"], "gpt-4o")
        self.assertEqual(gpt["also"], ["openai-gpt-4o"])
        self.assertEqual(len(gpt["places"]), 2)

    def test_a_left_out_spelling_of_a_used_model_is_not_reported_as_left_out(self):
        rows = display.build_rows([item("gpt-4o"), item("openai-gpt-4o", tier="rejected", reason="comment", use="comment")])
        self.assertEqual(rows["left_out"], [])

    def test_listed_and_used_are_separated(self):
        rows = display.build_rows([item("gpt-4o"), item("gpt-3.5-turbo", role="listed")])
        self.assertEqual(([r["name"] for r in rows["used"]], [r["name"] for r in rows["listed"]]), (["gpt-4o"], ["gpt-3.5-turbo"]))


class Links(unittest.TestCase):
    def test_github_gitlab_bitbucket_and_none(self):
        self.assertEqual(Linker("https://github.com/o/r.git", "abc123", "").url_for("src/a.py", 7), "https://github.com/o/r/blob/abc123/src/a.py#L7")
        self.assertEqual(Linker("https://gitlab.com/o/r", "abc", "").url_for("a.py", 3), "https://gitlab.com/o/r/-/blob/abc/a.py#L3")
        self.assertEqual(Linker("https://bitbucket.org/o/r", "abc", "").url_for("a.py", 3), "https://bitbucket.org/o/r/src/abc/a.py#lines-3")
        self.assertEqual(Linker("https://example.com/o/r", "abc", "").url_for("a.py", 3), "")
        self.assertEqual(Linker().url_for("a.py", 3), "")

    def test_folder_and_odd_characters(self):
        self.assertEqual(Linker("https://github.com/o/r", "abc", "sub/dir").url_for("my file.py", 2), "https://github.com/o/r/blob/abc/sub/dir/my%20file.py#L2")

    def test_saved_test_apps_are_looked_up(self):
        lk = Linker.for_saved_app("go-openai")
        self.assertTrue(lk.ok and lk.host == "github.com")
        self.assertFalse(Linker.for_saved_app("no-such-app").ok)


@unittest.skipUnless(__import__("shutil").which("git"), "git is not installed")
class GitFolders(unittest.TestCase):
    ENV = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@t", GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@t")

    def git(self, d, *args):
        subprocess.run(["git", "-C", d] + list(args), check=True, env=self.ENV, capture_output=True)

    def make(self, d):
        write(d, "sub/a.py", 'M = "gpt-4o"\n')
        for args in (("init", "-q"), ("add", "."), ("commit", "-q", "-m", "x"), ("remote", "add", "origin", "git@github.com:o/r.git")):
            self.git(d, *args)

    def test_a_clean_clone_gets_links(self):
        from aibom_engine.source import linker_for_git_folder
        with tempfile.TemporaryDirectory() as d:
            self.make(d)
            lk = linker_for_git_folder(os.path.join(d, "sub"))
            self.assertTrue(lk.ok)
            self.assertTrue(lk.url_for("a.py", 1).startswith("https://github.com/o/r/blob/"))
            self.assertIn("/sub/a.py#L1", lk.url_for("a.py", 1))

    def test_uncommitted_changes_mean_no_links(self):
        from aibom_engine.source import linker_for_git_folder
        with tempfile.TemporaryDirectory() as d:
            self.make(d)
            write(d, "sub/a.py", 'M = "something else"\n')
            self.assertFalse(linker_for_git_folder(d).ok)

    def test_a_plain_folder_gets_no_links(self):
        from aibom_engine.source import linker_for_git_folder
        with tempfile.TemporaryDirectory() as d:
            self.assertFalse(linker_for_git_folder(d).ok)


class Outputs(unittest.TestCase):
    ITEMS = [item("gpt-4o", file="src/app.py", line=12), item("openai-gpt-4o", file="src/other.py", line=3), item("o1", role="listed", file="t.py", line=5),
             item("gpt-3", tier="rejected", reason="comment", use="comment", file="old.py", line=9)]
    LINKS = Linker("https://github.com/o/r", "deadbeefcafe")

    def test_csv_is_readable_in_a_spreadsheet(self):
        rows = list(csv.reader(io.StringIO(build_csv(self.ITEMS, self.LINKS))))
        header = rows[0]
        self.assertEqual(header[:7], ["model", "made_by", "type", "role", "confidence", "evidence_level", "reachability"])
        self.assertTrue(all(len(r) == len(header) for r in rows), "every row has a value for every column")
        col = {name: i for i, name in enumerate(header)}
        self.assertEqual({r[col["role"]] for r in rows[1:]}, {"used directly", "only listed", "left out"})
        first = next(r for r in rows if r[0] == "gpt-4o")
        self.assertEqual(first[col["link"]], "https://github.com/o/r/blob/deadbeefcafe/src/app.py#L12")
        self.assertIn("openai-gpt-4o", first[col["also_written_as"]])
        self.assertEqual((first[col["evidence_level"]], first[col["reachability"]]), ("declared", "not_verified"))

    def test_pipeline_writes_the_csv_with_an_excel_friendly_start(self):
        with tempfile.TemporaryDirectory() as d, tempfile.TemporaryDirectory() as out:
            write(d, "a.py", 'MODEL = "gpt-4o"\n')
            run(d, out)
            with open(os.path.join(out, "models.csv"), "rb") as f:
                self.assertTrue(f.read(3) == b"\xef\xbb\xbf")

    def test_html_has_the_parts_a_newcomer_needs(self):
        page = build_html(self.ITEMS, "demo", "https://github.com/o/r", self.LINKS)
        for must in ("AI models found in demo", "used directly in the code", "id='q'", "What this scan cannot see", "Left out, and why", "also written as", "Confirmed",
                     "https://github.com/o/r/blob/deadbeefcafe/src/app.py#L12", "version deadbeefca"):
            self.assertIn(must, page)

    def test_html_escapes_names_from_the_repository(self):
        page = build_html([item('<script>alert(1)</script>')], "x<b>", "", None)
        self.assertNotIn("<script>alert(1)</script>", page)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", page)
        self.assertNotIn("x<b>", page)

    def test_html_is_black_and_white_and_needs_no_internet(self):
        page = build_html(self.ITEMS, "demo", "", self.LINKS)
        colours = set(re.findall(r"#[0-9a-fA-F]{3,6}\b", page.split("<body>")[0]))
        self.assertTrue(colours <= {"#000", "#fff"}, colours)
        self.assertNotRegex(page, r"<(script|link|img)[^>]+(src|href)=[\"']https?://")

    def test_generated_text_has_no_long_dashes(self):
        for text in (build_html(self.ITEMS, "demo", "", self.LINKS), build_markdown(self.ITEMS, "demo", "", self.LINKS), build_csv(self.ITEMS, self.LINKS)):
            self.assertNotIn("\u2014", text)
            self.assertNotIn("\u2013", text)

    def test_the_sentence_reads_naturally(self):
        one = display.build_rows([item("gpt-4o"), item("o1", role="listed")])
        self.assertIn("uses 1 model directly in its code", intro(one, "demo"))
        self.assertIn("1 more model only appears in", intro(one, "demo"))
        many = display.build_rows([item("gpt-4o"), item("claude-3", maker="Anthropic"), item("a-1", role="listed"), item("b-2", role="listed")])
        self.assertIn("uses 2 models directly", intro(many, "demo"))
        self.assertIn("2 more models only appear in", intro(many, "demo"))

    def test_a_scan_that_stopped_early_says_so_on_the_page_and_in_the_summary(self):
        meta = {"warnings": ["The time limit of 120 seconds was reached, so part of the repository was not read."]}
        page = build_html(self.ITEMS, "demo", "", self.LINKS, meta)
        self.assertIn("This scan may be incomplete", page)
        self.assertIn("time limit of 120 seconds", page)
        self.assertIn("WARNING, this scan may be incomplete", build_markdown(self.ITEMS, "demo", "", self.LINKS, meta))
        self.assertNotIn("may be incomplete", build_html(self.ITEMS, "demo", "", self.LINKS))

    def test_nothing_found_explains_why(self):
        self.assertIn("picks its model when it runs", build_markdown([], "demo"))
        self.assertIn("picks its model when it runs", build_html([], "demo"))


class Terminal(unittest.TestCase):
    def test_type_column_never_cuts_a_word(self):
        from aibom_engine.cli import SHORT_MODE
        for label in ("chat model", "embedding model", "image model", "speech-to-text model", "text-to-speech model", "text model", "reranking model", "moderation model", "realtime voice model", "video model"):
            self.assertLessEqual(len(SHORT_MODE[label]), 11, label)


class Commands(unittest.TestCase):
    def cli(self, *args):
        return subprocess.run([sys.executable, "-m", "aibom_engine"] + list(args), cwd=ROOT, capture_output=True, text=True)

    def setUp(self):
        self.d, self.out = tempfile.mkdtemp(), tempfile.mkdtemp()
        write(self.d, "app/config.py", 'DEFAULT_MODEL = "gpt-4o-mini"\n# old: "gpt-4.1-nano"\nprint("calling gpt-4 now")\n')
        self.r = self.cli("scan", self.d, "--out", self.out, "--quiet")

    def test_scan_summary_is_plain_ascii_and_shows_the_next_steps(self):
        self.assertEqual(self.r.returncode, 0, self.r.stderr)
        self.assertTrue(self.r.stdout.isascii())
        for must in ("Scan finished", "models used directly in the code", "The main ones:", "gpt-4o-mini", "report.html", "models.csv", "explain", "Limits:"):
            self.assertIn(must, self.r.stdout)
        self.assertTrue(all(len(line) <= 140 for line in self.r.stdout.splitlines()))

    def test_show_all_and_left_out(self):
        self.assertIn("gpt-4o-mini", self.cli("show", self.out, "--all").stdout)
        left = self.cli("show", self.out, "--left-out").stdout
        self.assertIn("gpt-4.1-nano", left)
        self.assertIn("only in a comment", left)

    def test_explain_a_model_a_left_out_name_and_an_unknown_name(self):
        ok = self.cli("explain", self.out, "gpt-4o-mini").stdout
        self.assertIn("set or used directly in the code", ok)
        self.assertIn("config.py", ok)
        gone = self.cli("explain", self.out, "gpt-4.1-nano").stdout
        self.assertIn("NOT counted", gone)
        bad = self.cli("explain", self.out, "no-such-model")
        self.assertEqual(bad.returncode, 2)
        self.assertNotIn("Traceback", bad.stderr)

    def test_rebuild_recreates_the_readable_files(self):
        for f in ("report.html", "report.md", "models.csv"):
            os.remove(os.path.join(self.out, f))
        r = self.cli("rebuild", self.out)
        self.assertEqual(r.returncode, 0, r.stderr)
        for f in ("report.html", "report.md", "models.csv"):
            self.assertTrue(os.path.exists(os.path.join(self.out, f)), f)


if __name__ == "__main__":
    unittest.main()
