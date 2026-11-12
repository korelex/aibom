"""The guided menu (M2.8) and the `packages` command it uses.

The menu logic is tested with a scripted prompter: it fails when the flow asks something unexpected or when the script picks
something the menu did not offer. The real prompter is tested with simulated keystrokes (prompt_toolkit's pipe input)."""
import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest

from aibom_engine import cli, interactive
from aibom_engine.interactive import BACK, Menu, Prompter
from aibom_engine.pipeline import run
from aibom_engine.source import SourceError
from test_packages import Repo

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")

PROJECT = {
    "requirements.txt": "openai==1.30.0\nlangchain-community==0.0.20\nlangchain-openai>=0.1\n",
    "app.py": """
        from openai import OpenAI
        from langchain_community.vectorstores import Chroma
        client = OpenAI()
        client.chat.completions.create(model="gpt-4o-2024-08-06", messages=[])
        store = Chroma()
        """,
}


class Scripted:
    """Stands in for the person: answers = [(text the question must contain, answer)]."""

    def __init__(self, *answers):
        self.answers = list(answers)
        self.asked = []

    def _next(self, kind, message, choices=None):
        self.asked.append((kind, message, choices))
        if not self.answers:
            raise AssertionError("the menu asked something the script did not expect: %r" % message)
        want, value = self.answers.pop(0)
        if want not in message:
            raise AssertionError("expected a question containing %r, got %r" % (want, message))
        if isinstance(value, type) and issubclass(value, BaseException):
            raise value()
        return value

    def select(self, message, choices, search=False):
        value = self._next("select", message, choices)
        if value is not BACK and value not in [v for _, v in choices]:
            raise AssertionError("the script chose %r, which is not offered: %r" % (value, [v for _, v in choices]))
        return value

    def text(self, message, default="", validate=None):
        value = self._next("text", message)
        if value is BACK:
            return BACK
        value = value or default
        if validate:
            verdict = validate(value)
            if verdict is not True:
                raise AssertionError("the script typed %r and the menu rejects it: %s" % (value, verdict))
        return value

    def offered(self, index=-1):
        return [v for _, v in self.asked[index][2]]


class InTempFolder(unittest.TestCase):
    def setUp(self):
        self._cwd = os.getcwd()
        self._tmp = tempfile.TemporaryDirectory()
        os.chdir(self._tmp.name)
        self.addCleanup(self._cleanup)

    def _cleanup(self):
        os.chdir(self._cwd)
        self._tmp.cleanup()

    def drive(self, prompter, runs_dir="runs"):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = Menu(prompter, runs_dir=runs_dir).run()
        return code, out.getvalue()


class MenuFlows(InTempFolder):
    @classmethod
    def setUpClass(cls):
        cls.repo = Repo(PROJECT)
        cls.saved = tempfile.TemporaryDirectory()
        cls.first = os.path.join(cls.saved.name, "runs", "first")
        run(cls.repo.tmp.name, cls.first, app="first")

    @classmethod
    def tearDownClass(cls):
        cls.repo.close()
        cls.saved.cleanup()

    def test_scan_then_look_at_everything(self):
        source = self.repo.tmp.name
        app = os.path.basename(source)
        prompts = Scripted(("What do you want to do", "scan"), ("Folder or GitHub link", source),
                           (app, "models"), (app, "packages"), (app, "explain"), ("Which model", "gpt-4o-2024-08-06"),
                           (app, "package"), ("Which package", "openai"), (app, "left"), (app, "rebuild"), (app, "back"),
                           ("What do you want to do", "quit"))
        code, text = self.drive(prompts)
        self.assertEqual(code, 0)
        self.assertTrue(os.path.isfile(os.path.join("runs", app, "aibom.cdx.json")), "the scan wrote its results under runs/")
        self.assertIn("gpt-4o-2024-08-06", text)                       # the model list
        self.assertIn("AI packages found", text)                       # the packages list
        self.assertIn("client = OpenAI()", text)                       # a package in detail: where it is called
        self.assertIn("How sure:", text)                               # explain
        self.assertIn("rebuilt", text)
        for equivalent in ("scan", "show", "packages", "explain", "rebuild"):
            self.assertIn("Same thing without the menu:  %s" % cli.command(), text)
            self.assertIn("%s %s" % (cli.command(), equivalent), text)

    def test_every_action_prints_the_command_that_does_the_same(self):
        run_dir = os.path.join("runs", "first")
        os.makedirs("runs")
        import shutil
        shutil.copytree(self.first, run_dir)
        prompts = Scripted(("What do you want to do", "open"), ("Which scan", run_dir), ("first", "models"), ("first", "packages"),
                           ("first", "package"), ("Which package", "langchain-community"), ("first", "back"), ("What do you want to do", "quit"))
        _, text = self.drive(prompts)
        self.assertIn("Same thing without the menu:  %s show %s" % (cli.command(), run_dir), text)
        self.assertIn("Same thing without the menu:  %s packages %s langchain-community" % (cli.command(), run_dir), text)

    def test_vulnerabilities_worst_first_is_in_the_menu_and_names_its_command(self):
        run_dir = os.path.join("runs", "first")
        os.makedirs("runs")
        import shutil
        shutil.copytree(self.first, run_dir)
        prompts = Scripted(("What do you want to do", "open"), ("Which scan", run_dir), ("first", "vulns"), ("first", "back"), ("What do you want to do", "quit"))
        _, text = self.drive(prompts)
        self.assertIn("Fix plan", text)
        self.assertIn("Same thing without the menu:  %s vulns %s" % (cli.command(), run_dir), text)
        self.assertEqual(prompts.offered(2)[:3], ["report", "models", "vulns"])

    def test_esc_goes_back_one_step_and_quits_at_the_main_menu(self):
        code, text = self.drive(Scripted(("What do you want to do", "scan"), ("Folder or GitHub link", BACK), ("What do you want to do", BACK)))
        self.assertEqual(code, 0)
        self.assertEqual(text.count("Same thing without the menu"), 0)  # nothing ran
        import shutil
        os.makedirs("runs")
        shutil.copytree(self.first, os.path.join("runs", "first"))
        prompts = Scripted(("What do you want to do", "open"), ("Which scan", BACK), ("What do you want to do", "open"),
                           ("Which scan", os.path.join("runs", "first")), ("first", BACK), ("What do you want to do", BACK))
        self.assertEqual(self.drive(prompts)[0], 0)

    def test_the_menu_offers_only_what_exists(self):
        prompts = Scripted(("What do you want to do", "quit"))
        self.drive(prompts)
        self.assertEqual(prompts.offered(0), ["scan", "quit"])  # no saved scan, so no "look at a scan"
        import shutil
        os.makedirs("runs")
        shutil.copytree(self.first, os.path.join("runs", "first"))
        prompts = Scripted(("What do you want to do", "quit"))
        self.drive(prompts)
        self.assertEqual(prompts.offered(0), ["scan", "open", "quit"])

    def test_a_scan_made_before_packages_has_no_package_entries(self):
        import shutil
        os.makedirs("runs")
        old = os.path.join("runs", "old")
        shutil.copytree(self.first, old)
        os.remove(os.path.join(old, "packages.json"))
        prompts = Scripted(("What do you want to do", "open"), ("Which scan", old), ("first", "back"), ("What do you want to do", "quit"))
        self.drive(prompts)
        # asked: 0 = the main menu, 1 = which scan, 2 = what to see in it
        self.assertEqual(prompts.offered(2), ["report", "models", "explain", "left", "rebuild", "back"])

    def test_an_existing_scan_asks_before_it_is_replaced(self):
        import shutil
        source = self.repo.tmp.name
        app = os.path.basename(source)
        os.makedirs("runs")
        shutil.copytree(self.first, os.path.join("runs", app))
        marker = os.path.join("runs", app, "marker.txt")
        with open(marker, "w") as fh:
            fh.write("x")
        # look at the saved scan: nothing is rescanned
        prompts = Scripted(("What do you want to do", "scan"), ("Folder or GitHub link", source), ("already saved", "open"), ("what do you want to see", "back"), ("What do you want to do", "quit"))
        self.drive(prompts)
        self.assertTrue(os.path.exists(marker))
        # choose another folder, then give up
        prompts = Scripted(("What do you want to do", "scan"), ("Folder or GitHub link", source), ("already saved", "again"),
                           ("Folder or GitHub link", BACK), ("What do you want to do", "quit"))
        self.drive(prompts)
        self.assertTrue(os.path.exists(marker))
        # replace it: the folder is rewritten by the scan
        prompts = Scripted(("What do you want to do", "scan"), ("Folder or GitHub link", source), ("already saved", "replace"), ("what do you want to see", "back"), ("What do you want to do", "quit"))
        self.drive(prompts)
        self.assertTrue(os.path.isfile(os.path.join("runs", app, "aibom.cdx.json")))

    def test_a_failed_scan_returns_to_the_menu(self):
        original = cli.do_scan
        self.addCleanup(setattr, cli, "do_scan", original)

        def failing(args):
            raise SourceError("The AI-BOM did not pass the format check")
        cli.do_scan = failing
        code, text = self.drive(Scripted(("What do you want to do", "scan"), ("Folder or GitHub link", self.repo.tmp.name), ("What do you want to do", "quit")))
        self.assertEqual(code, 0)
        self.assertIn("Problem: The AI-BOM did not pass the format check", text)
        self.assertIn("Same thing without the menu:", text)

    def test_ctrl_c_while_an_action_runs_stops_it_and_returns_to_the_menu(self):
        original = cli.do_scan
        self.addCleanup(setattr, cli, "do_scan", original)

        def interrupted(args):
            raise KeyboardInterrupt
        cli.do_scan = interrupted
        code, text = self.drive(Scripted(("What do you want to do", "scan"), ("Folder or GitHub link", self.repo.tmp.name), ("What do you want to do", "quit")))
        self.assertEqual(code, 0)
        self.assertIn("Stopped.", text)

    def test_ctrl_c_at_a_question_ends_aibom(self):
        with self.assertRaises(KeyboardInterrupt):
            self.drive(Scripted(("What do you want to do", KeyboardInterrupt)))

    def test_an_unexpected_error_does_not_end_the_menu(self):
        original = cli.do_scan
        self.addCleanup(setattr, cli, "do_scan", original)

        def broken(args):
            raise RuntimeError("boom")
        cli.do_scan = broken
        code, text = self.drive(Scripted(("What do you want to do", "scan"), ("Folder or GitHub link", self.repo.tmp.name), ("What do you want to do", "quit")))
        self.assertEqual(code, 0)
        self.assertIn("Something went wrong (RuntimeError: boom)", text)


class Helpers(InTempFolder):
    def test_a_source_is_checked_with_the_same_rules_as_the_scan_command(self):
        self.assertTrue(interactive.check_source(self._tmp.name))
        self.assertTrue(interactive.check_source("owner/repo"))
        self.assertTrue(interactive.check_source("https://github.com/owner/repo"))
        self.assertIn("Type a folder", interactive.check_source("  "))
        self.assertIn("could not find a folder", interactive.check_source("no such folder"))

    def test_a_scan_folder_is_checked(self):
        self.assertIsInstance(interactive.check_run(self._tmp.name), str)
        for name in ("manifest.json", "merged.json"):
            with open(name, "w") as fh:
                fh.write("{}")
        self.assertTrue(interactive.check_run("."))

    def test_finished_scans_are_found_newest_first(self):
        for i, name in enumerate(("a", "b", "c")):
            os.makedirs(os.path.join("runs", name))
            for f in ("manifest.json", "merged.json"):
                with open(os.path.join("runs", name, f), "w") as fh:
                    fh.write("{}")
            os.utime(os.path.join("runs", name, "manifest.json"), (1_700_000_000 + i * 100,) * 2)
        os.makedirs(os.path.join("runs", "half"))  # a folder without merged.json is not a finished scan
        with open(os.path.join("runs", "half", "manifest.json"), "w") as fh:
            fh.write("{}")
        self.assertEqual(interactive.find_runs("runs"), [os.path.join("runs", n) for n in ("c", "b", "a")])

    def test_commands_are_quoted_for_the_persons_shell(self):
        self.assertEqual(interactive.quote("runs/app"), "runs/app")
        self.assertEqual(interactive.quote("owner/repo"), "owner/repo")
        spaced = interactive.quote("my project")
        self.assertNotEqual(spaced, "my project")
        self.assertIn("my project", spaced)
        self.assertIn(cli.command(), interactive.command_line("scan", "my project"))

    def test_without_a_terminal_aibom_prints_help_and_exits_cleanly(self):
        done = subprocess.run([sys.executable, "-m", "aibom_engine"], cwd=ROOT, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=60)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn("usage:", done.stdout)
        self.assertIn("guided menu", done.stdout)
        piped = subprocess.run([sys.executable, "-m", "aibom_engine"], cwd=ROOT, input="1\n", capture_output=True, text=True, timeout=60)
        self.assertEqual(piped.returncode, 0)
        self.assertIn("usage:", piped.stdout)

    def test_a_wrong_command_is_still_an_error(self):
        done = subprocess.run([sys.executable, "-m", "aibom_engine", "nosuch"], cwd=ROOT, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=60)
        self.assertEqual(done.returncode, 2)


CHILD = r"""
import json, sys
from prompt_toolkit.input import create_pipe_input
from prompt_toolkit.output import DummyOutput
from aibom_engine.interactive import Prompter, BACK
spec = json.loads(sys.argv[1])
with create_pipe_input() as inp:
    inp.send_text(spec["keys"])
    p = Prompter(input=inp, output=DummyOutput())
    try:
        if spec["kind"] == "select":
            r = p.select("?", [tuple(c) for c in spec["choices"]], search=spec.get("search", False))
        else:
            check = (lambda t: True if t != "x" else "not x") if spec.get("validate") else None
            r = p.text("?", default=spec.get("default", ""), validate=check)
        out = {"result": "<BACK>" if r is BACK else r}
    except KeyboardInterrupt:
        out = {"raised": "KeyboardInterrupt"}
print(json.dumps(out))
"""


class RealPrompts(unittest.TestCase):
    """The real prompter, fed simulated keystrokes. Each prompt runs in its own process with a time limit: a prompt that is
    waiting for a key that never comes (a broken Esc binding) is killed and reported, instead of freezing the test run."""

    def ask(self, keys, kind="select", **spec):
        spec.update(keys=keys, kind=kind)
        try:
            done = subprocess.run([sys.executable, "-c", CHILD, json.dumps(spec)], cwd=ROOT, capture_output=True, text=True, timeout=25)
        except subprocess.TimeoutExpired:
            self.fail("the prompt did not return after the keys %r: it is still waiting for a key" % keys)
        self.assertEqual(done.returncode, 0, done.stderr[-500:])
        return json.loads(done.stdout.strip().splitlines()[-1])

    CHOICES = [("Scan", "scan"), ("Open", "open"), ("Quit", "quit")]

    def test_arrows_and_enter_choose(self):
        self.assertEqual(self.ask("\r", choices=self.CHOICES), {"result": "scan"})
        self.assertEqual(self.ask("\x1b[B\x1b[B\r", choices=self.CHOICES), {"result": "quit"})

    def test_a_lone_esc_goes_back_and_arrows_still_work(self):
        self.assertEqual(self.ask("\x1b", choices=self.CHOICES), {"result": "<BACK>"})
        self.assertEqual(self.ask("abc\x1b", "text"), {"result": "<BACK>"})

    def test_ctrl_c_raises_so_aibom_can_stop_the_usual_way(self):
        self.assertEqual(self.ask("\x03", choices=self.CHOICES), {"raised": "KeyboardInterrupt"})
        self.assertEqual(self.ask("\x03", "text"), {"raised": "KeyboardInterrupt"})

    def test_typing_filters_a_long_list(self):
        names = [[n, n] for n in ("gpt-4o", "claude-sonnet-4-5", "gemini-2.5-flash", "mistral-large")]
        self.assertEqual(self.ask("gem\r", choices=names, search=True), {"result": "gemini-2.5-flash"})

    def test_text_uses_the_default_on_an_empty_line_and_the_typed_text_otherwise(self):
        self.assertEqual(self.ask("\r", "text", default="."), {"result": "."})
        self.assertEqual(self.ask("owner/repo\r", "text", default="."), {"result": "owner/repo"})

    def test_an_invalid_answer_keeps_asking(self):
        # Enter on "x" is refused by the check, so only Esc gets out
        self.assertEqual(self.ask("x\r\x1b", "text", validate=True), {"result": "<BACK>"})


class PackagesCommand(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.repo = Repo(dict(PROJECT, **{
            "web/package.json": json.dumps({"name": "web", "dependencies": {"ai": "^4.0.0"}}),
            "web/package-lock.json": json.dumps({"lockfileVersion": 3, "packages": {
                "": {"name": "web", "dependencies": {"ai": "^4.0.0"}}, "node_modules/ai": {"version": "4.3.1"},
                "node_modules/@langchain/core": {"version": "0.3.0"}}}),
            "web/chat.ts": 'import { generateText } from "ai";\ngenerateText({ model: m });\n',
        }))
        cls.out = tempfile.TemporaryDirectory()
        run(cls.repo.tmp.name, cls.out.name, app="demo")

    @classmethod
    def tearDownClass(cls):
        cls.repo.close()
        cls.out.cleanup()

    def say(self, fn, *args):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            fn(*args)
        return buf.getvalue()

    def test_the_list_shows_the_most_severe_first_and_marks_what_is_not_checked(self):
        text = self.say(cli.packages_view, self.out.name)
        lines = [ln for ln in text.splitlines() if ln.startswith("  ") and "PACKAGE" not in ln]
        self.assertTrue(lines[0].lstrip().startswith("langchain-community"), lines[0])
        self.assertIn("6 known (1 critical", lines[0])
        self.assertIn("None known", next(ln for ln in lines if ln.lstrip().startswith("openai ")))
        self.assertIn("Not checked", next(ln for ln in lines if ln.lstrip().startswith("langchain-openai")))
        self.assertIn("not that the app reaches the vulnerable code", text)

    def test_transitive_packages_are_listed_only_with_all(self):
        self.assertNotIn("@langchain/core", self.say(cli.packages_view, self.out.name))
        self.assertIn("more only in a lockfile (use --all)", self.say(cli.packages_view, self.out.name))
        self.assertIn("@langchain/core", self.say(cli.packages_view, self.out.name, None, True))

    def test_one_package_in_detail(self):
        text = self.say(cli.packages_view, self.out.name, "langchain-community")
        self.assertIn("langchain-community 0.0.20", text)
        self.assertIn("Called: live code calls it", text)
        self.assertIn("app.py:", text)
        self.assertIn("6 known for this exact version", text)
        self.assertIn("fixed in 0.2.4", text)
        self.assertIn("not yet verified", text)
        self.assertIn("not checked", self.say(cli.packages_view, self.out.name, "langchain-openai"))

    def test_an_unknown_package_is_a_clear_error(self):
        with self.assertRaises(SourceError) as caught:
            self.say(cli.packages_view, self.out.name, "nosuchthing")
        self.assertIn("no AI package called 'nosuchthing'", str(caught.exception))

    def test_a_scan_without_package_data_says_so(self):
        with tempfile.TemporaryDirectory() as old:
            for name in ("manifest.json", "merged.json"):
                with open(os.path.join(self.out.name, name), encoding="utf-8") as src, open(os.path.join(old, name), "w", encoding="utf-8") as dst:
                    dst.write(src.read())
            with self.assertRaises(SourceError) as caught:
                self.say(cli.packages_view, old)
            self.assertIn("older aibom", str(caught.exception))

    def test_the_command_runs_from_the_command_line(self):
        done = subprocess.run([sys.executable, "-m", "aibom_engine", "packages", self.out.name], cwd=ROOT, capture_output=True, text=True, timeout=60)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn("AI packages found", done.stdout)
        bad = subprocess.run([sys.executable, "-m", "aibom_engine", "packages", self.out.name, "nosuchthing"], cwd=ROOT, capture_output=True, text=True, timeout=60)
        self.assertEqual(bad.returncode, 2)


if __name__ == "__main__":
    unittest.main()
