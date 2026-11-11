"""The guided menu: `aibom` with no arguments, in a terminal.

The menu calls the same functions as the commands (`scan`, `show`, `packages`, `explain`, `report`, `rebuild`), so what it
shows can never differ from what they show, and after every action it prints the command that does the same thing without
the menu. It only opens when both input and output are a terminal; anywhere else (a script, a pipe, CI) `aibom` prints its
help, so nothing can hang waiting for a key.

Keys: arrow keys move, Enter chooses, Esc goes back one step (at the main menu it quits), Ctrl-C stops. Ctrl-C while an
action runs (a scan) stops that action and returns to the menu; at a question it ends aibom, like everywhere else.
"""
import argparse
import os
import subprocess
import sys
import time

from . import __version__
from . import cli
from .display import build_rows
from .report import package_rows
from .source import SourceError, parse

BACK = object()  # the answer to a question when Esc is pressed


def is_interactive():
    """Whether a person is at a terminal: input and output must both be one."""
    try:
        return bool(sys.stdin and sys.stdin.isatty() and sys.stdout and sys.stdout.isatty())
    except (AttributeError, ValueError):
        return False


def quote(text):
    """A command-line argument as the person's own shell needs it, so the printed command can be pasted as it is."""
    text = str(text)
    if text and not any(c in text for c in " \t\"'&|<>()^;$`*?[]{}!#~"):
        return text
    if os.name == "nt":
        return subprocess.list2cmdline([text])
    import shlex
    return shlex.quote(text)


def command_line(*parts):
    return " ".join([cli.command()] + [quote(p) for p in parts])


def short_path(path):
    """The path as the person would type it: relative to the current folder when that is shorter."""
    try:
        rel = os.path.relpath(path)
    except ValueError:  # another drive on Windows
        return path
    return rel if len(rel) < len(path) and not rel.startswith("..") else path


class Prompter:
    """Asks the questions, with questionary. Esc answers BACK; Ctrl-C raises KeyboardInterrupt."""
    KEYS = "(arrow keys to move, Enter to choose, Esc to go back)"

    def __init__(self, input=None, output=None):
        self._io = {k: v for k, v in (("input", input), ("output", output)) if v is not None}

    def _ask(self, question):
        from prompt_toolkit.key_binding import KeyBindings, merge_key_bindings
        keys = KeyBindings()

        @keys.add("escape", eager=True)
        def _back(event):
            event.app.exit(result=BACK)
        question.application.key_bindings = merge_key_bindings([question.application.key_bindings, keys])
        question.application.ttimeoutlen = 0.15  # how long to wait before a lone Esc counts as Esc (the default, 0.5 s, feels slow)
        return question.unsafe_ask()  # unlike ask(), Ctrl-C raises KeyboardInterrupt: the caller decides what it means

    def select(self, message, choices, search=False):
        """choices: [(title, value)]. With search=True the person can type to filter a long list."""
        import questionary
        items = [questionary.Choice(title, value=value) for title, value in choices]
        instruction = "(type to filter, arrow keys to move, Enter to choose, Esc to go back)" if search else self.KEYS
        return self._ask(questionary.select(message, choices=items, instruction=instruction, use_search_filter=search,
                                            use_jk_keys=not search, **self._io))

    def text(self, message, default="", validate=None):
        """A line of text. Enter on an empty line means `default`, which is shown in the question, not typed for the person."""
        import questionary
        check = (lambda t: validate(t or default)) if validate else None
        answer = self._ask(questionary.text(message, validate=check, instruction="(Esc to go back) ", **self._io))
        if answer is BACK:
            return BACK
        return answer.strip() or default


def check_source(text):
    """True, or the reason a folder or link cannot be scanned (for the question to show)."""
    if not str(text).strip():
        return "Type a folder or a link."
    try:
        parse(text)
    except SourceError as e:
        return str(e)
    return True


def check_run(text):
    path = str(text).strip().strip("\"'")
    if os.path.isfile(os.path.join(path, "manifest.json")) and os.path.isfile(os.path.join(path, "merged.json")):
        return True
    return "There is no finished aibom scan in that folder (it holds manifest.json and merged.json)."


def find_runs(runs_dir="runs", limit=12):
    """Finished scans the person can open: the folders under runs/ and under the current folder, newest first."""
    found, seen = [], set()
    for base in (runs_dir, "."):
        try:
            names = sorted(os.listdir(base))
        except OSError:
            continue
        for name in names:
            d = os.path.join(base, name)
            marker = os.path.join(d, "manifest.json")
            if os.path.isfile(marker) and os.path.isfile(os.path.join(d, "merged.json")) and os.path.abspath(d) not in seen:
                seen.add(os.path.abspath(d))
                found.append((os.path.getmtime(marker), os.path.normpath(d)))
    return [d for _, d in sorted(found, reverse=True)[:limit]]


def describe_run(run_dir):
    """One line about a finished scan: its app, what it found and when."""
    try:
        info = cli.load(run_dir, "manifest.json")
    except (SourceError, ValueError, OSError):
        return run_dir
    app = info.get("app") or os.path.basename(run_dir)
    pk = (info.get("packages") or {}).get("ai_packages")
    when = time.strftime("%Y-%m-%d", time.localtime(os.path.getmtime(os.path.join(run_dir, "manifest.json"))))
    return "%s: %d models%s, scanned %s (%s)" % (app, info.get("models_used", 0), ", %d AI packages" % pk if pk else "", when, run_dir)


class Menu:
    def __init__(self, prompter=None, runs_dir="runs", say=print):
        self.ask = prompter or Prompter()
        self.runs_dir = runs_dir
        self.say = say

    # -- the main menu ---------------------------------------------------------------------------------------------------
    def run(self):
        self.banner()
        while True:
            runs = find_runs(self.runs_dir)
            choices = [("Scan a folder or a GitHub link", "scan")]
            if runs:
                choices.append(("Look at a scan I already made (%d found)" % len(runs), "open"))
            choices.append(("Quit", "quit"))
            pick = self.ask.select("What do you want to do?", choices)
            if pick is BACK or pick == "quit":
                return 0
            run_dir = self.scan() if pick == "scan" else self.choose_run(runs)
            if run_dir:
                self.scan_menu(run_dir)

    def banner(self):
        dates = ""
        try:
            from .db import load_db
            meta = load_db().get("meta") or {}
            dates = " Data: models %s, vulnerabilities %s." % (meta.get("built", "?"), (meta.get("vulnerabilities") or {}).get("fetched", "?"))
        except Exception:
            pass
        self.say("aibom %s: finds the AI models and AI packages in an app, and proves each with a line of code.%s" % (__version__, dates))
        self.say("After every step it shows the command that does the same without this menu.\n")

    # -- scanning --------------------------------------------------------------------------------------------------------
    def scan(self):
        """Ask what to scan, run the scan, and return the folder with the results (None when it was cancelled or failed)."""
        while True:
            source = self.ask.text("Folder or GitHub link to scan (Enter = this folder, or type a link such as owner/repo):", default=".", validate=check_source)
            if source is BACK:
                return None
            src = parse(source)
            out = os.path.join(self.runs_dir, src["name"])
            if os.path.isfile(os.path.join(out, "manifest.json")):
                choice = self.ask.select("A scan is already saved in %s." % out, [
                    ("Scan again and replace it", "replace"), ("Look at the saved scan instead", "open"), ("Choose another folder or link", "again")])
                if choice is BACK or choice == "again":
                    continue
                if choice == "open":
                    return out
            args = argparse.Namespace(source=source, out=out, finders="dictionary,context,shapes", max_seconds=120, keep=False,
                                      open=False, quiet=False, debug=False)
            ok = self.action(lambda: cli.do_scan(args), command_line("scan", source) if out == os.path.join("runs", src["name"]) else command_line("scan", source, "--out", out))
            return out if ok else None

    def choose_run(self, runs):
        choices = [(describe_run(r), r) for r in runs] + [("Type the path to a scan folder", "path")]
        pick = self.ask.select("Which scan?", choices)
        if pick is BACK:
            return None
        if pick == "path":
            path = self.ask.text("Folder of the finished scan:", validate=check_run)
            return None if path is BACK else os.path.normpath(path.strip("\"'"))
        return pick

    # -- looking at a scan -----------------------------------------------------------------------------------------------
    def scan_menu(self, run_dir):
        """Everything the person can do with one finished scan. Esc goes back to the main menu."""
        while True:
            try:
                info = cli.load(run_dir, "manifest.json")
                items = cli.load(run_dir, "merged.json")
            except (SourceError, ValueError, OSError) as e:
                self.say("\nProblem: %s" % e)
                return
            app = info.get("app") or os.path.basename(run_dir)
            rows = build_rows(items)
            models = [r["name"] for r in rows["used"] + rows["listed"]]
            try:
                packages = cli.load_packages(run_dir)
            except SourceError:
                packages = None  # a scan from before AI packages were read: the package entries are not offered
            names = sorted({r["name"] for r in package_rows(packages)}) if packages else []
            choices = [("Open the report in my browser", "report"), ("List the AI models", "models")]
            if names:
                choices.append(("List the AI packages and their vulnerabilities", "packages"))
            if models:
                choices.append(("Why is a model in the result?", "explain"))
            if names:
                choices.append(("Look closer at one AI package", "package"))
            choices += [("See the names that were left out, and why", "left"), ("Rebuild the report and spreadsheets", "rebuild"),
                        ("Back to the main menu", "back")]
            pick = self.ask.select("%s: what do you want to see?" % app, choices)
            if pick is BACK or pick == "back":
                return
            r = short_path(run_dir)
            if pick == "report":
                self.action(lambda: cli.open_report(run_dir), command_line("report", r))
            elif pick == "models":
                self.action(lambda: cli.show(run_dir, 20), command_line("show", r))
            elif pick == "packages":
                self.action(lambda: cli.packages_view(run_dir), command_line("packages", r))
            elif pick == "left":
                self.action(lambda: cli.show(run_dir, 20, False, True), command_line("show", r, "--left-out"))
            elif pick == "rebuild":
                self.action(lambda: self.rebuild(run_dir), command_line("rebuild", r))
            elif pick == "explain":
                model = self.ask.select("Which model?", [(m, m) for m in models], search=True)
                if model is not BACK:
                    self.action(lambda: cli.explain(run_dir, model), command_line("explain", r, model))
            elif pick == "package":
                package = self.ask.select("Which package?", [(n, n) for n in names], search=True)
                if package is not BACK:
                    self.action(lambda: cli.packages_view(run_dir, package), command_line("packages", r, package))

    @staticmethod
    def rebuild(run_dir):
        app, linked = cli.rebuild(run_dir)
        print("rebuilt %-34s %s" % (app, "with links to the code" if linked else "(no web links: local folder)"))

    # -- running things --------------------------------------------------------------------------------------------------
    def action(self, fn, equivalent):
        """Run something that prints. Its failure never ends the menu, and the equivalent command is always shown."""
        ok = False
        try:
            fn()
            ok = True
        except SourceError as e:
            self.say("\nProblem: %s" % e)
        except KeyboardInterrupt:  # Ctrl-C while it runs stops it and returns here; at a question it ends aibom
            self.say("\nStopped.")
        except Exception as e:  # keep the menu alive; the same command, run on its own, shows the details
            self.say("\nSomething went wrong (%s: %s)." % (type(e).__name__, str(e)[:160]))
        self.say("\n  Same thing without the menu:  %s\n" % equivalent)
        return ok


def run():
    """Open the menu. Returns the exit code."""
    try:
        import questionary  # noqa: F401
    except ImportError:
        print("The guided menu needs the 'questionary' package: python -m pip install questionary\n"
              "Everything else works without it; run  %s --help  to see the commands." % cli.command(), file=sys.stderr)
        return 1
    return Menu().run()
