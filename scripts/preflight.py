"""Run this 10 minutes before the meeting:  python scripts/preflight.py
It checks the tools, runs a quick self-test, and tells you whether scanning from a link will work right now."""
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, ROOT)
good = True


def line(ok, text, fix=""):
    global good
    good = good and ok
    print(("[ok]   " if ok else "[FIX]  ") + text + ("" if ok else "   -> " + fix))


line(sys.version_info >= (3, 9), f"Python {sys.version.split()[0]}", "install Python 3.9 or newer")
try:
    import cyclonedx, jsonschema  # noqa: F401,E401
    line(True, "the two Python packages are installed")
except ImportError:
    line(False, "the two Python packages", "python -m pip install -r requirements.txt")
    sys.exit(1)
from aibom_engine.pipeline import run  # noqa: E402

with tempfile.TemporaryDirectory() as d, tempfile.TemporaryDirectory() as out:
    os.makedirs(os.path.join(d, "app"))
    with open(os.path.join(d, "app", "config.py"), "w", encoding="utf-8") as f:
        f.write('DEFAULT_MODEL = "gpt-4o-mini"\n# old: "gpt-4.1-nano"\n')
    r = run(d, out, app="selftest")
    line(r["valid"] and r["items"] == 1 and r["rejected"] == 1, "self-test: finds 1 model, leaves out 1 commented-out name, writes a valid AI-BOM", "re-extract the zip and run again")
saved = os.path.join(ROOT, "runs", "open_deep_research", "report.html")
line(os.path.exists(saved), "saved results for plan B (runs/open_deep_research/report.html)", "re-extract the zip")
if shutil.which("git") is None:
    line(False, "git is installed (needed to scan a link)", "install git from git-scm.com; until then scan folders you already have")
else:
    try:
        env = dict(os.environ, GIT_TERMINAL_PROMPT="0")
        ok = subprocess.run(["git", "ls-remote", "https://github.com/octocat/Hello-World", "HEAD"], capture_output=True, timeout=20, env=env).returncode == 0
    except subprocess.TimeoutExpired:
        ok = False
    line(ok, "internet and GitHub are reachable: scanning from a link will work", "no internet: use plan B (scan a folder, or show the saved results in runs/)")
print("\nReady for the meeting." if good else "\nFix the lines marked [FIX] first.")
print("Live command:    python -m aibom_engine scan https://github.com/OWNER/REPO --open")
print("Plan B:          python -m aibom_engine show runs/open_deep_research     (saved results, no internet needed)")
sys.exit(0 if good else 1)
