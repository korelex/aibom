"""Run this first:  python scripts/setup_check.py
It checks that everything needed for the demo is in place and tells you what to fix."""
import importlib
import os
import shutil
import subprocess
import sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
ok = True


def line(good, text, fix=""):
    global ok
    ok = ok and good
    print(("[ok]   " if good else "[FIX]  ") + text + ("" if good else "   -> " + fix))


line(sys.version_info >= (3, 9), f"Python {sys.version.split()[0]}", "install Python 3.9 or newer from python.org")
for mod, pkg in (("cyclonedx", "cyclonedx-python-lib[validation]"), ("jsonschema", "jsonschema")):
    try:
        importlib.import_module(mod)
        line(True, f"package {pkg}")
    except ImportError:
        line(False, f"package {pkg}", "python -m pip install -r requirements.txt")
line(shutil.which("git") is not None, "git is installed (needed once, to download the demo app)", "install git from git-scm.com")
for f in ("aibom_engine/cli.py", "knowledge/model_names.json", "benchmark/labels/go-openai.json", "runs/go-openai/merged.json"):
    line(os.path.exists(os.path.join(ROOT, f)), f"file {f}", "re-extract the zip: a file is missing")
if ok:
    r = subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", os.path.join(ROOT, "tests")], capture_output=True, text=True, cwd=ROOT)
    tail = (r.stderr.strip().splitlines() or ["?"])[-1]
    line(r.returncode == 0, f"automated tests: {tail}", "run: python -m unittest discover -s tests -v")
print("\nAll set. You can record the demo now." if ok else "\nFix the lines marked [FIX] and run this again.")
sys.exit(0 if ok else 1)
