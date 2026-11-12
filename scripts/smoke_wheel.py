"""Install-and-run check: build the wheel, install it in a clean virtualenv, and scan a small app with it.

This is the test that pytest cannot replace. pytest runs against the source checkout, where every data file is
present, so it cannot notice a file that is missing from the built package (the bug a normal `pip install .`
once had: the bundled database was not packaged and every scan crashed).

Usage:  python scripts/smoke_wheel.py            (needs the `build` package: python -m pip install build)
Exit 0 means a customer who installs the wheel can run a scan.
"""
import glob
import json
import os
import subprocess
import sys
import tempfile
import venv

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

APP = '''from openai import OpenAI

client = OpenAI()
client.chat.completions.create(model="gpt-4o-2024-08-06", messages=[])
'''


def run(cmd, **kw):
    print("$", " ".join(cmd))
    return subprocess.run(cmd, check=True, text=True, **kw)


def fail(message):
    print("SMOKE TEST FAILED:", message)
    sys.exit(1)


def main():
    with tempfile.TemporaryDirectory(prefix="aibom-smoke-") as tmp:
        dist = os.path.join(tmp, "dist")
        try:
            run([sys.executable, "-m", "build", "--wheel", "--outdir", dist, ROOT])
        except subprocess.CalledProcessError:
            fail("could not build the wheel (is the `build` package installed?)")
        wheels = glob.glob(os.path.join(dist, "*.whl"))
        if len(wheels) != 1:
            fail(f"expected exactly one wheel, found {wheels}")

        env_dir = os.path.join(tmp, "venv")
        venv.EnvBuilder(with_pip=True, clear=True).create(env_dir)
        bindir = os.path.join(env_dir, "Scripts" if os.name == "nt" else "bin")
        python = os.path.join(bindir, "python.exe" if os.name == "nt" else "python")
        run([python, "-m", "pip", "install", "--quiet", "--disable-pip-version-check", wheels[0]])

        # Run from a different folder so nothing is picked up from the source checkout by accident.
        work = os.path.join(tmp, "work")
        app = os.path.join(work, "app")
        out = os.path.join(work, "out")
        os.makedirs(app)
        with open(os.path.join(app, "main.py"), "w", encoding="utf-8") as fh:
            fh.write(APP)

        aibom = os.path.join(bindir, "aibom.exe" if os.name == "nt" else "aibom")
        if not os.path.exists(aibom):
            fail("the `aibom` command was not installed")
        done = subprocess.run([aibom, "scan", app, "--out", out, "--quiet"], cwd=work, text=True, capture_output=True)
        print(done.stdout + done.stderr)
        if done.returncode != 0:
            fail(f"`aibom scan` exited with {done.returncode}")

        # `aibom` with no arguments opens the guided menu in a terminal; here there is none, so it must print the help
        # and exit cleanly instead of waiting for a key. questionary must have come in as a dependency of the wheel.
        bare = subprocess.run([aibom], cwd=work, text=True, capture_output=True, stdin=subprocess.DEVNULL, timeout=120)
        if bare.returncode != 0 or "usage:" not in bare.stdout:
            fail(f"`aibom` without a terminal should print the help and exit 0 (exit {bare.returncode}): {bare.stdout[:200]} {bare.stderr[:200]}")
        menu = run([python, "-c", "import questionary, aibom_engine.interactive as i; print(i.Prompter.KEYS)"], capture_output=True, cwd=work)
        if "Esc" not in menu.stdout:
            fail("the guided menu could not be imported from the installed wheel")
        listed = subprocess.run([aibom, "packages", out], cwd=work, text=True, capture_output=True)
        if listed.returncode != 0 or "openai" not in listed.stdout:
            fail(f"`aibom packages` did not list the openai package (exit {listed.returncode}): {listed.stdout[:200]} {listed.stderr[:200]}")

        vulns = subprocess.run([aibom, "vulns", out], cwd=work, text=True, capture_output=True, stdin=subprocess.DEVNULL)
        if vulns.returncode != 0 or "Affected is not the same as exploitable" not in vulns.stdout or "\x1b" in vulns.stdout:
            fail(f"`aibom vulns` should print plain text and exit 0 (exit {vulns.returncode}): {vulns.stdout[:200]} {vulns.stderr[:200]}")
        version = subprocess.run([aibom, "--version"], cwd=work, text=True, capture_output=True)
        if version.returncode != 0 or "vulnerability data:" not in version.stdout:
            fail(f"`aibom --version` did not print the version and data dates: {version.stdout[:200]} {version.stderr[:200]}")
        colour = run([python, "-c", "import rich; from aibom_engine import screens, ui; print('rich', ui.pretty())"], capture_output=True, cwd=work)
        if "rich" not in colour.stdout:
            fail("the terminal screens could not be imported from the installed wheel (rich missing?)")

        # The installed package must contain the database and the dictionary.
        probe = run([python, "-c", "import aibom_engine, os; print(os.path.dirname(aibom_engine.__file__))"],
                    capture_output=True, cwd=work)
        pkg = probe.stdout.strip()
        for name in ("knowledge/ai_db.json", "knowledge/model_names.json", "rules/calls.yaml"):
            if not os.path.exists(os.path.join(pkg, *name.split("/"))):
                fail(f"{name} is missing from the installed package")
        with open(os.path.join(out, "packages.json"), encoding="utf-8") as fh:
            levels = {c["name"]: c["evidence_level"] for c in json.load(fh).get("packages", [])}
        if levels.get("openai") != "called":
            fail(f"the scan did not find the OpenAI() call; package levels were {levels}")

        with open(os.path.join(out, "aibom.cdx.json"), encoding="utf-8") as fh:
            bom = json.load(fh)
        names = [c.get("name") for c in bom.get("components", [])]
        if "gpt-4o-2024-08-06" not in names:
            fail(f"the scan did not find the model in the app; components were {names}")
        with open(os.path.join(out, "report.md"), encoding="utf-8") as fh:
            text = fh.read()
            if "gpt-4o-2024-08-06" not in text:
                fail("report.md does not mention the model")
            if "## AI packages" not in text:
                fail("report.md has no AI packages section")
        libraries = [c for c in bom.get("components", []) if c.get("type") == "library" and c.get("name") == "openai"]
        if not libraries or not libraries[0].get("purl", "").startswith("pkg:pypi/openai"):
            fail("the AI-BOM has no openai library component with a purl")
        if "OpenAI API" not in [s.get("name") for s in bom.get("services", [])]:
            fail("the AI-BOM has no OpenAI API service (the providers rules are not packaged?)")
        if not os.path.exists(os.path.join(out, "packages.csv")):
            fail("packages.csv was not written")
        print("SMOKE TEST PASSED: wheel installs, `aibom scan` runs, database is packaged.")


if __name__ == "__main__":
    main()
