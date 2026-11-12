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
            if "gpt-4o-2024-08-06" not in fh.read():
                fail("report.md does not mention the model")
        print("SMOKE TEST PASSED: wheel installs, `aibom scan` runs, database is packaged.")


if __name__ == "__main__":
    main()
