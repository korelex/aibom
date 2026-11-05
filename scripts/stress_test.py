"""Scans a list of links exactly the way a live demo would, and records time and outcome.
Needs internet and git. Usage: python scripts/stress_test.py [--out benchmark/stress_test.md]
This checks that nothing crashes and that it is fast enough. It does NOT measure accuracy."""
import argparse
import os
import re
import subprocess
import sys
import time

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
CASES = [
    ("openai/openai-cookbook", "Python + notebooks, large"),
    ("huggingface/transformers", "Python, very large, thousands of model names"),
    ("langchain-ai/langchain", "Python monorepo"),
    ("ollama/ollama", "Go, large"),
    ("microsoft/semantic-kernel", "C#, very large"),
    ("BerriAI/litellm", "Python, the source of our dictionary"),
    ("pallets/flask", "Python, no AI at all"),
    ("octocat/Hello-World", "tiny, almost no code"),
    ("https://github.com/langchain-ai/open_deep_research/tree/main/src/legacy", "link to one folder"),
    ("https://github.com/octocat/this-repo-does-not-exist-12345", "broken link (should fail politely)"),
    ("not a link", "nonsense input (should fail politely)"),
]
p = argparse.ArgumentParser()
p.add_argument("--out", default=os.path.join(ROOT, "benchmark", "stress_test.md"))
p.add_argument("--max-seconds", default="120")
a = p.parse_args()
rows = []
for link, what in CASES:
    t = time.time()
    try:
        r = subprocess.run([sys.executable, "-m", "aibom_engine", "scan", link, "--out", os.path.join(ROOT, "runs", "_stress"), "--quiet", "--max-seconds", a.max_seconds],
                           cwd=ROOT, capture_output=True, text=True, timeout=600)
        out, code = r.stdout, r.returncode
        err = r.stderr
    except subprocess.TimeoutExpired:
        out, code, err = "", -9, "timed out after 600 s"
    wall = time.time() - t
    m = re.search(r"Scan finished in ([\d.]+)s", out)
    used = re.search(r"(\d+)\s+models used directly", out)
    listed = re.search(r"(\d+)\s+more only listed", out)
    left = re.search(r"(\d+)\s+names left out", out)
    note = re.search(r"Note: (.*)", out)
    status = "ok" if code == 0 else ("polite error" if code == 2 and "Traceback" not in err else "CRASH")
    detail = (err.strip().splitlines() or [""])[-1][:110] if code != 0 else ""
    rows.append((link.replace("https://github.com/", ""), what, status, f"{wall:.0f}", m.group(1) if m else "-", used.group(1) if used else "0", listed.group(1) if listed else "0", left.group(1) if left else "0", (note.group(1)[:60] if note else detail)))
    print(f"{link[:58]:58} {status:12} wall {wall:5.0f}s scan {rows[-1][4]:>6}s used {rows[-1][5]:>4} listed {rows[-1][6]:>4} left out {rows[-1][7]:>4}  {rows[-1][8]}", flush=True)
lines = ["# Stress test: scanning from links", "", "Checks that it does not crash and is fast enough. It does not measure accuracy (no answer keys for these repos).", "",
         "| Link | What it tests | Result | Total seconds | Scan seconds | Used directly | Only listed | Left out | Note |", "|---|---|---|---|---|---|---|---|---|"]
lines += ["| " + " | ".join(r) + " |" for r in rows]
with open(a.out, "w", encoding="utf-8") as f:
    f.write("\n".join(lines) + "\n")
import shutil
shutil.rmtree(os.path.join(ROOT, "runs", "_stress"), ignore_errors=True)  # clean up the temporary results
print("saved", a.out)
