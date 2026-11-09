"""Run the benchmark: clone each labelled repo at its pinned commit, scan it with this checkout, and score it.

Usage:  python benchmark/run.py [--repos DIR] [--score-only] [name ...]   (no names = every repo in benchmark/repos.json)
Clones go to DIR (default: repos/), scans to runs/benchmark/<name>/. Needs git and internet for the first clone.
Prints a table and writes runs/benchmark/results.json.
"""
import argparse
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)
from aibom_engine.pipeline import run as scan  # noqa: E402
import score as S  # noqa: E402

ROUND3 = ["fragments", "llm", "OpenAI", "anthropic-quickstarts", "browser-use"]


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--repos", default=os.path.join(ROOT, "repos"))
    p.add_argument("--score-only", action="store_true", help="score the existing runs in runs/benchmark/ without cloning or scanning")
    p.add_argument("names", nargs="*")
    a = p.parse_args()
    with open(os.path.join(HERE, "repos.json"), encoding="utf-8") as fh:
        repos = [r for r in json.load(fh)["repos"] if not a.names or r["name"] in a.names]
    if not a.score_only:
        subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "fetch_repos.py"), "--dir", a.repos] + [r["name"] for r in repos],
                       check=True)

    out_root = os.path.join(ROOT, "runs", "benchmark")
    results = {}
    print(f"\n{'repo':34} {'key':>5} {'found':>13} {'reported':>9} {'correct':>14} {'unreviewed':>11}")
    for r in repos:
        key = S.load_key(r["name"])
        out = os.path.join(out_root, r["name"])
        if not a.score_only:
            scan(os.path.join(a.repos, r["name"]), out, app=r["name"], max_seconds=600)
        s = S.score(S.load_run(out), key)
        results[r["name"]] = s
        if not s["key_models"]:
            print(f"{r['name']:34} {0:>5} {'-':>13} {s['reported']:>9} {'-':>14} {s['unreviewed']:>11}   "
                  f"(no models in the key: {s['junk']} reported name(s) wrong)")
            continue
        prec = f"{s['correct']} ({s['precision']:.0%})" if s["reported"] else "-"
        print(f"{r['name']:34} {s['key_models']:>5} {s['found']:>5} ({s['recall']:>4.0%}) {s['reported']:>9} {prec:>14} {s['unreviewed']:>11}")
    scored = [results[n] for n in ROUND3 if n in results]
    if len(scored) == len(ROUND3):
        rec = sum(s["recall"] for s in scored) / len(scored)
        prec = sum(s["precision"] for s in scored) / len(scored)
        print(f"\nround-3 repos, average: found {rec:.0%} of the key models; {prec:.0%} of reported names correct "
              f"(names not yet labelled count as wrong)")
    os.makedirs(out_root, exist_ok=True)
    with open(os.path.join(out_root, "results.json"), "w", encoding="utf-8") as fh:
        json.dump(results, fh, indent=1, sort_keys=True)


if __name__ == "__main__":
    main()
