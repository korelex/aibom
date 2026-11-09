"""Runs the engine on every benchmark repo and saves the results in runs/<name>.
Usage: python scripts/run_all.py [--repos DIR]     (DIR holds the clones; default repos/, the folder scripts/fetch_repos.py fills)"""
import argparse
import json
import os
import sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, ROOT)
from aibom_engine.pipeline import run  # noqa: E402

p = argparse.ArgumentParser()
p.add_argument("--repos", default="repos")
a = p.parse_args()
for r in json.load(open(os.path.join(ROOT, "benchmark", "repos.json"), encoding="utf-8"))["repos"]:
    d = os.path.join(a.repos, r["name"])
    if not os.path.isdir(d):
        print("missing clone, skipped:", d)
        continue
    res = run(d, os.path.join(ROOT, "runs", r["name"]))
    print(f"{r['name']:34} {res['items']:>4} models kept, {res['rejected']:>3} left out, valid={res['valid']}, {res['seconds']}s")
