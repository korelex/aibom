"""Clones the benchmark repos at their pinned commits (works on Windows, Mac and Linux).
Usage: python scripts/fetch_repos.py [--dir repos] [name ...]     (no names = all of them)"""
import argparse
import json
import os
import subprocess
import sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
p = argparse.ArgumentParser()
p.add_argument("--dir", default="repos")
p.add_argument("names", nargs="*")
a = p.parse_args()
os.makedirs(a.dir, exist_ok=True)
for r in json.load(open(os.path.join(ROOT, "benchmark", "repos.json"), encoding="utf-8"))["repos"]:
    if a.names and r["name"] not in a.names:
        continue
    d = os.path.join(a.dir, r["name"])
    if not os.path.isdir(d):
        subprocess.run(["git", "clone", "-q", r["url"], d], check=True)
    subprocess.run(["git", "-C", d, "checkout", "-q", r["commit"]], check=True)
    print("ready:", d, r["commit"][:10])
