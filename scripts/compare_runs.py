"""Compares what two engine versions found: same names, same tiers?
Usage: python scripts/compare_runs.py save SNAPSHOT.json     (save what runs/ holds now)
       python scripts/compare_runs.py diff SNAPSHOT.json     (compare runs/ with a saved snapshot)"""
import json
import os
import sys

RUNS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "runs")


def snap():
    out = {}
    for repo in sorted(os.listdir(RUNS)):
        p = os.path.join(RUNS, repo, "merged.json")
        if os.path.exists(p):
            out[repo] = sorted([i["name"], i.get("tier", "")] for i in json.load(open(p, encoding="utf-8")))
    return out


mode, path = sys.argv[1], sys.argv[2]
if mode == "save":
    json.dump(snap(), open(path, "w", encoding="utf-8"))
    print("saved", path, "for", len(snap()), "repos")
else:
    old, new = json.load(open(path, encoding="utf-8")), snap()
    same = True
    for repo in sorted(set(old) | set(new)):
        a = {tuple(x) for x in old.get(repo, [])}
        b = {tuple(x) for x in new.get(repo, [])}
        if a != b:
            same = False
            print(f"{repo}: {len(a - b)} only before, {len(b - a)} only now")
            for x in sorted(a - b)[:5]: print("   before only:", x)
            for x in sorted(b - a)[:5]: print("   now only:   ", x)
        else:
            print(f"{repo}: identical ({len(a)} names with tiers)")
    print("\nRESULT:", "identical to the snapshot" if same else "DIFFERENCES FOUND")
