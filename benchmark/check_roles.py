"""Checks the used/listed label against the role written in each answer key.
Every model the key calls a default or a direct use must be 'used'. Exits with 1 if one is wrongly 'listed'.
Usage: python benchmark/check_roles.py"""
import collections
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import score as S  # noqa: E402

wrong, tot = [], collections.Counter()
for repo in sorted(os.listdir(os.path.join(HERE, "..", "runs"))):
    kp = os.path.join(HERE, "labels", repo + ".json")
    if not os.path.exists(kp):
        continue
    with open(kp, encoding="utf-8") as f:
        truth = json.load(f)
    with open(os.path.join(HERE, "..", "runs", repo, "merged.json"), encoding="utf-8") as f:
        items = [i for i in json.load(f) if i["tier"] != "rejected"]
    idx = {}
    for it in items:
        for v in S.variants(it["name"]):
            idx[v] = it
    for k in truth["items"]:
        if k["kind"] != "model" or k.get("role") not in ("default", "used"):
            continue
        hit = next((idx[v] for name in [k["name"]] + k.get("aliases", []) for v in S.variants(name) if v in idx), None)
        if hit:
            tot[hit["role"]] += 1
            if hit["role"] == "listed":
                wrong.append((repo, k["name"]))
    print(f"{repo:34} used {sum(1 for i in items if i['role'] == 'used'):>4}   only listed {sum(1 for i in items if i['role'] == 'listed'):>4}")
print(f"\nkey items marked default or direct use: {tot['used']} labelled used, {tot['listed']} wrongly labelled listed")
for w in wrong:
    print("  WRONG:", w)
sys.exit(1 if wrong else 0)
