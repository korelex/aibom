"""Score one engine run (merged.json) against a hand-written answer key in benchmark/labels/.

Only models are scored: that is what this engine detects. Some keys also list frameworks, providers or tools for
future work; those items are not counted.

Recall:    answer-key models the engine reported / answer-key models.
Precision: reported names that are correct / reported names. A reported name counts as correct when it is in the key,
           or was labelled real afterwards (`extra_real`, `reference_ranges`). A name nobody has labelled yet
           ("unreviewed") counts as NOT correct, so precision can be understated but never inflated.

Usage:  python benchmark/score.py <repo-name> <run-folder>
"""
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def norm(s):
    return re.sub(r"\s+", "", str(s).strip().lower().replace("_", "-"))


def variants(name):
    n = norm(name)
    out = {n}
    for sep in (":", "/"):
        if sep in n:
            out.add(n.split(sep)[-1])
    return out


def load_key(repo):
    with open(os.path.join(HERE, "labels", repo + ".json"), encoding="utf-8") as fh:
        return json.load(fh)


def load_run(run_dir):
    """The names the engine reports: every item the Verify step kept, pointed at its first live place."""
    with open(os.path.join(run_dir, "merged.json"), encoding="utf-8") as fh:
        items = json.load(fh)
    out = []
    for it in items:
        if it.get("tier") == "rejected":
            continue
        ev = [e for e in it["evidence"] if e.get("use") == "live"] or it["evidence"]
        if ev:
            out.append({"kind": it["kind"], "name": it["name"], "file": ev[0]["file"], "line": ev[0]["line"]})
    return out


def score(reported, key):
    models = [t for t in key["items"] if t["kind"] == "model"]
    index = {}
    for i, t in enumerate(models):
        for v in [t["name"]] + t.get("aliases", []):
            for x in variants(v):
                index.setdefault(x, set()).add(i)
    extra = {x for e in key.get("extra_real", []) for x in variants(e["name"])}
    junk = {norm(j) for j in key.get("junk", [])}
    ranges = key.get("reference_ranges", [])
    found, verdicts = set(), {}
    for f in reported:
        if f["kind"] != "model":
            continue
        k = (f["kind"], norm(f["name"]))
        if k in verdicts:
            continue
        hit = set().union(*(index.get(v, set()) for v in variants(f["name"])))
        if hit:
            found |= hit
            verdicts[k] = "matched"
        elif variants(f["name"]) & extra or any(r["file"] == f["file"] and r["from"] <= f["line"] <= r["to"] for r in ranges):
            verdicts[k] = "extra_real"
        elif norm(f["name"]) in junk:
            verdicts[k] = "junk"
        else:
            verdicts[k] = "unreviewed"
    counts = {v: sum(1 for x in verdicts.values() if x == v) for v in ("matched", "extra_real", "junk", "unreviewed")}
    total = len(models)
    reported_n = len(verdicts)
    correct = counts["matched"] + counts["extra_real"]
    return {
        "key_models": total, "found": len(found), "recall": len(found) / total if total else None,
        "reported": reported_n, "correct": correct, "precision": correct / reported_n if reported_n else None,
        **counts, "unreviewed_names": sorted(n for (_, n), v in verdicts.items() if v == "unreviewed"),
    }


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    r = score(load_run(sys.argv[2]), load_key(sys.argv[1]))
    print(json.dumps(r, indent=1))


if __name__ == "__main__":
    main()
