"""Score a list of findings against a labelled answer key.
Usage: python benchmark/score.py <repo-name>    (scores the four baseline scanners)"""
import json
import os
import re
import sys
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
from aibom_engine.adapters import LOADERS  # noqa: E402
from aibom_engine.finding import Finding  # noqa: E402


def norm(s):
    s = str(s).strip().lower().replace("_", "-")
    return re.sub(r"\s+", "", s)


def variants(name):
    n = norm(name)
    out = {n}
    for sep in (":", "/"):
        if sep in n:
            out.add(n.split(sep)[-1])
    return out


def truth_index(truth):
    idx = {}
    for i, t in enumerate(truth["items"]):
        for v in [t["name"]] + t.get("aliases", []):
            for x in variants(v):
                idx.setdefault(x, set()).add(i)
    return idx


def match(finding, idx):
    hits = set()
    for v in variants(finding.name):
        hits |= idx.get(v, set())
    return hits


def score(findings, truth):
    """Returns: found truth indexes, per-kind recall, unique reported items split into
    matched / extra_real / junk / unreviewed (secrets are ignored)."""
    idx = truth_index(truth)
    extra = {x for e in truth.get("extra_real", []) for x in variants(e["name"])}
    junk = {norm(j) for j in truth.get("junk", [])}
    found, seen = set(), {}
    for f in findings:
        if f.kind == "secret" or (truth.get("scope") == "models" and f.kind != "model"):
            continue
        key = (f.kind, norm(f.name))
        if key in seen:
            continue
        hit = match(f, idx)
        if hit:
            found |= hit
            seen[key] = ("matched", f)
        elif variants(f.name) & extra or any(r["file"] == f.file and r["from"] <= f.line <= r["to"] for r in truth.get("reference_ranges", [])):
            seen[key] = ("extra_real", f)
        elif norm(f.name) in junk or (f.kind == "vector_db" and any(norm(b["name"]) in variants(f.name) for b in truth.get("not_real", []))):
            seen[key] = ("junk", f)
        else:
            seen[key] = ("unreviewed", f)
    by_kind = {}
    for i, t in enumerate(truth["items"]):
        k = by_kind.setdefault(t["kind"], [0, 0])
        k[1] += 1
        if i in found:
            k[0] += 1
    return found, by_kind, seen


def summarize(seen):
    c = {"matched": 0, "extra_real": 0, "junk": 0, "unreviewed": 0}
    for v, _ in seen.values():
        c[v] += 1
    reported = sum(c.values())
    good = c["matched"] + c["extra_real"]
    prec = (good / reported * 100) if reported else 0
    return c, reported, prec


def load_run(run_dir, only=None, verified=False):
    """Read an engine run (merged.json) as findings.
    only:     keep items that have evidence in those file categories (old, pre-Verify way of cleaning)
    verified: keep only items the Verify step accepted, and point each at its first live place"""
    out = []
    for it in json.load(open(os.path.join(run_dir, "merged.json"), encoding="utf-8")):
        if verified and it.get("tier") == "rejected":
            continue
        ev = it["evidence"]
        if verified:
            ev = [e for e in ev if e.get("use") == "live"] or ev
        if only is not None:
            ev = [e for e in ev if e["category"] in only]
        if ev:
            out.append(Finding("engine", it["kind"], it["name"], ev[0]["file"], ev[0]["line"], "", ev[0]["category"], ev[0]["snippet"]))
    return out


def main():
    repo = sys.argv[1]
    args = [a for a in sys.argv[1:] if not a.startswith('--')]
    compact = '--compact' in sys.argv
    run_dir = args[1] if len(args) > 1 else None
    truth = json.load(open(os.path.join(HERE, "labels", repo + ".json"), encoding="utf-8"))
    base = os.path.join(HERE, "baseline", repo)
    root = os.path.join(os.environ.get("AIBOM_REPOS", "/tmp/mid"), repo)
    total = len(truth["items"])
    hard = {i for i, t in enumerate(truth["items"]) if t.get("hard")}
    if not compact:
        print(f"== {repo}: {total} answer-key items ({len(hard)} tagged hard) | {truth['status'][:60]}")
    allf, rows = [], []
    for tool, (fn, loader) in LOADERS.items():
        path = os.path.join(base, fn)
        if not os.path.exists(path):
            rows.append((tool, None, None, None))
            continue
        fs = loader(path, root)
        allf += fs
        rows.append((tool,) + score(fs, truth))
    rows.append(("all four",) + score(allf, truth))
    if run_dir:
        rows.append(("engine (before verify)",) + score(load_run(run_dir), truth))
        rows.append(("engine (verified)",) + score(load_run(run_dir, verified=True), truth))
    if compact:
        print(f"{repo}: {total} real models in the answer key\n")
        print(f"{'tool':22} {'found':>7} {'reported':>9} {'correct':>8} {'precision':>10}")
        for tool, found, by_kind, seen in rows:
            if tool in ("all four", "engine (before verify)"):
                continue
            if found is None:
                print(f"{tool:22} (did not finish)")
                continue
            c, rep, prec = summarize(seen)
            print(f"{tool:22} {len(found):>3}/{total:<3} {rep:>9} {c['matched'] + c['extra_real']:>8} {(format(prec, '.0f') + '%') if rep else '-':>10}")
        return rows
    print(f"{'tool':22} {'found':>9} {'easy':>8} {'hard':>8} {'reported':>9} {'correct':>8} {'junk':>5} {'unrev.':>7} {'precision':>10}")
    for tool, found, by_kind, seen in rows:
        if found is None:
            print(f"{tool:22} (no output: did not finish)")
            continue
        c, rep, prec = summarize(seen)
        eh = len(found & hard)
        print(f"{tool:22} {len(found):>4}/{total:<4} {len(found) - eh:>4}/{total - len(hard):<3} {eh:>4}/{len(hard):<3} {rep:>9} {c['matched'] + c['extra_real']:>8} {c['junk']:>5} {c['unreviewed']:>7} {prec:>9.0f}%")
    return rows


if __name__ == "__main__":
    main()
