"""One-screen summary: engine vs the best existing tool, per app, in two honest groups."""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))
import score as S  # noqa: E402
from aibom_engine.adapters import LOADERS  # noqa: E402

FRESH = ["go-openai", "azure-search-openai-demo-csharp", "ollama-js", "open-canvas"]
USED_FOR_FIXES = ["open_deep_research", "langchain4j-examples", "bedrock-claude-chat", "azure-search-openai-demo"]
NO_MODELS = "private-gpt"
RUNS = os.path.join(HERE, "..", "runs")
FROZEN = os.path.join(HERE, "round2_frozen")   # engine v0.2.0 outputs on the fresh apps, saved before any further change


def row(repo, runs=RUNS):
    truth = json.load(open(os.path.join(HERE, "labels", repo + ".json"), encoding="utf-8"))
    n = len(truth["items"])
    found, _, seen = S.score(S.load_run(os.path.join(runs, repo), verified=True), truth)
    c, rep, prec = S.summarize(seen)
    best = ("-", 0)
    for tool, (fn, loader) in LOADERS.items():
        p = os.path.join(HERE, "baseline", repo, fn)
        if os.path.exists(p):
            f2, _, _ = S.score(loader(p, os.path.join("/x", repo)), truth)
            if len(f2) > best[1]:
                best = (tool, len(f2))
    return n, len(found), prec, best


def table(title, repos, runs=RUNS):
    print(title)
    print(f"{'app':34} {'real models':>11} {'engine finds':>14} {'engine correct':>15} {'best other tool finds':>26}")
    er, ep, br = [], [], []
    for repo in repos:
        n, f, prec, best = row(repo, runs)
        er.append(f / n * 100); ep.append(prec); br.append(best[1] / n * 100)
        print(f"{repo:34} {n:>11} {f:>7} ({f / n * 100:>3.0f}%) {prec:>13.0f}% {best[0] + ': ' + str(best[1]) + ' (' + format(best[1] / n * 100, '.0f') + '%)':>26}")
    m = lambda xs: sum(xs) / len(xs)
    print(f"{'average':34} {'':>11} {m(er):>13.0f}% {m(ep):>14.0f}% {m(br):>25.0f}%\n")
    return m(er), m(ep), m(br)


if __name__ == "__main__":
    a = table("A. FRESH APPS, engine v0.2.0 frozen when these were tested (the honest numbers)", FRESH, FROZEN)
    items = json.load(open(os.path.join(FROZEN, NO_MODELS, "merged.json"), encoding="utf-8"))
    accepted = [i for i in items if i["tier"] != "rejected"]
    print(f"B. APP WITH NO MODELS NAMED IN ITS CODE ({NO_MODELS}), v0.2.0: {len(items)} names looked like models; "
          f"{len(items) - len(accepted)} correctly left out (docs, tests, docstrings); {len(accepted)} false alarm(s)\n")
    table("C. APPS USED TO BUILD THE FIXES: results are no longer independent", USED_FOR_FIXES)
    table("D. SAME FRESH APPS AFTER ONE MORE FIX, engine v0.2.1 (test files in Go, Java, C#, Python): no longer independent", FRESH)
    print(f"average on fresh apps (frozen v0.2.0): engine finds {a[0]:.0f}% of the real models, {a[1]:.0f}% of what it reports is correct; best other tool finds {a[2]:.0f}%")
