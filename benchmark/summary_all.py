"""One screen with every app: what the engine finds, how much of it is correct, and the best other tool.
Run after `python scripts/run_all.py`.   Usage: python benchmark/summary_all.py"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))
import score as S  # noqa: E402
from aibom_engine.adapters import LOADERS  # noqa: E402

GROUPS = [("ROUND 3: five fresh apps, engine v0.4.0 frozen before they were scanned (the honest numbers)", ["fragments", "llm", "OpenAI", "anthropic-quickstarts", "browser-use"]),
          ("Fresh apps (round 2; no longer independent after the v0.2.1 fix)", ["go-openai", "azure-search-openai-demo-csharp", "ollama-js", "open-canvas"]),
          ("Apps used to build earlier fixes", ["open_deep_research", "langchain4j-examples", "bedrock-claude-chat", "azure-search-openai-demo"])]
ROOT = os.environ.get("AIBOM_REPOS", "/tmp/repos")
FRESH = "/tmp/fresh"


def row(repo):
    truth = json.load(open(os.path.join(HERE, "labels", repo + ".json"), encoding="utf-8"))
    n = len(truth["items"])
    found, _, seen = S.score(S.load_run(os.path.join(HERE, "..", "runs", repo), verified=True), truth)
    c, rep, prec = S.summarize(seen)
    best = ("", 0)
    for tool, (fn, loader) in LOADERS.items():
        p = os.path.join(HERE, "baseline", repo, fn)
        if os.path.exists(p):
            f2, _, _ = S.score(loader(p, os.path.join(ROOT, repo)), truth)
            if len(f2) > best[1]:
                best = (tool, len(f2))
    return n, len(found), prec, best


for title, repos in GROUPS:
    print(title)
    print(f"{'app':32} {'real models':>11} {'engine finds':>14} {'engine correct':>15} {'best other tool finds':>24}")
    fr, pr, br = [], [], []
    for r in repos:
        n, f, p, best = row(r)
        fr.append(f / n * 100); pr.append(p); br.append(best[1] / n * 100)
        print(f"{r:32} {n:>11} {f:>6} ({f / n * 100:>3.0f}%) {p:>14.0f}% {best[0] + ': ' + str(best[1]) + ' (' + format(best[1] / n * 100, '.0f') + '%)':>24}")
    m = lambda xs: sum(xs) / len(xs)
    print(f"{'average':32} {'':>11} {m(fr):>13.0f}% {m(pr):>14.0f}% {m(br):>23.0f}%\n")
items = json.load(open(os.path.join(HERE, "..", "runs", "private-gpt", "merged.json"), encoding="utf-8"))
kept = [i for i in items if i.get("tier") != "rejected"]
print(f"No models named in code (private-gpt): {len(items)} candidate names, {len(items) - len(kept)} correctly left out, {len(kept)} false alarm(s)")
