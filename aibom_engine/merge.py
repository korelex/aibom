"""Step 3 of the design: one item per real-world thing, with every location kept as evidence."""
import re
from collections import OrderedDict

# Names that appear in front of a model name as the API provider or model vendor (openai/gpt-4o, anthropic:claude-...).
# Hugging Face owners such as sentence-transformers/ are NOT here, because there the owner is part of the real name.
VENDORS = {"openai", "anthropic", "google", "google-genai", "googleai", "vertex-ai", "vertexai", "gemini", "azure", "azure-ai", "azure-openai", "bedrock", "groq",
           "mistral", "mistralai", "cohere", "xai", "deepseek", "moonshotai", "ollama", "together", "together-ai", "fireworks", "fireworks-ai", "openrouter",
           "perplexity", "baseten", "huggingface", "hf", "amazon", "alibaba", "zai", "minimax"}


MAX_EVIDENCE = 2000
CAT_RANK = {"code": 0, "config": 0, "manifest": 0, "notebook": 0, "test": 1, "docs": 2}


def canon(kind, name):
    n = re.sub(r"\s+", "", str(name).strip().lower().replace("_", "-"))
    if kind == "model":
        parts = re.split(r"[/:]", n)
        while len(parts) > 1 and parts[0] in VENDORS:
            parts.pop(0)
        n = "/".join(parts)
    return kind, n


def merge(findings):
    groups = OrderedDict()
    for f in findings:
        k = canon(f.kind, f.name)
        g = groups.setdefault(k, {"kind": f.kind, "names": [], "tools": set(), "evidence": [], "providers": set()})
        if " | " in f.note:
            g["providers"].add(f.note.split(" | ")[0])
        if f.name not in g["names"]:
            g["names"].append(f.name)
        g["tools"].add(f.tool)
        ev = {"file": f.file, "line": f.line, "col": f.col, "category": f.category, "snippet": f.snippet,
              "via": f.note[len("identifier:"):] if f.note.startswith("identifier:") else ""}
        if ev not in g["evidence"]:
            g["evidence"].append(ev)
    items = []
    for i, (k, g) in enumerate(sorted(groups.items()), 1):
        total = len(g["evidence"])
        if total > MAX_EVIDENCE:  # a name that appears thousands of times: keep code and config places first
            g["evidence"] = sorted(g["evidence"], key=lambda e: (CAT_RANK.get(e["category"], 3), e["file"], e["line"]))[:MAX_EVIDENCE]
        g["evidence"].sort(key=lambda e: (e["file"], e["line"]))
        shown = next((n for n in g["names"] if canon(g["kind"], n)[1] == n.lower()), None) or min(g["names"], key=len)
        items.append({"id": f"item-{i:04d}", "kind": g["kind"], "name": shown, "aliases": sorted(n for n in g["names"] if n != shown),
                      "found_by": sorted(g["tools"]), "hint_providers": sorted(g["providers"]), "evidence": g["evidence"], "evidence_total": total})
    return items
