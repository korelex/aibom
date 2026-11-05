"""Turns the raw items into what people read: one row per model (different spellings merged), the important ones first.
This changes only how results are shown. The AI-BOM file and merged.json keep every spelling as its own entry."""
import re
from collections import OrderedDict

from .verify import REASON_TEXT

DISPLAY_VENDORS = r"openai|anthropic|google|azure|bedrock|vertex|cerebras|groq|xai|deepseek|mistral|cohere|amazon|alibaba|moonshotai|zai"
PREFIX = re.compile(r"^(?:(?:" + DISPLAY_VENDORS + r")[/:.]|openai-|azure-)+")


def key_of(name):
    """Spellings that are the same model get the same key: openai-gpt-4o, openai/gpt-4o and gpt-4o; gpt-35-turbo and gpt-3.5-turbo."""
    n = str(name).strip().lower().replace("_", "-")
    prev = None
    while prev != n:
        prev = n
        m = PREFIX.match(n)
        if m and len(n) - m.end() >= 3:
            n = n[m.end():]
    n = n.split("/")[-1]
    n = n.replace("gpt-35-", "gpt-3.5-").replace(".", "-")
    return n


def live_places(items):
    seen, out = set(), []
    for it in items:
        for e in it["evidence"]:
            if e.get("use") == "live" and (e["file"], e["line"]) not in seen:
                seen.add((e["file"], e["line"]))
                out.append({"file": e["file"], "line": e["line"], "snippet": e.get("snippet", ""), "category": e.get("category", "")})
    out.sort(key=lambda p: (p["file"], p["line"]))
    return out


def build_rows(items):
    """Returns {'used': [...], 'listed': [...], 'left_out': [...]}. Each model row merges every spelling of the same model."""
    groups, left = OrderedDict(), OrderedDict()
    for it in items:
        if it["tier"] == "rejected":
            left.setdefault(key_of(it["name"]), []).append(it)
        else:
            groups.setdefault(key_of(it["name"]), []).append(it)
    rows = []
    for k, members in groups.items():
        primary = min(members, key=lambda m: (bool(PREFIX.match(m["name"].lower())), "_" in m["name"], len(m["name"])))
        also = sorted({m["name"] for m in members if m is not primary} | {a for m in members for a in m.get("aliases", [])} - {primary["name"]})
        places = live_places(members)
        rows.append({"key": k, "name": primary["name"], "also": also, "maker": next((m.get("maker") for m in [primary] + members if m.get("maker")), ""),
                     "mode": next((m.get("mode") for m in [primary] + members if m.get("mode")), ""),
                     "role": "used" if any(m.get("role", "used") != "listed" for m in members) else "listed",
                     "tier": "declared" if any(m["tier"] == "declared" for m in members) else "inferred",
                     "places": places, "other_places": sum(len(m["evidence"]) for m in members) - len(places), "members": members})
    order = lambda r: (r["tier"] != "declared", -len(r["places"]), r["name"].lower())
    used = sorted([r for r in rows if r["role"] == "used"], key=order)
    listed = sorted([r for r in rows if r["role"] == "listed"], key=order)
    gone = []
    for k, members in left.items():
        if k in groups:  # the same model is used somewhere else, so this spelling is not "left out"
            continue
        m = min(members, key=lambda x: len(x["name"]))
        e = m["evidence"][0]
        gone.append({"name": m["name"], "reason": m["reason"], "why": REASON_TEXT.get(m["reason"], m["reason"]), "file": e["file"], "line": e["line"]})
    gone.sort(key=lambda g: (g["reason"], g["name"].lower()))
    return {"used": used, "listed": listed, "left_out": gone}


def by_maker(rows):
    """Group rows by who makes the model; the biggest group first."""
    g = OrderedDict()
    for r in rows:
        g.setdefault(r["maker"] or "Other or unknown maker", []).append(r)
    return sorted(g.items(), key=lambda kv: (kv[0].startswith("Other"), -len(kv[1]), kv[0]))
