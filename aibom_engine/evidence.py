"""Evidence levels for model names, kept apart from how sure the name itself is.

Every component of the AI-BOM says how strongly its use is proven, with the levels of the product spec:

  declared   the name is written in the project: a dependency file for a package, code or settings for a model
  imported   live code imports the package (packages only: a model name is never imported)
  called     live code calls the package, or passes the model name into a call on an AI SDK
             (client.chat.completions.create(model="gpt-4o"), ChatOpenAI(model=MODEL), from_pretrained("..."))

A fourth level, proof that a request from outside reaches that code, needs a full call graph and is not attempted, so
every component also says reachability: not_verified.

Confidence is a separate question that only model names have: is the name written out ("confirmed") or worked out from
a constant such as GPT_4O ("worked_out")? A worked-out name can still be called, and a confirmed one only declared.
"""
import re

REACHABILITY = "not_verified"
CONFIDENCE = {"declared": "confirmed", "inferred": "worked_out"}


def _matches(value, names, via):
    low = value.lower()
    if via:
        return value == via or value.endswith("." + via)
    return any(re.search(r"(?<![a-z0-9])" + re.escape(n) + r"(?![a-z0-9])", low) for n in names)


def assign_levels(items, arguments):
    """Set evidence_level, reachability and confidence on every model item. `arguments` are {file, line, value} for what
    live code passes into AI calls (from the package step). A live place whose line passes the name into such a call is
    marked called: True, and makes the item called."""
    at = {}
    for a in arguments:
        at.setdefault((a["file"], a["line"]), []).append(a["value"])
    for it in items:
        it["reachability"] = REACHABILITY
        it["confidence"] = CONFIDENCE.get(it.get("tier"), "")
        if it.get("tier") == "rejected":
            it["evidence_level"] = ""
            continue
        names = [n.lower() for n in [it["name"]] + it.get("aliases", [])]
        called = False
        for e in it["evidence"]:
            if e.get("use") != "live":
                continue
            values = at.get((e["file"], e["line"]), [])
            if any(_matches(v, names, e.get("via")) for v in values):
                e["called"] = True
                called = True
        it["evidence_level"] = "called" if called else "declared"
    return items
