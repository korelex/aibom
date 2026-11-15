"""The risk flags of a scan as SARIF 2.1.0, the format GitHub code scanning (and most CI security dashboards) reads.

One SARIF rule per aibom rule id, one result per flag. A flag's file and line become the result's location, so GitHub shows
the finding on that line of a pull request and lists it in the repository's Security tab. Nothing is added that the flags do
not already hold, and a flag never carries a secret's value, so neither does this file.

Two choices that matter:
- GitHub ranks alerts by the rule's `security-severity` (a number from 0 to 10), not by each result. A few aibom rules have a
  severity that depends on where the finding is (a key in a test file is low, in the product's code high), so the rule gets the
  worst severity seen for it in this scan, and each result still carries its own level (error, warning or note).
- A flag about no file in particular cannot be placed on a line, and GitHub refuses results without a location, so such flags
  are left out here. They stay in flags.json and the reports; `skipped` in the result says how many.

The output is the same, byte for byte, for the same flags: there is no time stamp in it.
"""
import json
import os
from urllib.parse import quote

from . import __version__
from . import flags as flag_rules

SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
INFO_URI = "https://github.com/korelex/aibom"
RULES_URI = INFO_URI + "/blob/main/docs/how-it-works.md#risk-flags"
LEVEL = {"high": "error", "medium": "warning", "low": "note", "info": "note"}
SECURITY_SEVERITY = {"high": "8.0", "medium": "5.5", "low": "3.0", "info": "1.0"}   # GitHub: 7.0+ high, 4.0+ medium, 0.1+ low


def _uri(path, prefix):
    path = path.replace("\\", "/").lstrip("/")
    prefix = (prefix or "").replace("\\", "/").strip("/")
    if prefix in ("", "."):
        full = path
    else:
        full = prefix + "/" + path
    while full.startswith("./"):
        full = full[2:]
    return quote(full, safe="/")


def build(flags, prefix=""):
    """(the SARIF document as a dict, how many flags were left out because they have no file)."""
    flags = flag_rules.sort_flags(list(flags))
    worst, first = {}, {}
    for f in flags:
        if f.rule not in worst or flag_rules.RANK[f.severity] > flag_rules.RANK[worst[f.rule]]:
            worst[f.rule] = f.severity
        first.setdefault(f.rule, f)
    ids = sorted(worst)
    rules = []
    for rid in ids:
        f = first[rid]
        rules.append({
            "id": rid,
            "name": rid,
            "shortDescription": {"text": f.title},
            "fullDescription": {"text": f.title},
            "help": {"text": f.fix, "markdown": f"**Fix:** {f.fix}\n\nEvery rule is described in [how aibom works]({RULES_URI})."},
            "helpUri": RULES_URI,
            "defaultConfiguration": {"level": LEVEL[worst[rid]]},
            "properties": {"tags": ["security", "ai", f.category], "security-severity": SECURITY_SEVERITY[worst[rid]]},
        })
    index = {rid: i for i, rid in enumerate(ids)}
    results, skipped = [], 0
    for f in flags:
        if not f.file:
            skipped += 1
            continue
        location = {"physicalLocation": {"artifactLocation": {"uri": _uri(f.file, prefix)}}}
        if f.line > 0:
            location["physicalLocation"]["region"] = {"startLine": f.line}
        text = f.title + (" " + f.detail if f.detail else "") + " Fix: " + f.fix
        results.append({
            "ruleId": f.rule,
            "ruleIndex": index[f.rule],
            "level": LEVEL[f.severity],
            "message": {"text": text},
            "locations": [location],
            "properties": {"severity": f.severity, "subject": f.subject},
        })
    doc = {
        "$schema": SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "aibom", "version": __version__, "semanticVersion": __version__, "informationUri": INFO_URI, "rules": rules}},
            "results": results,
            "columnKind": "unicodeCodePoints",
        }],
    }
    return doc, skipped


def write(path, flags, prefix=""):
    """Write the SARIF file and return how many flags were left out because they have no file."""
    doc, skipped = build(flags, prefix)
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(doc, fh, indent=1, sort_keys=True, ensure_ascii=False)
        fh.write("\n")
    return skipped
