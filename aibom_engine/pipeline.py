"""Runs the pipeline of the high-level design, one step after another, saving plain JSON after every step."""
import collections
import json
import os
import time

from . import __version__
from .db import resolve_model
from .finders import context, dictionary, shapes
from .merge import merge
from .display import build_rows
from .report import build_csv, build_html, build_markdown
from .triage import triage
from .vendors import maker_of, type_of
from .verify import verify
from .writer import build_bom, validate

FINDERS = {"dictionary": dictionary.run, "context": context.run, "shapes": shapes.run}
LABEL = {"dictionary": "known model names", "context": "names in model settings", "shapes": "names by their shape"}


def save(path, obj):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=1, sort_keys=True)


def enrich(items, names, online=False):
    """Add who makes the model, what kind of model it is, and canonical DB metadata (pinning, lifecycle, license)."""
    for it in items:
        info = names.get(it["name"]) or names.get(it["name"].split("/")[-1]) or {}
        resolved = resolve_model(it["name"], online=online) if it.get("kind") == "model" else {}
        it["maker"] = maker_of(it["name"]) or resolved.get("maker", "")
        it["mode"] = type_of(it["name"], info.get("mode", "")) or resolved.get("mode", "")
        if resolved:
            it["canonical_id"] = resolved["canonical_id"]
            it["provider"] = (it.get("hint_providers") or [resolved["provider"]])[0] if resolved.get("provider") or it.get("hint_providers") else ""
            it["version"] = resolved["version"]
            it["pinned"] = resolved["pinned"]
            it["floating"] = resolved["floating"]
            it["hf_repo"] = resolved["hf_repo"]
            it["status"] = resolved["status"]
            it["deprecation_date"] = resolved["deprecation_date"]
            it["retirement_date"] = resolved["retirement_date"]
            it["replacement"] = resolved["replacement"]
            it["lifecycle_source_url"] = resolved["lifecycle_source_url"]
            it["lifecycle_checked"] = resolved["lifecycle_checked"]
            it["lifecycle_scope"] = resolved["lifecycle_scope"]
            it["license"] = resolved["license"]
            it["license_restricted"] = resolved["license_restricted"]
            it["license_reason"] = resolved["license_reason"]
    return items


def write_readable(out, items, app, source="", links=None, warnings=None):
    """The three outputs for people: the web page, the markdown summary and the spreadsheet."""
    with open(os.path.join(out, "report.html"), "w", encoding="utf-8") as f:
        f.write(build_html(items, app, source, links, {"warnings": warnings or []}))
    with open(os.path.join(out, "report.md"), "w", encoding="utf-8") as f:
        f.write(build_markdown(items, app, source, links, {"warnings": warnings or []}))
    with open(os.path.join(out, "models.csv"), "w", encoding="utf-8-sig", newline="") as f:  # the BOM makes Excel read it correctly
        f.write(build_csv(items, links))


def run(root, out, finders=("dictionary", "context", "shapes"), app=None, source="", log=None, max_seconds=120, links=None):
    log = log or (lambda msg: None)
    root = os.path.abspath(root)
    app = app or os.path.basename(root.rstrip("/\\")) or "app"
    os.makedirs(out, exist_ok=True)
    t0 = time.time()
    warnings = []
    log("Sorting the files ...")
    files = triage(root)
    cats = dict(collections.Counter(f.category for f in files))
    log(f"  {len(files):,} files: {cats.get('code', 0):,} code, {cats.get('config', 0):,} settings, {cats.get('docs', 0):,} docs, {cats.get('test', 0):,} tests")
    names = dictionary.load_names()
    deadline = t0 + max_seconds
    findings, partial = [], False
    log("Looking for model names ...")
    for name in finders:
        t1 = time.time()
        try:
            got = FINDERS[name](root, files, names=names, deadline=deadline)
        except Exception as e:  # one finder failing must not stop the scan
            warnings.append(f"The finder '{name}' failed and was skipped: {type(e).__name__}: {e}")
            got = []
        findings += got
        if time.time() > deadline:
            partial = True
        log(f"  {LABEL.get(name, name)}: {len(got):,} places ({time.time() - t1:.1f}s)")
    if partial:
        warnings.append(f"The time limit of {max_seconds} seconds was reached, so part of the repository was not read. Raise it with --max-seconds.")
    log("Checking every name (live code, comment, message, test, docs) ...")
    items = verify(enrich(merge(findings), names), root)
    included = [i for i in items if i["tier"] != "rejected"]
    used = sum(1 for i in included if i.get("role") == "used")
    log("Writing the AI-BOM and the report ...")
    bom = build_bom(included, app)
    problem = validate(bom)
    save(os.path.join(out, "files.json"), {"categories": cats, "files": [vars(f) for f in files]})
    save(os.path.join(out, "findings.json"), [f.to_dict() for f in findings])
    save(os.path.join(out, "merged.json"), items)
    save(os.path.join(out, "aibom.cdx.json"), bom)
    write_readable(out, items, app, source, links, warnings)
    rows = build_rows(items)
    tiers = dict(collections.Counter(i["tier"] for i in items))
    reasons = dict(collections.Counter(i["reason"] for i in items if i["tier"] == "rejected"))
    seconds = round(time.time() - t0, 2)
    save(os.path.join(out, "manifest.json"), {"engine_version": __version__, "scanned_folder": root, "app": app, "source": source or root, "files": len(files), "file_categories": cats,
                                              "finders": list(finders), "raw_findings": len(findings), "items_in_aibom": len(included), "models_used": used,
                                              "models_only_listed": len(included) - used, "display_models_used": len(rows["used"]), "display_models_listed": len(rows["listed"]),
                                              "display_left_out": len(rows["left_out"]), "items_by_tier": tiers, "rejected_reasons": reasons, "partial": partial,
                                              "warnings": warnings, "cyclonedx_1_6_valid": problem is None, "validation_error": problem, "seconds": seconds,
                                              **(links.to_dict() if links else {})})
    return {"items": len(included), "used": len(rows["used"]), "listed": len(rows["listed"]), "left_out": len(rows["left_out"]), "rows": rows, "rejected": len(items) - len(included), "valid": problem is None, "error": problem,
            "seconds": seconds, "tiers": tiers, "partial": partial, "warnings": warnings, "app": app, "files": len(files)}
