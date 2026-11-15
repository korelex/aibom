"""Runs the pipeline of the high-level design, one step after another, saving plain JSON after every step."""
import collections
import json
import os
import time

from . import __version__
from .db import resolve_model
from . import packages as package_finder
from .finders import context, dictionary, shapes
from .merge import merge
from .display import build_rows
from .evidence import assign_levels
from . import flags as flag_rules
from . import credentials as credential_finder
from . import modelfiles as modelfile_finder
from . import remote_code as remote_code_finder
from . import mcp as mcp_finder
from . import sarif
from .mcp_flags import mcp_flags
from .report import build_csv, build_html, build_markdown, build_mcp_csv, build_packages_csv
from .triage import triage
from .vendors import maker_of, type_of
from .verify import verify
from .writer import build_bom, item_ref, validate

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
            it["license_name"] = resolved["license_name"]
            it["license_commercial_use"] = resolved["license_commercial_use"]
            it["license_source_url"] = resolved["license_source_url"]
            it["license_checked"] = resolved["license_checked"]
    return items


def write_readable(out, items, app, source="", links=None, warnings=None, packages=None, flags=None, mcp=None, model_files=None):
    """The outputs for people: the web page, the markdown summary and the spreadsheets (models, and AI packages)."""
    meta = {"warnings": warnings or [], "packages": packages or [], "flags": flags or [], "mcp": mcp or {"servers": [], "files": [], "problems": []},
            "model_files": model_files or {"files": [], "problems": [], "remote_code": {"findings": []}}}
    with open(os.path.join(out, "report.html"), "w", encoding="utf-8") as f:
        f.write(build_html(items, app, source, links, meta))
    with open(os.path.join(out, "report.md"), "w", encoding="utf-8") as f:
        f.write(build_markdown(items, app, source, links, meta))
    with open(os.path.join(out, "packages.csv"), "w", encoding="utf-8-sig", newline="") as f:
        f.write(build_packages_csv(packages or [], links))
    with open(os.path.join(out, "mcp.csv"), "w", encoding="utf-8-sig", newline="") as f:
        f.write(build_mcp_csv(mcp, links))
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
    log("Reading MCP config files ...")
    try:
        found_mcp = mcp_finder.find(root, deadline=deadline)
    except Exception as e:  # the MCP step must never stop the model scan
        warnings.append(f"MCP config files could not be read: {type(e).__name__}: {e}")
        found_mcp = {"servers": [], "files": [], "problems": []}
    for p in found_mcp["problems"]:
        warnings.append(f"Could not read the MCP config file {p['file']}: {p['error']}")
    if found_mcp.get("partial"):
        warnings.append("The time limit was reached while looking for MCP config files, so some may be missing. Raise it with --max-seconds.")
    ms = mcp_finder.summary(found_mcp)
    if ms["servers"]:
        log(f"  {ms['servers']:,} MCP servers in {ms['config_files']:,} config files")
    log("Looking for hardcoded API keys ...")
    try:
        found_keys = credential_finder.find(root, files, deadline=deadline)
    except Exception as e:  # the key search must never stop the model scan
        warnings.append(f"The search for hardcoded API keys failed and was skipped: {type(e).__name__}: {e}")
        found_keys = {"findings": [], "files_scanned": 0, "problems": [], "partial": False, "truncated": False}
    for p in found_keys["problems"]:
        warnings.append(f"Could not read {p['file']} while looking for hardcoded API keys: {p['error']}")
    if found_keys.get("partial"):
        warnings.append("The time limit was reached while looking for hardcoded API keys, so some files were not read. Raise it with --max-seconds.")
    if found_keys.get("truncated"):
        warnings.append(f"More possible API keys were found than are listed: no more than {credential_finder.MAX_PER_FILE} per file and {credential_finder.MAX_FINDINGS} in all.")
    ks = credential_finder.summary(found_keys)
    if ks["keys"] or ks["other"]:
        log(f"  {ks['keys']:,} hardcoded API keys in {ks['files']:,} files; {ks['other']:,} more in tests, examples or documentation")
    log("Looking for model files ...")
    try:
        found_models = modelfile_finder.find(root, files, deadline=deadline)
    except Exception as e:  # the model-file search must never stop the model scan
        warnings.append(f"The search for model files failed and was skipped: {type(e).__name__}: {e}")
        found_models = {"files": [], "problems": [], "partial": False, "truncated": False}
    try:
        found_remote = remote_code_finder.find(root, files, deadline=deadline)
    except Exception as e:
        warnings.append(f"The search for trust_remote_code failed and was skipped: {type(e).__name__}: {e}")
        found_remote = {"findings": [], "files_scanned": 0, "partial": False, "truncated": False}
    for p in found_models["problems"]:
        warnings.append(f"Could not read the model file {p['file']}: {p['error']}")
    if found_models.get("partial") or found_remote.get("partial"):
        warnings.append("The time limit was reached while looking for model files, so some were not read. Raise it with --max-seconds.")
    if found_models.get("truncated"):
        warnings.append(f"More than {modelfile_finder.MAX_FILES} model files were found; only the first {modelfile_finder.MAX_FILES} are listed.")
    ms2 = modelfile_finder.summary(found_models)
    if ms2["files"] or ms2["other"]:
        log(f"  {ms2['files']:,} model files, {ms2['dangerous']:,} with dangerous imports or a misleading name; {len(found_remote['findings']):,} uses of trust_remote_code")
    log("Reading dependency files ...")
    try:
        found_packages = package_finder.find(root, files, deadline=deadline)
    except Exception as e:  # the package step must never stop the model scan
        warnings.append(f"Dependency files could not be read: {type(e).__name__}: {e}")
        found_packages = {"packages": [], "files": [], "problems": [], "notes": [], "summary": {}}
    model_arguments = found_packages.pop("model_arguments", [])
    ps = found_packages["summary"]
    if ps:
        log(f"  {ps['dependency_files']:,} dependency files, {ps['packages_read']:,} packages, {ps['ai_packages']:,} AI packages ({ps['seconds']:.1f}s)")
        if ps.get("ai_packages"):
            log(f"  {ps['advisories']:,} known vulnerabilities in {ps['vulnerable_packages']:,} AI packages; "
                f"{ps['not_checked']:,} not checked (no exact version). Advisory data from {ps['advisory_data'] or 'an unknown date'}.")
    for p in found_packages["problems"]:
        warnings.append(f"Could not read the dependency file {p['file']}: {p['error']}")
    for note in found_packages.get("notes", []):
        warnings.append(f"Dependency file {note}.")
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
    items = assign_levels(verify(enrich(merge(findings), names), root), model_arguments)
    included = [i for i in items if i["tier"] != "rejected"]
    used = sum(1 for i in included if i.get("role") == "used")
    flags = flag_rules.collect(flag_rules.model_flags(included, item_ref), mcp_flags(found_mcp["servers"]), credential_finder.credential_flags(found_keys["findings"]),
                               modelfile_finder.model_file_flags(found_models["files"]), remote_code_finder.remote_code_flags(found_remote["findings"]))
    log("Writing the AI-BOM and the report ...")
    bom = build_bom(included, app, found_packages["packages"], ps.get("advisory_data", "") if ps else "", flags, found_mcp["servers"], found_models["files"])
    problem = validate(bom)
    save(os.path.join(out, "files.json"), {"categories": cats, "files": [vars(f) for f in files]})
    save(os.path.join(out, "findings.json"), [f.to_dict() for f in findings])
    save(os.path.join(out, "merged.json"), items)
    save(os.path.join(out, "packages.json"), found_packages)
    save(os.path.join(out, "mcp.json"), found_mcp)
    save(os.path.join(out, "credentials.json"), found_keys)
    save(os.path.join(out, "modelfiles.json"), {**found_models, "remote_code": found_remote})
    save(os.path.join(out, "aibom.cdx.json"), bom)
    save(os.path.join(out, "flags.json"), {"flags": [f.to_dict() for f in flags], "counts": flag_rules.counts(flags)})
    sarif.write(os.path.join(out, "aibom.sarif"), flags)
    write_readable(out, items, app, source, links, warnings, found_packages["packages"], flags, found_mcp, {**found_models, "remote_code": found_remote})
    rows = build_rows(items)
    tiers = dict(collections.Counter(i["tier"] for i in items))
    reasons = dict(collections.Counter(i["reason"] for i in items if i["tier"] == "rejected"))
    seconds = round(time.time() - t0, 2)
    save(os.path.join(out, "manifest.json"), {"engine_version": __version__, "scanned_folder": root, "app": app, "source": source or root, "files": len(files), "file_categories": cats,
                                              "finders": list(finders), "raw_findings": len(findings), "items_in_aibom": len(included), "models_used": used,
                                              "models_only_listed": len(included) - used, "display_models_used": len(rows["used"]), "display_models_listed": len(rows["listed"]),
                                              "display_left_out": len(rows["left_out"]), "items_by_tier": tiers, "rejected_reasons": reasons, "partial": partial,
                                              "warnings": warnings, "packages": found_packages["summary"], "flags": flag_rules.counts(flags), "mcp": ms, "secrets": ks, "model_files": ms2, "remote_code": len(found_remote["findings"]), "cyclonedx_1_6_valid": problem is None, "validation_error": problem, "seconds": seconds,
                                              **(links.to_dict() if links else {})})
    return {"packages": found_packages["summary"], "items": len(included), "used": len(rows["used"]), "listed": len(rows["listed"]), "left_out": len(rows["left_out"]), "rows": rows, "rejected": len(items) - len(included), "valid": problem is None, "error": problem,
            "seconds": seconds, "tiers": tiers, "partial": partial, "warnings": warnings, "app": app, "files": len(files), "flags": flags, "mcp": ms, "secrets": ks, "model_files": ms2, "remote_code": len(found_remote["findings"])}
