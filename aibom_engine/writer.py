"""Step 5 of the design: write a CycloneDX 1.6 AI-BOM and check it against the official schema."""
import hashlib
import json
import uuid

from . import __version__

COMPONENT_TYPE = {"model": "machine-learning-model", "framework": "framework", "agent": "application", "dataset": "data"}
NS = "aibom-engine:"
USE_RANK = {"live": 0, "comment": 2, "message": 2, "text": 2, "output": 2, "test": 3, "docs": 3, "data": 3}  # proof lines: live first
RANK = {"code": 0, "config": 0, "manifest": 0, "notebook": 0, "test": 1, "docs": 2}


def slug(s):
    return "".join(c if c.isalnum() or c in "-._" else "-" for c in str(s).lower())


def build_bom(items, app_name):
    components, services = [], []
    for it in items:
        props = [{"name": NS + "kind", "value": it["kind"]}, {"name": NS + "tier", "value": it.get("tier", "unverified")},
                 {"name": NS + "found-by", "value": ",".join(it["found_by"])}]
        if it.get("maker"):
            props.append({"name": NS + "made-by", "value": it["maker"]})
        if it.get("mode"):
            props.append({"name": NS + "type", "value": it["mode"]})
        if it.get("role"):
            props.append({"name": NS + "role", "value": it["role"]})
        if it.get("canonical_id"):
            props.append({"name": NS + "canonical-id", "value": it["canonical_id"]})
        if "pinned" in it:
            props.append({"name": NS + "pinned", "value": str(bool(it["pinned"])).lower()})
        if "floating" in it:
            props.append({"name": NS + "floating-alias", "value": str(bool(it["floating"])).lower()})
        if it.get("status"):
            props.append({"name": NS + "status", "value": it["status"]})
        for key, name in (("deprecation_date", "deprecation-date"), ("retirement_date", "retirement-date"),
                          ("replacement", "replacement"), ("lifecycle_source_url", "lifecycle-source")):
            if it.get(key):
                props.append({"name": NS + name, "value": it[key]})
        if it.get("license") and it.get("license") != "unknown":
            props.append({"name": NS + "license", "value": it["license"]})
        if it.get("places"):
            props.append({"name": NS + "live-places", "value": str(it["places"]["live"])})
        for a in it["aliases"]:
            props.append({"name": NS + "alias", "value": a})
        ref = f"{it['kind']}:{slug(it['name'])}"
        occ = [{"location": e["file"] or "(no file)", "line": e["line"], "additionalContext": (e.get("use", "") + ": " if e.get("use") else "") + (e["snippet"] or e["category"])}
               for e in sorted(it["evidence"], key=lambda e: (USE_RANK.get(e.get("use", ""), RANK.get(e["category"], 3)), e["file"], e["line"])) if e["line"] > 0]
        if it["kind"] in COMPONENT_TYPE:
            c = {"bom-ref": ref, "type": COMPONENT_TYPE[it["kind"]], "name": it["name"], "properties": props}
            if occ:
                c["evidence"] = {"occurrences": occ}
            components.append(c)
        else:
            if occ:
                props.append({"name": NS + "evidence", "value": json.dumps([{"file": o["location"], "line": o["line"]} for o in occ])})
            services.append({"bom-ref": ref, "name": it["name"], "properties": props})
    bom = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
           "metadata": {"component": {"bom-ref": "app", "type": "application", "name": app_name},
                        "tools": {"components": [{"type": "application", "name": "aibom-engine", "version": __version__}]}},
           "components": components}
    if services:
        bom["services"] = services
    body = json.dumps(bom, sort_keys=True)
    bom["serialNumber"] = "urn:uuid:" + str(uuid.uuid5(uuid.NAMESPACE_URL, hashlib.sha256(body.encode()).hexdigest()))
    return bom


def validate(bom):
    """Returns None when valid, otherwise a short error text."""
    from cyclonedx.schema import SchemaVersion
    from cyclonedx.validation.json import JsonStrictValidator
    err = JsonStrictValidator(SchemaVersion.V1_6).validate_str(json.dumps(bom))
    return None if err is None else str(err)[:300]
