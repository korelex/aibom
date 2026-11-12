"""Step 5 of the design: write a CycloneDX 1.6 AI-BOM and check it against the official schema."""
import hashlib
import json
import re
import uuid

from . import __version__
from .evidence import REACHABILITY
from .flags import as_property
from .mcp import component_purl

COMPONENT_TYPE = {"model": "machine-learning-model", "framework": "framework", "agent": "application", "dataset": "data"}
NS = "aibom-engine:"
USE_RANK = {"live": 0, "comment": 2, "message": 2, "text": 2, "output": 2, "test": 3, "docs": 3, "data": 3}  # proof lines: live first
RANK = {"code": 0, "config": 0, "manifest": 0, "notebook": 0, "test": 1, "docs": 2}


def slug(s):
    return "".join(c if c.isalnum() or c in "-._" else "-" for c in str(s).lower())


def item_ref(it):
    """The bom-ref of the component or service made for a found item."""
    return f"{it['kind']}:{slug(it['name'])}"


def attach_flags(bom, flags):
    """Put each risk flag on the component it is about; a flag about no component, or one that is not in the BOM, goes on the app.
    Every flag ends up in exactly one place."""
    parts = {p["bom-ref"]: p for p in bom.get("components", []) + bom.get("services", [])}
    app = bom["metadata"]["component"]
    for f in flags:
        target = parts.get(f.ref) if f.ref else None
        (target if target is not None else app).setdefault("properties", []).append(as_property(f))


MAX_OCCURRENCES = 25  # proof lines per package: a package called in 130 places keeps the first 25 and says how many there are
SCOPE = {"runtime": "required", "optional": "optional", "peer": "optional", "dev": "excluded"}
VULN_SOURCE = (("GHSA-", "GitHub Advisory Database", "https://github.com/advisories"),
               ("PYSEC-", "PyPI Advisory Database", "https://github.com/pypa/advisory-database"),
               ("CVE-", "NVD", "https://nvd.nist.gov"), ("GO-", "Go Vulnerability Database", "https://pkg.go.dev/vuln"))
CVSS_METHOD = {"CVSS:3.1": "CVSSv31", "CVSS:3.0": "CVSSv3", "CVSS:4.0": "CVSSv4"}


def _source(vuln_id):
    for prefix, name, base in VULN_SOURCE:
        if vuln_id.startswith(prefix):
            return {"name": name, "url": base}
    return {"name": "OSV", "url": "https://osv.dev"}


def package_parts(packages):
    """(components, services, vulnerabilities, dependsOn) for the AI packages of a scan, in CycloneDX 1.6 form.

    A package is a `library`, or a `framework` for agent frameworks, with a purl and the lines that prove its use. A
    vulnerability is listed once and affects every component it applies to. The app depends on the packages the project
    declares itself; the dependency files do not tell which package needs which, so no edges between packages are drawn."""
    components, providers, vulns, depends = [], {}, {}, []
    for c in packages:
        if c.get("left_out"):
            continue
        ref = f"package:{c['ecosystem']}:{c['name'].lower()}@{c['version']}"
        props = [{"name": NS + "kind", "value": "package"}, {"name": NS + "category", "value": c.get("category") or "unknown"},
                 {"name": NS + "evidence-level", "value": c["evidence_level"]},
                 {"name": NS + "reachability", "value": c.get("reachability") or REACHABILITY},
                 {"name": NS + "declared", "value": str(bool(c["declared"])).lower()},
                 {"name": NS + "direct", "value": {True: "true", False: "false"}.get(c.get("direct"), "unknown")}]
        if c.get("requested"):
            props.append({"name": NS + "requested", "value": ", ".join(c["requested"])})
        vuln = c.get("vulnerabilities") or {}
        props.append({"name": NS + "vulnerability-check", "value": vuln.get("status", "not_checked")})
        if vuln.get("status") == "not_checked" and vuln.get("reason"):
            props.append({"name": NS + "vulnerability-check-reason", "value": vuln["reason"]})
        for svc in c.get("services") or []:
            props.append({"name": NS + "ai-service", "value": svc})
        proofs = ([("called", k) for k in c.get("calls", [])] + [("imported", i) for i in c.get("imports", [])]
                  + [("declared", e) for e in c.get("evidence", [])])
        proofs = [(kind, p) for kind, p in proofs if not p.get("left_out") and p.get("line", 0) > 0]
        occ = []
        for kind, p in proofs[:MAX_OCCURRENCES]:
            what = p.get("snippet") or ("the lockfile" if p.get("kind") == "lock" else "a dependency file")
            occ.append({"location": p["file"], "line": p["line"], "additionalContext": f"{kind}: {what}"})
        if len(proofs) > MAX_OCCURRENCES:
            props.append({"name": NS + "proof-lines", "value": f"{MAX_OCCURRENCES} of {len(proofs)} shown"})
        comp = {"bom-ref": ref, "type": "framework" if c.get("category") == "agent_framework" else "library", "name": c["name"],
                "properties": props}
        if c["version"]:
            comp["version"] = c["version"]
        if c.get("purl"):
            comp["purl"] = c["purl"]
        if c.get("vendor"):
            comp["publisher"] = c["vendor"]
        if SCOPE.get(c.get("scope")):
            comp["scope"] = SCOPE[c["scope"]]
        if occ:
            comp["evidence"] = {"occurrences": occ}
        components.append(comp)
        if c.get("direct") is True:
            depends.append(ref)
        for adv in vuln.get("advisories", []):
            v = vulns.setdefault(adv["id"], {"adv": adv, "affects": []})
            affected = {"version": c["version"], "status": "affected"}
            v["affects"].append({"ref": ref, "versions": [affected]})
        live_call = c["evidence_level"] == "called" and any(not k.get("left_out") for k in c.get("calls", []))
        if live_call and c.get("provider_service"):
            providers.setdefault(c["provider_service"], []).append(c["name"])
    services = []
    for name, via in sorted(providers.items()):
        services.append({"bom-ref": "service:" + slug(name), "name": name, "properties": [
            {"name": NS + "kind", "value": "provider-service"}, {"name": NS + "evidence-level", "value": "called"},
            {"name": NS + "client-library", "value": ", ".join(sorted(set(via)))},
            {"name": NS + "note", "value": "live code calls the provider's own client library; the endpoint it is configured for is not checked"}]})
    vuln_list = []
    for vid, v in sorted(vulns.items()):
        adv = v["adv"]
        severity = adv.get("severity") if adv.get("severity") in ("critical", "high", "medium", "low", "info", "none") else "unknown"
        rating = {"severity": severity}
        method = next((m for prefix, m in CVSS_METHOD.items() if (adv.get("cvss") or "").startswith(prefix)), "")
        if method:
            rating.update({"method": method, "vector": adv["cvss"]})
        entry = {"id": vid, "source": _source(vid), "ratings": [rating], "affects": v["affects"]}
        if adv.get("url"):
            entry["advisories"] = [{"url": adv["url"]}]
        if adv.get("summary"):
            entry["description"] = adv["summary"]
        if adv.get("fixed_in"):
            entry["recommendation"] = f"Upgrade to {adv['fixed_in']} or later."
        if adv.get("aliases"):
            entry["references"] = [{"id": a, "source": _source(a)} for a in adv["aliases"]]
        vuln_list.append(entry)
    return components, services, vuln_list, depends


URI = re.compile(r"^[a-z][a-z0-9+.-]*://[^\s${}]+$", re.I)


def mcp_parts(servers):
    """(components, services) for the MCP servers a project declares, in CycloneDX 1.6 form.

    A server started as a local program is an `application` component (with a purl when it is an npm or PyPI package); a
    remote one is a `service` with its endpoint. Environment variables and headers are listed by name only. Servers that
    sit in tests, examples or documentation are not part of the product and are left out."""
    components, services, taken = [], [], set()
    for sv in servers:
        if sv.get("left_out"):
            continue
        ref = f"mcp:{slug(sv['file'])}:{slug(sv['name'])}"
        n = 2
        while ref in taken:
            ref, n = f"mcp:{slug(sv['file'])}:{slug(sv['name'])}-{n}", n + 1
        taken.add(ref)
        props = [{"name": NS + "kind", "value": "mcp-server"}, {"name": NS + "client", "value": sv["client"]},
                 {"name": NS + "transport", "value": sv["transport"]}, {"name": NS + "evidence-level", "value": "declared"}]
        if sv["command"]:
            props.append({"name": NS + "command", "value": sv["command"]})
        if sv["args"]:
            props.append({"name": NS + "args", "value": json.dumps(sv["args"], ensure_ascii=False)})
        for key in ("launcher", "package", "ecosystem", "version"):
            if sv[key]:
                props.append({"name": NS + key, "value": sv[key]})
        if sv["pinned"] is not None:
            props.append({"name": NS + "pinned", "value": str(bool(sv["pinned"])).lower()})
        props += [{"name": NS + "environment-name", "value": k} for k in sv["env_keys"]]
        props += [{"name": NS + "header-name", "value": k} for k in sv["header_names"]]
        if sv["enabled"] is False:
            props.append({"name": NS + "enabled", "value": "false"})
        if sv["url_has_credentials"]:
            props.append({"name": NS + "url-has-credentials", "value": "true"})
        if sv["note"]:
            props.append({"name": NS + "note", "value": sv["note"]})
        evidence = {"occurrences": [{"location": sv["file"], "line": sv["line"], "additionalContext": f"declared in a {sv['client']} config"}]} if sv["line"] > 0 else None
        if sv["transport"] in ("http", "sse", "remote"):
            part = {"bom-ref": ref, "name": sv["name"], "properties": props}
            if sv["url"] and URI.match(sv["url"]):
                part["endpoints"] = [sv["url"]]
            elif sv["url"]:
                props.append({"name": NS + "url", "value": sv["url"]})
            if any(h.lower() in ("authorization", "proxy-authorization") for h in sv["header_names"]):
                part["authenticated"] = True
            if sv["line"] > 0:  # a CycloneDX service has no evidence block, so the place is a property
                props.append({"name": NS + "declared-in", "value": f"{sv['file']}:{sv['line']}"})
            services.append(part)
        else:
            part = {"bom-ref": ref, "type": "application", "name": sv["name"], "properties": props}
            purl = component_purl(sv)
            if purl:
                part["purl"] = purl
                if sv["pinned"] and sv["version"]:
                    part["version"] = sv["version"]
            if evidence:
                part["evidence"] = evidence
            components.append(part)
    return components, services


def build_bom(items, app_name, packages=None, advisory_data="", flags=None, mcp_servers=None):
    components, services = [], []
    for it in items:
        # evidence-level: how strongly the use is proven (declared / called); confidence: how sure the name itself is
        # (confirmed / worked_out). Kept apart on purpose: they answer different questions.
        props = [{"name": NS + "kind", "value": it["kind"]}]
        if it.get("evidence_level"):  # never claimed when it was not worked out
            props.append({"name": NS + "evidence-level", "value": it["evidence_level"]})
        props.append({"name": NS + "reachability", "value": it.get("reachability") or REACHABILITY})
        if it.get("confidence"):
            props.append({"name": NS + "confidence", "value": it["confidence"]})
        props.append({"name": NS + "found-by", "value": ",".join(it["found_by"])})
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
        ref = item_ref(it)
        occ = [{"location": e["file"] or "(no file)", "line": e["line"], "additionalContext": (("called" if e.get("called") else e.get("use", "")) + ": " if e.get("use") else "") + (e["snippet"] or e["category"])}
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
    pkg_components, pkg_services, vuln_list, depends = package_parts(packages or [])
    components += pkg_components
    taken = {s["bom-ref"] for s in services}
    services += [s for s in pkg_services if s["bom-ref"] not in taken]
    mcp_components, mcp_services = mcp_parts(mcp_servers or [])
    components += mcp_components
    services += mcp_services
    bom = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
           "metadata": {"component": {"bom-ref": "app", "type": "application", "name": app_name},
                        "tools": {"components": [{"type": "application", "name": "aibom-engine", "version": __version__}]}},
           "components": components}
    if advisory_data:
        bom["metadata"]["properties"] = [{"name": NS + "advisory-data-fetched", "value": advisory_data}]
    if services:
        bom["services"] = services
    attach_flags(bom, flags or [])
    if depends:
        bom["dependencies"] = [{"ref": "app", "dependsOn": depends}]
    if vuln_list:
        bom["vulnerabilities"] = vuln_list
    body = json.dumps(bom, sort_keys=True)
    bom["serialNumber"] = "urn:uuid:" + str(uuid.uuid5(uuid.NAMESPACE_URL, hashlib.sha256(body.encode()).hexdigest()))
    return bom


def validate(bom):
    """Returns None when valid, otherwise a short error text."""
    from cyclonedx.schema import SchemaVersion
    from cyclonedx.validation.json import JsonStrictValidator
    err = JsonStrictValidator(SchemaVersion.V1_6).validate_str(json.dumps(bom))
    return None if err is None else str(err)[:300]
