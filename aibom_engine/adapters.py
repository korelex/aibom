"""Turn the output of the four existing scanners into Finding lists.
These are also the 'Finder D' adapters of the design."""
import json
import re

from .finding import Finding, rel, to_int


def read_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)

CISCO_KIND = {"model": "model", "embedding": "model", "agent": "agent", "mcp_client": "mcp", "mcp_server": "mcp",
              "tool": "tool", "datastore": "vector_db", "dataset": "dataset", "secret": "secret", "dependency": "framework",
              "prompt": "other", "memory": "other"}


def load_cisco(path, root):
    out = []
    data = read_json(path)
    for src in data["aibom_analysis"]["sources"].values():
        for cat, items in src["components"].items():
            for c in items:
                name = c.get("model_name") or c.get("embedding_model") or c.get("name") or ""
                out.append(Finding("cisco", CISCO_KIND.get(c.get("component_type"), "other"), str(name),
                                   rel(c.get("file_path"), root), to_int(c.get("line_number")), c.get("component_type", "")))
    return out


def load_cdxgen(path, root):
    out = []
    data = read_json(path)
    for c in data.get("components", []):
        t = c.get("type")
        if t not in ("machine-learning-model", "service", "data", "library", "framework"):
            continue
        kind = {"machine-learning-model": "model", "service": "service", "data": "dataset"}.get(t, "framework")
        occ = (c.get("evidence") or {}).get("occurrences") or [{}]
        loc = str(occ[0].get("location", ""))
        m = re.match(r"(.*?)#L(\d+)", loc)
        f, ln = (m.group(1), int(m.group(2))) if m else (loc, 0)
        out.append(Finding("cdxgen", kind, c.get("name", ""), f, ln, t))
    return out


def load_trusera(path, root):
    out = []
    data = read_json(path)
    for c in data.get("components", []):
        props = {p["name"]: p["value"] for p in c.get("properties", [])}
        t = c.get("type")
        kind = {"machine-learning-model": "model", "framework": "framework", "service": "service", "library": "framework", "container": "other"}.get(t, "other")
        loc = str(props.get("trusera:source_location", ""))
        m = re.match(r"(.*?):(\d+)$", loc)
        f, ln = (m.group(1), int(m.group(2))) if m else (loc, 0)
        out.append(Finding("trusera", kind, c.get("name", ""), rel(f, root), ln, props.get("trusera:provider", "")))
    return out


def load_aibom_scanner(path, root):
    out = []
    data = read_json(path)
    for d in data.get("detections", []):
        mn = d.get("model_name")
        has = mn not in (None, "None", "")
        out.append(Finding("aibom-scanner", "model" if has else "framework", str(mn) if has else str(d.get("sdk_name") or d.get("provider")),
                           rel(d.get("file_path"), root), to_int(d.get("line_number")), str(d.get("provider", ""))))
    for s in data.get("mcp_servers", []):
        out.append(Finding("aibom-scanner", "mcp", str(s.get("name", "mcp")), "", 0, "mcp_server"))
    return out


LOADERS = {"cisco": ("cisco.json", load_cisco), "cdxgen": ("cdxgen.json", load_cdxgen),
           "trusera": ("trusera.json", load_trusera), "aibom-scanner": ("aibom_scanner.json", load_aibom_scanner)}
