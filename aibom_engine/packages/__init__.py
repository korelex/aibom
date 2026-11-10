"""Find the AI packages a project depends on, from its dependency files (evidence level: declared).

Every manifest and lockfile is parsed into Declarations (one per entry). Declarations of the same package are merged into
one component per package and version, with every file and line kept as evidence. Lockfiles list the whole installed
tree, so they are where transitive dependencies come from; a project with only a manifest gets its direct dependencies.

Only packages the database knows as AI packages are reported; the others are counted, so the report can say how much
was read.
"""
import os
import time

from ..db import load_db, lookup_package
from ..evidence import REACHABILITY
from .common import Declaration, left_out_reason, normalize, purl
from . import javascript, python
from .calls import find_calls
from .imports import find_imports

PARSERS = python.PARSERS + javascript.PARSERS
ECOSYSTEM_LABEL = {"pypi": "PyPI", "npm": "npm"}
SCOPE_ORDER = ("runtime", "optional", "peer", "dev", "unknown")
# Evidence levels, weakest first. Level 4, proof that an entry point reaches the code, is not attempted, and every
# component says so.
LEVELS = ("declared", "imported", "called")
SERVICE_VENDOR = {"boto3": "Amazon Web Services"}  # general SDKs that are reported when code calls an AI service with them


def select(files):
    """(path, parser) for every dependency file in the triaged file list."""
    out = []
    for fi in files:
        for matches, parser in PARSERS:
            if matches(fi.path):
                out.append((fi.path, parser))
                break
    return out


def _project_of(path, lock_dirs):
    """The folder of the nearest lockfile at or above this file: the project it belongs to."""
    d = os.path.dirname(path)
    while True:
        if d in lock_dirs:
            return d
        if not d:
            return None
        d = os.path.dirname(d)


def _resolve_direct(decls):
    """Lockfiles that do not mark direct dependencies (yarn.lock, package-lock v1, Pipfile.lock, poetry.lock) learn it
    from the manifests of their project: the same folder, or workspace folders below it without a lockfile of their own."""
    lock_dirs = {os.path.dirname(d.file) for d in decls if d.kind == "lock"}
    declared = {}
    for d in decls:
        if d.kind == "manifest":
            project = _project_of(d.file, lock_dirs)
            if project is not None:
                wanted = declared.setdefault((project, d.ecosystem), {}).setdefault(normalize(d.ecosystem, d.name), set())
                wanted.update(x for x in (d.spec, d.version) if x)
    for d in decls:
        if d.kind == "lock" and d.direct is None:
            names = declared.get((os.path.dirname(d.file), d.ecosystem))
            if names is None:
                continue
            wanted = names.get(normalize(d.ecosystem, d.name))
            if wanted is None:
                d.direct = False
            elif d.resolves:
                # yarn.lock says which requested ranges this version satisfies: only that version is the direct one
                d.direct = bool(wanted & set(d.resolves))
            else:
                d.direct = True


def _merge(decls):
    """One component per (ecosystem, package, version). A manifest range with a lockfile in the same project joins the
    version that lockfile resolved, so "langchain>=0.1" in pyproject.toml and "0.1.20" in uv.lock become one entry."""
    lock_dirs = {os.path.dirname(d.file) for d in decls if d.kind == "lock"}
    in_lock = {}
    for d in decls:
        if d.kind == "lock" and d.version:
            in_lock.setdefault((os.path.dirname(d.file), d.ecosystem, normalize(d.ecosystem, d.name)), []).append(d)

    def resolved_version(d, norm):
        project = _project_of(d.file, lock_dirs)
        candidates = in_lock.get((project, d.ecosystem, norm)) if project is not None else None
        if not candidates:
            return ""
        exact = [c for c in candidates if d.spec and d.spec in c.resolves]  # the lockfile names the range it resolved
        if not exact:
            exact = [c for c in candidates if c.direct is True]  # the version the project itself depends on
        versions = {c.version for c in (exact or candidates)}
        return versions.pop() if len(versions) == 1 else ""  # several possible versions and no way to tell: do not guess

    groups = {}
    for d in decls:
        norm = normalize(d.ecosystem, d.name)
        version = d.version or (resolved_version(d, norm) if d.kind == "manifest" else "")
        g = groups.setdefault((d.ecosystem, norm, version), {"decls": [], "names": []})
        g["decls"].append(d)
        if d.name not in g["names"]:
            g["names"].append(d.name)
    return groups


def _component(eco, version, g, info, left_out):
    """One package component from the declarations merged for it."""
    flags = [d.direct for d in g["decls"]]
    direct = True if True in flags else (False if flags and all(f is False for f in flags) else None)
    scopes = {d.scope for d in g["decls"]}
    lock_name = next((d.name for d in g["decls"] if d.kind == "lock"), g["names"][0])
    return {
        "kind": "package",
        "ecosystem": eco,
        "name": lock_name,
        "version": version,
        "purl": purl(eco, lock_name, version),
        "category": info.get("category", ""),
        "vendor": info.get("vendor", ""),
        "direct": direct,
        "scope": next(s for s in SCOPE_ORDER if s in scopes),
        "requested": sorted({d.spec for d in g["decls"] if d.spec}),
        "evidence_level": "declared",
        "reachability": REACHABILITY,
        "declared": True,
        "left_out": left_out,
        "evidence": [{"file": d.file, "line": d.line, "kind": d.kind, "direct": d.direct, "scope": d.scope}
                     for d in sorted(g["decls"], key=lambda d: (d.file, d.line))],
        "imports": [],
        "calls": [],
    }


def _group(hits):
    out = {}
    for h in hits:
        out.setdefault((h["ecosystem"], normalize(h["ecosystem"], h["package"])), []).append(h)
    return out


def _evidence(group, keys):
    return sorted(({k: h[k] for k in keys} for h in group), key=lambda h: (h["file"], h["line"]))


def _targets(components, eco, norm, group, db):
    """The components that code evidence for a package belongs to: the version the project depends on directly
    (transitive copies are not what its own code uses), else every version; a new undeclared component when none."""
    targets = [c for c in components if c["ecosystem"] == eco and normalize(eco, c["name"]) == norm and not c["left_out"]]
    targets = [c for c in targets if c["direct"] is True] or targets
    if targets:
        return targets
    info = lookup_package(ECOSYSTEM_LABEL[eco], norm, db=db) or {}
    live = [h for h in group if not h["left_out"]]
    c = {
        "kind": "package", "ecosystem": eco, "name": group[0]["package"], "version": "", "purl": purl(eco, group[0]["package"]),
        "category": info.get("category", ""), "vendor": info.get("vendor", ""), "direct": None, "scope": "runtime",
        "requested": [], "evidence_level": "declared", "reachability": REACHABILITY, "declared": False,
        "left_out": "" if live else sorted({h["left_out"] for h in group})[0], "evidence": [], "imports": [], "calls": [],
    }
    components.append(c)
    return [c]


def _depth(component, path):
    """How deep the nearest folder declaring this component is, among the folders at or above `path`; -1 when none."""
    best = -1
    for e in component["evidence"]:
        d = os.path.dirname(e["file"])
        if not d or path.startswith(d + "/"):
            best = max(best, len(d.split("/")) if d else 0)
    return best


def _attach(components, eco, norm, group, db):
    """[(component, hits)]: each import or call goes to the version declared by the nearest project at or above its file,
    so a monorepo with boto3 1.34 in one service and 1.40 in another credits each file to its own. A file with no
    declaration above it goes to every candidate version."""
    targets = _targets(components, eco, norm, group, db)
    if len(targets) == 1:
        return [(targets[0], group)]
    out = {id(c): (c, []) for c in targets}
    for h in group:
        depths = [(_depth(c, h["file"]), c) for c in targets]
        deepest = max(d for d, _ in depths)
        for d, c in depths:
            if d == deepest:
                out[id(c)][1].append(h)
    return [v for v in out.values() if v[1]]


def find(root, files, db=None, deadline=None):
    """Read every dependency file and return the AI packages found, with what was read and any file that failed."""
    db = db or load_db()
    started = time.time()
    decls, read, problems, notes = [], [], [], []
    seen = set()
    for path, parser in select(files):
        if deadline and time.time() > deadline:
            problems.append({"file": path, "error": "not read: the time limit was reached"})
            continue
        try:
            got = parser(root, path)
        except Exception as exc:  # a broken or unusual file must not stop the scan; it is reported instead
            problems.append({"file": path, "error": f"{type(exc).__name__}: {str(exc)[:200]}"})
            continue
        notes += [n for n in getattr(got, "notes", []) if n not in notes]
        fresh = []
        for d in got:
            key = (d.file, d.line, d.ecosystem, normalize(d.ecosystem, d.name), d.version)
            if key not in seen:
                seen.add(key)
                fresh.append(d)
        decls += fresh
        read.append({"file": path, "entries": len(fresh), "left_out": left_out_reason(path)})

    _resolve_direct(decls)
    components, total, other = [], set(), {}
    for (eco, norm, version), g in sorted(_merge(decls).items()):
        reasons = {left_out_reason(d.file) for d in g["decls"]}
        left_out = "" if "" in reasons else sorted(reasons)[0]
        if not left_out:
            total.add((eco, norm, version))
        info = lookup_package(ECOSYSTEM_LABEL[eco], norm, db=db)
        if not info:
            # Not an AI package; kept aside, because a general SDK becomes one when code calls an AI service with it.
            other.setdefault((eco, norm), []).append(_component(eco, version, g, {}, left_out))
            continue
        components.append(_component(eco, version, g, info, left_out))

    # Imports in code (evidence level: imported). An import belongs to the version the project depends on directly;
    # transitive copies of the same package are not what its own code imports.
    declared = {(c["ecosystem"], normalize(c["ecosystem"], c["name"])) for c in components}
    hits = find_imports(root, files, declared=declared, db=db, deadline=deadline)
    for (eco, norm), group in sorted(_group(hits).items()):
        for c, mine in _attach(components, eco, norm, group, db):
            c["imports"] = _evidence(mine, ("module", "file", "line", "snippet", "left_out"))
            if any(not h["left_out"] for h in mine):
                c["evidence_level"] = "imported"

    # Calls in code (evidence level: called), credited to the package whose import bound the name.
    arguments = []
    calls = find_calls(root, files, hits, deadline=deadline, arguments=arguments)
    for (eco, norm), group in sorted(_group(calls).items()):
        services = sorted({h["service"] for h in group if h["service"]})
        if services and not any(c["ecosystem"] == eco and normalize(eco, c["name"]) == norm for c in components):
            # boto3 calling Bedrock: the versions of the SDK whose project makes the call are now AI packages; a copy
            # declared by a service that only uses S3 is not
            pool = list(other.get((eco, norm), []))
            pairs = _attach(pool, eco, norm, group, db)
            components += [c for c, _ in pairs]
        else:
            pairs = _attach(components, eco, norm, group, db)
        for c, mine in pairs:
            c["calls"] = _evidence(mine, ("rule", "what", "call", "operation", "file", "line", "snippet", "left_out"))
            if services:
                c["services"] = sorted({h["service"] for h in mine if h["service"]})
                c["category"] = c["category"] or "llm_sdk"
                c["vendor"] = c["vendor"] or SERVICE_VENDOR.get(norm, "")
            if any(not h["left_out"] for h in mine):
                c["evidence_level"] = "called"
    components.sort(key=lambda c: (c["ecosystem"], normalize(c["ecosystem"], c["name"]), c["version"]))
    kept = [c for c in components if not c["left_out"]]
    return {
        "packages": components,
        "model_arguments": arguments,  # for the model step: what live code passes into AI calls
        "files": read,
        "problems": problems,
        "notes": notes,  # what a file refers to but the scan could not follow, such as a missing -r file
        "summary": {
            "dependency_files": len(read),
            "packages_read": len(total),
            "ai_packages": len(kept),
            "ai_direct": sum(1 for c in kept if c["direct"] is True),
            "ai_transitive": sum(1 for c in kept if c["direct"] is False),
            "ai_left_out": len(components) - len(kept),
            "ai_imported": sum(1 for c in kept if c["evidence_level"] in ("imported", "called")),
            "ai_called": sum(1 for c in kept if c["evidence_level"] == "called"),
            "ai_imported_not_declared": sum(1 for c in kept if not c["declared"]),
            "has_lockfile": any(d.kind == "lock" for d in decls),
            "seconds": round(time.time() - started, 2),
        },
    }


__all__ = ["Declaration", "find", "select"]
