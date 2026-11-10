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
from .common import Declaration, left_out_reason, normalize, purl
from . import javascript, python

PARSERS = python.PARSERS + javascript.PARSERS
ECOSYSTEM_LABEL = {"pypi": "PyPI", "npm": "npm"}
SCOPE_ORDER = ("runtime", "optional", "peer", "dev", "unknown")


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


def find(root, files, db=None, deadline=None):
    """Read every dependency file and return the AI packages found, with what was read and any file that failed."""
    db = db or load_db()
    started = time.time()
    decls, read, problems = [], [], []
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
        fresh = []
        for d in got:
            key = (d.file, d.line, d.ecosystem, normalize(d.ecosystem, d.name), d.version)
            if key not in seen:
                seen.add(key)
                fresh.append(d)
        decls += fresh
        read.append({"file": path, "entries": len(fresh), "left_out": left_out_reason(path)})

    _resolve_direct(decls)
    components, total = [], set()
    for (eco, norm, version), g in sorted(_merge(decls).items()):
        reasons = {left_out_reason(d.file) for d in g["decls"]}
        left_out = "" if "" in reasons else sorted(reasons)[0]
        if not left_out:
            total.add((eco, norm, version))
        info = lookup_package(ECOSYSTEM_LABEL[eco], norm, db=db)
        if not info:
            continue
        flags = [d.direct for d in g["decls"]]
        direct = True if True in flags else (False if flags and all(f is False for f in flags) else None)
        scopes = {d.scope for d in g["decls"]}
        lock_name = next((d.name for d in g["decls"] if d.kind == "lock"), g["names"][0])
        components.append({
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
            "left_out": left_out,
            "evidence": [{"file": d.file, "line": d.line, "kind": d.kind, "direct": d.direct, "scope": d.scope}
                         for d in sorted(g["decls"], key=lambda d: (d.file, d.line))],
        })
    kept = [c for c in components if not c["left_out"]]
    return {
        "packages": components,
        "files": read,
        "problems": problems,
        "summary": {
            "dependency_files": len(read),
            "packages_read": len(total),
            "ai_packages": len(kept),
            "ai_direct": sum(1 for c in kept if c["direct"] is True),
            "ai_transitive": sum(1 for c in kept if c["direct"] is False),
            "ai_left_out": len(components) - len(kept),
            "has_lockfile": any(d.kind == "lock" for d in decls),
            "seconds": round(time.time() - started, 2),
        },
    }


__all__ = ["Declaration", "find", "select"]
