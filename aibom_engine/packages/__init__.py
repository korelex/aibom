"""Find the AI packages a project depends on, from its dependency files (evidence level: declared).

Every manifest and lockfile is parsed into Declarations (one per entry). Declarations of the same package are merged into
one component per package and version, with every file and line kept as evidence. Lockfiles list the whole installed
tree, so they are where transitive dependencies come from; a project with only a manifest gets its direct dependencies.

Only packages the database knows as AI packages are reported; the others are counted, so the report can say how much
was read.
"""
import fnmatch
import json
import os
import time

from ..db import load_db, lookup_package, vulnerability_check
from ..evidence import REACHABILITY
from .common import Declaration, left_out_reason, normalize, purl, read_text, vendored_dirs
from . import javascript, python
from .calls import find_calls
from .imports import find_imports
from .python import tomllib

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


def _workspace_globs(root, lock_dir, lock_name):
    """The workspace member patterns a lockfile's project declares, from the small files beside it."""
    def read(name):
        try:
            return read_text(root, os.path.join(lock_dir, name).replace("\\", "/"))
        except (OSError, ValueError):
            return None
    try:
        if lock_name in ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock"):
            ws = json.loads(read("package.json") or "{}").get("workspaces") or []
            return ws.get("packages", []) if isinstance(ws, dict) else ws
        if lock_name == "pnpm-lock.yaml":
            import yaml
            return (yaml.safe_load(read("pnpm-workspace.yaml") or "") or {}).get("packages") or []
        if lock_name == "uv.lock":
            data = tomllib.loads(read("pyproject.toml") or "")
            return ((data.get("tool") or {}).get("uv") or {}).get("workspace", {}).get("members") or []
    except Exception:
        return []
    return []


def _lock_scopes(root, decls):
    """{lockfile folder: the manifest folders it installs}: its own folder and its workspace members. A manifest below a
    lockfile that is not one of its members (a package.json in a sub-folder of a pnpm project whose workspace lists only the root) has
    its own installs, and does not get the lockfile's versions."""
    manifest_dirs = {os.path.dirname(d.file) for d in decls if d.kind == "manifest"}
    scopes = {}
    for d in decls:
        if d.kind != "lock":
            continue
        lock_dir = os.path.dirname(d.file)
        if lock_dir in scopes:
            continue
        covered = {lock_dir}
        for pattern in _workspace_globs(root, lock_dir, os.path.basename(d.file)):
            if not isinstance(pattern, str) or pattern.startswith("!"):
                continue
            pat = os.path.normpath(os.path.join(lock_dir, pattern)).replace("\\", "/").rstrip("/")
            pat = "" if pat == "." else pat
            covered |= {m for m in manifest_dirs if m == pat or fnmatch.fnmatch(m, pat)}
        scopes[lock_dir] = covered
    return scopes


def _project_of(path, scopes):
    """The folder of the lockfile that installs this manifest (the nearest one at or above it whose project includes
    it), or None when no lockfile does."""
    here = os.path.dirname(path)
    d = here
    while True:
        if d in scopes and here in scopes[d]:
            return d
        if not d:
            return None
        d = os.path.dirname(d)


def _resolve_direct(decls, scopes):
    """Lockfiles that do not mark direct dependencies (yarn.lock, package-lock v1, Pipfile.lock, poetry.lock) learn it
    from the manifests of their project: the same folder, or workspace folders below it without a lockfile of their own."""
    declared = {}
    for d in decls:
        if d.kind == "manifest":
            project = _project_of(d.file, scopes)
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


def _merge(decls, scopes):
    """One component per (ecosystem, package, version). A manifest range with a lockfile in the same project joins the
    version that lockfile resolved, so "langchain>=0.1" in pyproject.toml and "0.1.20" in uv.lock become one entry."""
    in_lock = {}
    for d in decls:
        if d.kind == "lock" and d.version:
            in_lock.setdefault((os.path.dirname(d.file), d.ecosystem, normalize(d.ecosystem, d.name)), []).append(d)

    def resolved_versions(d, norm):
        """The versions the project's lockfile installs for this declaration: one, or several when the lockfile itself
        marks several as direct (poetry.lock keeps one per Python version marker); [""] when it cannot be told."""
        project = _project_of(d.file, scopes)
        candidates = in_lock.get((project, d.ecosystem, norm)) if project is not None else None
        if not candidates:
            return [""]
        exact = [c for c in candidates if d.spec and d.spec in c.resolves]  # the lockfile names the range it resolved
        if exact:
            versions = {c.version for c in exact}
            return sorted(versions) if len(versions) == 1 else [""]
        direct = {c.version for c in candidates if c.direct is True}  # the versions the project itself depends on
        if direct:
            return sorted(direct)
        versions = {c.version for c in candidates}
        return sorted(versions) if len(versions) == 1 else [""]  # only transitive copies at several versions: do not guess

    groups = {}
    for d in decls:
        norm = normalize(d.ecosystem, d.name)
        for version in ([d.version] if d.version or d.kind != "manifest" else resolved_versions(d, norm)):
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


def _project_dir(path, dep_dirs):
    """The nearest folder at or above a file that holds a dependency file: the project the file belongs to; None when
    there is none (a notebook folder with no manifest)."""
    d = os.path.dirname(path)
    while True:
        if d in dep_dirs:
            return d
        if not d:
            return None
        d = os.path.dirname(d)


def _installed_for(path, candidates, scopes):
    """npm: the version Node itself would load for a file, by its own resolution rule: walk up the folders to the first
    one a lockfile installs that has the package (in that project's manifest or its lockfile). [] when none does."""
    d = os.path.dirname(path)
    while True:
        installer = next((lock for lock, covered in scopes.items() if d in covered), None)
        if installer is not None:
            mine = [c for c in candidates if any(os.path.dirname(e["file"]) in (d, installer) for e in c["evidence"])]
            if mine:
                return mine
        if not d:
            return []
        d = os.path.dirname(d)


def _attach(components, eco, norm, group, db, dep_dirs, scopes=None):
    """[(component, hits)]: each import or call goes to the version its own project declares or locks: the nearest
    folder with a dependency file at or above the file. A project that does not have the package (a notebook folder
    without a manifest, a plugin with its own pyproject.toml that never lists it) does not borrow another project's
    version: the hit goes to the package with no version, imported but not declared there.

    npm differs, because Node walks up the folders to find a package: a file gets the version installed for the
    nearest project above it that a lockfile installs, even through a nested package.json nothing installs from."""
    same = [c for c in components if c["ecosystem"] == eco and normalize(eco, c["name"]) == norm]
    candidates = [c for c in same if not c["left_out"]]
    out = {}
    for h in group:
        project = _project_dir(h["file"], dep_dirs)
        mine = _installed_for(h["file"], candidates, scopes or {}) if eco == "npm" else []
        if not mine:
            mine = [c for c in candidates if project is not None and any(os.path.dirname(e["file"]) == project for e in c["evidence"])]
        mine = [c for c in mine if c["direct"] is True] or mine  # the version the project itself depends on
        if not mine:
            # no version the file's own project has: the package without a version, declared that way elsewhere (a
            # range with no lockfile) or not declared at all; one such component per package
            unversioned = [c for c in candidates if c["version"] == ""] or [c for c in same if c["version"] == "" and not c["evidence"]]
            mine = unversioned[:1] or _targets([], eco, norm, [h], db)
            if mine[0] not in same:
                same.append(mine[0])
                components.append(mine[0])
        for c in mine:
            out.setdefault(id(c), (c, []))[1].append(h)
    for c, hits in out.values():
        if not c["evidence"]:  # not declared anywhere: left out only when every place that uses it is left out
            uses = hits + [u for u in c["imports"] + c["calls"] if u not in hits]
            c["left_out"] = "" if any(not u["left_out"] for u in uses) else sorted({u["left_out"] for u in uses})[0]
    return list(out.values())


def _own_packages(root, files):
    """(ecosystem, normalized name) of every package this repository defines: the name in each package.json and
    pyproject.toml. A file that does not parse is skipped; the dependency step reports it."""
    own = set()
    for fi in files:
        base = os.path.basename(fi.path)
        try:
            if base == "package.json":
                name = json.loads(read_text(root, fi.path) or "{}").get("name")
                eco = "npm"
            elif base == "pyproject.toml":
                data = tomllib.loads(read_text(root, fi.path))
                name = (data.get("project") or {}).get("name") or ((data.get("tool") or {}).get("poetry") or {}).get("name")
                eco = "pypi"
            else:
                continue
        except Exception:
            continue
        if isinstance(name, str) and name.strip():
            own.add((eco, normalize(eco, name)))
    return own


def find(root, files, db=None, deadline=None):
    """Read every dependency file and return the AI packages found, with what was read and any file that failed."""
    db = db or load_db()
    started = time.time()
    decls, read, problems, notes = [], [], [], []
    vendored = vendored_dirs(fi.path for fi in files)
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
        read.append({"file": path, "entries": len(fresh), "left_out": left_out_reason(path, vendored)})

    # The repository's own packages (its npm workspaces, its Python projects) are its code, not dependencies: a root
    # package.json that lists "@scope/server-memory": "*" is pointing at a folder of the same repository.
    own = _own_packages(root, files)
    decls = [d for d in decls if (d.ecosystem, normalize(d.ecosystem, d.name)) not in own]
    scopes = _lock_scopes(root, decls)
    dep_dirs = {"pypi": set(), "npm": set()}
    for path, parser in select(files):
        dep_dirs["pypi" if parser in [p for _, p in python.PARSERS] else "npm"].add(os.path.dirname(path))
    _resolve_direct(decls, scopes)
    components, total, other = [], set(), {}
    for (eco, norm, version), g in sorted(_merge(decls, scopes).items()):
        reasons = {left_out_reason(d.file, vendored) for d in g["decls"]}
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
    # Packages the project depends on itself settle shared import names (vertexai is in both vertexai and
    # google-cloud-aiplatform): a transitive copy in a lockfile is not what its code was written against.
    declared = {(c["ecosystem"], normalize(c["ecosystem"], c["name"])) for c in components if c["direct"] is not False}
    hits = find_imports(root, files, declared=declared, db=db, deadline=deadline, vendored=vendored)
    hits = [h for h in hits if (h["ecosystem"], normalize(h["ecosystem"], h["package"])) not in own]
    for (eco, norm), group in sorted(_group(hits).items()):
        for c, mine in _attach(components, eco, norm, group, db, dep_dirs[eco], scopes):
            c["imports"] = _evidence(mine, ("module", "file", "line", "snippet", "left_out"))
            if any(not h["left_out"] for h in mine):
                c["evidence_level"] = "imported"

    # Calls in code (evidence level: called), credited to the package whose import bound the name.
    arguments = []
    calls = find_calls(root, files, hits, deadline=deadline, arguments=arguments, vendored=vendored)
    for (eco, norm), group in sorted(_group(calls).items()):
        services = sorted({h["service"] for h in group if h["service"]})
        if services and not any(c["ecosystem"] == eco and normalize(eco, c["name"]) == norm for c in components):
            # boto3 calling Bedrock: the versions of the SDK whose project makes the call are now AI packages; a copy
            # declared by a service that only uses S3 is not
            pool = list(other.get((eco, norm), []))
            pairs = _attach(pool, eco, norm, group, db, dep_dirs[eco], scopes)
            components += [c for c, _ in pairs]
        else:
            pairs = _attach(components, eco, norm, group, db, dep_dirs[eco], scopes)
        for c, mine in pairs:
            c["calls"] = _evidence(mine, ("rule", "what", "call", "operation", "file", "line", "snippet", "left_out"))
            if services:
                c["services"] = sorted({h["service"] for h in mine if h["service"]})
                c["category"] = c["category"] or "llm_sdk"
                c["vendor"] = c["vendor"] or SERVICE_VENDOR.get(norm, "")
            if any(not h["left_out"] for h in mine):
                c["evidence_level"] = "called"
    components.sort(key=lambda c: (c["ecosystem"], normalize(c["ecosystem"], c["name"]), c["version"]))
    # Known vulnerabilities of each exact version (OSV advisories bundled in ai_db.json). A package without one exact
    # installed version is "not_checked", never "no vulnerabilities".
    for c in components:
        c["vulnerabilities"] = vulnerability_check(ECOSYSTEM_LABEL[c["ecosystem"]], c["name"], c["version"], db=db)
    kept = [c for c in components if not c["left_out"]]
    severities = [a["severity"] for c in kept for a in c["vulnerabilities"]["advisories"]]
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
            "vulnerable_packages": sum(1 for c in kept if c["vulnerabilities"]["advisories"]),
            "advisories": len(severities),
            "advisories_by_severity": {s: severities.count(s) for s in ("critical", "high", "medium", "low", "unknown") if s in severities},
            "not_checked": sum(1 for c in kept if c["vulnerabilities"]["status"] == "not_checked"),
            "advisory_data": (db.get("meta") or {}).get("vulnerabilities", {}).get("fetched", ""),
            "seconds": round(time.time() - started, 2),
        },
    }


__all__ = ["Declaration", "find", "select"]
