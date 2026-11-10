"""JavaScript and TypeScript dependency files: package.json, package-lock.json, pnpm-lock.yaml and yarn.lock."""
import json
import re

import yaml

from .common import Declaration, line_of, read_text

SECTIONS = (("dependencies", "runtime"), ("devDependencies", "dev"), ("optionalDependencies", "optional"), ("peerDependencies", "peer"))
EXACT = re.compile(r"^=?v?(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?)$")
LOCAL = ("workspace:", "file:", "link:", "portal:", "patch:")

try:  # the C loader is much faster on large lockfiles, when PyYAML was built with it
    YAML_LOADER = yaml.CSafeLoader
except AttributeError:  # pragma: no cover
    YAML_LOADER = yaml.SafeLoader


def exact(spec):
    """"1.2.3" or "=1.2.3" pins one version; "^1.2.3", "~1.2", "latest" and git URLs do not."""
    m = EXACT.match(str(spec).strip())
    return m.group(1) if m else ""


def _key_lines(lines, pattern):
    """{key: line} for every line matching `pattern` (group 1 is the key)."""
    rx, where = re.compile(pattern), {}
    for i, line in enumerate(lines):
        m = rx.match(line)
        if m:
            where.setdefault(m.group(1), i + 1)
    return where


def parse_package_json(root, rel):
    text = read_text(root, rel)
    data = json.loads(text)
    lines = text.split("\n")
    out = []
    for section, scope in SECTIONS:
        start = line_of(lines, r'"' + section + r'"\s*:') or 1  # a compact package.json can hold everything on one line
        for name, spec in (data.get(section) or {}).items():
            spec = str(spec)
            if spec.startswith(LOCAL):
                continue  # a package of this repository, not a dependency
            version = exact(spec)
            line = line_of(lines, r'"' + re.escape(name) + r'"\s*:', start - 1) or start
            out.append(Declaration("npm", name, rel, line, "manifest", version=version, spec="" if version else spec, direct=True, scope=scope))
    return out


def parse_package_lock(root, rel):
    """package-lock.json: version 2 and 3 list every installed package under "packages"; version 1 nests "dependencies"."""
    text = read_text(root, rel)
    data = json.loads(text)
    lines = text.split("\n")
    out = []
    packages = data.get("packages")
    if isinstance(packages, dict):
        direct = set()
        for key, entry in packages.items():  # the root ("") and workspace members list what they depend on directly
            if key == "" or "node_modules/" not in key:
                for section, _ in SECTIONS:
                    direct.update(n.lower() for n in (entry.get(section) or {}))
        where = _key_lines(lines, r'^\s*"((?:[^"]*/)?node_modules/[^"]+)"\s*:')
        for key, entry in packages.items():
            if "node_modules/" not in key or entry.get("link"):
                continue
            name = entry.get("name") or key.rsplit("node_modules/", 1)[1]
            nested = key.count("node_modules/") > 1  # a second copy, inside another package
            scope = "dev" if entry.get("dev") or entry.get("devOptional") else ("optional" if entry.get("optional") else
                                                                               ("peer" if entry.get("peer") else "runtime"))
            out.append(Declaration("npm", name, rel, where.get(key, 0), "lock", version=str(entry.get("version", "")),
                                   direct=(not nested) and name.lower() in direct, scope=scope))
        return out

    where = _key_lines(lines, r'^\s*"([^"]+)"\s*:\s*\{')

    def walk(deps, depth):
        for name, entry in (deps or {}).items():
            scope = "dev" if entry.get("dev") else ("optional" if entry.get("optional") else "runtime")
            out.append(Declaration("npm", name, rel, where.get(name, 0), "lock", version=str(entry.get("version", "")),
                                   direct=None if depth == 0 else False, scope=scope))
            walk(entry.get("dependencies"), depth + 1)

    walk(data.get("dependencies"), 0)  # version 1 does not mark direct dependencies; package.json in the same folder does
    return out


def _pnpm_key(key):
    """Name and version from a pnpm package key: "name@1.2.3" (v9), "/name@1.2.3(peer@1)" (v6), "/name/1.2.3_peer" (v5)."""
    k = key.strip("'\"").lstrip("/")
    k = k.split("(", 1)[0]
    v5 = re.match(r"^(@[^/@]+/[^/@]+|[^/@][^/@]*)/(\d[^/]*)$", k)
    if v5:
        return v5.group(1), v5.group(2).split("_", 1)[0]
    at = k.find("@", 1)
    if at > 0 and not k[at + 1:].startswith(("npm:", "http")) and "/" not in k[at + 1:]:
        return k[:at], k[at + 1:]
    head, _, version = k.rpartition("/")  # v5: /@scope/name/1.2.3 or /name/1.2.3
    return head, version.split("_", 1)[0]


def parse_pnpm_lock(root, rel):
    text = read_text(root, rel)
    data = yaml.load(text, Loader=YAML_LOADER) or {}
    lines = text.split("\n")
    importers = data.get("importers") or {".": data}  # single-project v5 files keep dependencies at the top level
    direct, direct_scope = set(), {}
    for imp in importers.values():
        for section, scope in SECTIONS:
            for name, spec in (imp.get(section) or {}).items():
                resolved = spec.get("version", "") if isinstance(spec, dict) else str(spec)  # v6+: {specifier, version}; v5: the version
                resolved = str(resolved).split("(", 1)[0].split("_", 1)[0]
                if resolved.startswith(LOCAL):
                    continue
                direct.add((name.lower(), resolved))
                direct_scope.setdefault((name.lower(), resolved), scope)
    where = {}
    for i, line in enumerate(lines):
        m = re.match(r"^  (['\"]?/?[^\s'\"][^:]*?['\"]?):\s*$", line)
        if m:
            where.setdefault(m.group(1).strip("'\""), i + 1)
    out = []
    for key, entry in (data.get("packages") or {}).items():
        name, version = _pnpm_key(key)
        if not name or version.startswith(LOCAL):
            continue
        entry = entry or {}
        here = (name.lower(), version)
        if entry.get("dev") is True:
            scope = "dev"
        elif entry.get("optional") is True:
            scope = "optional"
        elif here in direct_scope:
            scope = direct_scope[here]
        else:
            scope = "runtime" if "dev" in entry else "unknown"  # v9 does not say whether a transitive package is only for development
        out.append(Declaration("npm", name, rel, where.get(key.strip("'\""), 0), "lock", version=version, direct=here in direct, scope=scope))
    return out


def parse_yarn_lock(root, rel):
    """yarn.lock, both the classic v1 format and the YAML-style format of Yarn 2 and later ("berry")."""
    lines = read_text(root, rel).split("\n")
    out, current = [], None
    for i, line in enumerate(lines):
        if not line or line.startswith("#"):
            continue
        if not line.startswith(" ") and line.rstrip().endswith(":"):
            header = line.rstrip()[:-1]
            first = header.split(",")[0].strip().strip('"')
            if first == "__metadata" or "@workspace:" in header or "@file:" in header or "@link:" in header:
                current = None
                continue
            at = first.rfind("@")
            name = first[:at] if at > 0 else first
            ranges = []
            for descriptor in header.split(","):
                descriptor = descriptor.strip().strip('"')
                cut = descriptor.rfind("@")
                if cut > 0:
                    ranges.append(re.sub(r"^npm:", "", descriptor[cut + 1:]))
            current = Declaration("npm", name, rel, i + 1, "lock", direct=None, resolves=ranges)
            continue
        m = re.match(r'^\s+version:?\s+"?([^"\s]+)"?\s*$', line)
        if m and current is not None:
            current.version = m.group(1)
            out.append(current)
            current = None
    return out  # yarn.lock does not mark direct dependencies; package.json in the same folder does


def _named(filename):
    return lambda path: path.rsplit("/", 1)[-1] == filename


PARSERS = [
    (_named("package.json"), parse_package_json),
    (_named("package-lock.json"), parse_package_lock),
    (_named("pnpm-lock.yaml"), parse_pnpm_lock),
    (_named("yarn.lock"), parse_yarn_lock),
]
