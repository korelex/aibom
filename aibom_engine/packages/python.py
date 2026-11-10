"""Python dependency files: requirements*.txt, pyproject.toml, Pipfile, Pipfile.lock, poetry.lock and uv.lock."""
import json
import os
import re

from packaging.requirements import InvalidRequirement, Requirement

from .common import Declaration, Parsed, line_of, read_text

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:  # pragma: no cover - exercised on Python 3.9 and 3.10
    import tomli as tomllib

REQUIREMENTS = re.compile(r"(^|/)(requirements[^/]*\.txt|[^/]*-requirements\.txt|requirements/[^/]+\.txt)$", re.IGNORECASE)
EXACT_POETRY = re.compile(r"^==?\s*\d+(\.\d+)*[a-z0-9.+-]*$|^\d+(\.\d+)*[a-z0-9.+-]*$", re.IGNORECASE)


def exact_version(specifier_set):
    """The pinned version when the requirement allows exactly one version (==1.2.3), else ""."""
    specs = list(specifier_set)
    if len(specs) == 1 and specs[0].operator in ("==", "===") and "*" not in specs[0].version:
        return specs[0].version
    return ""


def from_requirement(text, rel, line, kind="manifest", scope="runtime"):
    """One PEP 508 line ("openai==1.30.0", "langchain[openai]>=0.1; python_version>'3.8'") as a Declaration, or None."""
    try:
        req = Requirement(text)
    except InvalidRequirement:
        return None
    version = exact_version(req.specifier)
    spec = "" if version else (req.url or str(req.specifier))
    return Declaration("pypi", req.name, rel, line, kind, version=version, spec=spec, direct=True, scope=scope)


def parse_requirements(root, rel, seen=None):
    """A requirements file, following `-r other.txt`.

    Files written by pip-compile mark where each line comes from with "# via". A line that is there only because other
    packages need it is transitive; one that comes from the input file ("# via -r requirements.in") is direct.
    """
    seen = set() if seen is None else seen
    if rel in seen:
        return Parsed()
    seen.add(rel)
    lines = read_text(root, rel).split("\n")
    out, pending = Parsed(), None
    i = 0
    while i < len(lines):
        start = i
        raw = lines[i]
        while raw.rstrip().endswith("\\") and i + 1 < len(lines):  # line continuation, used by --hash lists
            i += 1
            raw = raw.rstrip()[:-1] + " " + lines[i]
        i += 1
        stripped = raw.strip()
        via = re.match(r"#\s*via\b(.*)", stripped)
        if via and pending is not None:
            sources = [via.group(1).strip()]
            while i < len(lines) and re.match(r"\s*#\s{2,}\S", lines[i]):  # "#   langchain" continuation lines
                sources.append(lines[i].strip().lstrip("#").strip())
                i += 1
            sources = [s for s in sources if s]
            pending.direct = any(s.startswith(("-r", "-c")) for s in sources)
            pending = None
            continue
        if not stripped or stripped.startswith("#"):
            continue
        text = re.sub(r"\s+#.*$", "", stripped)
        if re.match(r"^(-r|--requirement)\b", text):
            target = re.sub(r"^(-r|--requirement)[ =]?", "", text).strip()
            path = os.path.normpath(os.path.join(os.path.dirname(rel), target)).replace(os.sep, "/")
            if os.path.isfile(os.path.join(root, path)):
                sub = parse_requirements(root, path, seen)
                out += sub
                out.notes += sub.notes
            else:
                out.notes.append(f"{rel} line {start + 1} includes {target}, which is not in the repository, so the "
                                 f"packages it lists are not in the results")
            pending = None
            continue
        if text.startswith("-"):  # -e, -c, --index-url, --hash ...: not a package requirement
            pending = None
            continue
        text = re.split(r"\s--hash[ =]", text)[0].strip()
        d = from_requirement(text, rel, start + 1)
        if d:
            out.append(d)
        pending = d
    return out


def _quoted_line(lines, text):
    return line_of(lines, r"""["']""" + re.escape(text) + r"""(?=[\s\[<>=!~;@,"']|$)""") or line_of(lines, re.escape(text))


def parse_pyproject(root, rel):
    """PEP 621 [project] dependencies, PEP 735 dependency groups, and the Poetry, uv and PDM dependency tables."""
    text = read_text(root, rel)
    data = tomllib.loads(text)
    lines = text.split("\n")
    out = []

    def add_pep508(items, scope):
        for item in items or []:
            if not isinstance(item, str):
                continue  # {include-group = "..."} inside a dependency group
            d = from_requirement(item, rel, 0, scope=scope)
            if d:
                d.line = _quoted_line(lines, item.split(";")[0].strip()) or _quoted_line(lines, d.name)
                out.append(d)

    project = data.get("project") or {}
    add_pep508(project.get("dependencies"), "runtime")
    for items in (project.get("optional-dependencies") or {}).values():
        add_pep508(items, "optional")
    for items in (data.get("dependency-groups") or {}).values():
        add_pep508(items, "dev")
    tool = data.get("tool") or {}
    add_pep508((tool.get("uv") or {}).get("dev-dependencies"), "dev")
    for items in ((tool.get("pdm") or {}).get("dev-dependencies") or {}).values():
        add_pep508(items, "dev")

    poetry = tool.get("poetry") or {}
    tables = [(poetry.get("dependencies"), "runtime"), (poetry.get("dev-dependencies"), "dev")]
    for group, body in (poetry.get("group") or {}).items():
        tables.append(((body or {}).get("dependencies"), "runtime" if group == "main" else "dev"))
    for table, scope in tables:
        for name, value in (table or {}).items():
            if name.lower() == "python":
                continue
            spec = str(value.get("version", "")) if isinstance(value, dict) else str(value)
            here = "optional" if isinstance(value, dict) and value.get("optional") else scope
            version = spec.lstrip("= ") if EXACT_POETRY.match(spec.strip()) else ""
            line = line_of(lines, r"^\s*[\"']?" + re.escape(name) + r"[\"']?\s*=")
            out.append(Declaration("pypi", name, rel, line, "manifest", version=version, spec="" if version else spec, direct=True, scope=here))
    return out


def parse_pipfile(root, rel):
    text = read_text(root, rel)
    data = tomllib.loads(text)
    lines = text.split("\n")
    out = []
    for section, scope in (("packages", "runtime"), ("dev-packages", "dev")):
        for name, value in (data.get(section) or {}).items():
            spec = str(value.get("version", "")) if isinstance(value, dict) else str(value)
            spec = "" if spec == "*" else spec
            version = spec[2:] if spec.startswith("==") and "*" not in spec else ""
            line = line_of(lines, r"^\s*[\"']?" + re.escape(name) + r"[\"']?\s*=")
            out.append(Declaration("pypi", name, rel, line, "manifest", version=version, spec="" if version else spec, direct=True, scope=scope))
    return out


def parse_pipfile_lock(root, rel):
    text = read_text(root, rel)
    data = json.loads(text)
    lines = text.split("\n")
    out = []
    for section, scope in (("default", "runtime"), ("develop", "dev")):
        start = line_of(lines, r'^\s*"' + section + r'"\s*:') or 1
        for name, value in (data.get(section) or {}).items():
            version = str((value or {}).get("version", ""))
            version = version[2:] if version.startswith("==") else ""
            line = line_of(lines, r'^\s*"' + re.escape(name) + r'"\s*:', start - 1)
            out.append(Declaration("pypi", name, rel, line, "lock", version=version, scope=scope))
    return out


def _package_lines(lines):
    """Line of each [[package]] entry of a TOML lockfile, keyed by (lowercase name, version)."""
    where, name, name_line = {}, None, 0
    for i, line in enumerate(lines):
        if line.strip() == "[[package]]":
            name = None
            continue
        if name is None:
            m = re.match(r'^name\s*=\s*"([^"]+)"', line)
            if m:
                name, name_line = m.group(1).lower(), i + 1
            continue
        m = re.match(r'^version\s*=\s*"([^"]+)"', line)
        if m:
            where.setdefault((name, m.group(1)), name_line)
    return where


def parse_poetry_lock(root, rel):
    text = read_text(root, rel)
    data = tomllib.loads(text)
    where = _package_lines(text.split("\n"))
    out = []
    for pkg in data.get("package") or []:
        name, version = pkg.get("name", ""), str(pkg.get("version", ""))
        groups = pkg.get("groups") or ([pkg["category"]] if pkg.get("category") else [])
        scope = "runtime" if not groups or "main" in groups else "dev"
        if pkg.get("optional"):
            scope = "optional"
        out.append(Declaration("pypi", name, rel, where.get((name.lower(), version), 0), "lock", version=version, scope=scope))
    return out


def parse_uv_lock(root, rel):
    """uv.lock lists every resolved package. The project itself (source editable or virtual) names the direct ones."""
    text = read_text(root, rel)
    data = tomllib.loads(text)
    where = _package_lines(text.split("\n"))
    packages = data.get("package") or []
    direct, optional, dev, local = set(), set(), set(), set()
    for pkg in packages:
        source = pkg.get("source") or {}
        if "editable" in source or "virtual" in source:
            local.add(pkg.get("name", "").lower())
            direct.update(d.get("name", "").lower() for d in pkg.get("dependencies") or [])
            for deps in (pkg.get("optional-dependencies") or {}).values():
                optional.update(d.get("name", "").lower() for d in deps)
            for deps in (pkg.get("dev-dependencies") or {}).values():
                dev.update(d.get("name", "").lower() for d in deps)
    out = []
    for pkg in packages:
        name, version = pkg.get("name", ""), str(pkg.get("version", ""))
        low = name.lower()
        if low in local:
            continue  # the project itself or a workspace member, not a dependency
        is_direct = (low in direct or low in optional or low in dev) if local else None
        scope = "runtime" if low in direct or not is_direct else ("optional" if low in optional else "dev")
        out.append(Declaration("pypi", name, rel, where.get((low, version), 0), "lock", version=version, direct=is_direct, scope=scope))
    return out


def _named(filename):
    return lambda path: path.rsplit("/", 1)[-1] == filename


PARSERS = [
    (lambda path: bool(REQUIREMENTS.search(path)), parse_requirements),
    (_named("pyproject.toml"), parse_pyproject),
    (_named("Pipfile"), parse_pipfile),
    (_named("Pipfile.lock"), parse_pipfile_lock),
    (_named("poetry.lock"), parse_poetry_lock),
    (_named("uv.lock"), parse_uv_lock),
]
