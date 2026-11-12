"""MCP servers declared in a project's config files (M3.1).

An MCP server is a program or a web service an AI tool is allowed to call. Editors and agents list them in small config
files that live in the repository (`.mcp.json`, `.cursor/mcp.json`, ...). This reads those files as text, never starts a
server, and records for each server what it is, how it is started and where in the file it is declared.

Formats are the ones the tools document (checked against their documentation on 2026-11-12):
  .mcp.json                 key "mcpServers"          Claude Code, and the workspace file VS Code reads
  .cursor/mcp.json          key "mcpServers"          Cursor
  .vscode/mcp.json          key "servers"             VS Code (the older editor-managed file)
  .gemini/settings.json     key "mcpServers"          Gemini CLI (`url` is SSE, `httpUrl` is streamable HTTP)
  .codex/config.toml        tables [mcp_servers.NAME] Codex
  claude_desktop_config.json key "mcpServers"         Claude Desktop (a user file that sometimes sits in a repository)
  any other *mcp*.json with an "mcpServers" or "servers" object of server-like entries.

What is recorded about a server never includes a secret: environment variables and HTTP headers are kept as NAMES only, a
URL loses its user name, password, query string and fragment, and every other text goes through the same redaction as every
other finding (a value after `--token` or `--api-key=...` is masked too).
"""
import os
import re
import time
from dataclasses import asdict, dataclass, field
from urllib.parse import urlsplit

from . import jsonc
from .packages.common import left_out_reason, normalize, purl
from .packages.python import tomllib
from .redact import PLACEHOLDER, redact
from .triage import MAX_BYTES, SKIP_DIRS

# A project's own .vscode folder is where VS Code keeps mcp.json, so unlike the other scan steps this one reads it.
WALK_SKIP = SKIP_DIRS - {".vscode"}
SECRET_FLAG = re.compile(r"key|secret|token|passw|pwd|auth|credential|bearer", re.I)
MASK = "*"

# (path suffix, what the client is called, the keys that hold the servers). Matched on the lower-cased path.
KNOWN = (
    (".cursor/mcp.json", "Cursor", ("mcpServers",)),
    (".vscode/mcp.json", "VS Code", ("servers", "mcpServers")),
    (".gemini/settings.json", "Gemini CLI", ("mcpServers",)),
    (".mcp.json", "Claude Code or VS Code", ("mcpServers",)),
    ("claude_desktop_config.json", "Claude Desktop", ("mcpServers",)),
)
CODEX = ".codex/config.toml"
LOOKS_LIKE_A_SERVER = ("command", "url", "httpUrl", "type")


@dataclass
class McpServer:
    name: str
    client: str                  # which tool reads this file
    file: str
    line: int
    transport: str               # stdio, http, sse, remote (a URL with no stated type), or unknown
    command: str = ""
    args: list = field(default_factory=list)
    url: str = ""                # scheme, host and path only
    url_has_query: bool = False
    url_has_credentials: bool = False
    env_keys: list = field(default_factory=list)       # names only, never values
    header_names: list = field(default_factory=list)   # names only, never values
    enabled: object = None       # False when the config switches it off
    launcher: str = ""           # npx, uvx, pipx, docker, node, python, ... (what runs the server)
    package: str = ""            # the npm or PyPI package, or the container image, the launcher fetches and runs
    ecosystem: str = ""          # npm, pypi, docker, source (a git URL or a path) or ""
    version: str = ""
    pinned: object = None        # True when an exact version or digest is given, False when not, None when no package
    left_out: str = ""           # test, example, docs, vendored: the file is not the product's own
    note: str = ""               # why a field is missing, when it is

    def to_dict(self):
        return asdict(self)


# ---- what a value looks like once it is safe to keep ----

def _safe_text(value):
    return redact(str(value))


def scrub_args(args):
    """The arguments as text with secrets masked: pattern-based (a key shape), and the value of a flag whose name says it is one."""
    out, mask_next = [], False
    for raw in args:
        a = _safe_text(raw)
        if mask_next:
            mask_next = False
            if not a.startswith("-") and a and not PLACEHOLDER.match(a) and MASK * len(a) != a:
                a = MASK * len(a)
        elif a.startswith("-") and "=" in a:
            flag, _, val = a.partition("=")
            if SECRET_FLAG.search(flag) and val and not PLACEHOLDER.match(val) and MASK * len(val) != val:
                a = flag + "=" + MASK * len(val)
        elif a.startswith("-") and SECRET_FLAG.search(a):
            mask_next = True
        out.append(a)
    return out


def safe_url(raw):
    """(url without credentials, query or fragment, had a query, had credentials)."""
    text = str(raw).strip()
    try:
        parts = urlsplit(text)
        userinfo, at, host = parts.netloc.rpartition("@")  # the host text is kept as written: a ${HOST} placeholder must stay ${HOST}
        if not parts.scheme or not host:
            return _safe_text(text.split("?")[0].split("#")[0]), "?" in text, False
        return _safe_text(f"{parts.scheme}://{host}{parts.path}"), bool(parts.query), bool(at)
    except ValueError:
        return _safe_text(text.split("?")[0].split("#")[0]), "?" in text, False


# ---- how a stdio server is started ----

SEMVER = re.compile(r"^v?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.+-]*)?$")
PEP440_EXACT = re.compile(r"^\d+(?:\.\d+)*(?:(?:a|b|rc|\.post|\.dev)\d+)*$")
NPM_NAME = re.compile(r"^(?:@[a-z0-9~][a-z0-9._~-]*/)?[a-z0-9~][a-z0-9._~-]*$", re.I)
PYPI_SPEC = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*(==|@|>=|<=|~=|!=|>|<)?\s*(.*)$")
NPX_BOOLEAN = {"-y", "--yes", "-q", "--quiet", "--no", "--no-install", "--offline", "--prefer-offline", "--prefer-online", "--ignore-existing", "-n", "--no-yes"}
NPX_VALUE = {"--registry", "--userconfig", "--cache", "--prefix", "--loglevel", "--node-options"}
UV_VALUE = {"--from", "--with", "--python", "-p", "--with-requirements", "--index", "--index-url", "--extra-index-url", "--default-index", "--env-file",
            "--directory", "--project", "--with-editable", "--refresh-package", "-w", "--prerelease", "--resolution", "--constraints", "--overrides",
            "--cache-dir", "--config-file", "--link-mode", "--keyring-provider"}
UV_BOOLEAN = {"--isolated", "--no-cache", "-n", "--quiet", "-q", "--verbose", "-v", "--offline", "--no-config", "--refresh", "--native-tls", "--no-progress", "--no-python-downloads", "--no-managed-python"}
PIPX_VALUE = {"--spec", "--python", "--pip-args", "--index-url"}
DOCKER_VALUE = {"-e", "--env", "-v", "--volume", "-p", "--publish", "--name", "-w", "--workdir", "--network", "--net", "--entrypoint", "-u", "--user",
                "--env-file", "--mount", "--platform", "--label", "-l", "--add-host", "--cap-add", "--cap-drop", "--memory", "-m", "--cpus", "--pull"}
DOCKER_BOOLEAN = {"--rm", "-i", "--interactive", "-t", "--tty", "-it", "-d", "--detach", "--init", "--read-only", "--privileged", "-a"}


def _base(command):
    name = os.path.basename(str(command).replace("\\", "/")).lower()
    return re.sub(r"\.(cmd|exe|bat|ps1)$", "", name)


def _empty():
    return {"launcher": "", "package": "", "ecosystem": "", "version": "", "pinned": None}


def _npm(spec):
    spec = spec.strip()
    if not spec:
        return _empty()
    cut = spec.rfind("@")
    name, version = (spec[:cut], spec[cut + 1:]) if cut > 0 else (spec, "")
    if not NPM_NAME.match(name):
        return {"launcher": "", "package": _safe_text(spec), "ecosystem": "source", "version": "", "pinned": False}
    return {"launcher": "", "package": name.lower(), "ecosystem": "npm", "version": version, "pinned": bool(SEMVER.match(version))}


def _pypi(spec):
    spec = spec.strip()
    if not spec:
        return _empty()
    if "://" in spec or spec.startswith(("git+", ".", "/", "~")):
        return {"launcher": "", "package": _safe_text(spec.split("#")[0]), "ecosystem": "source", "version": "", "pinned": False}
    m = PYPI_SPEC.match(spec)
    if not m:
        return {"launcher": "", "package": _safe_text(spec), "ecosystem": "source", "version": "", "pinned": False}
    name, _extras, op, rest = m.groups()
    version = rest.strip() if op else ""
    exact = op in ("==", "@") and bool(PEP440_EXACT.match(version))
    return {"launcher": "", "package": normalize("pypi", name), "ecosystem": "pypi", "version": version if op else "", "pinned": exact}


def _scan_options(args, boolean, value, package_flags=()):
    """Walk the arguments of a launcher up to the first positional one.

    Returns (package flag values found, the first positional argument, the arguments after it) or None when an option is not
    known, because then a value could be mistaken for the package and a guess would be a false claim."""
    found, i = [], 0
    while i < len(args):
        a = str(args[i])
        if a == "--":
            i += 1
            break
        if not a.startswith("-"):
            break
        flag, eq, val = a.partition("=")
        if flag in package_flags:
            if eq:
                found.append(val)
            elif i + 1 < len(args):
                found.append(str(args[i + 1]))
                i += 1
        elif flag in value:
            i += 0 if eq else 1
        elif flag in boolean and not eq:
            pass
        else:
            return None
        i += 1
    if i < len(args):
        return found, str(args[i]), args[i + 1:]
    return found, "", []


def parse_launcher(command, args):
    """What a stdio server fetches and runs: {launcher, package, ecosystem, version, pinned}. Fields stay empty when it cannot be told."""
    args = [str(a) for a in args]
    base = _base(command)
    if base == "cmd" and args and args[0].lower() in ("/c", "/k") and len(args) > 1:  # Windows: cmd /c npx ...
        base, args = _base(args[1]), args[2:]
    out = _empty()
    out["launcher"] = base
    if base in ("npx", "pnpx", "bunx") or (base in ("pnpm", "yarn") and args[:1] == ["dlx"]):
        rest = args[1:] if base in ("pnpm", "yarn") else args
        scanned = _scan_options(rest, NPX_BOOLEAN | {"--bun", "-b"}, NPX_VALUE, ("-p", "--package"))  # -c runs a shell string: not a known option, so no guess
        if scanned:
            packages, first, _ = scanned
            spec = packages[0] if packages else first
            if spec:
                out.update(_npm(spec), launcher=base if base not in ("pnpm", "yarn") else base + " dlx")
        return out
    if base in ("uvx", "uv") and (base == "uvx" or args[:2] == ["tool", "run"]):
        rest = args if base == "uvx" else args[2:]
        scanned = _scan_options(rest, UV_BOOLEAN, UV_VALUE, ("--from",))
        if scanned:
            packages, first, _ = scanned
            spec = packages[0] if packages else first
            if spec:
                out.update(_pypi(spec), launcher="uvx")
        out["launcher"] = "uvx"
        return out
    if base == "pipx" and args[:1] == ["run"]:
        scanned = _scan_options(args[1:], set(), PIPX_VALUE, ("--spec",))
        if scanned:
            packages, first, _ = scanned
            spec = packages[0] if packages else first
            if spec:
                out.update(_pypi(spec), launcher="pipx")
        return out
    if base in ("docker", "podman") and args[:1] == ["run"]:
        scanned = _scan_options(args[1:], DOCKER_BOOLEAN, DOCKER_VALUE)
        if scanned and scanned[1]:
            image = scanned[1]
            digest = image.partition("@")[2]
            name = image.partition("@")[0]
            tag = ""
            if not digest and ":" in name.rsplit("/", 1)[-1]:
                name, _, tag = name.rpartition(":")
            version = digest or tag
            out.update(package=_safe_text(name), ecosystem="docker", version=version, pinned=bool(digest) or bool(tag and SEMVER.match(tag)))
        return out
    return out


# ---- reading one server entry ----

def _transport(client, entry):
    declared = str(entry.get("type", "")).strip().lower()
    if declared in ("stdio", "local"):
        return "stdio"
    if declared in ("http", "streamable-http", "streamable_http", "streamablehttp"):
        return "http"
    if declared == "sse":
        return "sse"
    if declared:
        return declared
    if entry.get("command"):
        return "stdio"
    if entry.get("httpUrl"):
        return "http"
    if entry.get("url"):
        return "sse" if client == "Gemini CLI" else "remote"
    return "unknown"


def _names(value):
    return sorted(str(k) for k in value) if isinstance(value, dict) else []


def _header_names(entry):
    """The names of the HTTP headers a server sends: its `headers`, Codex's `http_headers`, and Authorization when a bearer token is set by name."""
    names = set(_names(entry.get("headers"))) | set(_names(entry.get("http_headers")))
    if entry.get("bearer_token_env_var"):
        names.add("Authorization")
    return sorted(names)


def server_from_entry(name, entry, client, rel, line):
    """An McpServer from one entry of a config file (a dict), or None when it is not a mapping."""
    if not isinstance(entry, dict):
        return None
    transport = _transport(client, entry)
    command = entry.get("command")
    args = entry.get("args") if isinstance(entry.get("args"), list) else []
    raw_url = entry.get("httpUrl") or entry.get("url") or ""
    url, has_query, has_credentials = safe_url(raw_url) if raw_url else ("", False, False)
    s = McpServer(name=_safe_text(name), client=client, file=rel, line=line, transport=transport,
                  command=_safe_text(command) if isinstance(command, str) else "", args=scrub_args(args), url=url,
                  url_has_query=has_query, url_has_credentials=has_credentials,
                  env_keys=_names(entry.get("env")), header_names=_header_names(entry))
    if entry.get("enabled") is False or entry.get("disabled") is True:
        s.enabled = False
    if transport == "stdio" and isinstance(command, str) and command:
        for key, value in parse_launcher(command, args).items():
            setattr(s, key, value)
    if transport == "unknown":
        s.note = "the entry has neither a command nor a URL"
    elif transport == "stdio" and not s.command:
        s.note = "a stdio server with no command"
    elif transport in ("http", "sse", "remote") and not s.url:
        s.note = "a remote server with no URL"
    return s


def _servers_in_json(client, keys, node, rel, only_server_like=False):
    found = []
    for key in keys:
        group = node.get(key) if isinstance(node, dict) else None
        if isinstance(group, dict):
            for name, entry in group.items():
                if only_server_like and not (isinstance(entry, dict) and any(k in entry for k in LOOKS_LIKE_A_SERVER)):
                    continue
                s = server_from_entry(name, entry, client, rel, group.lines.get(name, 0) if isinstance(group, jsonc.Node) else 0)
                if s:
                    found.append(s)
    return found


def _servers_in_toml(text, rel):
    data = tomllib.loads(text)
    table = data.get("mcp_servers")
    if not isinstance(table, dict):
        return []
    lines = text.split("\n")
    found = []
    for name, entry in table.items():
        quoted = re.escape(name)
        header = re.compile(r"^\s*\[\s*mcp_servers\s*\.\s*(?:%s|\"%s\"|'%s')\s*(?:\]|\.)" % (quoted, quoted, quoted))
        line = next((i + 1 for i, text_line in enumerate(lines) if header.match(text_line)), 0)
        s = server_from_entry(name, entry, "Codex", rel, line)
        if s:
            if isinstance(entry, dict) and entry.get("url") and s.transport == "remote":
                s.transport = "http"  # Codex documents `url` servers as streamable HTTP
            found.append(s)
    return found


def read_config(rel, text):
    """The servers declared in one file, as (servers, client), or ([], "") when the file is not an MCP config of a known kind.
    Raises ValueError for a known config name whose text cannot be parsed."""
    low = rel.lower()
    if low == CODEX or low.endswith("/" + CODEX):
        return _servers_in_toml(text, rel), "Codex"
    for suffix, client, keys in KNOWN:
        if low == suffix or low.endswith("/" + suffix) or (not suffix.startswith(".") and os.path.basename(low) == suffix):
            return _servers_in_json(client, keys, jsonc.loads(text), rel), client
    base = os.path.basename(low)
    if base.endswith(".json") and "mcp" in base:
        try:
            node = jsonc.loads(text)
        except jsonc.JsoncError:
            return [], ""  # a JSON file that only has "mcp" in its name is not necessarily one
        return _servers_in_json("an MCP config", ("mcpServers", "servers"), node, rel, only_server_like=True), "an MCP config"
    return [], ""


def _candidate(rel):
    low = rel.lower()
    base = os.path.basename(low)
    if low == CODEX or low.endswith("/" + CODEX):
        return True
    if any(low == s or low.endswith("/" + s) or (not s.startswith(".") and base == s) for s, _, _ in KNOWN):
        return True
    return base.endswith(".json") and "mcp" in base


def find(root, deadline=None):
    """Every MCP server declared under `root`: {"servers": [McpServer dicts], "files": [...], "problems": [...], "partial": True when the time limit stopped the search}."""
    deadline = deadline or (time.time() + 120)
    servers, files, problems, partial = [], [], [], False
    for base, dirs, names in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in WALK_SKIP)
        if time.time() > deadline:
            partial = True  # the caller says so: a missing server must never be silent
            break
        for name in sorted(names):
            path = os.path.join(base, name)
            rel = os.path.relpath(path, root).replace(os.sep, "/")
            if not _candidate(rel) or os.path.islink(path):
                continue
            try:
                if os.path.getsize(path) > MAX_BYTES:
                    problems.append({"file": rel, "error": "larger than 1.5 MB, not read"})
                    continue
                with open(path, encoding="utf-8-sig", errors="replace") as fh:
                    text = fh.read()
                got, client = read_config(rel, text)
            except (OSError, ValueError) as e:  # a bad file is reported and the scan goes on (tomllib and jsonc errors are ValueErrors)
                problems.append({"file": rel, "error": _safe_text(str(e))[:200]})
                continue
            if not got:
                continue
            reason = left_out_reason(rel)
            for s in got:
                s.left_out = reason
            files.append({"file": rel, "client": client, "servers": len(got), "left_out": reason})
            servers += got
    servers.sort(key=lambda s: (bool(s.left_out), s.file, s.line, s.name))
    return {"servers": [s.to_dict() for s in servers], "files": files, "problems": problems, "partial": partial}


def summary(found):
    live = [s for s in found["servers"] if not s["left_out"]]
    return {"servers": len(live), "stdio": sum(1 for s in live if s["transport"] == "stdio"),
            "remote": sum(1 for s in live if s["transport"] in ("http", "sse", "remote")),
            "config_files": sum(1 for f in found["files"] if not f["left_out"]), "left_out": len(found["servers"]) - len(live)}


def component_purl(server):
    """The package URL of the npm or PyPI package a server runs, or ""."""
    if server["ecosystem"] in ("npm", "pypi") and server["package"]:
        return purl(server["ecosystem"], server["package"], server["version"] if server["pinned"] else "")
    return ""
