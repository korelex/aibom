"""Risk flags for the MCP servers a project declares (M3.2).

Each rule says what was found, how serious it is, where, and what to do. The references are to OWASP's published MCP
guidance (the OWASP MCP Top 10, and its MCP Security Cheat Sheet), checked on 2026-11-12 and quoted only for what they say.
The Cloud Security Alliance's "MCP Security Baseline", which the product spec mentions, was listed there as v0.1 and "coming
soon", with no published text, so nothing here claims to follow it.

Rules (severity):
  mcp.plaintext-secret        high when the value has a well-known key format or the URL carries a password, else medium.
                              A credential is written in the config file (OWASP MCP01; cheat sheet section 6: never store tokens
                              in plaintext in MCP config files). A placeholder such as ${TOKEN} is not a credential.
  mcp.shell-command           medium: the server is started through a shell string or inline code; high when that text downloads
                              and runs something (OWASP MCP05; cheat sheet section 5: never pass raw shell commands).
  mcp.unpinned-package        medium: an npm, PyPI or container package with no exact version, so a new release changes what runs
                              (OWASP MCP04, software supply chain).
  mcp.package-from-url        medium: the server runs code fetched from a URL or git address (OWASP MCP04).
  mcp.broad-filesystem-path   high for the root of a drive or a system folder, medium for a home folder: the server is given
                              access to a very broad part of the file system (OWASP MCP02; cheat sheet section 3: restrict file
                              system access to only the required directories).

A server that the config switches off is not started, so only its credentials are flagged. A server in tests, examples, docs or
vendored folders is not the product's own and gets no flags.
"""
import re

from .flags import Flag
from .mcp import _base

MCP01 = "OWASP MCP Top 10: MCP01 (Token Mismanagement & Secret Exposure)."
MCP02 = "OWASP MCP Top 10: MCP02 (Privilege Escalation via Scope Creep); MCP Security Cheat Sheet section 3."
MCP04 = "OWASP MCP Top 10: MCP04 (Software Supply Chain Attacks & Dependency Tampering)."
MCP05 = "OWASP MCP Top 10: MCP05 (Command Injection & Execution); MCP Security Cheat Sheet section 5."

WHERE = {"env": "environment variable", "header": "HTTP header", "url": "the URL", "url-query": "URL query parameter", "arg": "command-line argument"}

SHELLS = {"sh", "bash", "zsh", "dash", "fish", "ksh", "csh", "tcsh", "pwsh", "powershell", "cmd"}
INLINE_FLAGS = {"cmd": {"/c", "/k"}, "pwsh": {"-command", "-c", "-encodedcommand", "-e", "-ec"}, "powershell": {"-command", "-c", "-encodedcommand", "-e", "-ec"}}
SHELL_FLAGS = {"-c", "-lc", "-ic", "-xc"}
INTERPRETERS = {"python": {"-c"}, "python3": {"-c"}, "py": {"-c"}, "node": {"-e", "--eval", "-p", "--print"}, "nodejs": {"-e", "--eval", "-p", "--print"},
                "bun": {"-e", "--eval"}, "deno": {"eval"}, "ruby": {"-e"}, "perl": {"-e", "-E"}, "php": {"-r"}}
# `cmd /c npx ...` is the way Windows runs npx: the shell is only a wrapper there, not a command string
LAUNCHERS = {"npx", "pnpx", "bunx", "uvx", "uv", "pipx", "docker", "podman", "node", "python", "python3", "py", "pnpm", "yarn", "npm", "deno", "bun", "java", "dotnet", "go"}
DOWNLOAD_RUN = re.compile(r"\b(?:curl|wget)\b[^|]*\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b|\b(?:curl|wget)\b[^|]*\|\s*(?:python3?|node)\b|\b(?:iwr|irm|invoke-webrequest|invoke-restmethod|curl|wget)\b.*\b(?:iex|invoke-expression)\b", re.I)

HOME_FORMS = {"~", "$home", "${home}", "%userprofile%", "${userhome}", "${env:home}", "${env:userprofile}", "$env:userprofile", "$env:home", "%homepath%"}
SYSTEM_DIRS = {"/etc", "/root", "/var", "/usr", "/bin", "/sbin", "/boot", "/proc", "/sys", "/dev", "/system", "/library", "/private",
               "c:/windows", "c:/windows/system32", "c:/program files", "c:/program files (x86)", "c:/programdata"}


def inline_code(command, args):
    """The shell string or inline code a server is started with, or None when it is not started that way."""
    base = _base(command)
    items = [str(a) for a in args]
    if base in SHELLS:
        flags = INLINE_FLAGS.get(base, SHELL_FLAGS)
        for i, a in enumerate(items):
            if a.lower() in flags:
                rest = items[i + 1:]
                if base == "cmd" and rest and _base(rest[0]) in LAUNCHERS:
                    return None
                return " ".join(rest)
        return None
    flags = INTERPRETERS.get(base)
    if flags:
        for i, a in enumerate(items):
            if a in flags:
                return " ".join(items[i + 1:])
    return None


def broad_path(text):
    """"root", "system" or "home" when a path is a very broad place to give a server access to, else ""."""
    t = str(text).strip().strip("\"'")
    if not t or "\n" in t:
        return ""
    low = t.lower().replace("\\", "/")
    bare = low.rstrip("/") if len(low) > 1 else low
    if low in ("/", "//") or re.fullmatch(r"[a-z]:/*", low):
        return "root"
    if bare in SYSTEM_DIRS:
        return "system"
    if bare in HOME_FORMS or bare in ("/users", "/home", "c:/users"):
        return "home"
    if re.fullmatch(r"(?:/users|/home|[a-z]:/users)/[^/]+", bare):
        return "home"
    return ""


def _volume_source(spec):
    """The host side of a docker -v SRC:DST[:mode] value (a Windows drive letter's colon is not the separator)."""
    m = re.match(r"^([A-Za-z]:[\\/][^:]*|[^:]*):", spec)
    return m.group(1) if m else spec


def path_arguments(args):
    """The arguments that name a place on disk: bare paths, --flag=PATH, docker -v SRC:DST and --mount src=PATH."""
    items = [str(a) for a in args]
    out = []
    for i, a in enumerate(items):
        if a.startswith("-"):
            flag, eq, val = a.partition("=")
            if eq and flag not in ("--mount", "--volume"):
                out.append(val)
            if flag in ("-v", "--volume"):
                spec = val if eq else (items[i + 1] if i + 1 < len(items) else "")
                out.append(_volume_source(spec))
            if flag == "--mount":
                spec = val if eq else (items[i + 1] if i + 1 < len(items) else "")
                out += re.findall(r"(?:^|,)(?:src|source)=([^,]+)", spec)
        elif i == 0 or not items[i - 1] in ("-v", "--volume", "--mount"):
            out.append(a)
    return out


def _fixes_for(sv):
    pkg = sv["package"]
    if sv["ecosystem"] == "npm":
        return f"Pin an exact version, for example {pkg}@1.2.3."
    if sv["ecosystem"] == "pypi":
        return f"Pin an exact version, for example {pkg}==1.2.3."
    return "Pin an image digest or an exact version tag."


def mcp_flags(servers):
    """The risk flags of the MCP servers a scan found (server dicts from mcp.find)."""
    out = []
    for sv in servers:
        if sv.get("left_out"):
            continue
        base = {"category": "mcp", "file": sv["file"], "line": sv["line"], "ref": sv["ref"]}
        for sec in sv.get("secrets", []):
            strong = sec["kind"] in ("provider-key", "credentials")
            where = WHERE.get(sec["in"], sec["in"])
            what = f"{where} {sec['name']}".strip() if sec["name"] else f"{where} (user name and password)"
            out.append(Flag("mcp.plaintext-secret", "high" if strong else "medium", title="A key or password is written in this MCP config file.",
                            subject=f"{sv['name']}: {sec['name']}" if sec["name"] else sv["name"], fix="Read it from an environment variable (for example ${NAME}) and, if it is a real credential, rotate it.",
                            detail=f"In the {what}. {MCP01}", **{**base, "line": sec["line"]}))
        if sv.get("enabled") is False:
            continue
        base["subject"] = sv["name"]
        if sv["transport"] == "stdio" and sv["command"]:
            code = inline_code(sv["command"], sv["args"])
            if code is not None:
                download = bool(DOWNLOAD_RUN.search(code))
                shown = code if len(code) <= 100 else code[:97] + "..."
                out.append(Flag("mcp.shell-command", "high" if download else "medium",
                                title="The server is started through a shell string or inline code" + (", and it downloads and runs something." if download else "."),
                                fix="Run a named program with fixed arguments instead of a shell string.", detail=f"Runs: {shown}. {MCP05}", **base))
            if sv["ecosystem"] in ("npm", "pypi", "docker") and sv["pinned"] is False:
                out.append(Flag("mcp.unpinned-package", "medium", title="The package version is not pinned, so a new release changes what runs.",
                                fix=_fixes_for(sv), detail=f"{sv['launcher']} {sv['package']}" + (f" ({sv['version']})" if sv["version"] else "") + f". {MCP04}", **base))
            elif sv["ecosystem"] == "source" and re.match(r"^(?:[a-z][a-z0-9+.-]*://|git\+|github:|gitlab:|bitbucket:)", sv["package"], re.I):
                out.append(Flag("mcp.package-from-url", "medium", title="The server runs code fetched from a URL or git address.",
                                fix="Use a released package with an exact version instead.", detail=f"{sv['launcher']} {sv['package']}. {MCP04}", **base))
            seen = set()
            for path in path_arguments(sv["args"]):
                kind = broad_path(path)
                if kind and (kind, path) not in seen:
                    seen.add((kind, path))
                    out.append(Flag("mcp.broad-filesystem-path", "medium" if kind == "home" else "high",
                                    title="The server is given access to a very broad part of the file system.",
                                    fix="Give it only the folders it needs.", detail=f"Path: {path}. {MCP02}", **base))
    return out
