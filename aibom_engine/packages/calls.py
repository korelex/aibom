"""Find calls that prove live code uses an AI package (evidence level: called).

The call signatures live in rules/calls.yaml, not here. A call counts only when the name being called is bound by an
import in the same file, and that import was accepted as an AI package by the import finder; so a project's own class
named Agent or Client never matches, and the call is credited to the same package as the import.

Python is read with Python's own parser. Names are followed through aliases (import openai as oa), from-imports, plain
assignments (Client = OpenAI; client = boto3.client(...)), self attributes and `with ... as`. This is done in source order
for the whole file, without scopes: a name bound in one function is still known in the next one. That can, rarely, credit
a call to a binding from another function; it never credits a name that no AI import bound.

JavaScript and TypeScript are matched by pattern, with comments and strings ignored: the bindings come from import and
require statements, and a call is `name(...)`, `new Name(...)` or `ns.name(...)` on such a binding.

AI services reached through a general cloud SDK (Amazon Bedrock through boto3) count when the client is created for the
service, and the operations called on that client are recorded too.
"""
import ast
import bisect
import functools
import os
import re
import time

import yaml

from ..triage import read_lines
from ..verify import in_string, inside, lex
from .common import left_out_reason
from .imports import JS_EXT, PY_EXT, SCANNED, _js_package, notebook_cells

RULES_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "rules", "calls.yaml")
SERVICE = "<service:{}>"


def _pattern(text):
    """A rule pattern as a regex. A part that is just "*" stands for one or more name parts; "*" inside a part, for any
    letters. Neither matches a call ("Chroma()"), so methods of an object already counted are not counted again."""
    parts = []
    for part in text.split("."):
        if part == "*":
            parts.append(r"\w+(?:\.\w+)*")
        else:
            parts.append(r"\w*".join(re.escape(p) for p in part.split("*")))
    return re.compile(r"\.".join(parts) + r"\Z")


class Rules:
    """The call rules, checked and indexed for matching."""

    def __init__(self, data, source):
        if not isinstance(data, dict) or not isinstance(data.get("rules"), list):
            raise ValueError(f"{source}: expected a 'rules' list")
        self.version = str(data.get("version", ""))
        self.exact = {"python": {}, "javascript": {}}
        self.wild = {"python": [], "javascript": []}
        self.services = []
        seen = set()
        for rule in data["rules"] + (data.get("services") or []):
            rid = rule.get("id")
            if not rid or rid in seen:
                raise ValueError(f"{source}: every rule needs a unique id ({rid!r})")
            seen.add(rid)
        for rule in data["rules"]:
            pkg = rule.get("package") or {}
            if pkg.get("ecosystem") not in ("pypi", "npm") or not (pkg.get("name") or pkg.get("family")):
                raise ValueError(f"{source}: rule {rule['id']} needs package: {{ecosystem: pypi|npm, name or family: ...}}")
            entry = {"id": rule["id"], "what": rule.get("what", ""), "ecosystem": pkg["ecosystem"],
                     "package": pkg.get("name") or pkg["family"], "classes": bool(rule.get("classes"))}
            for lang in ("python", "javascript"):
                for pat in rule.get(lang) or []:
                    pat = str(pat)
                    if "*" in pat:
                        self.wild[lang].append((_pattern(pat), entry))
                    else:
                        self.exact[lang].setdefault(pat, entry)
            if not (rule.get("python") or rule.get("javascript")):
                raise ValueError(f"{source}: rule {rule['id']} has no python or javascript patterns")
        for svc in data.get("services") or []:
            via = svc.get("via") or {}
            self.services.append({
                "id": svc["id"], "service": svc.get("service", svc["id"]), "ecosystem": via.get("ecosystem", "pypi"),
                "package": via.get("name", ""), "what": f"creates a client for {svc.get('service', svc['id'])}",
                "patterns": {str(p) for p in svc.get("python") or []}, "names": set(svc.get("service_names") or []),
                "methods": set(svc.get("methods") or []),
            })

    def match(self, lang, name):
        rule = self.exact[lang].get(name)
        if rule:
            return rule
        for rx, rule in self.wild[lang]:
            if rx.match(name) and (not rule["classes"] or any(p[:1].isupper() for p in name.split(".")[1:])):
                return rule  # with classes: true, only a public class or its class methods, not helper functions
        return None

    def service_for(self, name, call):
        """The service a client-creating call is for, when it names one: boto3.client("bedrock-runtime")."""
        for svc in self.services:
            if name in svc["patterns"]:
                arg = call.args[0] if call.args else next((k.value for k in call.keywords if k.arg == "service_name"), None)
                if isinstance(arg, ast.Constant) and arg.value in svc["names"]:
                    return svc
        return None

    def service_roots(self):
        return {p.split(".")[0] for svc in self.services for p in svc["patterns"]}


@functools.lru_cache(maxsize=4)
def load_rules(path=RULES_PATH):
    with open(path, encoding="utf-8") as fh:
        return Rules(yaml.safe_load(fh), os.path.basename(path))


# ---------------------------------------------------------------------------------------------------------------- python

class _PythonCalls:
    """Walks one file's syntax trees in source order, keeping what each name is bound to."""

    def __init__(self, rules):
        self.rules = rules
        self.env = {}  # name or self.attr -> fully qualified name ("openai.OpenAI", "<service:aws.bedrock>")

    def qual(self, node):
        if isinstance(node, ast.Name):
            return self.env.get(node.id)
        if isinstance(node, ast.Attribute):
            dotted = self._dotted(node)
            if dotted and dotted in self.env:
                return self.env[dotted]
            base = self.qual(node.value)
            return f"{base}.{node.attr}" if base else None
        if isinstance(node, ast.Call):
            base = self.qual(node.func)
            if not base:
                return None
            svc = self.rules.service_for(base, node)
            return SERVICE.format(svc["id"]) if svc else base + "()"
        return None

    @staticmethod
    def _dotted(node):
        parts = []
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if isinstance(node, ast.Name):
            return ".".join([node.id] + parts[::-1])
        return None

    def _bind(self, target, value):
        key = target.id if isinstance(target, ast.Name) else self._dotted(target) if isinstance(target, ast.Attribute) else None
        if not key:
            return
        q = self.qual(value) if value is not None else None
        if q:
            self.env[key] = q
        else:
            self.env.pop(key, None)  # rebound to something else: the old binding no longer holds

    def run(self, tree, line_of=lambda n: n):
        """[(rule or service, qualified name, line)] for every matching call in the tree."""
        nodes = [n for n in ast.walk(tree) if isinstance(n, (ast.Import, ast.ImportFrom, ast.Assign, ast.AnnAssign,
                                                               ast.With, ast.AsyncWith, ast.Call, ast.FunctionDef,
                                                               ast.AsyncFunctionDef, ast.ClassDef))]
        nodes.sort(key=lambda n: (n.lineno, n.col_offset, not isinstance(n, ast.Call)))
        out = []
        for n in nodes:
            if isinstance(n, ast.Import):
                for a in n.names:
                    if a.asname:
                        self.env[a.asname] = a.name
                    else:
                        top = a.name.split(".")[0]
                        self.env[top] = top
            elif isinstance(n, ast.ImportFrom):
                if n.level or not n.module:
                    for a in n.names:
                        self.env.pop(a.asname or a.name, None)  # the project's own module
                    continue
                for a in n.names:
                    if a.name != "*":
                        self.env[a.asname or a.name] = f"{n.module}.{a.name}"
            elif isinstance(n, ast.ClassDef):
                # class PatchedQdrantVectorStore(QdrantVectorStore): creating one creates the SDK's class
                base = next((q for q in map(self.qual, n.bases) if q and self.rules.match("python", q)), None)
                if base:
                    self.env[n.name] = base
                else:
                    self.env.pop(n.name, None)  # the project's own Agent or OpenAI: the name is no longer the SDK's
            elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.env.pop(n.name, None)
            elif isinstance(n, ast.Assign):
                for t in n.targets:
                    self._bind(t, n.value)
            elif isinstance(n, ast.AnnAssign):
                self._bind(n.target, n.value)
            elif isinstance(n, (ast.With, ast.AsyncWith)):
                for item in n.items:
                    if item.optional_vars is not None:
                        self._bind(item.optional_vars, item.context_expr)
            else:
                q = self.qual(n.func)
                if not q:
                    continue
                svc = self.rules.service_for(q, n)
                if svc:
                    out.append((svc, q, line_of(n.lineno), None))
                    continue
                m = re.match(r"<service:([^>]+)>\.(\w+)\Z", q)
                if m:
                    svc = next((s for s in self.rules.services if s["id"] == m.group(1)), None)
                    if svc and m.group(2) in svc["methods"]:
                        out.append((svc, q, line_of(n.lineno), m.group(2)))
                    continue
                rule = self.rules.match("python", q)
                if rule:
                    out.append((rule, q, line_of(n.lineno), None))
        return out


def _python_calls(text, rules, notebook=False):
    """[(rule, qualified name, line, operation)] for a Python file or notebook; None when it does not parse."""
    walker = _PythonCalls(rules)
    if not notebook:
        try:
            return walker.run(ast.parse(text))
        except (SyntaxError, ValueError, RecursionError):
            return None
    out = []
    for code, line_map, _src in notebook_cells(text):  # one cell after another, so names bound earlier carry over
        try:
            tree = ast.parse(code)
        except (SyntaxError, ValueError, RecursionError):
            continue
        out += walker.run(tree, lambda li, m=line_map: m[li - 1] if 0 < li <= len(m) else 0)
    return out


# ------------------------------------------------------------------------------------------------------------ javascript

_IDENT = r"[A-Za-z_$][\w$]*"
_JS_IMPORT = re.compile(r"\bimport\s+(?!type\b)([^;'\"`]*?)\s*\bfrom\s*(['\"])([^'\"\n]+)\2")
_JS_REQUIRE = re.compile(r"\b(?:const|let|var)\s+(\{[^}]*\}|" + _IDENT + r")\s*=\s*(?:await\s+)?(require|import)\s*\(\s*(['\"])([^'\"\n]+)\3\s*\)")
_JS_CALL = re.compile(r"(?<![\w$.])(new\s+)?(" + _IDENT + r"(?:\s*\.\s*" + _IDENT + r")*)\s*(?:<[^()<>;]*(?:<[^()<>;]*>[^()<>;]*)*>\s*)?\(")
_JS_SKIP = {"if", "for", "while", "switch", "catch", "function", "return", "typeof", "await", "import", "require", "super"}


def _js_bindings(text, live):
    """{local name: "specifier:export"} from import and require statements outside comments and strings."""
    env = {}

    def names(group, spec, colon):
        for part in group.strip().strip("{}").split(","):
            part = part.strip()
            if not part or part.startswith("type "):
                continue
            pieces = [p.strip() for p in part.split(colon, 1)] if colon == ":" else [p.strip() for p in re.split(r"\s+as\s+", part, maxsplit=1)]
            exported, local = (pieces + pieces)[:2] if len(pieces) == 1 else pieces
            if re.fullmatch(_IDENT, local):
                env[local] = f"{spec}:{exported}"

    for m in _JS_IMPORT.finditer(text):
        if not live(m.start()):
            continue
        clause, spec = m.group(1).strip(), m.group(3)
        if clause.startswith("type "):
            continue
        ns = re.search(r"\*\s+as\s+(" + _IDENT + ")", clause)
        if ns:
            env[ns.group(1)] = f"{spec}:*"
        braces = re.search(r"\{([^}]*)\}", clause)
        if braces:
            names(braces.group(1), spec, " as ")
        default = re.match(r"(" + _IDENT + r")\s*(?:,|$)", clause)
        if default:
            env[default.group(1)] = f"{spec}:default"
    for m in _JS_REQUIRE.finditer(text):
        if not live(m.start()):
            continue
        target, how, spec = m.group(1), m.group(2), m.group(4)
        if target.startswith("{"):
            names(target, spec, ":")
        else:
            env[target] = f"{spec}:{'default' if how == 'require' else '*'}"
    return env


def _js_calls(text, ext, rules):
    """[(rule, binding name, line, None)] for calls on imported names outside comments and strings."""
    spans = lex(text, {".mts": ".ts", ".cts": ".ts"}.get(ext, ext))
    starts = [0]
    for line in text.split("\n"):
        starts.append(starts[-1] + len(line) + 1)
    lines = text.split("\n")

    def live(pos):
        li = bisect.bisect_right(starts, pos) - 1
        col = pos - starts[li]
        return not inside(spans, li, col) and not in_string(lines[li], col)

    env = _js_bindings(text, live)
    if not env:
        return []
    out = []
    for m in _JS_CALL.finditer(text):
        chain = [p.strip() for p in m.group(2).split(".")]
        if chain[0] not in env or chain[0] in _JS_SKIP or not live(m.start(2)):
            continue
        before = text[max(0, m.start() - 12):m.start()]
        if re.search(r"\b(?:function|class|interface|type)\s*$", before):
            continue  # a definition, not a call
        spec, _, export = env[chain[0]].partition(":")
        rest = chain[1:]
        if export == "*" and rest:
            export, rest = rest[0], rest[1:]
        names = [f"{spec}:{'.'.join([export] + rest)}"]
        if export == "default" and rest:  # require("x").Name and the default export's own members
            names.append(f"{spec}:{'.'.join(rest)}")
        for name in names:
            rule = rules.match("javascript", name)
            if rule:
                out.append((rule, name, bisect.bisect_right(starts, m.start(2)), None))
                break
    return out


# ------------------------------------------------------------------------------------------------------------------ find

def find_calls(root, files, import_hits, rules=None, deadline=None):
    """Every call that proves an AI package is used: {ecosystem, package, rule, what, call, operation, service, file, line,
    snippet, left_out}. `import_hits` come from find_imports: a call is credited to the package whose import, in the same
    file, bound the name. Service clients (boto3 for Amazon Bedrock) need no AI import, only the SDK's own."""
    rules = rules or load_rules()
    by_file = {}
    for h in import_hits:
        by_file.setdefault(h["file"], []).append(h)
    service_roots = rules.service_roots()
    out = []
    for fi in files:
        if deadline and time.time() > deadline:
            break
        ext = os.path.splitext(fi.path)[1].lower()
        notebook = fi.category == "notebook"
        if fi.category not in SCANNED or not (notebook or ext in PY_EXT or ext in JS_EXT):
            continue
        hits = by_file.get(fi.path, [])
        lines = read_lines(root, fi)
        text = "\n".join(lines)
        python = notebook or ext in PY_EXT
        if not hits and not (python and service_roots and re.search(r"\b(?:" + "|".join(map(re.escape, service_roots)) + r")\b", text)):
            continue
        found = _python_calls(text, rules, notebook) if python else _js_calls(text, ext, rules)
        reason = {"test": "test", "docs": "docs"}.get(fi.category) or left_out_reason(fi.path)
        for rule, name, li, operation in found or []:
            if "service" in rule:
                eco, package, service = rule["ecosystem"], rule["package"], rule["service"]
            else:
                if python:
                    mods = [h for h in hits if h["ecosystem"] == "pypi" and (name == h["module"] or name.startswith(h["module"] + "."))]
                else:
                    spec = name.split(":", 1)[0]
                    mods = [h for h in hits if h["ecosystem"] == "npm" and h["package"] == _js_package(spec)]
                if not mods:
                    continue  # the name was bound by an import the import finder did not accept (a local module)
                h = max(mods, key=lambda h: len(h["module"]))
                eco, package, service = h["ecosystem"], h["package"], ""
            snippet = lines[li - 1].strip() if 0 < li <= len(lines) else ""
            out.append({"ecosystem": eco, "package": package, "rule": rule["id"], "what": rule["what"], "call": name,
                        "operation": operation or "", "service": service, "file": fi.path, "line": li,
                        "snippet": snippet[:200], "left_out": reason})
    return out
