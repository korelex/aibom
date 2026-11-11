"""Find the AI packages that live code imports (evidence level: imported).

Python files and notebook code cells are read with Python's own parser, so comments, strings and docstrings can never
count as imports. JavaScript and TypeScript are matched by pattern, with comments removed first: `import ... from`,
`export ... from`, bare `import "x"`, dynamic `import("x")` and `require("x")`.

An import in a test, documentation, example or vendored file is kept as evidence with the reason it does not count, the
same way model names are treated.
"""
import ast
import bisect
import json
import os
import re
import time

from ..db import load_db, lookup_package
from ..triage import read_lines
from ..verify import inside, lex
from .common import left_out_reason, normalize

PY_EXT = {".py"}
JS_EXT = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".mts", ".cts", ".vue", ".svelte"}
SCANNED = {"code", "notebook", "test", "docs"}

# Import names that are also ordinary words, so a project's own module of that name is common. They count only when the
# package is declared in a dependency file, or when the project has no module or folder of that name itself.
GENERIC = {"agents", "llm", "phi", "strands", "guardrails", "haystack", "outlines", "instructor", "guidance", "workflows"}
# Several packages install the same import name; when none of them is declared, report the first one listed.
SHARED = {"pinecone": ["pinecone", "pinecone-client"], "faiss": ["faiss-cpu", "faiss-gpu"],
          "haystack": ["haystack-ai", "farm-haystack"], "autogen": ["autogen-agentchat", "pyautogen", "autogen"]}

JS_PATTERNS = [
    re.compile(r"""\b(?:import|export)\b[^;'"`]*?\bfrom\s*(['"])([^'"\n]+)\1"""),  # import x from "p"; export {y} from "p"
    re.compile(r"""\bimport\s*(['"])([^'"\n]+)\1"""),                            # import "p"
    re.compile(r"""\bimport\s*\(\s*(['"])([^'"\n]+)\1\s*\)"""),                  # import("p")
    re.compile(r"""\brequire\s*\(\s*(['"])([^'"\n]+)\1\s*\)"""),                 # require("p")
]


class PythonIndex:
    """Maps an imported module (langchain_community.vectorstores) to the AI package that provides it."""

    def __init__(self, db):
        self.db = db
        self.names = {}
        for pkg in db.get("packages", {}).values():
            if pkg.get("ecosystem") == "PyPI":
                for imp in pkg.get("import_names") or []:
                    self.names.setdefault(imp, []).append(pkg["name"])
        self.tops = {imp.split(".")[0] for imp in self.names} | {"langchain", "langgraph", "llama_index", "crewai", "autogen"}

    def package_of(self, module):
        """[package names] for an imported module, longest known import name first; [] when it is not an AI package."""
        parts = module.split(".")
        exact, exact_len = None, 0
        for n in range(len(parts), 0, -1):
            prefix = ".".join(parts[:n])
            if prefix in self.names:
                exact, exact_len = SHARED.get(prefix, self.names[prefix]), n
                break
        family = self._family(parts)
        # A specific integration beats an umbrella package: llama_index.llms.openai comes from llama-index-llms-openai,
        # not from llama-index, which only matched on the bare top-level name.
        if family and (exact is None or (exact_len == 1 and len(parts) > 1)):
            return family
        return exact or []

    def _family(self, parts):
        """Package names a family module can come from, the most likely first. LlamaIndex integrations are named after
        their module path: llama_index.llms.openai -> llama-index-llms-openai, but storage integrations go one level
        deeper (llama_index.storage.kvstore.postgres -> llama-index-storage-kvstore-postgres). Every shorter and longer
        reading is also returned, so a package the project declares can be preferred over the naming rule."""
        top = parts[0]
        if top == "llama_index" and len(parts) >= 2:
            depth = 4 if parts[1] == "storage" else 3
            names = ["llama-index-" + "-".join(p.replace("_", "-") for p in parts[1:n]) for n in range(len(parts), 1, -1)]
            likely = "llama-index-" + "-".join(p.replace("_", "-") for p in parts[1:depth])
            candidates = [likely] + [n for n in names if n != likely]
        elif re.match(r"^(langchain|langgraph|crewai|autogen|llama_index)_\w+$", top):  # langchain_groq -> langchain-groq
            candidates = [top.replace("_", "-")]  # also llama_index_instrumentation -> llama-index-instrumentation
        else:
            return []
        return [c for c in candidates if lookup_package("PyPI", c, db=self.db)]


def _python_imports(source):
    """(module, line, names) for every absolute import in Python source; None when it does not parse. `names` are the
    names a from-import takes, because the package can be in them: "from google import genai" is google.genai."""
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return None
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            out += [(alias.name, node.lineno, ()) for alias in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:  # relative imports are the project's own
            out.append((node.module, node.lineno, tuple(a.name for a in node.names if a.name != "*")))
    return sorted(out, key=lambda x: x[1])  # ast.walk is breadth-first; callers rely on source order


def notebook_cells(text):
    """[(code, line_map, source_lines)] for each code cell of a notebook. Shell (!) and magic (%) lines become empty lines,
    so line numbers stay right; line_map[i] is the line of the .ipynb file that holds code line i + 1 (0 when not found)."""
    try:
        cells = json.loads(text).get("cells") or []
    except (ValueError, AttributeError):
        return []
    lines = text.split("\n")
    out, cursor = [], 0
    for cell in cells:
        if not isinstance(cell, dict) or cell.get("cell_type") != "code":
            continue
        src = cell.get("source") or []
        src = [str(s) for s in src] if isinstance(src, list) else str(src).splitlines(True)
        code = "".join(("\n" if s.lstrip().startswith(("!", "%")) else s) for s in src)
        line_map = []
        for s in "".join(src).split("\n"):
            needle = json.dumps(s.strip())[1:-1][:80]
            where = 0
            if needle:
                for i in range(cursor, len(lines)):
                    if needle in lines[i]:
                        where = cursor = i + 1
                        break
            line_map.append(where)
        out.append((code, line_map, code.split("\n")))
    return out


def _notebook_imports(text):
    """(module, line in the .ipynb file, source line, names) for imports in notebook code cells."""
    out = []
    for code, line_map, src in notebook_cells(text):
        for module, li, names in _python_imports(code) or []:
            out.append((module, line_map[li - 1] if li - 1 < len(line_map) else 0, src[li - 1].strip() if li - 1 < len(src) else "", names))
    return out


def _js_package(spec):
    """The package an import specifier names: "@scope/name/sub" -> "@scope/name", "name/sub" -> "name"; "" for local paths."""
    if spec.startswith((".", "/", "~", "#", "node:", "http:", "https:", "data:")) or spec.startswith("@/"):
        return ""
    parts = spec.split("/")
    return "/".join(parts[:2]) if spec.startswith("@") and len(parts) >= 2 else parts[0]


def _js_imports(text, ext):
    """(package, line) for imports outside comments."""
    spans = lex(text, {".mts": ".ts", ".cts": ".ts"}.get(ext, ext))
    starts = [0]
    for line in text.split("\n"):
        starts.append(starts[-1] + len(line) + 1)
    out = []
    for rx in JS_PATTERNS:
        for m in rx.finditer(text):
            pos = m.start(2)
            first = bisect.bisect_right(starts, m.start()) - 1
            li = bisect.bisect_right(starts, pos) - 1  # the line that names the package, so the proof shows it
            if inside(spans, first, m.start() - starts[first]) or inside(spans, li, pos - starts[li]):
                continue  # commented out
            if re.match(r"(?:import|export)\s+type\b", m.group(0)):
                continue  # `import type`: erased at compile time, the package is never loaded
            pkg = _js_package(m.group(2))
            if pkg:
                out.append((pkg, li + 1))
    return out


def _local_modules(files):
    """Top-level names that the project's own Python files define: folders holding .py files, and .py file stems."""
    names = set()
    for fi in files:
        if fi.path.endswith(".py"):
            parts = fi.path.split("/")
            names.update(parts[:-1])
            names.add(parts[-1][:-3])
    return names


def find_imports(root, files, declared=frozenset(), db=None, deadline=None, vendored=None):
    """Every import of an AI package: {ecosystem, package, module, file, line, snippet, left_out}.

    `declared` holds (ecosystem, normalized name) of packages the dependency files declare; it settles shared and
    generic import names.
    """
    db = db or load_db()
    index = PythonIndex(db)
    local = _local_modules(files)
    # A cheap first pass: only files with an import starting like an AI package are parsed. No word boundary at the end,
    # because family modules continue the name (langchain_groq, llama_index_instrumentation); the parser checks exactly.
    quick = re.compile(r"^\s*(?:from|import)\s+(" + "|".join(sorted(map(re.escape, index.tops), key=len, reverse=True)) + r")", re.M)
    hits = []
    for fi in files:
        if deadline and time.time() > deadline:
            break
        ext = os.path.splitext(fi.path)[1].lower()
        if fi.category not in SCANNED or (ext not in PY_EXT and ext not in JS_EXT and fi.category != "notebook"):
            continue
        reason = {"test": "test", "docs": "docs"}.get(fi.category) or left_out_reason(fi.path, vendored)
        lines = read_lines(root, fi)
        text = "\n".join(lines)
        if fi.category == "notebook":
            found = [(m, li, s, "pypi", names) for m, li, s, names in _notebook_imports(text)]
        elif ext in PY_EXT:
            if not quick.search(text):
                continue  # no import of any AI package can be in this file
            parsed = _python_imports(text)
            if parsed is None:  # not valid Python 3 (a template or Python 2): fall back to whole-line imports
                parsed = [(m.group(1) or m.group(2), text[:m.start()].count("\n") + 1, ())
                          for m in re.finditer(r"^\s*(?:from\s+([\w.]+)\s+import|import\s+([\w.]+))", text, re.M)]
            found = [(m, li, lines[li - 1].strip() if 0 < li <= len(lines) else "", "pypi", names) for m, li, names in parsed]
        else:
            if "import" not in text and "require" not in text:
                continue
            found = [(p, li, lines[li - 1].strip() if 0 < li <= len(lines) else "", "npm", ()) for p, li in _js_imports(text, ext)]

        for module, li, snippet, eco, names in found:
            if eco == "pypi":
                candidates = index.package_of(module)
                if not candidates:
                    # "from google import genai": the package is the module plus a name the import takes
                    for name in names:
                        candidates = index.package_of(f"{module}.{name}")
                        if candidates:
                            module = f"{module}.{name}"
                            break
                if not candidates:
                    continue
                top = module.split(".")[0]
                chosen = next((c for c in candidates if ("pypi", normalize("pypi", c)) in declared), None)
                if top in GENERIC and chosen is None and top in local:
                    continue  # the project's own module that happens to share the name
                package = chosen or candidates[0]
            else:
                if not lookup_package("npm", module, db=db):
                    continue
                package = module
            hits.append({"ecosystem": eco, "package": package, "module": module, "file": fi.path, "line": li,
                         "snippet": snippet[:200], "left_out": reason})
    return hits
