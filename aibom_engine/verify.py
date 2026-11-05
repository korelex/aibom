"""Step 4 of the design: decide, for every item, whether the name is really used.

For each place a name was found, work out how it appears there:
  live     written in code or config that runs
  comment  only inside a comment
  message  only inside a printed, logged or error message
  text     only inside a docstring or a block of prompt text
  docs     only in documentation
  test     only in a test or a mock
  data     only in stored results or sample data
  output   (notebooks) only in a saved cell output
  example  only in an example payload of an API spec (openapi.yaml, swagger.json)
An item is
  declared  at least one live place spells the name out
  inferred  every live place only spells it through a constant (GPT_4_O_MINI)
  rejected  no live place (the reason says why)
Rejected items stay in merged.json with their reason, but they are not written into the AI-BOM."""
import json
import os
import re

from .triage import read_lines

C_STYLE = {".js", ".ts", ".tsx", ".jsx", ".mjs", ".cjs", ".java", ".go", ".cs", ".kt", ".kts", ".rs", ".swift", ".scala", ".php", ".svelte", ".vue",
           ".gradle", ".c", ".cpp", ".h", ".bicep", ".bicepparam", ".tf", ".tfvars", ".hcl"}
HASH_STYLE = {".py", ".sh", ".yaml", ".yml", ".toml", ".properties", ".env", ".example", ".cfg", ".ini", ".rb", ".r", ".conf", ".tf", ".tfvars", ".hcl", ".bicepparam"}
PRINT = re.compile(r"\bprint\w*\s*\(|\becho\b|\bputs\b|console\.\w+\s*\(|\blogger?\.\w+\s*\(|\blogging\.\w+\s*\(|System\.(?:out|err)\.\w+\s*\(|"
                   r"\bfmt\.(?:Print|Printf|Println|Errorf|Sprintf)\s*\(|Write-Host|Console\.Write\w*\s*\(|\bprintln!?\s*\(|\braise\b|\bthrow\b|"
                   r"\b(?:Error|Exception|Warning)\s*\(|\bassert\b|\blog\.(?:info|warn|error|debug)\s*\(")
REASON_ORDER = ["comment", "message", "text", "docs", "test", "data", "output", "example", "covered"]
REASON_TEXT = {"comment": "only in a comment", "message": "only in a printed, logged or error message", "text": "only in a docstring or prompt text",
               "docs": "only in documentation", "test": "only in tests or mocks", "data": "only in stored results or sample data", "output": "only in a saved notebook output", "example": "only in an example payload of an API spec", "covered": "already listed under its full name in the same file"}


def lex(text, ext):
    """Return {line_index: [(start_col, end_col, kind)]} for comments and text blocks. kind is 'comment' or 'text'."""
    spans = {}
    c_style = ext in C_STYLE
    hash_style = ext in HASH_STYLE or ext not in C_STYLE
    sql = ext == ".sql"
    py = ext == ".py"

    def add(line, a, b, kind):
        if b > a:
            spans.setdefault(line, []).append((a, b, kind))

    lines = text.split("\n")
    in_block = None   # "*/" or "-->" while inside a block comment
    in_triple = None  # '"""' or "'''" while inside a python text block
    in_tick = False   # JS template literal
    for li, line in enumerate(lines):
        i, n = 0, len(line)
        if in_block:
            j = line.find(in_block)
            if j < 0:
                add(li, 0, n, "comment"); continue
            add(li, 0, j + len(in_block), "comment"); i = j + len(in_block); in_block = None
        if in_triple:
            j = line.find(in_triple)
            if j < 0:
                add(li, 0, n, "text"); continue
            add(li, 0, j + 3, "text"); i = j + 3; in_triple = None
        quote = None
        while i < n:
            ch = line[i]
            if in_tick:
                if ch == "\\":
                    i += 2; continue
                if ch == "`":
                    in_tick = False
                i += 1; continue
            if quote:
                if ch == "\\":
                    i += 2; continue
                if ch == quote:
                    quote = None
                i += 1; continue
            two = line[i:i + 2]
            if py and line[i:i + 3] in ('"""', "'''"):
                q3 = line[i:i + 3]; j = line.find(q3, i + 3)
                if j < 0:
                    add(li, i, n, "text"); in_triple = q3; i = n; continue
                add(li, i, j + 3, "text"); i = j + 3; continue
            if c_style and two == "//":
                add(li, i, n, "comment"); break
            if (c_style or sql) and two == "/*":
                j = line.find("*/", i + 2)
                if j < 0:
                    add(li, i, n, "comment"); in_block = "*/"; i = n; continue
                add(li, i, j + 2, "comment"); i = j + 2; continue
            if sql and two == "--":
                add(li, i, n, "comment"); break
            if line[i:i + 4] == "<!--":
                j = line.find("-->", i + 4)
                if j < 0:
                    add(li, i, n, "comment"); in_block = "-->"; i = n; continue
                add(li, i, j + 3, "comment"); i = j + 3; continue
            if hash_style and ch in "#" and not sql and (py or ext in C_STYLE or i == 0 or line[i - 1] in " \t"):
                add(li, i, n, "comment"); break
            if ch == ";" and ext in (".ini", ".cfg") and (i == 0 or line[i - 1] in " \t"):
                add(li, i, n, "comment"); break
            if ch == "`" and c_style:
                in_tick = True; i += 1; continue
            if ch in "\"'" and (i == 0 or line[i - 1] in " \t=:([{,;!&|?+-*/%<>") :
                quote = ch
            i += 1
    return spans


def inside(spans, li, col):
    for a, b, kind in spans.get(li, []):
        if a <= col < b:
            return kind
    return None


def in_string(line, col):
    q = None
    i = 0
    while i < col and i < len(line):
        ch = line[i]
        if q:
            if ch == "\\":
                i += 2; continue
            if ch == q:
                q = None
        elif ch in "\"'`":
            q = ch
        i += 1
    return q is not None


def notebook_region(lines, li):
    """For a line of a .ipynb file, say whether it is in a code source, a markdown source or a cell output."""
    for j in range(li, -1, -1):
        t = lines[j].strip()
        if t.startswith('"outputs"'):
            return "output"
        if t.startswith('"source"'):
            for k in range(j, -1, -1):
                u = lines[k].strip()
                if u.startswith('"cell_type"'):
                    return "markdown" if "markdown" in u else "code"
            return "code"
        if t.startswith('"cell_type"'):
            return "markdown" if "markdown" in t else "code"
    return "code"


SPEC_FILE = re.compile(r"(?i)^(openapi|swagger)[^/]*\.(ya?ml|json)$")
EXAMPLE_KEY = re.compile(r"""^\s*-?\s*["']?(example|examples|x-oaiMeta)["']?\s*:""")


def in_spec_example(lines, li):
    """Is this line inside an `example:` or `examples:` block of an API spec? Works on indentation, for YAML and pretty-printed JSON."""
    cur = len(lines[li]) - len(lines[li].lstrip())
    for j in range(li - 1, -1, -1):
        t = lines[j]
        if not t.strip():
            continue
        ind = len(t) - len(t.lstrip())
        if ind < cur:
            if EXAMPLE_KEY.match(t):
                return True
            cur = ind
            if cur == 0:
                return False
    return False


def classify_place(ev, names, file_cache, root):
    """How does this name appear at this place? Returns one of the words in the module docstring."""
    cat = ev["category"]
    if cat == "docs":
        return "docs"
    if cat == "test":
        return "test"
    if cat == "data":
        return "data"
    path = ev["file"]
    if path not in file_cache:
        try:
            with open(os.path.join(root, path), encoding="utf-8", errors="ignore") as fh:
                text = fh.read()
        except OSError:
            text = ""
        ext = os.path.splitext(path)[1].lower()
        file_cache[path] = (text.split("\n"), None if ext == ".ipynb" else lex(text, ext))
    lines, spans = file_cache[path]
    li = ev["line"] - 1
    if not 0 <= li < len(lines):
        return "live"
    line = lines[li]
    if SPEC_FILE.match(os.path.basename(path)) and in_spec_example(lines, li):
        return "example"
    if cat == "notebook":
        region = notebook_region(lines, li)
        if region == "output":
            return "output"
        if region == "markdown":
            return "docs"
        body = line.strip().lstrip('"').lstrip()
        return "comment" if body.startswith("#") else ("message" if PRINT.search(body) and in_string(body, max(body.lower().find(names[0].lower()), 0)) else "live")
    cols = []
    if ev.get("col", -1) >= 0:
        cols = [ev["col"]]
    else:
        low = line.lower()
        for nm in names:
            k = low.find(nm.lower())
            while k >= 0:
                cols.append(k); k = low.find(nm.lower(), k + 1)
    if not cols:
        return "live"
    kinds = []
    for c in cols:
        kind = inside(spans, li, c)
        if kind is None and PRINT.search(line) and in_string(line, c):
            kind = "message"
        kinds.append(kind or "live")
    return "live" if "live" in kinds else kinds[0]


LIST_WINDOW, LIST_MIN, FILE_LIST_MIN = 60, 8, 20  # 8 or more models within 60 lines, or 20 or more in one file, = a table or list of models


def assign_roles(items):
    """A model is 'listed' when every live place sits inside a long table or list of models (for example a token-limit
    table or a model picker with many options). Otherwise it is 'used': set or called directly in the code."""
    by_file = {}
    for idx, it in enumerate(items):
        if it["tier"] == "rejected":
            continue
        for e in it["evidence"]:
            if e.get("use") == "live":
                by_file.setdefault(e["file"], []).append((e["line"], idx, e))
    for hits in by_file.values():
        if len({h[1] for h in hits}) >= FILE_LIST_MIN:  # a file that names this many models is a catalog (for example a data file of model profiles)
            for h in hits:
                h[2]["in_list"] = True
            continue
        hits.sort(key=lambda h: h[0])
        for i in range(len(hits)):
            window = [h for h in hits[i:] if h[0] - hits[i][0] <= LIST_WINDOW]
            if len({h[1] for h in window}) >= LIST_MIN:
                for h in window:
                    h[2]["in_list"] = True
    for it in items:
        if it["tier"] == "rejected":
            it["role"] = ""
            continue
        live = [e for e in it["evidence"] if e.get("use") == "live"]
        it["role"] = "listed" if live and all(e.get("in_list") for e in live) else "used"
    return items


def verify(items, root):
    cache = {}
    for it in items:
        names = [it["name"]] + it.get("aliases", []) + [e["via"] for e in it["evidence"] if e.get("via")]
        counts = {}
        for e in it["evidence"]:
            e["use"] = classify_place(e, names, cache, root)
            counts[e["use"]] = counts.get(e["use"], 0) + 1
        live = [e for e in it["evidence"] if e["use"] == "live"]
        it["places"] = {"live": len(live), "other": len(it["evidence"]) - len(live)}
        if live:
            it["tier"] = "declared" if any(not e.get("via") for e in live) else "inferred"
            it["reason"] = ""
        else:
            it["tier"] = "rejected"
            it["reason"] = next((r for r in REASON_ORDER if counts.get(r)), "comment")
    # an inferred name (from a constant like MISTRAL_LARGE) that only repeats a model declared in the same file adds nothing
    declared = [(i["name"].lower(), {e["file"] for e in i["evidence"] if e.get("use") == "live"}) for i in items if i["tier"] == "declared"]
    for it in items:
        if it["tier"] != "inferred":
            continue
        files = {e["file"] for e in it["evidence"] if e.get("use") == "live"}
        n = it["name"].lower().replace(".", "-")
        if any((d.replace(".", "-") == n or d.replace(".", "-").startswith(n + "-")) and (dfiles & files) for d, dfiles in declared):
            it["tier"], it["reason"] = "rejected", "covered"
    return assign_roles(items)
