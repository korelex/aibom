"""Code that lets a model's own repository run Python on this machine: trust_remote_code (M3.4).

With Hugging Face's `from_pretrained(..., trust_remote_code=True)`, and the same setting in vLLM, lm-evaluation-harness and similar
tools, loading a model also downloads and runs Python code that lives in the model's repository. That is a way for whoever controls
that repository, or anyone who gets into it, to run code on the machine. Hugging Face's own documentation asks for extra care and
recommends pinning the model to a specific revision.

Found here, in the project's own files:
  Python keyword arguments and assignments (read with the Python parser, so a comment or a string that mentions it does not count)
  the same setting in other files: YAML, JSON, TOML, .env, shell scripts, Dockerfiles, notebooks (`trust_remote_code: true`,
  `TRUST_REMOTE_CODE=1`) and the command-line flag `--trust-remote-code`

Not found: a value passed through a variable (`trust_remote_code=flag`), which cannot be known without running the code. Files that
document the setting (Markdown and other documentation) are not read.
"""
import ast
import os
import re
import time

from .credentials import location_of
from .flags import Flag
from .triage import MAX_BYTES

SETTING = re.compile(r"""trust[_-]remote[_-]code["']?\s*[:=]\s*["']?(?:true|1|yes|on)\b""", re.I)
FLAG = re.compile(r"(?<![\w-])--trust[-_]remote[-_]code(?![\w-])(?!\s*[= ]\s*[\"']?(?:false|0|no|off)\b)", re.I)
HINT = re.compile(r"trust[_-]remote[_-]code", re.I)
SKIP_CATEGORIES = {"docs", "lock", "minified", "translation", "data"}
COMMENT = re.compile(r"^\s*(#|//|;|--\s|REM\s)")
MAX_FINDINGS = 200
MAX_PER_FILE = 25


def _python_hits(text):
    """Lines where Python code passes trust_remote_code=True as an argument or assigns it True, or None when the text is not Python."""
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return None
    hits = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            for kw in node.keywords:
                if kw.arg == "trust_remote_code" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    hits.append((getattr(kw, "lineno", node.lineno), "keyword"))
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            value = node.value
            if isinstance(value, ast.Constant) and value.value is True:
                for t in targets:
                    name = t.id if isinstance(t, ast.Name) else (t.attr if isinstance(t, ast.Attribute) else "")
                    if name.lower() == "trust_remote_code":
                        hits.append((node.lineno, "assignment"))
    return hits


def _text_hits(text):
    """Lines where a setting or the command-line flag turns it on, skipping lines that are only a comment."""
    hits = []
    for number, line in enumerate(text.split("\n"), start=1):
        if "rust" not in line and "RUST" not in line:
            continue
        if COMMENT.match(line):
            continue
        if FLAG.search(line):                  # first: "--trust-remote-code=true" is a flag, though the setting pattern also matches inside it
            hits.append((number, "flag"))
        elif SETTING.search(line):
            hits.append((number, "setting"))
    return hits


def scan_text(text, rel):
    """[(line, how)] for one file's text. Python is read with the parser, other text line by line."""
    if not HINT.search(text):
        return []
    hits = _python_hits(text) if rel.lower().endswith(".py") else None
    if hits is None:
        hits = _text_hits(text)
    return sorted(set(hits))


def find(root, files, deadline=None):
    """The places the project turns trust_remote_code on: {"findings": [{file, line, how, location}], "files_scanned", "partial", "truncated"}."""
    deadline = deadline or (time.time() + 120)
    out, scanned, partial, truncated = [], 0, False, False
    for fi in files:
        if fi.category in SKIP_CATEGORIES or fi.size > MAX_BYTES or fi.size == 0:
            continue
        if time.time() > deadline:
            partial = True
            break
        path = os.path.join(root, fi.path)
        try:
            if os.path.islink(path):
                continue
            with open(path, "rb") as fh:
                raw = fh.read(MAX_BYTES + 1)
        except OSError:
            continue
        if b"\x00" in raw[:4096] or not HINT.search(raw.decode("latin-1")):
            continue
        scanned += 1
        text = raw.decode("utf-8", errors="replace")
        location = location_of(fi.path, fi.category)
        hits = scan_text(text, fi.path)
        if len(hits) > MAX_PER_FILE:
            hits, truncated = hits[:MAX_PER_FILE], True
        out += [{"file": fi.path, "line": line, "how": how, "location": location} for line, how in hits]
        if len(out) >= MAX_FINDINGS:
            truncated = True
            break
    out.sort(key=lambda f: (bool(f["location"]), f["file"], f["line"]))
    return {"findings": out[:MAX_FINDINGS], "files_scanned": scanned, "partial": partial, "truncated": truncated}


def remote_code_flags(findings):
    """One flag per place: medium in the project's own files, low in a test or example."""
    flags = []
    for f in findings:
        live = not f["location"]
        where = "" if live else f" It is in a {f['location']} file."
        what = {"keyword": "passed as an argument", "assignment": "set in an assignment", "setting": "set in a settings file", "flag": "given as a command-line flag"}[f["how"]]
        flags.append(Flag("code.trust-remote-code", "medium" if live else "low", category="code",
                          title="This code lets a model's own repository run Python on this machine: trust_remote_code is on.", subject="trust_remote_code",
                          fix="Turn it off, or pin the model to a commit you have reviewed (the revision argument).",
                          file=f["file"], line=f["line"], detail=f"trust_remote_code is {what}. The model's repository can then supply code that is run when the model is loaded.{where}"))
    return flags
