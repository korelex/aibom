"""Step 1 of the design: label every file so later steps know what a hit inside it means."""
import os
import re
from dataclasses import dataclass

SKIP_DIRS = {".git", "node_modules", ".next", "dist", "build", "__pycache__", ".venv", "venv", ".svelte-kit", "coverage",
             ".mypy_cache", ".pytest_cache", ".idea", ".vscode", "site-packages", "target"}
CODE = {".py", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".go", ".java", ".kt", ".rs", ".cs", ".rb", ".php", ".swift", ".svelte", ".vue", ".sh", ".scala"}
CONFIG = {".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".sql", ".tf", ".tfvars", ".hcl", ".env", ".example", ".properties", ".bicep", ".bicepparam", ".conf", ".gradle", ".kts"}
DATA_DIRS = {"results", "result", "output", "outputs", "snapshots", "__snapshots__", "fixtures", "sample_data", "datasets", "dataset", "testdata", "test_data", "cassettes", "evals", "eval", "evaluations", "experiments"}
DATA_EXT = {".json", ".jsonl", ".yaml", ".yml", ".csv", ".txt", ".xml", ".tsv"}
DOCS = {".md", ".mdx", ".rst", ".txt", ".adoc"}
LOCKS = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "uv.lock", "poetry.lock", "pipfile.lock", "bun.lockb", "cargo.lock", "go.sum", "composer.lock", "gemfile.lock"}
MANIFESTS = {"package.json", "pyproject.toml", "requirements.txt", "setup.py", "setup.cfg", "pipfile", "go.mod", "cargo.toml", "pom.xml", "build.gradle", "gemfile", "composer.json"}
MAX_BYTES = 1_500_000


@dataclass
class FileInfo:
    path: str       # relative to the scanned folder
    category: str   # code, config, manifest, notebook, docs, translation, test, lock, minified, other
    size: int


def classify(rel):
    low = "/" + rel.lower()
    name = os.path.basename(low)
    ext = os.path.splitext(name)[1]
    if name in LOCKS:
        return "lock"
    if name.endswith((".min.js", ".min.css", ".bundle.js", ".map")):
        return "minified"
    if any(x in low for x in ("/i18n/", "/locales/", "/locale/", "/translations/", "/lang/")) and ext in (".json", ".js", ".ts", ".yaml", ".yml", ".po"):
        return "translation"
    if name in MANIFESTS:
        return "manifest"
    if ext == ".ipynb":
        return "notebook"
    # Go (_test.go), Python (_test.py), Ruby (_spec.rb) mark tests by file name. Java, Kotlin and Scala mark tests by folder (src/test),
    # so a class called FooTest under src/main is runnable example code, not a test.
    if re.search(r"(_test|_tests|_spec)\.[a-z]+$", name) or any(seg.endswith((".tests", ".test")) for seg in low.split("/")[:-1]):
        return "test"
    if any(x in low for x in ("/test/", "/tests/", "/__tests__/", "/cypress/", "/e2e/", "/spec/", "/fixtures/")) or "/mocks/" in low or "/__mocks__/" in low or ".mock." in name or ".mocks." in name or ".test." in name or ".spec." in name or name.startswith(("test_", "conftest")):
        return "test"
    if ext in DOCS or "/docs/" in low or name in ("readme", "license", "changelog"):
        return "docs"
    if ext in DATA_EXT and any(seg in DATA_DIRS for seg in low.split("/")[:-1]):
        return "data"  # stored results and sample data are not configuration
    if name.startswith(".env") or name.startswith("dockerfile") or name in ("docker-compose.yml", "docker-compose.yaml") or ext in CONFIG:
        return "config"
    if ext in CODE:
        return "code"
    return "other"


def triage(root):
    out = []
    for base, dirs, files in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for f in sorted(files):
            p = os.path.join(base, f)
            try:
                size = os.path.getsize(p)
            except OSError:
                continue
            rel = os.path.relpath(p, root).replace(os.sep, "/")
            cat = classify(rel)
            if size > MAX_BYTES and cat != "other":
                cat = "other"
            out.append(FileInfo(rel, cat, size))
    return out


def read_lines(root, fi):
    try:
        with open(os.path.join(root, fi.path), encoding="utf-8", errors="ignore") as f:
            return f.read().split("\n")
    except OSError:
        return []
