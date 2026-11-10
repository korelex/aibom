"""What every dependency-file parser produces, and the small helpers they share."""
import os
import re
from dataclasses import asdict, dataclass, field

# Folders whose dependency files are not part of the product itself. Their packages are reported as left out, with the
# reason, instead of being mixed in with the app's own dependencies.
LEFT_OUT_DIRS = {
    "test": {"test", "tests", "__tests__", "spec", "specs", "e2e", "cypress", "fixtures", "testdata", "test_data", "mocks", "__mocks__"},
    "example": {"example", "examples", "sample", "samples", "demo", "demos"},
    "docs": {"docs", "doc", "documentation"},
    "vendored": {"vendor", "vendors", "third_party", "third-party", "external", "extern"},
}
MAX_LOCK_BYTES = 60_000_000  # real package-lock.json files reach 10 MB and more


@dataclass
class Declaration:
    """One package, as one dependency file states it."""
    ecosystem: str        # "pypi" or "npm"
    name: str             # as written in the file
    file: str             # path relative to the scanned folder
    line: int             # 1-based line of the entry
    kind: str             # "manifest" (what the project asks for) or "lock" (what was resolved and installed)
    version: str = ""     # exact version when the file pins one
    spec: str = ""        # the requested range when it is not an exact version (">=1.2", "^4.0.0")
    direct: object = None  # True: the project depends on it itself; False: pulled in by another package; None: unknown
    scope: str = "runtime"  # runtime, dev, optional, peer, or unknown
    resolves: list = field(default_factory=list)  # lockfile entries: the requested ranges this version satisfies (yarn.lock)

    def to_dict(self):
        return asdict(self)


class Parsed(list):
    """The declarations a parser read from a file, plus notes about what it could not follow (a missing `-r` file),
    which the scan shows as warnings."""

    def __init__(self, items=(), notes=()):
        super().__init__(items)
        self.notes = list(notes)


def normalize(ecosystem, name):
    """The comparable form of a package name: PyPI ignores case and treats -, _ and . alike; npm names are lowercase."""
    name = name.strip()
    if ecosystem == "pypi":
        return re.sub(r"[-_.]+", "-", name).lower()
    return name.lower()


def purl(ecosystem, name, version=""):
    """Package URL (https://github.com/package-url/purl-spec), the identifier CycloneDX uses for packages."""
    if ecosystem == "pypi":
        base = f"pkg:pypi/{normalize('pypi', name)}"
    else:
        n = name.lower()
        base = f"pkg:npm/%40{n[1:]}" if n.startswith("@") else f"pkg:npm/{n}"
    return f"{base}@{version}" if version else base


def left_out_reason(rel_path):
    """Why a dependency file is not counted as the product's own (test, example, docs, vendored), or "" when it is."""
    segments = [s.lower() for s in rel_path.replace("\\", "/").split("/")[:-1]]
    for reason, names in LEFT_OUT_DIRS.items():
        if any(s in names for s in segments):
            return reason
    return ""


def read_text(root, rel):
    path = os.path.join(root, rel)
    if os.path.getsize(path) > MAX_LOCK_BYTES:
        raise ValueError(f"larger than {MAX_LOCK_BYTES // 1_000_000} MB")
    with open(path, encoding="utf-8", errors="replace") as fh:
        return fh.read()


def line_of(lines, pattern, start=0):
    """1-based number of the first line from `start` matching the regex, or 0."""
    rx = re.compile(pattern)
    for i in range(start, len(lines)):
        if rx.search(lines[i]):
            return i + 1
    return 0
