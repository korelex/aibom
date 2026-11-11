"""One common shape for everything any finder or scanner reports."""
from dataclasses import dataclass, asdict

from .redact import redact


@dataclass
class Finding:
    tool: str      # which finder or scanner reported it
    kind: str      # model, provider, framework, agent, mcp, tool, vector_db, service, dataset, secret, other
    name: str      # the name as reported
    file: str = ""  # path relative to the scanned folder
    line: int = 0
    note: str = ""
    category: str = ""   # file category from triage (code, config, docs, test, ...)
    snippet: str = ""    # the line of code that proves it
    col: int = -1        # where in the line the name starts (-1 = unknown)

    def __post_init__(self):
        self.snippet = redact(self.snippet)  # a key on the same line as a model name must never reach the AI-BOM

    def to_dict(self):
        return asdict(self)


def rel(path, root):
    """Make a path relative to the scanned folder. Saved scanner outputs hold absolute paths from the machine
    that made them, so cut everything up to and including the app folder name."""
    path = str(path or "").replace("\\", "/")
    root = str(root).replace("\\", "/").rstrip("/")
    if path.startswith(root + "/"):
        return path[len(root) + 1:]
    name = root.rsplit("/", 1)[-1]
    marker = "/" + name + "/"
    if path.startswith("/") and marker in path:
        return path.split(marker, 1)[1]
    return path


def to_int(x):
    try:
        return int(str(x).strip())
    except Exception:
        return 0
