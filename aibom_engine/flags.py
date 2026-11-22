"""Risk flags: one shape for everything aibom warns about.

A flag says that something found in the scan is risky, how risky, where, and what to do about it. Every flag has a
rule id that never changes (`model.retired`, later `mcp.unpinned-package`, ...), a severity, the place it was found
and a one-line fix. The flags of one scan are saved in flags.json, attached to the components they are about in
aibom.cdx.json, shown in the reports, and are what `--fail-on` will test.

Severities (info, low, medium, high) say how much a reader should worry, not whether the app can be attacked:
- high:   something that breaks or exposes the app now (a retired model: its API calls fail).
- medium: act soon (a model with a retirement date; a licence that needs legal review).
- low:    good practice (a floating alias that a dated snapshot could pin).
- info:   worth knowing, no action required.

Text fields go through the same redaction as every other finding, so a flag can never carry a key or password even if a
detector hands one over by mistake. A flag has no field for a secret's value on purpose.
"""
import json
from dataclasses import asdict, dataclass

from .redact import redact

SEVERITIES = ("info", "low", "medium", "high")
RANK = {s: i for i, s in enumerate(SEVERITIES, start=1)}
PROPERTY = "aibom-engine:flag"


@dataclass
class Flag:
    rule: str            # stable id, e.g. "model.retired"
    severity: str        # one of SEVERITIES
    category: str        # model, mcp, secret, model-file, code
    title: str           # a short sentence a person reads in a list
    subject: str         # what it is about: a model, a server, a file
    fix: str             # one line: what to do
    file: str = ""       # path relative to the scanned folder ("" when it is not about a file)
    line: int = 0
    detail: str = ""     # one more sentence if the title is not enough; never a secret value
    ref: str = ""        # bom-ref of the component it is about; "" means the application as a whole

    def __post_init__(self):
        if self.severity not in RANK:
            raise ValueError(f"unknown severity {self.severity!r}; use one of {', '.join(SEVERITIES)}")
        if not self.rule or not self.title or not self.fix:
            raise ValueError(f"a flag needs a rule, a title and a fix (got rule={self.rule!r})")
        if not isinstance(self.line, int) or self.line < 0:
            raise ValueError(f"line must be a number, 0 or more (got {self.line!r})")
        self.file = str(self.file or "").replace("\\", "/")
        for name in ("title", "subject", "fix", "detail"):
            setattr(self, name, redact(str(getattr(self, name) or "")))

    def to_dict(self):
        return asdict(self)

    @classmethod
    def from_dict(cls, d):
        return cls(**{k: d[k] for k in cls.__dataclass_fields__ if k in d})

    def key(self):
        """What makes two flags the same flag: the same rule about the same subject in the same place."""
        return (self.rule, self.subject, self.file, self.line)


def sort_flags(flags):
    """Worst first; then by category, subject and place so the order never changes between runs."""
    return sorted(flags, key=lambda f: (-RANK[f.severity], f.category, f.subject.lower(), f.file, f.line, f.rule))


def dedupe(flags):
    seen, out = set(), []
    for f in flags:
        if f.key() not in seen:
            seen.add(f.key())
            out.append(f)
    return out


def collect(*groups):
    """The flags of every detector, with duplicates removed, worst first."""
    return sort_flags(dedupe([f for g in groups for f in g]))


def counts(flags):
    """{severity: how many}, worst first, every severity present (0 when none)."""
    return {s: sum(1 for f in flags if f.severity == s) for s in reversed(SEVERITIES)}


def at_least(flags, severity):
    """The flags at `severity` or worse."""
    if severity not in RANK:
        raise ValueError(f"unknown severity {severity!r}; use one of {', '.join(SEVERITIES)}")
    return [f for f in flags if RANK[f.severity] >= RANK[severity]]


def decide(flags, level, incomplete=()):
    """What a scan comes to, for the exit code and for the report alike: (outcome, the flags behind it).
    The outcome is "failed", "incomplete" or "passed", or "report-only" when no level was given to fail on."""
    if not level:
        return "report-only", at_least(flags, "high")
    hits = at_least(flags, level)
    if hits:
        return "failed", hits
    return ("incomplete" if incomplete else "passed"), []


def headline(flags):
    """(how many flags to put in a headline, the text beside it). Info notes are real but too many to be a headline: a scan of a
    large project has hundreds of "licence not known" notes, so they are named apart and the count is the flags that need a look."""
    real = at_least(flags, "low")
    text = ", ".join(f"{n} {s}" for s, n in counts(real).items() if n)
    info = len(flags) - len(real)
    note = f"{info} info note{'' if info == 1 else 's'}"
    if text and info:
        text += f"; plus {note}"
    elif info:
        text = f"{note} only"
    return len(real), text


def as_property(flag):
    """The CycloneDX property that carries a flag on its component (the value is compact JSON, always in the same key order)."""
    body = {"rule": flag.rule, "severity": flag.severity, "title": flag.title, "fix": flag.fix}
    for key in ("subject", "file", "line", "detail"):
        if getattr(flag, key):
            body[key] = getattr(flag, key)
    return {"name": PROPERTY, "value": json.dumps(body, sort_keys=True, ensure_ascii=False)}


# ---- the risks aibom already knew about for models: lifecycle, pinning and licence ----

def _where(item):
    """The first place a model is used in live code, else any place that names it."""
    places = [e for e in item.get("evidence", []) if e.get("line", 0) > 0]
    live = [e for e in places if e.get("use") == "live"] or places
    return (live[0]["file"], live[0]["line"]) if live else ("", 0)


def model_flags(items, ref_of):
    """Flags for the models: retired, deprecated, floating alias, unpinned Hugging Face repo, licence.

    `ref_of(item)` gives the bom-ref of a model's component so the flag can sit on it in the AI-BOM."""
    out = []
    for it in items:
        if it.get("kind") != "model":
            continue
        name = it["name"]
        file, line = _where(it)
        base = {"category": "model", "subject": name, "file": file, "line": line, "ref": ref_of(it)}
        status, replacement = it.get("status"), it.get("replacement")
        move = f"Move to {replacement}." if replacement else "Move to a current model from the provider's list."
        if status == "retired":
            out.append(Flag("model.retired", "high", title="This model is retired: calls to it fail.",
                            fix=move, detail=_dates(it), **base))
        elif status == "deprecated":
            when = it.get("retirement_date")
            out.append(Flag("model.deprecated", "medium", title="This model is deprecated and has a retirement date." if when else "This model is deprecated.",
                            fix=(move if not when else f"Move before {when}. " + move), detail=_dates(it), **base))
        if it.get("floating"):
            out.append(Flag("model.floating-alias", "low", title="A floating alias: the model behind this name can change.",
                            fix="Pin a dated snapshot of the model.", **base))
        if it.get("hf_repo"):
            out.append(Flag("model.unpinned-hf-repo", "info", title="A Hugging Face model: this scan does not check for a pinned revision.",
                            fix="Load it with a fixed commit revision.", **base))
        if it.get("license_restricted"):
            out.append(Flag("model.license-restricted", "medium", title="A licence that limits commercial use or needs review.",
                            fix="Have the licence reviewed before commercial use.", detail=it.get("license_name") or "", **base))
        elif not it.get("license") or it.get("license") == "unknown":
            out.append(Flag("model.license-unknown", "info", title="The licence of this model is not known to aibom.",
                            fix="Check the licence with the provider.", **base))
    return out


def _dates(it):
    bits = []
    if it.get("deprecation_date"):
        bits.append("deprecated " + it["deprecation_date"])
    if it.get("retirement_date"):
        bits.append(("retired " if it.get("status") == "retired" else "retires ") + it["retirement_date"])
    return ", ".join(bits)
