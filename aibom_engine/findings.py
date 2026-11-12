"""The known vulnerabilities of a scan as a list a person can read, worst first, and a plan to fix them.

`collect` flattens the advisories of every counted AI package into findings; `sort_findings` and `filter_findings` order and
narrow them; `fix_plan` picks, for each package, the lowest version that the advisories say fixes everything they name for
it, and then checks that version again with the same matcher that found the problem, so the plan never promises a fix the
database itself does not support. Nothing here draws anything: the terminal, the HTML report and the Markdown report all
read these same lists, so they cannot disagree.
"""
from . import db as database
from . import vulns

ORDER = ("critical", "high", "medium", "low", "unknown")
RANK = {sev: len(ORDER) - i for i, sev in enumerate(ORDER)}
LEVEL_RANK = {"called": 2, "imported": 1, "declared": 0}
ECOSYSTEM_LABEL = {"pypi": "PyPI", "npm": "npm"}


def _position(severity):
    """Position of a severity in ORDER (0 = critical); an unrecognised one counts as unknown."""
    return ORDER.index(severity) if severity in ORDER else len(ORDER) - 1


def counted(packages, everything=False):
    """The packages a list shows by default: those the project itself needs or its code imports, not the ones that are only in
    a lockfile because another package needs them (`everything` keeps those too)."""
    return [c for c in packages or [] if not c.get("left_out") and (everything or c.get("direct") is not False)]


def at_least(severity):
    """The severities from `severity` up to critical (`medium` -> critical, high, medium)."""
    return ORDER[: ORDER.index(severity) + 1]


def collect(packages):
    """One finding per advisory of each counted package (left-out packages are dropped)."""
    out = []
    for c in packages or []:
        if c.get("left_out"):
            continue
        for a in (c.get("vulnerabilities") or {}).get("advisories", []):
            out.append({"package": c["name"], "version": c.get("version") or "", "ecosystem": c.get("ecosystem", "pypi"),
                        "level": c.get("evidence_level", "declared"), "declared": c.get("declared", True),
                        "id": a["id"], "aliases": a.get("aliases", []), "severity": a.get("severity") or "unknown",
                        "summary": a.get("summary", ""), "fixed_in": a.get("fixed_in") or "", "url": a.get("url", ""),
                        "cvss": a.get("cvss", "")})
    return sort_findings(out)


def sort_findings(findings):
    """Critical first; inside a severity the packages your code calls come first, then by package and id."""
    return sorted(findings, key=lambda f: (-RANK.get(f["severity"], 1), -LEVEL_RANK.get(f["level"], 0), f["package"].lower(), f["id"]))


def filter_findings(findings, severity=None, called=False):
    """Keep the findings at or above `severity`, and only those in packages your code calls when `called`."""
    keep = at_least(severity) if severity else ORDER
    return [f for f in findings if f["severity"] in keep and (not called or f["level"] == "called")]


def counts(findings):
    return {sev: sum(1 for f in findings if f["severity"] == sev) for sev in ORDER}


def verdict(findings):
    """`N known vulnerabilities in M AI packages, X of them in packages your code calls.`"""
    if not findings:
        return "No known vulnerabilities in the AI packages checked."
    packages = {(f["package"], f["version"]) for f in findings}
    called = [f for f in findings if f["level"] == "called"]
    n, m = len(findings), len(packages)
    head = "%d known vulnerabilit%s in %d AI package%s" % (n, "y" if n == 1 else "ies", m, "" if m == 1 else "s")
    if not called:
        return head + ", none in packages your code calls."
    if len(called) == n:
        return head + ", all in packages your code calls."
    return head + ", %d of them in packages your code calls." % len(called)


def _jump(ecosystem, current, target):
    """Why moving from `current` to `target` may break the code: '' for a patch or minor step, else a short warning."""
    a, b = vulns.parse(ecosystem, current), vulns.parse(ecosystem, target)
    if a is None or b is None:
        return ""
    ca = a.core if hasattr(a, "core") else tuple(a.release[:3]) + (0,) * (3 - len(a.release[:3]))
    cb = b.core if hasattr(b, "core") else tuple(b.release[:3]) + (0,) * (3 - len(b.release[:3]))
    if ca[0] != cb[0]:
        return "major version jump (%d to %d)" % (ca[0], cb[0])
    if ca[0] == 0 and ca[1] != cb[1]:
        return "0.%d to 0.%d: 0.x versions can change anything" % (ca[1], cb[1])
    return ""


def fix_plan(packages, db=None):
    """[{package, version, ecosystem, level, target, clears, remaining, warning}] for each vulnerable package, worst first.

    `target` is the highest `fixed_in` among the package's advisories, so one upgrade covers every advisory that names a
    fix. It is then re-checked against the database: `remaining` lists the advisory ids still affecting the target (the
    ones that name no fix, or that the target itself is in), and a package with no named fix at all gets target ''."""
    db = db or database.load_db()
    plan = []
    for c in packages or []:
        if c.get("left_out"):
            continue
        advisories = (c.get("vulnerabilities") or {}).get("advisories", [])
        if not advisories:
            continue
        eco = c.get("ecosystem", "pypi")
        best, best_version = None, ""
        for a in advisories:
            v = vulns.parse(eco, a.get("fixed_in") or "")
            if v is not None and (best is None or v > best):
                best, best_version = v, a["fixed_in"]
        worst = min((_position(a.get("severity")) for a in advisories))
        row = {"package": c["name"], "version": c.get("version") or "", "ecosystem": eco, "level": c.get("evidence_level", "declared"),
               "worst": ORDER[worst], "total": len(advisories), "target": best_version, "clears": 0,
               "remaining": [a["id"] for a in advisories], "warning": ""}
        if best_version:
            after = database.vulnerability_check(ECOSYSTEM_LABEL.get(eco, "PyPI"), c["name"], best_version, db)
            left = [a["id"] for a in after.get("advisories", [])] if after.get("status") == "checked" else None
            if left is None:  # the target version could not be checked: promise nothing
                row["target"] = ""
            else:
                row.update(clears=len(advisories) - len([i for i in left if i in row["remaining"]]), remaining=left,
                           warning=_jump(eco, c.get("version") or "", best_version))
        plan.append(row)
    plan.sort(key=lambda r: (ORDER.index(r["worst"]), -LEVEL_RANK.get(r["level"], 0), r["package"].lower()))
    return plan

