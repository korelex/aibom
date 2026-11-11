"""Known vulnerabilities of an exact package version, decided by OSV's own rules.

The advisories in ai_db.json keep OSV's affected ranges as OSV wrote them (scripts/osv_data.py). A version is affected
when it is listed in an advisory's `versions`, or when a range's events put it inside: events are read in version
order, `introduced` opens the range, `fixed` closes it at that version, `last_affected` closes it after that version,
and `limit` stops the range (https://ossf.github.io/osv-schema/#evaluation).

Versions are compared the way their ecosystem does: PEP 440 for PyPI (with `packaging`), Semantic Versioning 2.0 for
npm. Only an exact installed version can be checked. A range ("^0.0.20", ">=1.0") says what is allowed, not what is
installed, so it is never matched: that would report vulnerabilities in versions nobody installed, or miss them.
"""
from __future__ import annotations

import re
from functools import lru_cache

from packaging.version import InvalidVersion, Version

_SEMVER = re.compile(r"^v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z.-]+)?$")


class SemVer:
    """A Semantic Versioning 2.0 version, ordered by the specification (build metadata is ignored)."""
    __slots__ = ("core", "pre")

    def __init__(self, text: str):
        m = _SEMVER.match(text.strip())
        if not m:
            raise ValueError(f"not a semantic version: {text!r}")
        self.core = (int(m.group(1)), int(m.group(2)), int(m.group(3)))
        self.pre = tuple(int(p) if p.isdigit() else p for p in m.group(4).split(".")) if m.group(4) else ()

    def _key(self):
        # A pre-release sorts before its release; identifiers: numbers before strings, numbers by value, strings in
        # ASCII order, and a longer list wins when the shared part is equal.
        pre = tuple((0, p, "") if isinstance(p, int) else (1, 0, p) for p in self.pre)
        return self.core, (0, pre) if self.pre else (1, ())

    def __lt__(self, other):
        return self._key() < other._key()

    def __le__(self, other):
        return self._key() <= other._key()

    def __gt__(self, other):
        return self._key() > other._key()

    def __ge__(self, other):
        return self._key() >= other._key()

    def __eq__(self, other):
        return isinstance(other, SemVer) and self._key() == other._key()

    def __hash__(self):
        return hash(self._key())


@lru_cache(maxsize=20000)
def parse(ecosystem: str, version: str):
    """A comparable version, or None when the text is not a version of that ecosystem."""
    try:
        if ecosystem == "npm":
            return SemVer(version)
        return Version(version)
    except (InvalidVersion, ValueError, TypeError):
        return None


def is_exact(ecosystem: str, version: str) -> bool:
    """Whether a version text names one installed version (not a range, not empty)."""
    return bool(version) and parse(ecosystem, version) is not None


def _event_key(ecosystem, event):
    kind, value = next(iter(event.items()))
    if kind == "introduced" and value == "0":
        return (0, None), kind, value
    v = parse(ecosystem, value)
    return ((1, v) if v is not None else (2, None)), kind, value


def _in_range(ecosystem: str, version, events: list[dict]) -> tuple[bool, str]:
    """(affected, the fixed version that closes the range above it or "") for one OSV range."""
    keyed = []
    for e in events:
        k = _event_key(ecosystem, e)
        if k[0][0] == 2:
            return False, ""  # an event that is not a version of this ecosystem: the range cannot be evaluated
        keyed.append(k)
    keyed.sort(key=lambda k: (k[0][0], k[0][1]) if k[0][1] is not None else (k[0][0],))
    affected = False
    for (_, v), kind, _value in keyed:
        if kind == "introduced":
            if v is None or version >= v:
                affected = True
        elif kind == "fixed":
            if version >= v:
                affected = False
        elif kind == "last_affected":
            if version > v:
                affected = False
        elif kind == "limit":
            if version >= v:
                affected = False
                break
    fixed_above = ""
    if affected:
        above = [(v, value) for (_, v), kind, value in keyed if kind == "fixed" and v is not None and v > version]
        fixed_above = min(above)[1] if above else ""
    return affected, fixed_above


def affected(ecosystem: str, version: str, advisory: dict) -> tuple[bool, str]:
    """(is this exact version affected by the advisory, the version that fixes it or "" when none is known)."""
    v = parse(ecosystem, version)
    if v is None:
        return False, ""
    listed = {parse(ecosystem, x) for x in advisory.get("versions") or []}
    hit, fixed = v in listed, ""
    for rng in advisory.get("ranges") or []:
        in_range, fixed_above = _in_range(ecosystem, v, rng.get("events") or [])
        if in_range:
            hit = True
            fixed = fixed or fixed_above
    return hit, fixed


def check(ecosystem: str, name: str, version: str, advisories: list[dict]) -> dict:
    """The result for one package: {"status": "checked" | "not_checked", "reason", "advisories": [...]}."""
    if not version:
        return {"status": "not_checked", "reason": "no installed version is known (a range, or no lockfile)", "advisories": []}
    if not is_exact(ecosystem, version):
        return {"status": "not_checked", "reason": f"'{version}' is not one {('npm' if ecosystem == 'npm' else 'PyPI')} version", "advisories": []}
    found = []
    for adv in advisories:
        hit, fixed = affected(ecosystem, version, adv)
        if hit:
            found.append({"id": adv["id"], "aliases": adv.get("aliases", []), "severity": adv.get("severity", "unknown"),
                          "summary": adv.get("summary", ""), "fixed_in": fixed, "url": adv.get("url", "")})
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4, "none": 5}
    found.sort(key=lambda a: (order.get(a["severity"], 4), a["id"]))
    return {"status": "checked", "reason": "", "advisories": found}
