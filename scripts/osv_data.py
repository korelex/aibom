"""Build the advisory table of ai_db.json from OSV's complete ecosystem dumps.

OSV publishes every advisory of an ecosystem as one zip (https://google.github.io/osv.dev/data/). Reading the whole
dump, instead of asking about a list of package names, means every advisory for every AI package is kept: there is no
cut-off per package, and the members of a family (langchain-*, @langchain/*) are covered even when nobody listed them.

Each advisory keeps OSV's affected ranges exactly as written (every range, every event, explicit version lists), so the
scanner can decide "is this exact version affected?" by OSV's own rules. Records of one issue from several databases
(a GHSA, a PYSEC and a CVE id for the same problem) are merged into one, preferring the GitHub advisory.
"""
from __future__ import annotations

import datetime
import json
import os
import re
import urllib.request
import sys
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from aibom_engine import vulns  # noqa: E402  (the same rules the scanner uses)

DUMP_URL = "https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/all.zip"
ECOSYSTEMS = {"PyPI": "pypi", "npm": "npm"}
PREFERRED = ("GHSA-", "PYSEC-", "CVE-")  # which id names a merged advisory; anything else (MAL-, OSV-) comes last
GHSA_SEVERITY = {"low": "low", "moderate": "medium", "medium": "medium", "high": "high", "critical": "critical"}


def pep503(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def norm(ecosystem: str, name: str) -> str:
    return pep503(name) if ecosystem == "PyPI" else name.lower()


def download(ecosystem: str, cache_dir: str, max_age_hours: float = 20) -> tuple[str, str]:
    """(path of the dump zip, its Last-Modified header). A cached copy younger than max_age_hours is reused."""
    os.makedirs(cache_dir, exist_ok=True)
    path = os.path.join(cache_dir, f"{ecosystem}-all.zip")
    meta = path + ".json"
    if os.path.exists(path) and os.path.exists(meta):
        age = (datetime.datetime.now().timestamp() - os.path.getmtime(path)) / 3600
        if age < max_age_hours:
            with open(meta, encoding="utf-8") as fh:
                return path, json.load(fh).get("last_modified", "")
    req = urllib.request.Request(DUMP_URL.format(ecosystem=ecosystem), headers={"User-Agent": "aibom-build-db"})
    with urllib.request.urlopen(req, timeout=300) as res, open(path + ".part", "wb") as out:
        last_modified = res.headers.get("Last-Modified", "")
        while True:
            chunk = res.read(1 << 20)
            if not chunk:
                break
            out.write(chunk)
    os.replace(path + ".part", path)
    with open(meta, "w", encoding="utf-8") as fh:
        json.dump({"last_modified": last_modified}, fh)
    return path, last_modified


_CVSS3 = {"AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}, "AC": {"L": 0.77, "H": 0.44}, "UI": {"N": 0.85, "R": 0.62},
          "C": {"H": 0.56, "L": 0.22, "N": 0.0}, "I": {"H": 0.56, "L": 0.22, "N": 0.0}, "A": {"H": 0.56, "L": 0.22, "N": 0.0}}


def _roundup(x: float) -> float:
    """CVSS 3.1 Roundup: the smallest number with one decimal that is >= x, free of floating-point error."""
    i = round(x * 100000)
    return i / 100000.0 if i % 10000 == 0 else (i // 10000 + 1) / 10.0


def cvss3_base_score(vector: str) -> float | None:
    """The base score of a CVSS 3.0 / 3.1 vector, by the formula in the CVSS 3.1 specification; None when the vector is
    not a complete 3.x base vector."""
    if not vector.startswith(("CVSS:3.0/", "CVSS:3.1/")):
        return None
    m = dict(part.split(":", 1) for part in vector.split("/")[1:] if ":" in part)
    try:
        scope_changed = m["S"] == "C"
        pr = {"N": 0.85, "L": 0.68 if scope_changed else 0.62, "H": 0.5 if scope_changed else 0.27}[m["PR"]]
        av, ac, ui = _CVSS3["AV"][m["AV"]], _CVSS3["AC"][m["AC"]], _CVSS3["UI"][m["UI"]]
        c, i, a = _CVSS3["C"][m["C"]], _CVSS3["I"][m["I"]], _CVSS3["A"][m["A"]]
    except KeyError:
        return None
    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if scope_changed else 6.42 * iss
    exploitability = 8.22 * av * ac * pr * ui
    if impact <= 0:
        return 0.0
    if scope_changed:
        return _roundup(min(1.08 * (impact + exploitability), 10))
    return _roundup(min(impact + exploitability, 10))


def rating(score: float) -> str:
    """The CVSS qualitative rating of a base score."""
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low" if score > 0 else "none"


def _severity(record: dict) -> str:
    """The GitHub advisory severity when the record has one; else the rating of its CVSS 3.x base score; else
    "unknown". Never guessed."""
    raw = ((record.get("database_specific") or {}).get("severity") or "").lower()
    if raw in GHSA_SEVERITY:
        return GHSA_SEVERITY[raw]
    for aff in record.get("affected") or []:
        raw = ((aff.get("database_specific") or {}).get("severity") or "").lower()
        if raw in GHSA_SEVERITY:
            return GHSA_SEVERITY[raw]
    score = cvss3_base_score(_cvss(record))
    return rating(score) if score is not None else "unknown"


def _cvss(record: dict) -> str:
    for s in record.get("severity") or []:
        if str(s.get("type", "")).startswith("CVSS") and s.get("score"):
            return s["score"]
    return ""


def _affected_for(record: dict, ecosystem: str, wanted) -> dict[str, dict]:
    """{normalized package name: {"ranges": [...], "versions": [...]}} for the affected entries of this record that are
    AI packages of this ecosystem."""
    out = {}
    for aff in record.get("affected") or []:
        pkg = aff.get("package") or {}
        if pkg.get("ecosystem") != ecosystem:
            continue
        name = norm(ecosystem, pkg.get("name", ""))
        if not wanted(name):
            continue
        entry = out.setdefault(name, {"ranges": [], "versions": []})
        for rng in aff.get("ranges") or []:
            if rng.get("type") in ("ECOSYSTEM", "SEMVER"):
                entry["ranges"].append({"type": rng["type"], "events": [dict(e) for e in rng.get("events") or []]})
        entry["versions"] += [str(v) for v in aff.get("versions") or []]
    return out


def read_dump(path: str, ecosystem: str, wanted) -> dict[str, list[dict]]:
    """{ "<eco>:<name>": [record summaries] } for every advisory in the dump that affects a wanted package."""
    found: dict[str, list[dict]] = {}
    with zipfile.ZipFile(path) as z:
        for info in z.infolist():
            if not info.filename.endswith(".json"):
                continue
            record = json.loads(z.read(info))
            if record.get("withdrawn"):
                continue
            for name, affected in _affected_for(record, ecosystem, wanted).items():
                if not affected["ranges"] and not affected["versions"]:
                    continue
                summary = (record.get("summary") or "").strip() or ((record.get("details") or "").strip().splitlines() or [""])[0]
                found.setdefault(f"{ECOSYSTEMS[ecosystem]}:{name}", []).append({
                    "id": record["id"],
                    "aliases": sorted(set(record.get("aliases") or []) - {record["id"]}),
                    "severity": _severity(record),
                    "cvss": _cvss(record),
                    "summary": summary[:240],
                    "published": (record.get("published") or "")[:10],
                    "modified": (record.get("modified") or "")[:10],
                    "ranges": affected["ranges"],
                    "versions": sorted(set(affected["versions"])),
                    "url": f"https://osv.dev/vulnerability/{record['id']}",
                })
    return found


def _rank(adv: dict) -> tuple:
    prefix = next((i for i, p in enumerate(PREFERRED) if adv["id"].startswith(p)), len(PREFERRED))
    return prefix, adv["id"]


def merge_mirrors(advisories: list[dict], ecosystem: str = "pypi") -> list[dict]:
    """One advisory per issue: records whose ids or aliases overlap are merged. The preferred record (GHSA, then PYSEC,
    then CVE) gives the id and summary; every other id becomes an alias; a severity comes from any record.

    The affected versions are the union of every record's: databases sometimes disagree (GitHub says fixed in 0.0.339,
    PYSEC says 0.1.11), and OSV itself counts a version as affected when any record says so. A listed version that
    the kept ranges already cover is not stored again."""
    groups: list[list[dict]] = []
    for adv in sorted(advisories, key=_rank):
        ids = {adv["id"], *adv["aliases"]}
        hit = [g for g in groups if ids & {x for a in g for x in (a["id"], *a["aliases"])}]
        if hit:
            merged = [a for g in hit for a in g] + [adv]
            groups = [g for g in groups if g not in hit] + [merged]
        else:
            groups.append([adv])
    out = []
    for g in groups:
        g.sort(key=_rank)
        best = dict(g[0])
        best["aliases"] = sorted({x for a in g for x in (a["id"], *a["aliases"])} - {best["id"]})
        if best["severity"] == "unknown":
            best["severity"] = next((a["severity"] for a in g if a["severity"] != "unknown"), "unknown")
        best["cvss"] = best["cvss"] or next((a["cvss"] for a in g if a["cvss"]), "")
        ranges = []
        for a in g:
            for r in a["ranges"]:
                if r not in ranges:
                    ranges.append(r)
        best["ranges"] = ranges
        listed = sorted({v for a in g for v in a["versions"]})
        only_ranges = {"ranges": ranges, "versions": []}
        best["versions"] = [v for v in listed if not vulns.affected(ecosystem, v, only_ranges)[0]]
        out.append(best)
    return sorted(out, key=lambda a: a["id"])


def build(packages: list[dict], families: list[dict], cache_dir: str) -> tuple[dict[str, list[dict]], dict]:
    """(advisory table, meta) for the catalogue packages and families."""
    table: dict[str, list[dict]] = {}
    meta = {"source": "OSV.dev ecosystem dumps", "fetched": datetime.date.today().isoformat(), "dumps": {}}
    for ecosystem in ECOSYSTEMS:
        names = {norm(ecosystem, p["name"]) for p in packages if p.get("ecosystem") == ecosystem}
        prefixes = tuple(norm(ecosystem, f["prefix"]) for f in families if f.get("ecosystem") == ecosystem)

        def wanted(name, names=names, prefixes=prefixes):
            return name in names or (bool(prefixes) and name.startswith(prefixes))

        path, last_modified = download(ecosystem, cache_dir)
        meta["dumps"][ecosystem] = {"url": DUMP_URL.format(ecosystem=ecosystem), "last_modified": last_modified}
        for key, advisories in read_dump(path, ecosystem, wanted).items():
            table[key] = merge_mirrors(advisories, ECOSYSTEMS[ecosystem])
    return dict(sorted(table.items())), meta
