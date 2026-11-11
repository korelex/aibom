"""The readable outputs for people who do not read JSON: a web page, a markdown summary and a spreadsheet (CSV).
The CycloneDX file stays the source of truth; these are built from the same items."""
import csv
import datetime
import html
import io

from . import __version__
from .db import today_iso
from .display import build_rows, by_maker

TIER_TEXT = {"declared": "Confirmed", "inferred": "Worked out"}
TIER_LONG = {"declared": "Confirmed: the name is written in the code", "inferred": "Worked out: the code names it through a constant such as GPT_4O"}
LEVEL_TEXT = {"called": "Called", "imported": "Imported", "declared": "Declared"}
LEVEL_LONG = {"called": "Called: live code passes this name into a call on an AI SDK",
              "declared": "Declared: the name is written in the code or settings, but no call on an AI SDK was proven to receive it "
                          "(it may still be used, for example through a variable, a lookup table or plain HTTP)",
              "": "Not assessed: this scan was made by an older version of aibom, which did not check it. Scan again to see it"}
REACHABILITY_TEXT = "not yet verified: the scanner does not prove that a request from outside reaches this code"
MODE_TEXT = {"chat": "chat model", "embedding": "embedding model", "image_generation": "image model", "audio_transcription": "speech-to-text model",
             "audio_speech": "text-to-speech model", "responses": "chat model", "completion": "text model", "rerank": "reranking model",
             "moderation": "moderation model", "realtime": "realtime voice model", "video_generation": "video model"}
NO_MODELS = ("This usually means the app picks its model when it runs (for example from an environment variable, a settings page or a database), "
             "or that it uses no AI models. A scan of the code cannot see choices made at run time.")
LISTED_NOTE = "long tables or lists of models, for example token-limit tables or model pickers"
# Round-3 benchmark result; reproduce it with `python benchmark/run.py` (see benchmark/README.md).
TESTED = ("In a blind test on five open-source apps, this scanner found about 79% of the AI models named in their code, and about "
          "99% of what it reported was correct (benchmark/README.md in the aibom repository).")
CANNOT_SEE = ["A model that the app chooses when it runs: an environment variable, a settings page, a database or a remote setting. A scan reads code; it does not run the app.",
              "Anything outside this one repository, such as code in other repositories or in private packages.",
              "AI packages are read from Python and JavaScript/TypeScript dependency files only (not Go, Java or C#), and the files do not say which package needs which, so no dependency tree between packages is drawn.",
              "AI parts other than models and packages: MCP servers, datasets, secrets and weight files are not covered yet.",
              "Some names. A name that no dictionary lists and that no rule recognises can be missed. " + TESTED]


def models(n):
    return f"{n} model" + ("" if n == 1 else "s")


STATUS_TEXT = {"retired": "retired", "deprecated": "deprecated", "active": "active", "unknown": "not tracked"}
PLATFORM_NOTE = ("* The date is for the maker's own API. Amazon Bedrock, Azure and Google Vertex AI set their own "
                 "retirement schedules, so check the one you use.")


def status_text(r):
    """The status as a reader sees it. 'not tracked' means no sourced record exists, which is not the same as 'active'."""
    s = r.get("status") or "unknown"
    text = STATUS_TEXT.get(s, s)
    return text + ("*" if s in ("retired", "deprecated", "active") and r.get("lifecycle_scope") == "platform" else "")


def pin_text(r):
    """Why a name is or is not pinned, so a reader can tell a real risk from a name that cannot be pinned."""
    if r.get("pinned") is True:
        return "yes"
    if r.get("hf_repo"):
        return "Hugging Face repo (revision not checked)"
    if r.get("floating"):
        return "no (floating alias)"
    if r.get("pinned") is False:
        return "no (no dated snapshot known)"
    return "-"


def risk_summary(rows):
    """Count the model-level risks a reader should see before the full table."""
    all_rows = rows["used"] + rows["listed"]
    return {
        "total": len(all_rows),
        "retired": [r for r in all_rows if r.get("status") == "retired"],
        "deprecated": [r for r in all_rows if r.get("status") == "deprecated"],
        "floating": [r for r in all_rows if r.get("floating")],
        "hf": [r for r in all_rows if r.get("hf_repo")],
        "restricted": [r for r in all_rows if r.get("license_restricted")],
        "unknown": [r for r in all_rows if not r.get("license") or r.get("license") == "unknown"],
        "untracked": [r for r in all_rows if (r.get("status") or "unknown") == "unknown"],
        "checked": max((r.get("lifecycle_checked") or "" for r in all_rows), default=""),
        "platform": any(r.get("lifecycle_scope") == "platform" and r.get("status") in ("retired", "deprecated", "active") for r in all_rows),
    }


def risk_lines(risk):
    """(label, models) pairs shown in the Risks block of every output."""
    return [("Retired (API calls fail)", risk["retired"]),
            ("Deprecated (retirement scheduled, still works)", risk["deprecated"]),
            ("Floating aliases (a dated snapshot exists to pin)", risk["floating"]),
            ("Hugging Face models (pin a commit revision; this scan does not check for one)", risk["hf"]),
            ("Restricted licenses (flag for legal review)", risk["restricted"]),
            ("Unknown licenses", risk["unknown"])]


STALE_AFTER_DAYS = 90


def lifecycle_notes(risk):
    """Plain-language limits of the lifecycle column, shown under the Risks block."""
    notes = []
    if risk["checked"]:
        age = (datetime.date.fromisoformat(today_iso()) - datetime.date.fromisoformat(risk["checked"])).days
        if age > STALE_AFTER_DAYS:
            notes.append(f"Warning: the lifecycle data was last checked {age} days ago ({risk['checked']}). Retirements announced since "
                         "then are not included; update aibom for newer data.")
    if risk["total"]:
        notes.append(f"Lifecycle: {risk['total'] - len(risk['untracked'])} of {risk['total']} models have a sourced record"
                     + (f" (checked against the providers' own pages on {risk['checked']})" if risk["checked"] else "")
                     + ". \"Not tracked\" means no record, not that the model is fine.")
    if risk["platform"]:
        notes.append(PLATFORM_NOTE)
    return notes


def risk_names(items, limit=5):
    # A "*" marks a date that is for the maker's own API while the code uses a cloud platform (see PLATFORM_NOTE).
    names = [r["name"] + ("*" if r.get("lifecycle_scope") == "platform" and r.get("status") in ("retired", "deprecated") else "") for r in items[:limit]]
    more = len(items) - len(names)
    return ", ".join(names) + (f" and {more} more" if more > 0 else "")


def license_label(r):
    name = r.get("license_name") or r.get("license") or "unknown"
    use = r.get("license_commercial_use") or ""
    if use == "conditional":
        return f"{name} (conditional)"
    if use == "no":
        return f"{name} (non-commercial)"
    if use == "provider-terms":
        return "Provider API terms"
    return name


def intro(rows, app):
    used, listed, gone = rows["used"], rows["listed"], rows["left_out"]
    if not used and not listed:
        extra = f" {models(len(gone))} named in comments, messages, tests or documentation {'was' if len(gone) == 1 else 'were'} left out." if gone else ""
        return f"No AI model names were found in the code of {app}.{extra} {NO_MODELS}"
    s = f"{app} uses {models(len(used))} directly in its code." if used else f"No model is set or used directly in the code of {app}."
    if listed:
        s += f" {len(listed)} more model{'' if len(listed) == 1 else 's'} only appear{'s' if len(listed) == 1 else ''} in {LISTED_NOTE}."
    if gone:
        s += f" {len(gone)} further name{'' if len(gone) == 1 else 's'} {'was' if len(gone) == 1 else 'were'} left out because they appear only in comments, messages, tests or documentation."
    return s


def where(row, links):
    p = row["places"][0] if row["places"] else None
    if not p:
        return "", "", 0
    return f"{p['file']}:{p['line']}", links.url_for(p["file"], p["line"]) if links else "", max(len(row["places"]) - 1, 0)


def source_line(source, links, meta):
    s = source or ""
    if links and links.ok:
        s = f"{links.url} at version {links.commit[:10]}" + (f" (folder {links.subpath})" if links.subpath else "")
    return s


KIND_TEXT = {"llm_sdk": "AI SDK", "agent_framework": "Agent framework", "vector_db": "Vector database", "mcp": "MCP",
             "model_runtime": "Model runtime", "guardrail": "Guardrail", "dataset_loader": "Dataset loader"}
SEVERITIES = ("critical", "high", "medium", "low", "unknown")
SEVERITY_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "unknown": 1}
LEVEL_RANK = {"called": 2, "imported": 1, "declared": 0}
PACKAGE_EVIDENCE_WHY = {"called": "Called: live code calls this package, so it is in use",
                        "imported": "Imported: live code imports this package, but no call to it was found",
                        "declared": "Declared: it is listed in a dependency file, but no live code imports it"}
PACKAGE_NOTE = ("A known vulnerability means this exact version is listed in an advisory, not that the app reaches the vulnerable "
                "code: reachability is not verified. Not checked means no exact installed version is known (a version range, or no "
                "lockfile), which is not the same as no vulnerabilities.")


def advisory_date():
    """When the bundled advisories were fetched from OSV."""
    try:
        from .db import load_db
        return ((load_db().get("meta") or {}).get("vulnerabilities") or {}).get("fetched", "")
    except Exception:
        return ""


def sev_chip(severity):
    """A severity as a coloured label. The word is always there, so a black-and-white print or a colour-blind reader loses nothing."""
    sev = severity if severity in SEVERITIES else "unknown"
    return f'<span class="sev sev-{sev}">{sev.upper()}</span>'


def sev_order(advisories):
    """Advisories worst first, then by id, so the order never depends on how the data was stored."""
    return sorted(advisories, key=lambda a: (-SEVERITY_RANK.get(a["severity"], 1), a["id"]))


def sev_bar_html(rows):
    """A stacked bar and key of the advisories by severity, worst first; nothing when there are none."""
    counts = {sev: sum(1 for r in rows for a in r["advisories"] if a["severity"] == sev) for sev in SEVERITIES}
    total = sum(counts.values())
    if not total:
        return ""
    bar = "".join(f'<i class="sev-{sev}" style="width:{counts[sev] * 100 / total:.2f}%" title="{counts[sev]} {sev}"></i>' for sev in SEVERITIES if counts[sev])
    key = " ".join(f'<span class="sev sev-{sev}">{sev.upper()}</span> {counts[sev]}' for sev in SEVERITIES if counts[sev])
    return f'<div class="sevbar" role="img" aria-label="{total} known vulnerabilities by severity">{bar}</div><p class="sevkey">{key}</p>'


def vuln_card(rows):
    """A summary card for the top of the page: how many known vulnerabilities, by severity, linking to the list."""
    direct = [r for r in rows if r["direct"] is not False]
    total = sum(len(r["advisories"]) for r in direct)
    if not total:
        return ""
    return (f"<div class='card vulncard'><b><a href='#vulns'>{total}</a></b><span>known vulnerabilities in AI packages</span>"
            f"{sev_bar_html(direct)}</div>")


def fix_plan_rows(packages):
    """The verified fix plan of a scan's packages; empty when it cannot be worked out (the report must still be written)."""
    try:
        from . import findings
        return findings.fix_plan(findings.counted(packages))
    except Exception:
        return []


def fix_plan_text(p):
    if not p["target"]:
        return "no fixed version is named by its advisories"
    done = f"clears all {p['total']}" if not p["remaining"] else f"clears {p['clears']} of {p['total']} (still open: {', '.join(p['remaining'])})"
    return f"upgrade to {p['target']}: {done}" + (f". Test your code: {p['warning']}" if p["warning"] else "")


def package_rows(packages):
    """Display rows for the AI packages the scan counts (left-out ones are dropped), most urgent first: known
    vulnerabilities by severity, then the strongest proof of use, then the name."""
    rows = []
    for c in packages or []:
        if c.get("left_out"):
            continue
        vuln = c.get("vulnerabilities") or {"status": "not_checked", "advisories": []}
        advisories = vuln.get("advisories", [])
        counts = {sev: sum(1 for a in advisories if a["severity"] == sev) for sev in SEVERITIES}
        worst = max((a["severity"] for a in advisories), key=lambda sev: SEVERITY_RANK.get(sev, 1), default="")
        if vuln.get("status") != "checked":
            vtext = "Not checked"
        elif not advisories:
            vtext = "None known"
        else:
            vtext = f"{len(advisories)} known (" + ", ".join(f"{n} {sev}" for sev, n in counts.items() if n) + ")"
        live = lambda items: [i for i in items if not i.get("left_out") and i.get("line", 0) > 0]  # noqa: E731
        proof = (live(c.get("calls", [])) or live(c.get("imports", [])) or live(c.get("evidence", [])) or [None])[0]
        rows.append({"name": c["name"], "version": c.get("version") or "", "kind": KIND_TEXT.get(c.get("category"), "AI package"),
                     "direct": c.get("direct"), "level": c["evidence_level"], "declared": c.get("declared", True), "proof": proof,
                     "vuln_status": vuln.get("status", "not_checked"), "vuln_reason": vuln.get("reason", ""), "vuln_text": vtext,
                     "advisories": advisories, "worst": worst, "purl": c.get("purl", ""), "vendor": c.get("vendor", "")})
    rows.sort(key=lambda r: (-SEVERITY_RANK.get(r["worst"], 0), -LEVEL_RANK[r["level"]], r["name"].lower(), r["version"]))
    return rows


def package_summary(rows):
    direct = [r for r in rows if r["direct"] is not False]
    advisories = sum(len(r["advisories"]) for r in rows)
    return {"all": len(rows), "direct": len(direct), "transitive": len(rows) - len(direct),
            "vulnerable": sum(1 for r in rows if r["advisories"]), "advisories": advisories,
            "not_checked": sum(1 for r in rows if r["vuln_status"] != "checked")}


def package_proof(r, links):
    """(label, url) of the first proof line of a package, or ("", "")."""
    p = r["proof"]
    if not p:
        return "", ""
    label = f"{p['file']}:{p['line']}"
    return label, (links.url_for(p["file"], p["line"]) if links else "")


def package_level_text(r):
    return LEVEL_TEXT[r["level"]] + ("" if r["declared"] else " (not in a dependency file)")


def build_packages_csv(packages, links=None):
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\r\n")
    w.writerow(["package", "version", "kind", "direct", "evidence_level", "reachability", "where_first_proof", "link", "vulnerability_check",
                "known_advisories", "worst_severity", "advisory_ids", "fixed_in", "purl"])
    for r in package_rows(packages):
        label, url = package_proof(r, links)
        w.writerow([r["name"], r["version"], r["kind"], {True: "yes", False: "no"}.get(r["direct"], "unknown"), r["level"], "not_verified",
                    label, url, r["vuln_status"], len(r["advisories"]), r["worst"], "; ".join(a["id"] for a in r["advisories"]),
                    "; ".join(sorted({a["fixed_in"] for a in r["advisories"] if a["fixed_in"]})), r["purl"]])
    return buf.getvalue()


def build_csv(items, links=None):
    rows = build_rows(items)
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\r\n")
    w.writerow(["model", "made_by", "type", "role", "confidence", "evidence_level", "reachability", "where_first_place", "link", "places_in_code", "also_written_as",
                "status", "pinned", "floating_alias", "deprecation_date", "retirement_date", "replacement", "lifecycle_source", "license",
                "license_restricted", "license_name", "license_commercial_use"])
    for role, group in (("used directly", rows["used"]), ("only listed", rows["listed"])):
        for r in group:
            p, url, _ = where(r, links)
            w.writerow([r["name"], r["maker"], MODE_TEXT.get(r["mode"], r["mode"]), role, TIER_TEXT[r["tier"]], r["evidence_level"] or "not_assessed", "not_verified", p, url, len(r["places"]), "; ".join(r["also"]),
                        r.get("status", "unknown"), "yes" if r.get("pinned") is True else ("no" if r.get("pinned") is False else "unknown"),
                        "yes" if r.get("floating") else "no", r.get("deprecation_date", ""), r.get("retirement_date", ""),
                        r.get("replacement", ""), r.get("lifecycle_source_url", ""), r.get("license", "unknown"),
                        "yes" if r.get("license_restricted") else "no", r.get("license_name", ""), r.get("license_commercial_use", "")])
    for g in rows["left_out"]:
        w.writerow([g["name"], "", "", "left out", g["why"], "", "", f"{g['file']}:{g['line']}", links.url_for(g["file"], g["line"]) if links else "", 0, ""] + [""] * 11)
    return buf.getvalue()


def build_markdown(items, app, source="", links=None, meta=None):
    rows = build_rows(items)
    used, listed, gone = rows["used"], rows["listed"], rows["left_out"]
    out = [f"# AI models found in {app}", ""]
    if source or (links and links.ok):
        out += [f"Scanned: {source_line(source, links, meta)}", ""]
    for w in (meta or {}).get("warnings", []):
        out += [f"WARNING, this scan may be incomplete: {w}", ""]
    out += [f"Summary (you can paste this into a message): {intro(rows, app)}", ""]
    risk = risk_summary(rows)
    out += ["## Risks", ""]
    for label, found in risk_lines(risk):
        line = f"- {label}: {len(found)}"
        if found:
            line += f" ({risk_names(found)})"
        out.append(line)
    out.append("")
    out += [f"_{note}_" for note in lifecycle_notes(risk)]
    out.append("")

    def table(rs):
        t = ["| Model | Made by | Type | Where it is used | Confidence | Status | Pinned | Deprecated | Retires or retired | Replacement | License |",
             "|---|---|---|---|---|---|---|---|---|---|---|"]
        for r in rs:
            p, url, more = where(r, links)
            cell = f"[{p}]({url})" if url else p
            alias = f" (also written as {', '.join(r['also'][:3])})" if r["also"] else ""
            lic = license_label(r)
            t.append(f"| {r['name']}{alias} | {r['maker'] or '-'} | {MODE_TEXT.get(r['mode'], r['mode']) or 'AI model'} | {cell}{f' (+{more} more)' if more else ''} | {TIER_TEXT[r['tier']]} | {status_text(r)} | {pin_text(r)} | {r.get('deprecation_date') or '-'} | {r.get('retirement_date') or '-'} | {r.get('replacement') or '-'} | {lic} |")
        return t

    if used:
        out += ["## Used directly in the code", ""] + table(used)
    if listed:
        out += ["", f"## Only listed in {LISTED_NOTE}", ""] + table(listed)
    if gone:
        out += ["", "## Left out, and why", "", "| Name | Why | Example place |", "|---|---|---|"]
        for g in gone:
            url = links.url_for(g["file"], g["line"]) if links else ""
            label = "%s:%s" % (g["file"], g["line"])
            out.append("| %s | %s | %s |" % (g["name"], g["why"], "[%s](%s)" % (label, url) if url else label))
    pk = package_rows((meta or {}).get("packages"))
    if pk:
        sm = package_summary(pk)
        out += ["", "## AI packages", "",
                f"{sm['direct']} AI packages found in the project" + (f", and {sm['transitive']} more only in a lockfile" if sm["transitive"] else "")
                + f". {sm['vulnerable']} have known vulnerabilities ({sm['advisories']} advisories), {sm['not_checked']} could not be checked."
                + (f" Advisory data from {advisory_date()}." if advisory_date() else ""), "", f"_{PACKAGE_NOTE}_", ""]

        def ptable(rs):
            t = ["| Package | Kind | Version | Evidence | Where | Known vulnerabilities |", "|---|---|---|---|---|---|"]
            for r in rs:
                label, url = package_proof(r, links)
                cell = (f"[{label}]({url})" if url else label) or "-"
                t.append(f"| {r['name']} | {r['kind']} | {r['version'] or '-'} | {package_level_text(r)} | {cell} | {r['vuln_text']} |")
            return t

        direct = [r for r in pk if r["direct"] is not False]
        out += ptable(direct)
        for r in pk:
            if r["advisories"]:
                out += ["", f"**{r['name']} {r['version']}**", ""]
                for a in sev_order(r["advisories"])[:15]:
                    fix = f", fixed in {a['fixed_in']}" if a["fixed_in"] else ", no fixed version stated"
                    out.append(f"- **{a['severity'].upper()}**: [{a['id']}]({a['url']}) {a['summary'][:140]}{fix}")
                if len(r["advisories"]) > 15:
                    out.append(f"- and {len(r['advisories']) - 15} more (see aibom.cdx.json)")
        later = [r for r in pk if r["direct"] is False]
        if later:
            out += ["", f"### Also in the lockfile (transitive, {len(later)})", ""] + ptable(later)
        plan = fix_plan_rows((meta or {}).get("packages"))
        if plan:
            out += ["", "### Fix plan", "", "For each package with known vulnerabilities, the lowest version that its advisories say fixes all of them. "
                    "Each target was checked again against the advisory data. Upgrading can break code: test it.", "",
                    "| Package | Now | Worst | What to do |", "|---|---|---|---|"]
            out += [f"| {p['package']} | {p['version'] or '-'} | {p['worst'].upper()} | {fix_plan_text(p)} |" for p in plan]
    out += ["", "## What this scan cannot see", ""] + [f"- {c}" for c in CANNOT_SEE]
    out += ["", "How to read this: every row links a model name to a line of code. Confirmed means the name is written in the code; Worked out means the code spells it through a constant. "
                "The standard AI-BOM file (aibom.cdx.json) holds the same facts for other tools; models.csv opens in a spreadsheet."]
    return "\n".join(out) + "\n"


CSS = """
:root{--bg:#f6f7f9;--card:#fff;--text:#1b1f27;--muted:#586272;--line:#dde1e7;--zebra:#f4f6f9;--accent:#1f4fd1;--chip:#eef1f6;
--critical:#7a0019;--high:#c62828;--medium:#f5b800;--low:#1769aa;--unknown:#8a919c;--on-medium:#000;--on-sev:#fff}
@media (prefers-color-scheme:dark){:root:not([data-theme=light]){--bg:#10131a;--card:#171b24;--text:#e8ebf0;--muted:#9aa4b2;--line:#2a303c;--zebra:#1b202b;--accent:#8fb0ff;--chip:#222836;
--critical:#c4153e;--high:#e0453a;--medium:#f2c230;--low:#3d8fd1;--unknown:#6d7683}}
:root[data-theme=dark]{--bg:#10131a;--card:#171b24;--text:#e8ebf0;--muted:#9aa4b2;--line:#2a303c;--zebra:#1b202b;--accent:#8fb0ff;--chip:#222836;
--critical:#c4153e;--high:#e0453a;--medium:#f2c230;--low:#3d8fd1;--unknown:#6d7683}
*{box-sizing:border-box}html{scroll-behavior:smooth}body{font-family:system-ui,-apple-system,"Segoe UI",Roboto,Arial,sans-serif;margin:0;color:var(--text);background:var(--bg);line-height:1.55}
.wrap{max-width:1180px;margin:0 auto;padding:28px 20px 72px}h1{font-size:30px;margin:0 0 4px;letter-spacing:-.01em}
h2{font-size:21px;margin:44px 0 12px;padding-bottom:8px;border-bottom:1px solid var(--line);scroll-margin-top:64px}h3{font-size:17px;margin:28px 0 8px;scroll-margin-top:64px}
.sub{font-size:13px;color:var(--muted);margin:0 0 18px}.lead{font-size:19px;margin:18px 0;padding:14px 18px;background:var(--card);border:1px solid var(--line);border-left:5px solid var(--accent);border-radius:8px}
a{color:var(--accent);font-weight:600;text-decoration:none}a:hover{text-decoration:underline}code{font-family:ui-monospace,Consolas,Menlo,monospace;font-size:12.5px}
.nav{position:sticky;top:0;z-index:5;display:flex;gap:4px;flex-wrap:wrap;padding:8px 0;margin:0 0 6px;background:var(--bg);border-bottom:1px solid var(--line)}
.nav a{padding:5px 12px;border-radius:999px;font-size:13px;font-weight:600;color:var(--muted)}.nav a:hover{background:var(--chip);color:var(--text);text-decoration:none}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:14px;margin:18px 0}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 18px}.card b{display:block;font-size:38px;line-height:1.1}.card span{font-size:13px;color:var(--muted)}
.card.vulncard{grid-column:span 2}.card.vulncard .sevkey{margin:6px 0 0}
.warn{background:var(--card);border:1px solid var(--line);border-left:5px solid var(--medium);border-radius:8px;padding:10px 18px;margin:16px 0;font-size:15px}.warn ul{margin:6px 0 0 18px;padding:0}
.how{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:4px 18px;font-size:14px;margin:18px 0}.how ul{margin:6px 0 10px 18px;padding:0}
.risks{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:8px 20px 14px;margin:18px 0}.risks h2{border:0;margin:6px 0 8px;padding:0}.risks ul{margin:0 0 0 18px;padding:0}.risks li{margin:4px 0}.risks .note{font-size:13px;color:var(--muted);margin:6px 0 0}
input#q{width:100%;padding:12px 14px;border:1px solid var(--line);border-radius:8px;background:var(--card);color:var(--text);font-size:16px;margin:14px 0 4px}input#q:focus{outline:2px solid var(--accent);outline-offset:1px}
.tw{overflow-x:auto;background:var(--card);border:1px solid var(--line);border-radius:10px;margin:8px 0 16px}
table{border-collapse:collapse;width:100%;font-size:14px}table.wide{min-width:1040px}
th,td{padding:9px 12px;text-align:left;vertical-align:top;overflow-wrap:break-word;border-bottom:1px solid var(--line)}table.wide td:nth-child(3){overflow-wrap:anywhere;min-width:240px}table.wide td{min-width:84px}.vcell{min-width:170px}table.wide td:first-child{min-width:130px}tr:last-child td{border-bottom:0}
th{font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted);background:var(--zebra);position:sticky;top:0}tbody tr:nth-child(even) td,table tr:nth-child(even) td{background:var(--zebra)}
.also{font-size:12px;color:var(--muted);margin-top:2px}
.badge{display:inline-block;border:1px solid currentColor;border-radius:999px;padding:0 9px;font-size:12px;font-weight:700;white-space:nowrap}.badge.worked{border-style:dashed}
details{margin:12px 0}summary{cursor:pointer;font-weight:600}details.grp{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:2px 14px}details.grp>summary{font-size:16px;padding:10px 0}details.grp .tw{border:0;border-radius:0;margin:0 -14px 8px}
details.more{margin:6px 0 0}details.more summary{font-weight:500;font-size:13px;color:var(--accent)}
.limits{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:6px 22px 14px;margin-top:40px}.limits h2{border:0;margin-top:12px}
.foot{font-size:12px;color:var(--muted);margin-top:28px;border-top:1px solid var(--line);padding-top:10px}#nomatch{display:none;font-weight:700;margin:12px 0}
.sev{display:inline-block;border-radius:5px;padding:1px 8px;font-size:11.5px;font-weight:800;letter-spacing:.03em;white-space:nowrap;color:var(--on-sev);-webkit-print-color-adjust:exact;print-color-adjust:exact}
.sev-critical{background:var(--critical)}.sev-high{background:var(--high)}.sev-medium{background:var(--medium);color:var(--on-medium)}.sev-low{background:var(--low)}.sev-unknown{background:var(--unknown)}
.sevbar{display:flex;height:14px;border-radius:7px;overflow:hidden;margin:8px 0 4px;-webkit-print-color-adjust:exact;print-color-adjust:exact}.sevbar i{display:block;height:100%}
.sevkey{font-size:13px;margin:0 0 10px}.sevkey .sev{margin:0 4px 0 10px}.sevkey .sev:first-child{margin-left:0}
.ev{display:inline-block;border-radius:999px;padding:0 9px;font-size:12px;font-weight:700;white-space:nowrap;background:var(--chip);cursor:help}
.ev-called{color:#0a7a3d;background:rgba(10,122,61,.12)}.ev-imported{color:#8a6100;background:rgba(245,184,0,.18)}.ev-declared{color:var(--muted)}
@media (prefers-color-scheme:dark){:root:not([data-theme=light]) .ev-called{color:#4fd48a}:root:not([data-theme=light]) .ev-imported{color:#f2c230}}
.vcard{background:var(--card);border:1px solid var(--line);border-radius:10px;margin:12px 0;overflow:hidden}
.vhead{display:flex;gap:10px;align-items:center;flex-wrap:wrap;padding:10px 16px;background:var(--zebra);border-bottom:1px solid var(--line)}.vhead b{font-size:16px}.vhead .grow{flex:1}
.adv{list-style:none;margin:0;padding:0}.adv li{display:grid;grid-template-columns:86px minmax(150px,230px) 1fr;gap:6px 14px;padding:9px 16px;border-bottom:1px solid var(--line);align-items:start}.adv li:last-child{border-bottom:0}
.adv .fix{font-size:13px;color:var(--muted)}.adv .fix b{color:#0a7a3d}@media (prefers-color-scheme:dark){:root:not([data-theme=light]) .adv .fix b{color:#4fd48a}}
.adv .what{grid-column:3;font-size:14px}.vcard details.more{margin:0;padding:8px 16px;border-top:1px solid var(--line)}.vcard details.more .adv{margin:6px -16px 0}
@media (max-width:720px){.adv li{grid-template-columns:1fr}.adv .what{grid-column:1}.card.vulncard{grid-column:auto}}
@media print{:root{--bg:#fff;--card:#fff;--text:#000;--muted:#333;--line:#999;--zebra:#fff;--accent:#000}.nav,input#q{display:none}.wrap{padding:0}.tw{overflow:visible}table.wide{min-width:0}th{position:static}.vcard{break-inside:avoid}}
"""
JS = """
const q=document.getElementById('q');
function run(){const t=q.value.trim().toLowerCase();let shown=0;
document.querySelectorAll('tr[data-t]').forEach(r=>{const ok=!t||r.dataset.t.indexOf(t)>-1;r.style.display=ok?'':'none';if(ok)shown++;});
document.querySelectorAll('details.grp').forEach(d=>{const any=[...d.querySelectorAll('tr[data-t]')].some(r=>r.style.display!=='none');d.style.display=any?'':'none';if(t&&any)d.open=true;});
document.getElementById('nomatch').style.display=(t&&!shown)?'block':'none';}
q.addEventListener('input',run);
window.addEventListener('beforeprint',()=>document.querySelectorAll('details').forEach(d=>d.open=true));
"""


def build_html(items, app, source="", links=None, meta=None):
    rows = build_rows(items)
    used, listed, gone = rows["used"], rows["listed"], rows["left_out"]
    h = html.escape

    def place_link(p):
        url = links.url_for(p["file"], p["line"]) if links else ""
        txt = h(f"{p['file']}:{p['line']}")
        return f'<a href="{h(url)}" target="_blank" rel="noopener">{txt}</a>' if url else f"<code>{txt}</code>"

    def row_html(r):
        first = r["places"][0] if r["places"] else None
        more = r["places"][1:]
        cell = place_link(first) if first else "-"
        if more:
            lis = "".join(f"<li>{place_link(p)} <code>{h(p['snippet'][:90])}</code></li>" for p in more[:14])
            rest = f"<li>and {len(more) - 14} more places</li>" if len(more) > 14 else ""
            cell += f'<details class="more"><summary>+{len(more)} more place{"" if len(more) == 1 else "s"} in the code</summary><ul>{lis}{rest}</ul></details>'
        alias = f'<div class="also">also written as: {h(", ".join(r["also"][:4]))}{" ..." if len(r["also"]) > 4 else ""}</div>' if r["also"] else ""
        badge = f'<span class="badge{" worked" if r["tier"] == "inferred" else ""}" title="{h(TIER_LONG[r["tier"]])}">{TIER_TEXT[r["tier"]]}</span>'
        status = status_text(r)
        pinned = pin_text(r)
        dep = r.get("deprecation_date") or "-"
        ret = r.get("retirement_date") or "-"
        repl = r.get("replacement") or "-"
        lic = license_label(r)
        text = " ".join([r["name"], r["maker"], r["mode"], status, dep, ret, repl, lic, " ".join(r["also"]), " ".join(p["file"] for p in r["places"][:30])]).lower()
        return (f'<tr data-t="{h(text)}"><td><b>{h(r["name"])}</b>{alias}</td><td>{h(MODE_TEXT.get(r["mode"], r["mode"]) or "AI model")}</td><td>{cell}</td><td>{badge}</td>'
                f'<td>{h(status)}</td><td>{h(pinned)}</td><td>{h(dep)}</td><td>{h(ret)}</td><td>{h(repl)}</td><td>{h(lic)}</td></tr>')

    def groups(rs, open_first):
        out = []
        for i, (maker, rr) in enumerate(by_maker(rs)):
            out.append(f'<details class="grp"{" open" if open_first and i < 3 else ""}><summary>{h(maker)} ({len(rr)})</summary>'
                       '<div class="tw"><table class="wide">'
                       '<tr><th>Model</th><th>Type</th><th>Where it is used (click to see the line)</th><th>Confidence</th><th>Status</th><th>Pinned</th><th>Deprecated</th><th>Retires or retired</th><th>Replacement</th><th>License</th></tr>' + "".join(row_html(r) for r in rr) + "</table></div></details>")
        return "".join(out)

    out = [f"<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><meta name='color-scheme' content='light dark'><title>AI models in {h(app)}</title><style>{CSS}</style></head><body><div class='wrap'>",
           f"<h1>AI models found in {h(app)}</h1>"]
    sub = source_line(source, links, meta)
    out.append(f"<p class='sub'>{('Scanned: ' + h(sub) + '. ') if sub else ''}Scanner version {h(__version__)}.</p>")
    nav_at = len(out)
    warns = (meta or {}).get("warnings", [])
    if warns:
        out.append("<div class='warn'><b>This scan may be incomplete.</b><ul>" + "".join(f"<li>{h(w)}</li>" for w in warns) + "</ul></div>")
    out.append(f"<p class='lead'>{h(intro(rows, app))}</p>")
    risk = risk_summary(rows)

    def risk_item(label, found):
        names = risk_names(found)
        return f"<li><b>{label}:</b> {len(found)}" + (f" &mdash; {h(names)}" if names else "") + "</li>"

    out.append("<div class='risks'><h2>Risks</h2><ul>" + "".join(risk_item(label, found) for label, found in risk_lines(risk)) + "</ul>"
               + "".join(f"<p class='note'>{h(note)}</p>" for note in lifecycle_notes(risk)) + "</div>")
    out.append(f"<div class='cards'><div class='card'><b>{len(used)}</b><span>used directly in the code</span></div>"
               f"<div class='card'><b>{len(listed)}</b><span>only listed in long tables or lists</span></div><div class='card'><b>{len(gone)}</b><span>names left out (comments, messages, tests, docs)</span></div>"
               + (f"<div class='card'><b>{len(package_rows((meta or {}).get('packages')))}</b><span>AI packages ({package_summary(package_rows((meta or {}).get('packages')))['vulnerable']} with known vulnerabilities)</span></div>" if package_rows((meta or {}).get("packages")) else "")
               + (vuln_card(package_rows((meta or {}).get("packages"))) if package_rows((meta or {}).get("packages")) else "")
               + "</div>")
    n_aibom = len([i for i in items if i["tier"] != "rejected"])
    link_tip = "Click a file name to open that exact line on the website where the code is hosted." if links and links.ok else "This scan was of a local folder, so there are no web links; the file and line are shown instead."
    out.append("<div class='how'><b>How to read this page</b><ul>"
               "<li>Every row names a model and the place in the code that proves it. " + h(link_tip) + "</li>"
               "<li><span class='badge'>Confirmed</span> means the name is written in the code. <span class='badge worked'>Worked out</span> means the code spells it through a constant, such as GPT_4O.</li>"
               "<li>Models grouped under their maker. Different spellings of one model are shown as one row (&quot;also written as&quot;)"
               + (f"; the standard AI-BOM file keeps each spelling as its own entry ({n_aibom} entries)." if n_aibom != len(used) + len(listed) else ".") + "</li></ul></div>")
    if used or listed:
        out.append("<input id='q' type='search' placeholder='Search by model, maker or file name...' autocomplete='off'><div id='nomatch'>Nothing matches that search.</div>")
    if used:
        out.append("<span id='models'></span><h2>Used directly in the code</h2>" + groups(used, True))
    if listed:
        out.append(f"<span id='listed'></span><h2>Only listed in {h(LISTED_NOTE)}</h2><p style='font-size:14px'>These names are written in the code, but only inside big tables or lists, not set or called on their own.</p>" + groups(listed, False))
    if not used and not listed:
        out.append(f"<h2>Nothing found</h2><p>{h(intro(rows, app))}</p>")
    pk = package_rows((meta or {}).get("packages"))
    if pk:
        sm = package_summary(pk)

        def vuln_cell(r):
            if not r["advisories"]:
                return h(r["vuln_text"]) + (f"<div class='also'>{h(r['vuln_reason'])}</div>" if r["vuln_status"] != "checked" and r["vuln_reason"] else "")
            return f"<div class='vcell'>{sev_chip(r['worst'])} <b>{h(r['vuln_text'])}</b></div>"

        def adv_item(a):
            fix = f"fixed in <b>{h(a['fixed_in'])}</b>" if a["fixed_in"] else "no fixed version stated"
            return (f"<li><span>{sev_chip(a['severity'])}</span><span><a href=\"{h(a['url'])}\" target=\"_blank\" rel=\"noopener\">{h(a['id'])}</a>"
                    f"<div class='fix'>{fix}</div></span><span class='what'>{h(a['summary'][:200])}</span></li>")

        def vcard(r):
            """One package with its advisories, worst first: the first five are shown, the rest open on a click."""
            advs = sev_order(r["advisories"])
            shown = "".join(adv_item(a) for a in advs[:5])
            rest = ""
            if len(advs) > 5:
                rest = f"<details class='more'><summary>show {len(advs) - 5} more</summary><ul class='adv'>{''.join(adv_item(a) for a in advs[5:])}</ul></details>"
            return (f"<div class='vcard'><div class='vhead'><b>{h(r['name'])}</b><span>{h(r['version'] or '-')}</span>{ev_chip(r)}<span class='grow'></span>"
                    f"{sev_chip(r['worst'])}<span>{len(advs)} known</span></div><ul class='adv'>{shown}</ul>{rest}</div>")

        def ev_chip(r):
            return f"<span class='ev ev-{r['level']}' title=\"{h(PACKAGE_EVIDENCE_WHY[r['level']])}\">{h(package_level_text(r))}</span>"

        def prow(r):
            label, url = package_proof(r, links)
            where = (f'<a href="{h(url)}" target="_blank" rel="noopener">{h(label)}</a>' if url else f"<code>{h(label)}</code>") if label else "-"
            text = " ".join([r["name"], r["kind"], r["version"], r["level"], r["vuln_text"], r["vendor"], " ".join(a["id"] for a in r["advisories"])]).lower()
            return (f'<tr data-t="{h(text)}"><td><b>{h(r["name"])}</b></td><td>{h(r["kind"])}</td><td>{h(r["version"] or "-")}</td>'
                    f'<td>{ev_chip(r)}</td><td>{where}</td><td>{vuln_cell(r)}</td></tr>')

        head = "<tr><th>Package</th><th>Kind</th><th>Version</th><th>Evidence</th><th>Where (click to see the line)</th><th>Known vulnerabilities</th></tr>"
        direct = [r for r in pk if r["direct"] is not False]
        later = [r for r in pk if r["direct"] is False]
        date = advisory_date()
        out.append("<span id='packages'></span><h2>AI packages</h2>"
                   f"<p style='font-size:14px'>{sm['direct']} AI packages found in the project"
                   + (f", and {sm['transitive']} more only in a lockfile" if sm["transitive"] else "")
                   + f". <b>{sm['vulnerable']}</b> have known vulnerabilities ({sm['advisories']} advisories); {sm['not_checked']} could not be checked."
                   + (f" Advisory data from {h(date)}." if date else "") + f"</p><p class='also' style='font-size:13px'>{h(PACKAGE_NOTE)}</p>"
                   + f"<div class='tw'><table>{head}{''.join(prow(r) for r in direct)}</table></div>")
        if later:
            out.append(f"<details><summary>{len(later)} more AI packages only in a lockfile (transitive)</summary>"
                       f"<div class='tw'><table>{head}{''.join(prow(r) for r in later)}</table></div></details>")
        cards = [r for r in direct if r["advisories"]]
        cards_later = [r for r in later if r["advisories"]]
        if cards or cards_later:
            out.append("<span id='vulns'></span><h3>Known vulnerabilities, worst first</h3>" + sev_bar_html(direct)
                       + "<p class='also' style='font-size:13px'>Packages your code calls come first inside each severity. "
                         "Affected is not the same as exploitable: reachability is not verified.</p>" + "".join(vcard(r) for r in cards))
            if cards_later:
                out.append(f"<details><summary>{len(cards_later)} more with vulnerabilities, only in a lockfile</summary>{''.join(vcard(r) for r in cards_later)}</details>")
        plan = fix_plan_rows((meta or {}).get("packages"))
        if plan:
            prs = "".join(f"<tr><td><b>{h(p['package'])}</b></td><td>{h(p['version'] or '-')}</td><td>{sev_chip(p['worst'])}</td><td>{h(fix_plan_text(p))}</td></tr>" for p in plan)
            out.append("<span id='fixplan'></span><h3>Fix plan</h3><p class='also' style='font-size:13px'>For each package with known vulnerabilities, the lowest version that its advisories say fixes all of them. "
                       "Each target was checked again against the advisory data. Upgrading can break code: test it.</p>"
                       f"<div class='tw'><table><tr><th>Package</th><th>Now</th><th>Worst</th><th>What to do</th></tr>{prs}</table></div>")
    if gone:
        rws = "".join(f"<tr><td>{h(g['name'])}</td><td>{h(g['why'])}</td><td>{place_link({'file': g['file'], 'line': g['line']})}</td></tr>" for g in gone)
        out.append(f"<span id='leftout'></span><h2>Left out, and why</h2><details><summary>{len(gone)} names that look like models but are not used (click to open)</summary>"
                   f"<div class='tw'><table class='slim'><colgroup><col style='width:32%'><col style='width:36%'><col style='width:32%'></colgroup><tr><th>Name</th><th>Why it was left out</th><th>Example place</th></tr>{rws}</table></div></details>")
    out.append("<div class='limits' id='limits'><h2>What this scan cannot see</h2><ul>" + "".join(f"<li>{h(c)}</li>" for c in CANNOT_SEE) + "</ul></div>")
    out.append("<p class='foot'>The standard AI-BOM file (aibom.cdx.json) holds the same facts for other tools, and models.csv opens in a spreadsheet. This page needs no internet connection.</p>")
    joined = "".join(out)
    wanted = [("models", "Models"), ("listed", "Listed only"), ("packages", "AI packages"), ("vulns", "Vulnerabilities"), ("fixplan", "Fix plan"),
              ("leftout", "Left out"), ("limits", "Limits")]
    links_html = "".join(f"<a href='#{k}'>{label}</a>" for k, label in wanted if f"id='{k}'" in joined)
    out.insert(nav_at, f"<nav class='nav' aria-label='Sections'>{links_html}</nav>" if links_html else "")
    out.append(f"</div><script>{JS}</script></body></html>")
    return "".join(out)
