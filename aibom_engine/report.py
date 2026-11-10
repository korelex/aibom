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
LEVEL_TEXT = {"called": "Called", "declared": "Declared"}
LEVEL_LONG = {"called": "Called: live code passes this name into a call on an AI SDK",
              "declared": "Declared: the name is written in the code or settings, but no call on an AI SDK was proven to receive it "
                          "(it may still be used, for example through a variable, a lookup table or plain HTTP)"}
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
              "AI parts other than models: agents, tools, vector databases and frameworks are not covered yet.",
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
            w.writerow([r["name"], r["maker"], MODE_TEXT.get(r["mode"], r["mode"]), role, TIER_TEXT[r["tier"]], r["evidence_level"], "not_verified", p, url, len(r["places"]), "; ".join(r["also"]),
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
    out += ["", "## What this scan cannot see", ""] + [f"- {c}" for c in CANNOT_SEE]
    out += ["", "How to read this: every row links a model name to a line of code. Confirmed means the name is written in the code; Worked out means the code spells it through a constant. "
                "The standard AI-BOM file (aibom.cdx.json) holds the same facts for other tools; models.csv opens in a spreadsheet."]
    return "\n".join(out) + "\n"


CSS = """
*{box-sizing:border-box}body{font-family:Arial,Helvetica,sans-serif;margin:0;color:#000;background:#fff;line-height:1.5}
.wrap{max-width:1100px;margin:0 auto;padding:32px 24px 72px}h1{font-size:32px;margin:0 0 4px}h2{font-size:21px;margin:40px 0 10px;border-bottom:3px solid #000;padding-bottom:4px}
.sub{font-size:13px;margin:0 0 22px}.lead{font-size:21px;border-left:8px solid #000;padding:8px 0 8px 18px;margin:22px 0}
.cards{display:flex;gap:16px;flex-wrap:wrap;margin:18px 0}.card{border:3px solid #000;padding:14px 18px;flex:1;min-width:220px}.card b{display:block;font-size:44px;line-height:1.05}.card span{font-size:14px}
.warn{border:4px double #000;padding:10px 18px;margin:16px 0;font-size:15px}.warn ul{margin:6px 0 0 18px;padding:0}.how{border:1px solid #000;padding:12px 18px;font-size:14px;margin:18px 0}.how ul{margin:6px 0 0 18px;padding:0}
input#q{width:100%;padding:12px;border:3px solid #000;font-size:16px;margin:14px 0 4px}
.tw{overflow-x:auto}table{border-collapse:collapse;width:100%;min-width:980px;font-size:14px;margin:8px 0 16px}table.slim{min-width:0;table-layout:fixed}th,td{border:1px solid #000;padding:7px 10px;text-align:left;vertical-align:top;overflow-wrap:break-word}td:nth-child(3){min-width:190px;overflow-wrap:anywhere}th{border-bottom:3px solid #000}
code{font-family:Consolas,Menlo,monospace;font-size:12.5px}a{color:#000;font-weight:bold}.also{font-size:12px;margin-top:2px}
.badge{display:inline-block;border:2px solid #000;padding:0 8px;font-size:12px;font-weight:bold;white-space:nowrap}.badge.worked{border-style:dashed}
details{margin:12px 0}summary{cursor:pointer;font-weight:bold}details.grp>summary{font-size:16px;padding:6px 0}details.more{margin:4px 0 0}details.more summary{font-weight:normal;font-size:12px}
details.more ul{margin:4px 0 0 16px;padding:0;font-size:12px}.limits{border:3px solid #000;padding:6px 20px 12px;margin-top:36px}.limits h2{border:0;margin-top:12px}
.foot{font-size:12px;margin-top:28px;border-top:1px solid #000;padding-top:10px}#nomatch{display:none;font-weight:bold;margin:12px 0}
.risks .note{font-size:13px;margin:6px 0 0}.risks{border:3px solid #000;padding:8px 18px 12px;margin:18px 0}.risks h2{border:0;margin:6px 0 8px}.risks ul{margin:0 0 0 18px;padding:0}.risks li{margin:4px 0}
@media print{input#q{display:none}.wrap{padding:0}}
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
                       '<div class="tw"><table>'
                       '<tr><th>Model</th><th>Type</th><th>Where it is used (click to see the line)</th><th>Confidence</th><th>Status</th><th>Pinned</th><th>Deprecated</th><th>Retires or retired</th><th>Replacement</th><th>License</th></tr>' + "".join(row_html(r) for r in rr) + "</table></div></details>")
        return "".join(out)

    out = [f"<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>AI models in {h(app)}</title><style>{CSS}</style></head><body><div class='wrap'>",
           f"<h1>AI models found in {h(app)}</h1>"]
    sub = source_line(source, links, meta)
    out.append(f"<p class='sub'>{('Scanned: ' + h(sub) + '. ') if sub else ''}Scanner version {h(__version__)}.</p>")
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
               f"<div class='card'><b>{len(listed)}</b><span>only listed in long tables or lists</span></div><div class='card'><b>{len(gone)}</b><span>names left out (comments, messages, tests, docs)</span></div></div>")
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
        out.append("<h2>Used directly in the code</h2>" + groups(used, True))
    if listed:
        out.append(f"<h2>Only listed in {h(LISTED_NOTE)}</h2><p style='font-size:14px'>These names are written in the code, but only inside big tables or lists, not set or called on their own.</p>" + groups(listed, False))
    if not used and not listed:
        out.append(f"<h2>Nothing found</h2><p>{h(intro(rows, app))}</p>")
    if gone:
        rws = "".join(f"<tr><td>{h(g['name'])}</td><td>{h(g['why'])}</td><td>{place_link({'file': g['file'], 'line': g['line']})}</td></tr>" for g in gone)
        out.append(f"<h2>Left out, and why</h2><details><summary>{len(gone)} names that look like models but are not used (click to open)</summary>"
                   f"<div class='tw'><table class='slim'><colgroup><col style='width:32%'><col style='width:36%'><col style='width:32%'></colgroup><tr><th>Name</th><th>Why it was left out</th><th>Example place</th></tr>{rws}</table></div></details>")
    out.append("<div class='limits'><h2>What this scan cannot see</h2><ul>" + "".join(f"<li>{h(c)}</li>" for c in CANNOT_SEE) + "</ul></div>")
    out.append("<p class='foot'>The standard AI-BOM file (aibom.cdx.json) holds the same facts for other tools, and models.csv opens in a spreadsheet. This page needs no internet connection.</p>")
    out.append(f"</div><script>{JS}</script></body></html>")
    return "".join(out)
