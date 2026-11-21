"""The readable outputs for people who do not read JSON: a web page, a markdown summary and a spreadsheet (CSV).
The CycloneDX file stays the source of truth; these are built from the same items."""
import csv
import datetime
import html
import io
import re

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
              "MCP servers are read as text from the config files of Claude Code, VS Code, Cursor, Gemini CLI, Codex and Claude Desktop that sit in the repository, "
              "not from a developer's own machine. No server is started, so the tools a server offers are not listed. Datasets are not covered yet.",
              "Model weight files are found by their extension and read by their content: pickle-based files (PyTorch, joblib, NumPy object arrays and others) are checked for dangerous imports and are never loaded; TensorFlow SavedModel, TFLite and files compressed in other ways are not read; and a file in which no dangerous import was found is not thereby safe to load.",
              "Hardcoded API keys are found in the files on disk, by the format of well-known providers' keys or by a provider-named variable with a literal value. Keys in the git history, keys with no distinctive format that are not given a provider-named name, and keys built from pieces are not found.",
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


FLAGS_NOTE = ("A flag is something worth a look, not proof of a problem. The risks of the models themselves (retired, deprecated, floating "
              "alias, licence) are also counted by kind under Model lifecycle and licences.")
CATEGORY_TEXT = {"secret": "API key", "mcp": "MCP server", "model-file": "Model file", "code": "Code", "model": "Model"}


def other_flags(meta):
    """The flags that are not about a model's lifecycle or licence (the Risks block covers those), worst first."""
    return [f for f in (meta or {}).get("flags", []) if f.category != "model"]


def flag_place(f):
    return f"{f.file}:{f.line}" if f.file and f.line else (f.file or "")


def md_cell(t):
    """Text safe inside a Markdown table cell."""
    return str(t).replace("|", "\\|").replace("\n", " ")


def mcp_rows(meta):
    """The MCP servers a reader should see (the product's own), and how many more were left out as tests, examples or docs."""
    found = (meta or {}).get("mcp") or {"servers": []}
    live = [s for s in found["servers"] if not s.get("left_out")]
    return live, len(found["servers"]) - len(live)


def mcp_how(s):
    """How a server is run, in words: the package a launcher fetches, the command, or the URL."""
    if s["transport"] == "stdio":
        if s["package"] and s["ecosystem"] in ("npm", "pypi", "docker"):
            joiner = (":" if not s["version"].startswith("sha256:") else "@") if s["ecosystem"] == "docker" else "@"
            return f"{s['launcher']} {s['package']}" + (joiner + s["version"] if s["version"] else "")
        if s["package"]:
            return f"{s['launcher']} {s['package']}"
        text = " ".join([s["command"]] + s["args"]).strip()
        return text if len(text) <= 70 else text[:67] + "..."
    return s["url"] or "(no URL)"


def mcp_notes(s):
    """What else a reader should know about a server, as short phrases (facts, not judgments)."""
    notes = []
    if s["transport"] == "stdio" and s["package"] and s["ecosystem"] in ("npm", "pypi", "docker"):
        notes.append("version pinned" if s["pinned"] else "version not pinned")
    elif s["transport"] == "stdio" and s["ecosystem"] == "source":
        notes.append("runs code from a URL or path")
    if s["env_keys"]:
        notes.append("environment: " + ", ".join(s["env_keys"]))
    if s["header_names"]:
        notes.append("headers: " + ", ".join(s["header_names"]))
    if s["url_has_credentials"]:
        notes.append("the URL has a user name or password")
    if s["url_has_query"]:
        notes.append("the URL has a query string")
    if s["enabled"] is False:
        notes.append("switched off in the config")
    if s["note"]:
        notes.append(s["note"])
    return notes


MCP_KIND = {"stdio": "local program", "http": "remote service (HTTP)", "sse": "remote service (SSE)", "remote": "remote service", "unknown": "unknown"}
MCP_NOTE = ("These are the servers the project's config files declare. Nothing was started, so what a server can do (its tools) is not "
            "listed, and a server declared in a developer's own settings outside the repository is not seen. Environment variables and headers "
            "are shown by name only; their values are never read into the output.")


def mcp_place(s, links):
    url = links.url_for(s["file"], s["line"]) if links and s["line"] else ""
    return f"{s['file']}:{s['line']}" if s["line"] else s["file"], url


def mcp_markdown(meta, links=None):
    live, hidden = mcp_rows(meta)
    if not live and not hidden:
        return []
    out = ["## MCP servers", ""]
    if live:
        out += [f"{len(live)} MCP server{'' if len(live) == 1 else 's'} declared in the project's config files.", "",
                "| Server | Kind | How it runs | Declared in | Notes |", "|---|---|---|---|---|"]
        for s in live:
            label, _ = mcp_place(s, links)
            out.append(f"| {md_cell(s['name'])} | {MCP_KIND.get(s['transport'], s['transport'])} | {md_cell(mcp_how(s))} | {md_cell(label)} | {md_cell('; '.join(mcp_notes(s)))} |")
        out += ["", f"_{MCP_NOTE}_"]
    if hidden:
        out += ["", f"{hidden} more declared only in tests, examples or documentation, left out."]
    return out + [""]


def wb(text):
    """Escaped text that may break onto a new line after each "/" or "_" and before a ":line" (a path, an npm scope, a Hugging Face id),
    and only inside a part that is longer than the whole column. Without it a name such as @huggingface/transformers is cut in the middle of a word."""
    return re.sub(r":(?=\d+$)", "<wbr>:", html.escape(str(text)).replace("/", "/<wbr>").replace("_", "_<wbr>"))


def wbc(code):
    """Escaped code that may break onto a new line after . / ( , = and spaces, the way an editor wraps a long line, so a snippet
    in a narrow column is never cut in the middle of a name."""
    out = html.escape(str(code))
    for ch in ("/", ".", "(", ",", "="):
        out = out.replace(ch, ch + "<wbr>")
    return re.sub(r"(?<=[a-z])(?=[A-Z])", "<wbr>", out)        # and between the words of a CamelCase name


def place_html(label, url=""):
    """A place in the code inside a table cell: the file name and line (the link), and its folder on a smaller line under it, so a
    long path never splits a name. The whole path is the link's title (shown on hover), and it is what a search finds."""
    h = html.escape
    label = str(label)
    folder, _, name = label.rpartition("/")
    head = f'<a href="{h(url)}" target="_blank" rel="noopener" title="{h(label)}">{wb(name)}</a>' if url else f'<code title="{h(label)}">{wb(name)}</code>'
    return head + (f"<div class='dir'>{wb(folder + '/')}</div>" if folder else "")


HOW_ON = {"keyword": "passed as an argument", "dict": "set in a dict of arguments", "assignment": "set in an assignment",
          "setting": "set in a settings file", "flag": "given as a command-line flag"}


def cols(*shares):
    """A table's column widths, as shares of its width. With them the table is laid out at the width of its card, and long text wraps
    inside its column instead of pushing the table past the edge."""
    return "<colgroup>" + "".join(f"<col style='width:{w}%'>" for w in shares) + "</colgroup>"


def worst_flag_chip(flags):
    """The worst severity among some flags, as a label with how many there are; a dash when there are none."""
    if not flags:
        return "<span class='none'>none</span>"
    order = {"high": 4, "medium": 3, "low": 2, "info": 1}
    worst = max(flags, key=lambda f: order.get(f.severity, 0)).severity
    chip = f"<span class='sev sev-{worst if worst != 'info' else 'unknown'}'>{worst.upper()}</span>"
    return chip + (f" <span class='cnt'>{len(flags)} flag{'' if len(flags) == 1 else 's'}</span>")


def mcp_html(meta, links=None):
    live, hidden = mcp_rows(meta)
    if not live and not hidden:
        return ""
    h = html.escape
    flags = [f for f in (meta or {}).get("flags", []) if f.category == "mcp"]
    rows = ""
    for s in live:
        label, url = mcp_place(s, links)
        where = place_html(label, url)
        mine = [f for f in flags if (s.get("ref") and getattr(f, "ref", "") == s["ref"]) or (f.file == s["file"] and f.subject.split(":")[0] == s["name"])]
        rows += (f"<tr><td><b>{h(s['name'])}</b><div class='also'>{h(s.get('client') or '')}</div></td><td>{h(MCP_KIND.get(s['transport'], s['transport']))}</td><td><code>{wbc(mcp_how(s))}</code></td>"
                 f"<td>{worst_flag_chip(mine)}</td><td>{where}</td><td>{h('; '.join(mcp_notes(s)))}</td></tr>")
    body = ""
    if live:
        local = sum(1 for s in live if s["transport"] == "stdio")
        body = (f"<p class='sec-lead'>{len(live)} MCP server{'' if len(live) == 1 else 's'} declared in the project's config files: {local} local, {len(live) - local} remote.</p>"
                f"<div class='tw'><table class='fit'>{cols(15, 11, 23, 12, 16, 23)}<thead><tr><th>Server</th><th>Kind</th><th>How it runs</th><th>Risk</th><th>Declared in</th><th>Notes</th></tr></thead><tbody>{rows}</tbody></table></div>"
                f"<p class='note'>{h(MCP_NOTE)}</p>")
    else:
        body = "<p class='sec-lead'>No MCP server is declared in the project's own config files.</p>"
    if hidden:
        body += f"<p class='note'>{hidden} more declared only in tests, examples or documentation, left out.</p>"
    return f"<section class='sec' id='mcp'><h2>MCP servers</h2>{body}</section>"


MCP_CSV_HEAD = ["server", "client", "kind", "command", "args", "url", "launcher", "package", "ecosystem", "version", "pinned", "environment_names",
                "header_names", "enabled", "file", "line", "link", "left_out"]


def build_mcp_csv(found, links=None):
    """One row per declared MCP server (the left-out ones too, with the reason), for a spreadsheet."""
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(MCP_CSV_HEAD)
    for s in (found or {}).get("servers", []):
        pinned = "" if s["pinned"] is None else ("yes" if s["pinned"] else "no")
        w.writerow([s["name"], s["client"], MCP_KIND.get(s["transport"], s["transport"]), s["command"], " ".join(s["args"]), s["url"], s["launcher"], s["package"],
                    s["ecosystem"], s["version"], pinned, ", ".join(s["env_keys"]), ", ".join(s["header_names"]), "no" if s["enabled"] is False else "yes",
                    s["file"], s["line"], (links.url_for(s["file"], s["line"]) if links and s["line"] else ""), s["left_out"]])
    return buf.getvalue()


def human_size(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024.0


def model_file_rows(meta):
    """The model files a reader should see (the product's own), and how many more were left out as tests, examples or docs."""
    found = (meta or {}).get("model_files") or {"files": []}
    live = [r for r in found["files"] if not r.get("location")]
    return live, len(found["files"]) - len(live)


def model_file_finding(r):
    """What the scan found in a model file, in words. It never says a file is safe: only what was and was not found."""
    if r["status"] == "safe-format":
        return "A format that holds only numbers" + ("; it is listed, not read" if r["serialization"] == "onnx" else "")
    parts = []
    if r["dangerous"]:
        parts.append("imports " + ", ".join(f"{d['module']}.{d['name']}" for d in r["dangerous"][:3]) + (" and more" if len(r["dangerous"]) > 3 else ""))
    if r["unresolved"]:
        parts.append(f"{r['unresolved']} import(s) it could not identify")
    if r["mislabelled"]:
        parts.append(r["mislabelled"])
    if r["lambda_layer"]:
        parts.append("a Lambda layer, which holds Python code")
    if not parts and r["status"] == "scanned":
        parts.append("no dangerous import found; that does not make loading it safe" if r["pickle_based"] else "scanned")
    if r["status"] in ("not-scanned", "partly-scanned"):
        parts.append(("not scanned: " if r["status"] == "not-scanned" else "partly scanned: ") + r["reason"])
    return "; ".join(parts)


def model_files_markdown(meta):
    live, hidden = model_file_rows(meta)
    rc = [f for f in ((meta or {}).get("model_files") or {}).get("remote_code", {}).get("findings", []) if not f["location"]]
    if not live and not hidden and not rc:
        return []
    out = ["## Model files", ""]
    if live:
        out += [f"{len(live)} model file{'' if len(live) == 1 else 's'} in the project.", "", "| File | Format | Size | What the scan found |", "|---|---|---|---|"]
        for r in live:
            out.append(f"| {md_cell(r['file'])} | {md_cell(r['format'])} | {human_size(r['size'])} | {md_cell(model_file_finding(r))} |")
        out += ["", f"_{MODEL_FILES_NOTE}_"]
    if hidden:
        out += ["", f"{hidden} more in tests, examples or documentation, left out."]
    if rc:
        out += ["", f"trust_remote_code is turned on in {len(rc)} place{'' if len(rc) == 1 else 's'}: " + ", ".join(f"{f['file']}:{f['line']}" for f in rc[:5]) + (" and more" if len(rc) > 5 else "") + "."]
    return out + [""]


def model_files_html(meta, links=None):
    live, hidden = model_file_rows(meta)
    rc = [f for f in ((meta or {}).get("model_files") or {}).get("remote_code", {}).get("findings", []) if not f["location"]]
    if not live and not hidden and not rc:
        return ""
    h = html.escape
    flags = [f for f in (meta or {}).get("flags", []) if f.category == "model-file"]
    body = ""
    if live:
        rank = {"high": 0, "medium": 1, "low": 2, "info": 3}
        mine = {r["file"]: [f for f in flags if f.file == r["file"]] for r in live}
        worst = lambda r: min((rank.get(f.severity, 4) for f in mine[r["file"]]), default=5)
        rows = "".join(f"<tr><td class='file'><code>{wb(r['file'])}</code></td><td>{h(r['format'])}</td><td class='num'>{human_size(r['size'])}</td>"
                       f"<td>{worst_flag_chip(mine[r['file']])}</td><td>{h(model_file_finding(r))}</td></tr>" for r in sorted(live, key=lambda r: (worst(r), r["file"])))
        risky = sum(1 for r in live if r["dangerous"] or r["unresolved"] or r["mislabelled"] or r["lambda_layer"])
        body = (f"<p class='sec-lead'>{len(live)} model file{'' if len(live) == 1 else 's'} in the project; {risky} with a dangerous or hidden import, a Lambda layer or a misleading name.</p>"
                f"<div class='tw'><table class='fit'>{cols(24, 15, 10, 12, 39)}<thead><tr><th>File</th><th>Format</th><th>Size</th><th>Risk</th><th>What the scan found</th></tr></thead><tbody>{rows}</tbody></table></div>"
                f"<p class='note'>{h(MODEL_FILES_NOTE)}</p>")
    else:
        body = "<p class='sec-lead'>No model weight file in the project's own files.</p>"
    if hidden:
        body += f"<p class='note'>{hidden} more in tests, examples or documentation, left out.</p>"
    if rc:
        def rc_row(f):
            where = place_html("%s:%s" % (f["file"], f["line"]), links.url_for(f["file"], f["line"]) if links else "")
            return f"<tr><td>{sev_chip('medium')}</td><td>{where}</td><td>{h(HOW_ON.get(f['how'], f['how']))}</td></tr>"
        rows = "".join(rc_row(f) for f in rc)
        body += (f"<h3>trust_remote_code</h3><p class='sec-lead'>Turned on in {len(rc)} place{'' if len(rc) == 1 else 's'} in the project's own files. "
                 "A model's own repository can then supply Python that runs on this machine when the model is loaded. Turn it off, or pin the model "
                 "to a commit you have reviewed (the revision argument).</p>"
                 f"<div class='tw'><table class='fit'>{cols(14, 56, 30)}<thead><tr><th>Severity</th><th>Where (click to see the line)</th><th>How it is turned on</th></tr></thead>"
                 f"<tbody>{rows}</tbody></table></div>")
    return f"<section class='sec' id='modelfiles'><h2>Model files</h2>{body}</section>"


MODEL_FILES_NOTE = ("Each model file was read as data and never loaded or run. What kind of file it is comes from its content, not its name. A file in a pickle-based "
                    "format can run code when it is loaded, whatever the scan found: \"no dangerous import found\" is not the same as safe. TensorFlow SavedModel and "
                    "TFLite files are not read.")


def flags_markdown(meta):
    flags = other_flags(meta)
    if not flags:
        return []
    cell = md_cell
    out = ["## Flags", "", "| Severity | What | About | Where | Fix |", "|---|---|---|---|---|"]
    for f in flags:
        out.append(f"| {f.severity.upper()} | {cell(f.title)} | {cell(f.subject)} | {cell(flag_place(f))} | {cell(f.fix)} |")
    return out + ["", f"_{FLAGS_NOTE}_", ""]


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
    return (f"<a class='card vulncard' href='#vulns'><span class='lbl'>Known vulnerabilities</span><b>{total}</b><span>in the AI packages</span>"
            f"{sev_bar_html(direct)}</a>")


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


FLAG_CSV_HEAD = ["severity", "rule", "type", "finding", "about", "file", "line", "link", "fix", "detail"]


def sheet_cell(value):
    """Text a spreadsheet shows as text: a cell that starts like a formula (=, +, -, @) gets a leading apostrophe, because names and
    paths come from the scanned repository and a crafted one must not run as a formula in the reader's spreadsheet."""
    text = "" if value is None else str(value)
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


def flag_records(flags, links=None):
    """Every flag as a row of FLAG_CSV_HEAD, worst first: the data behind flags.csv and the report's download button."""
    out = []
    for f in flags:
        url = links.url_for(f.file, f.line) if links and f.file and f.line else ""
        out.append([f.severity, f.rule, CATEGORY_TEXT.get(f.category, f.category), f.title, f.subject, f.file, f.line or "", url, f.fix, f.detail])
    return out


def build_flags_csv(flags, links=None):
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\r\n")
    w.writerow(FLAG_CSV_HEAD)
    for row in flag_records(flags, links):
        w.writerow([sheet_cell(v) for v in row])
    return buf.getvalue()


# The files a scan writes next to the report, in the order the Downloads list shows them, with what each one is for.
DOWNLOADS = [("report.pdf", "PDF report", "the same report, ready to send or print (made with aibom report --pdf)"),
             ("aibom.cdx.json", "AI-BOM (CycloneDX 1.6)", "the standard AI bill of materials, for other tools"),
             ("flags.csv", "Findings (CSV)", "every finding with its place and fix, for a spreadsheet"),
             ("flags.json", "Findings (JSON)", "the same findings, for scripts"),
             ("aibom.sarif", "Findings (SARIF)", "for GitHub code scanning and other security dashboards"),
             ("models.csv", "AI models (CSV)", "every model and where it is used"),
             ("packages.csv", "AI packages (CSV)", "every AI package and its known vulnerabilities"),
             ("mcp.csv", "MCP servers (CSV)", "every declared MCP server"),
             ("report.md", "Report (Markdown)", "this report as plain text")]


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
    out += flags_markdown(meta)

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
    section = mcp_markdown(meta, links)
    if section:
        out += [""] + section
    section = model_files_markdown(meta)
    if section:
        out += [""] + section
    out += ["", "## What this scan cannot see", ""] + [f"- {c}" for c in CANNOT_SEE]
    out += ["", "How to read this: every row links a model name to a line of code. Confirmed means the name is written in the code; Worked out means the code spells it through a constant. "
                "The standard AI-BOM file (aibom.cdx.json) holds the same facts for other tools; models.csv opens in a spreadsheet."]
    return "\n".join(out) + "\n"


CSS = """
:root{--bg:#f3f5f8;--card:#fff;--text:#131722;--muted:#576071;--faint:#8b93a2;--line:#e1e5eb;--line2:#cbd2dc;--zebra:#f7f8fa;--chip:#eef1f5;
--head:#0e1a31;--head2:#172a4d;--on-head:#edf1f8;--on-head-muted:#a7b4cc;--accent:#2350c4;--accent-soft:#e8eefc;--ok:#17734a;
--critical:#7a1b2c;--high:#bf2630;--medium:#a35700;--low:#2a5fa5;--unknown:#687083;--on-medium:#fff;--on-sev:#fff}
*{box-sizing:border-box}html{scroll-behavior:smooth}
body{font-family:"Segoe UI",system-ui,-apple-system,Roboto,"Helvetica Neue",Arial,sans-serif;margin:0;color:var(--text);background:var(--bg);line-height:1.5;font-size:14.5px;-webkit-font-smoothing:antialiased}
a{color:var(--accent);font-weight:600;text-decoration:none}a:hover{text-decoration:underline}code{font-family:ui-monospace,"Cascadia Code",Consolas,Menlo,monospace;font-size:12.5px;overflow-wrap:break-word}
.top{background:linear-gradient(160deg,var(--head) 0%,var(--head2) 100%);color:var(--on-head);-webkit-print-color-adjust:exact;print-color-adjust:exact}
.top-in{max-width:1440px;margin:0 auto;padding:26px 28px 24px}
.brand{display:flex;align-items:center;gap:10px;font-size:11.5px;letter-spacing:.14em;text-transform:uppercase;color:var(--on-head-muted);font-weight:600}
.logo{font-size:14px;letter-spacing:.01em;text-transform:none;color:#fff;font-weight:800;padding:2px 9px;border-radius:6px;background:rgba(255,255,255,.1);border:1px solid rgba(255,255,255,.2)}
.top h1{font-size:30px;line-height:1.2;margin:12px 0 2px;color:#fff;letter-spacing:-.015em;overflow-wrap:anywhere}.top .what{margin:0;color:var(--on-head-muted);font-size:14px}
.facts{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:12px 28px;margin:20px 0 0;padding:16px 0 0;border-top:1px solid rgba(255,255,255,.12)}
.facts dt{font-size:11px;letter-spacing:.08em;text-transform:uppercase;color:var(--on-head-muted);margin:0 0 2px}.facts dd{margin:0;font-size:13.5px;color:var(--on-head);overflow-wrap:anywhere}.facts a{color:#c3d3ff}
.actions{display:flex;flex-wrap:wrap;gap:8px;margin:18px 0 0}
.act{font:inherit;font-size:13px;font-weight:600;color:var(--on-head);background:rgba(255,255,255,.08);border:1px solid rgba(255,255,255,.22);border-radius:8px;padding:7px 14px;cursor:pointer;text-decoration:none}
.act:hover{background:rgba(255,255,255,.16);text-decoration:none}.act.pri{background:#fff;color:var(--head);border-color:#fff}.act.pri:hover{background:#e8edf7}
.shell{max-width:1440px;margin:0 auto;display:grid;grid-template-columns:212px minmax(0,1fr);gap:28px;padding:26px 28px 64px}
.nav{position:sticky;top:18px;align-self:start;display:flex;flex-direction:column;gap:1px;font-size:13.5px}
.nh{display:flex;align-items:center;justify-content:space-between;margin:0 0 8px 10px}
.nav .nt{font-size:11px;letter-spacing:.1em;text-transform:uppercase;color:var(--faint);font-weight:700}
.navx{font:inherit;font-size:12px;font-weight:600;color:var(--muted);background:none;border:1px solid transparent;border-radius:6px;padding:2px 8px;cursor:pointer}.navx:hover{background:var(--card);border-color:var(--line)}
.navshow{display:none;position:fixed;left:20px;bottom:20px;z-index:10;font:inherit;font-size:13px;font-weight:600;color:#fff;background:var(--head);border:0;border-radius:8px;padding:9px 16px;cursor:pointer;box-shadow:0 6px 18px rgba(14,26,49,.25)}
.navshow:hover{background:var(--head2)}body.navoff .nav{display:none}body.navoff .navshow{display:block}body.navoff .shell{grid-template-columns:minmax(0,1fr)}
.nav a{display:flex;justify-content:space-between;gap:8px;color:var(--muted);font-weight:500;padding:6px 10px;border-radius:7px;border-left:2px solid transparent}
.nav a.sub{padding-left:24px;font-size:12.5px}.nav a:hover{background:var(--chip);color:var(--text);text-decoration:none}.nav a.on{color:var(--text);background:var(--card);border-left-color:var(--accent);font-weight:650}
.nav .n{color:var(--faint);font-variant-numeric:tabular-nums;font-weight:500}
main{min-width:0;counter-reset:sec}
.sec{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:24px 28px 22px;margin:0 0 20px;scroll-margin-top:16px;box-shadow:0 1px 2px rgba(16,24,40,.04)}
.sec>h2{counter-increment:sec;display:flex;align-items:center;gap:12px;font-size:19px;letter-spacing:-.01em;margin:0 0 6px}
.sec>h2::before{content:counter(sec,decimal-leading-zero);font-size:11.5px;font-weight:700;color:var(--accent);background:var(--accent-soft);border-radius:6px;padding:3px 7px;font-variant-numeric:tabular-nums}
h3{font-size:15px;margin:26px 0 10px;scroll-margin-top:16px}
.sec-lead{color:var(--muted);margin:0 0 16px;font-size:14px}.note{font-size:12.5px;color:var(--muted);margin:10px 0 0}.also{font-size:12px;color:var(--muted);margin-top:2px}
.banner{display:flex;align-items:flex-start;gap:12px;border-radius:10px;padding:14px 16px;margin:4px 0 18px;border:1px solid var(--line);background:var(--zebra);font-size:14px}
.banner b{display:block;font-size:15px;margin-bottom:2px}.banner .dot{flex:none;width:10px;height:10px;border-radius:50%;margin-top:6px;background:var(--unknown)}
.banner.bad{background:#fdf1f1;border-color:#f1cfd1}.banner.bad .dot{background:var(--high)}.banner.mid{background:#fdf6ea;border-color:#efd9b3}.banner.mid .dot{background:var(--medium)}
.banner.good{background:#eef7f2;border-color:#c9e5d5}.banner.good .dot{background:var(--ok)}
.cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(178px,1fr));gap:12px;margin:0}
.card{display:block;background:var(--card);border:1px solid var(--line);border-radius:10px;padding:13px 15px 12px;color:var(--text);font-weight:400;transition:border-color .15s,box-shadow .15s}
a.card:hover{text-decoration:none;border-color:var(--line2);box-shadow:0 2px 8px rgba(16,24,40,.07)}
.card .lbl{display:block;font-size:11px;letter-spacing:.07em;text-transform:uppercase;color:var(--faint);font-weight:700;margin:0 0 6px}
.card b{display:block;font-size:27px;line-height:1.1;font-weight:700;font-variant-numeric:tabular-nums}.card b.hot{color:var(--high)}
.card span{font-size:12.5px;color:var(--muted)}.card .sev{color:var(--on-sev);font-size:10.5px}.card .sev-medium{color:var(--on-medium)}
.card.vulncard{grid-column:span 2}.card .sevbar{margin:9px 0 6px}.card .sevkey{margin:0}
.warn{background:#fdf6ea;border:1px solid #efd9b3;border-radius:10px;padding:12px 16px;margin:0 0 18px;font-size:14px}.warn ul{margin:6px 0 0 18px;padding:0}
.lead{font-size:15px;margin:0 0 16px;color:var(--text)}
details.how{margin:4px 0 16px;font-size:13.5px;background:var(--zebra);border:1px solid var(--line);border-radius:10px;padding:2px 16px}.how ul{margin:4px 0 12px 18px;padding:0}
.risks{border:1px solid var(--line);border-radius:10px;padding:14px 18px;margin:18px 0 0;background:var(--zebra)}.risks h3{margin:0 0 8px}.risks ul{margin:0 0 0 18px;padding:0}.risks li{margin:4px 0}
input#q{width:100%;padding:10px 14px;border:1px solid var(--line2);border-radius:8px;background:var(--card);color:var(--text);font-size:14.5px;margin:4px 0 12px}input#q:focus{outline:2px solid var(--accent);outline-offset:1px;border-color:transparent}
.tw{overflow-x:auto;background:var(--card);border:1px solid var(--line);border-radius:10px;margin:6px 0 4px}
table{border-collapse:collapse;width:100%;font-size:13.5px}table.fit{table-layout:fixed}
th,td{padding:10px 10px;text-align:left;vertical-align:top;overflow-wrap:break-word;border-bottom:1px solid var(--line)}tr:last-child td{border-bottom:0}
th{font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);background:var(--zebra);font-weight:700;line-height:1.35}
tbody tr:hover td{background:#fafbfd}td.num{font-variant-numeric:tabular-nums}
td{overflow-wrap:break-word}td .sev,td .ev,td .badge,td .cat{max-width:100%;white-space:normal;vertical-align:top}
table.flags .d{font-size:12.5px;color:var(--muted);margin-top:3px}
.cat{display:inline-block;font-size:11.5px;color:var(--muted);background:var(--chip);border-radius:5px;padding:1px 7px;white-space:nowrap}
.dir{font-size:11.5px;color:var(--faint);margin-top:1px;overflow-wrap:break-word}.none{color:var(--faint);font-size:12.5px}.cnt{display:block;margin-top:3px;font-size:12px;color:var(--muted);white-space:nowrap}
.badge{display:inline-block;border:1px solid var(--line2);color:var(--muted);border-radius:999px;padding:0 7px;font-size:11.5px;font-weight:650;white-space:nowrap}.badge.worked{border-style:dashed}
details{margin:10px 0}summary{cursor:pointer;font-weight:600}
details.grp{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:0 14px;margin:10px 0}details.grp>summary{font-size:14.5px;padding:11px 0}details.grp .tw{border:0;border-top:1px solid var(--line);border-radius:0;margin:0 -14px}
details.more{margin:6px 0 0}details.more summary{font-weight:500;font-size:12.5px;color:var(--accent)}details.more ul{margin:6px 0 0;padding:0;list-style:none;font-size:12.5px}details.more li{margin:0 0 6px}code.snip{display:block;color:var(--muted);font-size:11.5px;margin-top:1px}
.filters{display:flex;flex-wrap:wrap;gap:6px;align-items:center;margin:0 0 12px}.filters .fl{font-size:11px;letter-spacing:.07em;text-transform:uppercase;color:var(--faint);font-weight:700;margin:0 4px 0 6px}.filters .fl:first-child{margin-left:0}
.fb{font:inherit;font-size:12.5px;border:1px solid var(--line2);background:var(--card);color:var(--text);border-radius:999px;padding:3px 11px;cursor:pointer}.fb:hover{border-color:var(--faint)}.fb[aria-pressed=true]{background:var(--head);border-color:var(--head);color:#fff}
.fb.more{margin:10px 0 0;padding:6px 14px;font-weight:600;color:var(--accent);border-color:var(--line2)}
.foot{font-size:12px;color:var(--muted);margin:8px 0 0;padding:0 4px}#nomatch,#nofl{display:none;font-weight:600;margin:12px 0;color:var(--muted)}
.sev{display:inline-block;border-radius:4px;padding:2px 7px;font-size:10.5px;font-weight:750;letter-spacing:.05em;line-height:1.35;white-space:nowrap;color:var(--on-sev);-webkit-print-color-adjust:exact;print-color-adjust:exact}
.sev-critical{background:var(--critical)}.sev-high{background:var(--high)}.sev-medium{background:var(--medium);color:var(--on-medium)}.sev-low{background:var(--low)}.sev-unknown{background:var(--unknown)}
.sevbar{display:flex;height:8px;border-radius:4px;overflow:hidden;background:var(--chip);margin:10px 0 6px;-webkit-print-color-adjust:exact;print-color-adjust:exact}.sevbar i{display:block;height:100%}
.sevkey{font-size:12.5px;margin:0 0 12px;color:var(--muted)}.sevkey .sev{margin:0 4px 0 10px}.sevkey .sev:first-child{margin-left:0}
.ev{display:inline-block;border-radius:7px;padding:1px 8px;font-size:11.5px;font-weight:650;line-height:1.35;white-space:nowrap;background:var(--chip);cursor:help}
.ev-called{color:#11683f;background:rgba(17,104,63,.1)}.ev-imported{color:#855300;background:rgba(163,87,0,.11)}.ev-declared{color:var(--muted)}
.vcard{background:var(--card);border:1px solid var(--line);border-radius:10px;margin:10px 0;overflow:hidden}
.vhead{display:flex;gap:10px;align-items:center;flex-wrap:wrap;padding:10px 16px;background:var(--zebra);border-bottom:1px solid var(--line)}.vhead b{font-size:14.5px}.vhead .grow{flex:1}
.adv{list-style:none;margin:0;padding:0}.adv li{display:grid;grid-template-columns:78px minmax(150px,230px) 1fr;gap:6px 14px;padding:9px 16px;border-bottom:1px solid var(--line);align-items:start}.adv li:last-child{border-bottom:0}
.adv .fix{font-size:12.5px;color:var(--muted)}.adv .fix b{color:var(--ok)}.adv .what{grid-column:3;font-size:13.5px}.vcard details.more{margin:0;padding:8px 16px;border-top:1px solid var(--line)}.vcard details.more .adv{margin:6px -16px 0}
@media (max-width:1199px){.shell{grid-template-columns:1fr;gap:0;padding:0 16px 48px}.top-in{padding:20px 16px}.top h1{font-size:24px}.facts{grid-template-columns:1fr 1fr;gap:10px 16px}.facts div:first-child{grid-column:1/-1}
.nav{top:0;z-index:5;flex-direction:row;overflow-x:auto;gap:4px;margin:0 -16px 16px;padding:8px 16px;background:var(--bg);border-bottom:1px solid var(--line)}
.nav .nh,.nav .n,.navshow,body.navoff .navshow{display:none}body.navoff .nav{display:flex}.nav a,.nav a.sub{padding:5px 11px;font-size:13px;white-space:nowrap;border-left:0;border-radius:999px}.nav a.on{background:var(--head);color:#fff}
.sec{padding:18px 16px;border-radius:10px}.card.vulncard{grid-column:auto}table.fit{min-width:860px}.adv li{grid-template-columns:1fr}.adv .what{grid-column:1}}
@media print{:root{--bg:#fff;--zebra:#f6f7f9}.nav,.navshow,input#q,.filters,.actions,#downloads,#flmore{display:none}.shell{display:block;padding:0}.sec{border:0;box-shadow:none;padding:0;margin:0 0 18px}
.tw{overflow:visible}table.wide{min-width:0}th{position:static}.vcard,.card{break-inside:avoid}}
"""
JS = """
const q=document.getElementById('q');
function run(){const t=q.value.trim().toLowerCase();let shown=0;
document.querySelectorAll('#models tr[data-t], #listed tr[data-t]').forEach(r=>{const ok=!t||r.dataset.t.indexOf(t)>-1;r.style.display=ok?'':'none';if(ok)shown++;});
document.querySelectorAll('details.grp').forEach(d=>{const any=[...d.querySelectorAll('tr[data-t]')].some(r=>r.style.display!=='none');d.style.display=any?'':'none';if(t&&any)d.open=true;});
document.getElementById('nomatch').style.display=(t&&!shown)?'block':'none';}
if(q)q.addEventListener('input',run);
const want={sev:'all',cat:'all'};let all=false;const more=document.getElementById('flmore');
function filt(){let n=0;document.querySelectorAll('table.flags tbody tr').forEach(r=>{const ok=(want.sev==='all'||r.dataset.sev===want.sev)&&(want.cat==='all'||r.dataset.cat===want.cat);
const show=ok&&(all||n<25);r.style.display=show?'':'none';if(ok)n++;});
const e=document.getElementById('nofl');if(e)e.style.display=n?'none':'block';
if(more){more.style.display=(!all&&n>25)?'':'none';more.textContent='Show all '+n+' flags';}}
if(more)more.addEventListener('click',()=>{all=true;filt();});filt();
document.querySelectorAll('.fb').forEach(b=>b.addEventListener('click',()=>{const k=b.dataset.k;want[k]=b.dataset.v;
document.querySelectorAll('.fb[data-k="'+k+'"]').forEach(x=>x.setAttribute('aria-pressed',x===b?'true':'false'));filt();}));
const navs=[...document.querySelectorAll('.nav a')];
if('IntersectionObserver' in window&&navs.length){const ob=new IntersectionObserver(es=>{es.forEach(e=>{if(e.isIntersecting){navs.forEach(a=>a.classList.toggle('on',a.getAttribute('href')==='#'+e.target.id));}});},{rootMargin:'-10% 0px -80% 0px'});
navs.forEach(a=>{const s=document.getElementById(a.getAttribute('href').slice(1));if(s)ob.observe(s);});}
window.addEventListener('beforeprint',()=>{document.querySelectorAll('details').forEach(d=>d.open=true);all=true;filt();});
const nb=document.body,nh=document.getElementById('navhide'),ns=document.getElementById('navshow');
const navset=off=>{nb.classList.toggle('navoff',off);try{localStorage.setItem('aibom-nav',off?'off':'on');}catch(e){}};
try{if(localStorage.getItem('aibom-nav')==='off')nb.classList.add('navoff');}catch(e){}
if(nh)nh.addEventListener('click',()=>navset(true));if(ns)ns.addEventListener('click',()=>navset(false));
const pr=document.getElementById('doprint');if(pr)pr.addEventListener('click',()=>window.print());
const dl=document.getElementById('dlcsv');
if(dl)dl.addEventListener('click',()=>{const d=JSON.parse(document.getElementById('flagdata').textContent);
const cell=v=>{let t=v==null?'':String(v);if(/^[=+\\-@\\t\\r]/.test(t))t="'"+t;return '"'+t.replace(/"/g,'""')+'"';};
const csv=[d.head].concat(d.rows).map(r=>r.map(cell).join(',')).join('\\r\\n');
const a=document.createElement('a');a.href=URL.createObjectURL(new Blob(['\\ufeff'+csv],{type:'text/csv;charset=utf-8'}));
a.download=(d.app||'aibom').replace(/[^A-Za-z0-9._-]+/g,'-')+'-findings.csv';document.body.appendChild(a);a.click();setTimeout(()=>{URL.revokeObjectURL(a.href);a.remove();},0);});
"""


PDF_CSS = """
@page{size:A4 landscape;margin:14mm 12mm 16mm 12mm;@bottom-left{content:"aibom AI-BOM report";font:9px system-ui,sans-serif;color:#555}@bottom-right{content:"Page " counter(page) " of " counter(pages);font:9px system-ui,sans-serif;color:#555}}
body{font-size:12px;background:#fff}.top{display:none}.shell{display:block;max-width:none;padding:0}h2{break-after:avoid}h3{break-after:avoid}
.sec{border:0;box-shadow:none;padding:0;margin:0 0 22px;break-before:auto}.sec>h2{font-size:17px;border-bottom:1px solid var(--line);padding-bottom:8px;margin-bottom:10px}
.cover{min-height:165mm;display:flex;flex-direction:column;justify-content:center;break-after:page;border-left:10px solid var(--head);padding-left:28px}
.cover .kicker{font-size:13px;letter-spacing:.12em;text-transform:uppercase;color:var(--muted);margin:0 0 10px}.cover h1{font-size:44px;line-height:1.1;margin:0 0 8px}
.cover .what{font-size:18px;margin:0 0 28px;max-width:60ch}.cover dl{display:grid;grid-template-columns:150px 1fr;gap:6px 16px;margin:0;font-size:14px}.cover dt{color:var(--muted)}.cover dd{margin:0;overflow-wrap:anywhere}
.cover .stamp{margin-top:34px;font-size:12px;color:var(--muted);max-width:75ch}
tr,.vcard,.card,.risks,.warn,.banner{break-inside:avoid}.tw{overflow:visible}table.wide{min-width:0}th{position:static}.card b{font-size:24px}table{font-size:11px}th,td{padding:6px 8px}
.cards{grid-template-columns:repeat(4,1fr)}.card.vulncard{grid-column:span 2}details>summary{list-style:none}details.how{display:none}details.more>summary{display:none}
"""


def data_dates():
    """The dates of the model and vulnerability data this aibom carries, as one line."""
    try:
        from .db import load_db
        dbmeta = load_db().get("meta") or {}
        return f"models {dbmeta.get('built', '?')}, vulnerabilities {(dbmeta.get('vulnerabilities') or {}).get('fetched', '?')}"
    except Exception:
        return "unknown"


def cover_html(app, source, links, meta, rows, today=None):
    """The first page of the PDF: what was scanned, with which version of the tool and which data, and when."""
    h = html.escape
    day = today or datetime.date.today().isoformat()
    src = source_line(source, links, meta)
    pk = package_rows((meta or {}).get("packages"))
    direct = [r for r in pk if r["direct"] is not False]
    advisories = sum(len(r["advisories"]) for r in direct)
    later = sum(len(r["advisories"]) for r in pk if r["direct"] is False)
    facts = [("Scanned", src or app), ("Report date", day), ("Scanner", f"aibom {__version__}"), ("Data", data_dates()),
             ("Found", f"{len(rows['used'])} models used directly in the code; {len(direct)} AI packages the project depends on, with {advisories} known vulnerabilities"
              + (f" ({later} more in {len(pk) - len(direct)} packages that are only in a lockfile)" if later else ""))]
    counts = flag_counts((meta or {}).get("flags", []))
    if sum(counts.values()):
        facts.append(("Risk flags", f"{counts['high']} high, {counts['medium']} medium, {counts['low']} low; {counts['info']} info notes"))
    dl = "".join(f"<dt>{h(k)}</dt><dd>{h(v)}</dd>" for k, v in facts)
    return (f"<section class='cover'><p class='kicker'>AI bill of materials</p><h1>{h(app)}</h1>"
            "<p class='what'>The AI in this code: models, AI packages and their known vulnerabilities, MCP servers, model files and hardcoded keys, each with the place in the code that proves it.</p>"
            f"<dl>{dl}</dl><p class='stamp'>This report lists what aibom reads in the code and dependency files. It does not run the app. "
            "A known vulnerability means the exact version is named in an advisory; it does not mean the app is exploitable. The full list of places and the standard CycloneDX 1.6 file (aibom.cdx.json) come with the scan.</p></section>")


FLAGS_SHOWN = 25   # on screen, the flags table opens on this many rows; a button shows the rest


def flag_counts(flags):
    out = {"high": 0, "medium": 0, "low": 0, "info": 0}
    for f in flags:
        out[f.severity] = out.get(f.severity, 0) + 1
    return out


def flags_html(meta, links=None, pdf=False):
    """Every flag of the scan in one table, worst first. On screen it can be filtered by severity and type; a PDF leaves the info notes out
    (it says how many), because nobody can filter paper."""
    every = list((meta or {}).get("flags", []))
    flags = [f for f in every if f.severity != "info"] if pdf else every
    if not flags:
        return ""
    h = html.escape

    def place(f):
        if not f.file:
            return "<span class='none'>the whole project</span>"
        url = links.url_for(f.file, f.line) if links and f.line else ""
        return place_html(flag_place(f), url)

    rows = "".join(f"<tr data-sev='{h(f.severity)}' data-cat='{h(f.category)}'><td><span class='sev sev-{f.severity if f.severity != 'info' else 'unknown'}'>{f.severity.upper()}</span></td>"
                   f"<td><b>{h(f.title)}</b>" + (f"<div class='d'>{h(f.subject)}</div>" if f.subject else "") + "</td>"
                   f"<td><span class='cat'>{h(CATEGORY_TEXT.get(f.category, f.category))}</span></td><td>{place(f)}</td><td>{h(f.fix)}</td></tr>" for f in flags)
    bar = ""
    if not pdf:
        sevs = [s for s in ("high", "medium", "low", "info") if any(f.severity == s for f in flags)]
        cats = [c for c in CATEGORY_TEXT if any(f.category == c for f in flags)]
        btn = lambda k, v, label, on=False: f"<button type='button' class='fb' data-k='{k}' data-v='{v}' aria-pressed='{'true' if on else 'false'}'>{h(label)}</button>"
        bar = ("<div class='filters' role='group' aria-label='Filter the flags'><span class='fl'>Severity</span>" + btn("sev", "all", "All", True)
               + "".join(btn("sev", s, f"{s.capitalize()} ({sum(1 for f in flags if f.severity == s)})") for s in sevs)
               + "<span class='fl'>Type</span>" + btn("cat", "all", "All", True)
               + "".join(btn("cat", c, f"{CATEGORY_TEXT[c]} ({sum(1 for f in flags if f.category == c)})") for c in cats) + "</div>")
    return (f"{bar}<div class='tw'><table class='flags fit'>{cols(12, 31, 11, 19, 27)}<thead><tr><th>Severity</th><th>Finding</th><th>Type</th><th>Where</th><th>Fix</th></tr></thead><tbody>"
            + rows + "</tbody></table></div><div id='nofl'>No flag matches these filters.</div>"
            + ("" if pdf or len(flags) <= FLAGS_SHOWN else f"<button type='button' class='fb more' id='flmore'>Show all {len(flags)} flags</button>")
            + (f"<p class='note'>{len(every) - len(flags)} info notes are left out of the PDF; they are in the HTML report and flags.json.</p>" if len(every) > len(flags) else "")
            + f"<p class='note'>{h(FLAGS_NOTE)}</p>")


def summary_html(meta, rows, items):
    """The first section: one line on whether anything needs attention, then one tile per part of the scan, each linking to its section."""
    h = html.escape
    meta = meta or {}
    flags = meta.get("flags", [])
    c = flag_counts(flags)
    pk = package_rows(meta.get("packages"))
    direct = [r for r in pk if r["direct"] is not False]
    advisories = sum(len(r["advisories"]) for r in direct)
    mcp_live, _ = mcp_rows(meta)
    mf_live, _ = model_file_rows(meta)
    risky_files = sum(1 for r in mf_live if r["dangerous"] or r["unresolved"] or r["mislabelled"] or r["lambda_layer"])
    keys = [f for f in flags if f.category == "secret"]
    rc = [f for f in (meta.get("model_files") or {}).get("remote_code", {}).get("findings", []) if not f["location"]]
    if c["high"]:
        tone, head = "bad", f"{c['high']} high-severity finding{'' if c['high'] == 1 else 's'} need{'s' if c['high'] == 1 else ''} attention"
    elif c["medium"]:
        tone, head = "mid", f"No high-severity findings; {c['medium']} at medium"
    else:
        tone, head = "good", "No high or medium findings"
    body = f"{c['high']} high, {c['medium']} medium and {c['low']} low risk flags, plus {c['info']} info notes"
    if advisories:
        body += f"; {advisories} known vulnerabilit{'y' if advisories == 1 else 'ies'} in the AI packages"
    body += ". Each one has its place in the code and a fix. A clean result is not proof of safety: it covers what this scan can read."
    out = [f"<div class='banner {tone}'><span class='dot'></span><div><b>{h(head)}</b>{h(body)}</div></div>", "<div class='cards'>"]

    def card(href, label, number, text, hot=False):
        hot_attr = " class='hot'" if hot and number else ""
        return f"<a class='card' href='#{href}'><span class='lbl'>{h(label)}</span><b{hot_attr}>{number}</b><span>{h(text)}</span></a>"
    if flags:
        out.append(card("flags", "Risk flags", sum(c.values()), f"{c['high']} high · {c['medium']} medium · {c['low']} low · {c['info']} info", c["high"] > 0))
    if advisories:
        out.append(vuln_card(pk))
    out.append(card("models", "AI models", len(rows["used"]), f"used directly in the code; {len(rows['listed'])} more only listed") if rows["used"] or rows["listed"]
               else card("limits", "AI models", 0, "named in the code"))
    if pk:
        sm = package_summary(pk)
        out.append(card("packages", "AI packages", len(direct), f"{sm['vulnerable']} with known vulnerabilities"))
    if mcp_live:
        local = sum(1 for s in mcp_live if s["transport"] == "stdio")
        out.append(card("mcp", "MCP servers", len(mcp_live), f"{local} local, {len(mcp_live) - local} remote"))
    if mf_live:
        out.append(card("modelfiles", "Model files", len(mf_live), f"{risky_files} can run code or hide what they are", risky_files > 0))
    ks = meta.get("secrets") or {}
    if ks.get("keys") or ks.get("other"):          # the key search's own count: a key in an MCP config is counted here, though the MCP rule flags it
        out.append(card("flags", "Hardcoded API keys", ks.get("keys", 0), f"in {ks.get('files', 0)} of the product's files; {ks.get('other', 0)} more in tests or docs", ks.get("keys", 0) > 0))
    elif keys:                                      # a scan saved before the key count was kept
        live_keys = [f for f in keys if f.severity != "low"]
        out.append(card("flags", "Hardcoded API keys", len(live_keys), f"in the product's files; {len(keys) - len(live_keys)} more in tests or docs", bool(live_keys)))
    if rc:
        out.append(card("modelfiles", "trust_remote_code", len(rc), "places in the product's files turn it on"))
    out.append("</div>")
    return "".join(out)


def actions_html(files):
    """The buttons under the header: the PDF (the file when the scan has one, else the browser's own Save as PDF), the findings as a
    spreadsheet (made in the page, so it works even when the page is sent on its own), the AI-BOM, and the list of every file."""
    files = set(files or ())
    pdf = ("<a class='act pri' href='report.pdf' download>Download PDF</a>" if "report.pdf" in files
           else "<button type='button' class='act pri' id='doprint'>Save as PDF</button>")
    bom = "<a class='act' href='aibom.cdx.json' download>AI-BOM (CycloneDX)</a>" if "aibom.cdx.json" in files else ""
    return (f"<div class='actions'>{pdf}<button type='button' class='act' id='dlcsv'>Download findings (CSV)</button>{bom}"
            + ("<a class='act' href='#downloads'>All files</a>" if files else "") + "</div>")


def downloads_html(files):
    """The Downloads section: a link to each file of the scan that sits next to this report."""
    files = set(files or ())
    rows = [(name, label, what) for name, label, what in DOWNLOADS if name in files]
    if not rows:
        return ""
    h = html.escape
    lis = "".join(f"<tr><td><a href='{h(name)}' download>{h(label)}</a></td><td><code>{h(name)}</code></td><td>{h(what)}</td></tr>" for name, label, what in rows)
    return ("<section class='sec' id='downloads'><h2>Downloads</h2><p class='sec-lead'>The files of this scan. They sit next to this report in the scan folder: "
            "to share the report with these links working, send the whole folder (for example as a zip). Download findings (CSV) at the top works on its own.</p>"
            f"<div class='tw'><table class='fit'>{cols(26, 22, 52)}<thead><tr><th>File</th><th>Name</th><th>What it is for</th></tr></thead><tbody>{lis}</tbody></table></div></section>")


def build_html(items, app, source="", links=None, meta=None, pdf=False, today=None, files=None):
    rows = build_rows(items)
    used, listed, gone = rows["used"], rows["listed"], rows["left_out"]
    h = html.escape

    def place_link(p):
        url = links.url_for(p["file"], p["line"]) if links else ""
        txt = wb(f"{p['file']}:{p['line']}")
        return f'<a href="{h(url)}" target="_blank" rel="noopener">{txt}</a>' if url else f"<code>{txt}</code>"

    def place_cell(p):
        return place_html(f"{p['file']}:{p['line']}", links.url_for(p["file"], p["line"]) if links else "")

    def row_html(r):
        first = r["places"][0] if r["places"] else None
        more = r["places"][1:]
        cell = place_cell(first) if first else "-"
        if more:
            lis = "".join(f"<li>{place_link(p)}<code class='snip'>{wbc(p['snippet'][:90])}</code></li>" for p in more[:14])
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
        dates = ((f"<div class='also'>deprecated {h(dep)}</div>" if dep != "-" else "")
                 + (f"<div class='also'>{'retired' if (r.get('status') or '') == 'retired' else 'retires'} {h(ret)}</div>" if ret != "-" else ""))
        kind = h(MODE_TEXT.get(r["mode"], r["mode"]) or "AI model")
        return (f'<tr data-t="{h(text)}"><td><b>{wb(r["name"])}</b><div class="also">{kind}</div>{alias}</td><td>{cell}</td><td>{badge}</td>'
                f'<td>{h(status)}{dates}</td><td>{h(pinned)}</td><td>{h(repl)}</td><td>{h(lic)}</td></tr>')

    def groups(rs, open_first):
        out = []
        for i, (maker, rr) in enumerate(by_maker(rs)):
            out.append(f'<details class="grp"{" open" if open_first and i < 3 else ""}><summary>{h(maker)} ({len(rr)})</summary>'
                       '<div class="tw"><table class="wide fit">' + cols(17, 19, 13, 14, 11, 11, 15) +
                       '<tr><th>Model</th><th>Where it is used (click to see the line)</th><th>Confidence</th><th>Status and dates</th><th>Pinned</th><th>Replaced by</th><th>License</th></tr>' + "".join(row_html(r) for r in rr) + "</table></div></details>")
        return "".join(out)

    day = today or today_iso()
    sub = source_line(source, links, meta)
    facts = [("Source", sub or app), ("Report date", day), ("Scanner", f"aibom {__version__}"), ("Data", data_dates())]
    head = (f"<header class='top'><div class='top-in'><div class='brand'><span class='logo'>aibom</span>AI bill of materials</div>"
            f"<h1>{h(app)}</h1><p class='what'>AI models found in {h(app)}: models, AI packages, MCP servers, model files and keys, each proved by a line of code.</p>"
            "<dl class='facts'>" + "".join(f"<div><dt>{h(k)}</dt><dd>{h(v)}</dd></div>" for k, v in facts) + "</dl>" + ("" if pdf else actions_html(files)) + "</div></header>")
    out = [f"<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><meta name='color-scheme' content='light'><title>AI models in {h(app)}</title><style>{CSS}{PDF_CSS if pdf else ''}</style></head><body>",
           head, "<div class='shell'>"]
    nav_at = len(out)
    out.append("<main>")
    out.append(cover_html(app, source, links, meta, rows, today) if pdf else "")
    warns = (meta or {}).get("warnings", [])
    summary = "<section class='sec' id='summary'><h2>Summary</h2>"
    if warns:
        summary += "<div class='warn'><b>This scan may be incomplete.</b><ul>" + "".join(f"<li>{h(w)}</li>" for w in warns) + "</ul></div>"
    summary += summary_html(meta, rows, items).replace("<div class='cards'>", f"<p class='lead'>{h(intro(rows, app))}</p><div class='cards'>", 1) + "</section>"
    out.append(summary)

    risk = risk_summary(rows)

    def risk_item(label, found):
        names = risk_names(found)
        return f"<li><b>{label}:</b> {len(found)}" + (f" &mdash; {h(names)}" if names else "") + "</li>"

    risks = ("<div class='risks'><h3>Model lifecycle and licences</h3><ul>" + "".join(risk_item(label, found) for label, found in risk_lines(risk)) + "</ul>"
             + "".join(f"<p class='note'>{h(note)}</p>" for note in lifecycle_notes(risk)) + "</div>")
    table = flags_html(meta, links, pdf)
    lead = ("Everything worth a look, worst first. Each row says where it is and how to fix it." if table
            else "No risk flags were raised by this scan. That covers what it can read; it is not proof of safety.")
    out.append(f"<section class='sec' id='flags'><h2>Findings</h2><p class='sec-lead'>{lead}</p>" + table + risks + "</section>")

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
            return (f"<div class='vcard'><div class='vhead'><b>{wb(r['name'])}</b><span>{h(r['version'] or '-')}</span>{ev_chip(r)}<span class='grow'></span>"
                    f"{sev_chip(r['worst'])}<span>{len(advs)} known</span></div><ul class='adv'>{shown}</ul>{rest}</div>")

        def ev_chip(r):
            return f"<span class='ev ev-{r['level']}' title=\"{h(PACKAGE_EVIDENCE_WHY[r['level']])}\">{h(package_level_text(r))}</span>"

        def prow(r):
            label, url = package_proof(r, links)
            where = place_html(label, url) if label else "-"
            text = " ".join([r["name"], r["kind"], r["version"], r["level"], r["vuln_text"], r["vendor"], " ".join(a["id"] for a in r["advisories"])]).lower()
            return (f'<tr data-t="{h(text)}"><td><b>{wb(r["name"])}</b></td><td>{h(r["kind"])}</td><td>{h(r["version"] or "-")}</td>'
                    f'<td>{ev_chip(r)}</td><td>{where}</td><td>{vuln_cell(r)}</td></tr>')

        PK_COLS = cols(23, 11, 10, 13, 17, 26)
        head_row = "<tr><th>Package</th><th>Kind</th><th>Version</th><th>Evidence</th><th>Where (click to see the line)</th><th>Known vulnerabilities</th></tr>"
        direct = [r for r in pk if r["direct"] is not False]
        later = [r for r in pk if r["direct"] is False]
        date = advisory_date()
        sec = ("<section class='sec' id='packages'><h2>AI packages</h2>"
               f"<p class='sec-lead'>{sm['direct']} AI packages found in the project"
               + (f", and {sm['transitive']} more only in a lockfile" if sm["transitive"] else "")
               + f". <b>{sm['vulnerable']}</b> have known vulnerabilities ({sm['advisories']} advisories); {sm['not_checked']} could not be checked."
               + (f" Advisory data from {h(date)}." if date else "") + "</p>"
               + f"<div class='tw'><table class='pk fit'>{PK_COLS}{head_row}{''.join(prow(r) for r in direct)}</table></div><p class='note'>{h(PACKAGE_NOTE)}</p>")
        if later:
            sec += (f"<details><summary>{len(later)} more AI packages only in a lockfile (transitive)</summary>"
                    f"<div class='tw'><table class='pk fit'>{PK_COLS}{head_row}{''.join(prow(r) for r in later)}</table></div></details>")
        cards = [r for r in direct if r["advisories"]]
        cards_later = [r for r in later if r["advisories"]]
        if cards or cards_later:
            sec += ("<span id='vulns'></span><h3>Known vulnerabilities, worst first</h3>" + sev_bar_html(direct)
                    + "<p class='note'>Packages your code calls come first inside each severity. "
                      "Affected is not the same as exploitable: reachability is not verified.</p>" + "".join(vcard(r) for r in cards))
            if cards_later:
                sec += f"<details><summary>{len(cards_later)} more with vulnerabilities, only in a lockfile</summary>{''.join(vcard(r) for r in cards_later)}</details>"
        plan = fix_plan_rows((meta or {}).get("packages"))
        if plan:
            prs = "".join(f"<tr><td><b>{wb(p['package'])}</b></td><td>{h(p['version'] or '-')}</td><td>{sev_chip(p['worst'])}</td><td>{h(fix_plan_text(p))}</td></tr>" for p in plan)
            sec += ("<span id='fixplan'></span><h3>Fix plan</h3><p class='note'>For each package with known vulnerabilities, the lowest version that its advisories say fixes all of them. "
                    "Each target was checked again against the advisory data. Upgrading can break code: test it.</p>"
                    f"<div class='tw'><table class='fit'>{cols(24, 12, 13, 51)}<tr><th>Package</th><th>Now</th><th>Worst</th><th>What to do</th></tr>{prs}</table></div>")
        out.append(sec + "</section>")

    n_aibom = len([i for i in items if i["tier"] != "rejected"])
    link_tip = "Click a file name to open that exact line on the website where the code is hosted." if links and links.ok else "This scan was of a local folder, so there are no web links; the file and line are shown instead."
    how = ("<details class='how'><summary>How to read this table</summary><ul>"
           "<li>Every row names a model and the place in the code that proves it. " + h(link_tip) + "</li>"
           "<li><span class='badge'>Confirmed</span> means the name is written in the code. <span class='badge worked'>Worked out</span> means the code spells it through a constant, such as GPT_4O.</li>"
           "<li>Models grouped under their maker. Different spellings of one model are shown as one row (&quot;also written as&quot;)"
           + (f"; the standard AI-BOM file keeps each spelling as its own entry ({n_aibom} entries)." if n_aibom != len(used) + len(listed) else ".") + "</li></ul></details>")
    msec = "<section class='sec' id='models'><h2>AI models</h2>"
    if used or listed:
        msec += f"<p class='sec-lead'>{len(used)} used directly in the code" + (f"; {len(listed)} more only listed in {h(LISTED_NOTE)}" if listed else "") + ".</p>" + how
        if not pdf:
            msec += "<input id='q' type='search' placeholder='Search by model, maker or file name...' autocomplete='off'><div id='nomatch'>Nothing matches that search.</div>"
    if used:
        msec += "<h3>Used directly in the code</h3>" + groups(used, True)
    if listed and pdf:
        msec += f"<span id='listed'></span><h3>Only listed in {h(LISTED_NOTE)}</h3><p>{len(listed)} more model names are written in the code only inside big tables or lists. They are in models.csv and in the HTML report.</p>"
    elif listed:
        msec += (f"<span id='listed'></span><h3>Only listed in {h(LISTED_NOTE)}</h3><p class='note'>These names are written in the code, but only inside big tables or lists, not set or called on their own.</p>"
                 + groups(listed, False))
    if not used and not listed:
        msec += f"<p class='sec-lead'>Nothing found.</p><p>{h(intro(rows, app))}</p>"
    out.append(msec + "</section>")
    out.append(mcp_html(meta, links))
    out.append(model_files_html(meta, links))

    scope = "<section class='sec' id='scope'><h2>Scope and method</h2>"
    if gone and pdf:
        scope += f"<span id='leftout'></span><h3>Left out, and why</h3><p>{len(gone)} names that look like models were left out because they appear only in comments, messages, tests or documentation. Each one, with the reason, is in the HTML report.</p>"
    elif gone:
        rws = "".join(f"<tr><td>{h(g['name'])}</td><td>{h(g['why'])}</td><td>{place_cell({'file': g['file'], 'line': g['line']})}</td></tr>" for g in gone)
        scope += (f"<span id='leftout'></span><h3>Left out, and why</h3><details><summary>{len(gone)} names that look like models but are not used (click to open)</summary>"
                  f"<div class='tw'><table class='slim fit'><colgroup><col style='width:32%'><col style='width:36%'><col style='width:32%'></colgroup><tr><th>Name</th><th>Why it was left out</th><th>Example place</th></tr>{rws}</table></div></details>")
    scope += "<span id='limits'></span><h3>What this scan cannot see</h3><ul>" + "".join(f"<li>{h(c)}</li>" for c in CANNOT_SEE) + "</ul></section>"
    out.append(scope)
    if not pdf:
        out.append(downloads_html(files))
    out.append("<p class='foot'>The standard AI-BOM file (aibom.cdx.json) holds the same facts for other tools, and models.csv opens in a spreadsheet. This page needs no internet connection.</p></main>")
    joined = "".join(out)
    flags_n = sum(flag_counts((meta or {}).get("flags", [])).values())
    wanted = [("summary", "Summary", "", ""), ("flags", "Findings", "", flags_n), ("packages", "AI packages", "", len(pk) if pk else ""),
              ("vulns", "Vulnerabilities", "sub", ""), ("fixplan", "Fix plan", "sub", ""), ("models", "Models", "", len(used) if used else ""),
              ("listed", "Listed only", "sub", ""), ("mcp", "MCP servers", "", len(mcp_rows(meta)[0]) or ""), ("modelfiles", "Model files", "", len(model_file_rows(meta)[0]) or ""),
              ("leftout", "Left out", "sub", ""), ("limits", "Limits", "sub", ""), ("downloads", "Downloads", "", "")]
    links_html = "".join(f"<a href='#{k}'" + (" class='sub'" if cls else "") + f">{label}" + (f"<span class='n'>{n}</span>" if n != "" else "") + "</a>"
                         for k, label, cls, n in wanted if f"id='{k}'" in joined and (k != "models" or used or listed))
    out.insert(nav_at, (f"<nav class='nav' id='nav' aria-label='Sections'><div class='nh'><span class='nt'>Contents</span>"
                        "<button type='button' class='navx' id='navhide' aria-controls='nav' title='Hide the menu'>Hide</button></div>"
                        f"{links_html}</nav><button type='button' class='navshow' id='navshow' aria-controls='nav'>Contents</button>") if not pdf else "")
    if pdf:  # nobody can click in a PDF: every folded part is opened, and nothing needs a script
        return "".join(out).replace("<details", "<details open").replace(" (click to see the line)", "").replace(" (click to open)", "") + "</div></body></html>"
    import json
    data = json.dumps({"app": app, "head": FLAG_CSV_HEAD, "rows": flag_records((meta or {}).get("flags", []), links)}, ensure_ascii=False).replace("<", "\\u003c")
    out.append(f"</div><script type='application/json' id='flagdata'>{data}</script><script>{JS}</script></body></html>")
    return "".join(out)
