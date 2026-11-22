"""Command line entry."""
import argparse
import json
import os
import shutil
import sys
import traceback

from rich.text import Text

from . import flags as flag_rules
from . import screens, ui
from . import MAX_SECONDS, __version__, safety
from .display import build_rows
from .report import (CANNOT_SEE, LEVEL_LONG, MODE_TEXT, PACKAGE_NOTE, REACHABILITY_TEXT, TIER_LONG, advisory_date, package_level_text,
                     package_rows, package_summary)
from .source import Linker, SourceError, cleanup, fetch, linker_for_git_folder, parse


SHORT_MODE = {"chat model": "chat", "embedding model": "embedding", "image model": "image", "speech-to-text model": "speech-in", "text-to-speech model": "speech-out", "text model": "text",
              "reranking model": "rerank", "moderation model": "moderation", "realtime voice model": "realtime", "video model": "video",
              "chat": "chat", "responses": "chat", "embedding": "embedding", "image_generation": "image", "audio_transcription": "speech-in", "audio_speech": "speech-out",
              "completion": "text", "rerank": "rerank", "moderation": "moderation", "realtime": "realtime", "video_generation": "video"}


def command():
    """How the person started aibom, so every hint they see can be copied and run as it is."""
    # Split on both separators: os.path only knows its own platform's, and the result must not depend on it.
    name = (sys.argv[0] or "").replace("\\", "/").rsplit("/", 1)[-1]
    exe = os.path.splitext(name)[0].lower()
    return "aibom" if exe in ("aibom", "aibom-script") else "python -m aibom_engine"


def width():
    return max(80, min(shutil.get_terminal_size((100, 24)).columns, 140))


def fit(text, n):
    text = str(text)
    return text if len(text) <= n else "..." + text[-(n - 3):]


def clip(text, n):
    """Cut prose at the end ("six known vulnerabilities..."), unlike fit(), which keeps the end of a file path."""
    text = str(text)
    return text if len(text) <= n else text[:n - 3] + "..."


KIND_SHORT = {"AI SDK": "SDK", "Agent framework": "framework", "Vector database": "vector db", "Model runtime": "runtime",
              "MCP": "MCP", "Guardrail": "guardrail", "Dataset loader": "dataset", "AI package": "package"}


def load(run_dir, name):
    path = os.path.join(run_dir, name)
    if not os.path.exists(path):
        raise SourceError("There is no finished scan in '%s'. Run: %s scan <folder or link>" % (run_dir, command()))
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def links_for(info):
    """Links to the exact line on the code-hosting site: from the saved scan, or, for the saved test apps, from benchmark/repos.json."""
    lk = Linker.from_manifest(info)
    return lk if lk.ok else Linker.for_saved_app(info.get("app", ""))


def model_table(rows, links, limit, role=False):
    w = width()
    cols = 28 + 1 + 10 + 1 + 11 + 1 + (8 if role else 0)
    room = w - 2 - cols
    head = "  %-28s %-10s %-11s %s%s" % ("MODEL", "MADE BY", "TYPE", "ROLE    " if role else "", "WHERE (file:line)")
    lines = [head]
    for r in rows[:limit]:
        p = r["places"][0] if r["places"] else None
        where = "%s:%s" % (fit(p["file"], max(room - 14, 20)), p["line"]) if p else "-"
        more = len(r["places"]) - 1
        tail = "  (+%d more)" % more if more > 0 else ""
        lines.append("  %-28s %-10s %-11s %s%s%s" % (fit(r["name"], 28)[-28:] if len(r["name"]) <= 28 else r["name"][:27] + "~", fit(r["maker"] or "-", 10),
                                                      SHORT_MODE.get(r["mode"], r["mode"] or "model")[:11], ("%-8s" % r["role"]) if role else "", where, tail))
    if len(rows) > limit:
        lines.append("  ... and %d more (use --all, or open the report)" % (len(rows) - limit))
    return "\n".join(lines)


def show(run_dir, limit, everything=False, left_out=False):
    """Print a finished scan as a plain list: what was found and where the proof is."""
    items = load(run_dir, "merged.json")
    info = load(run_dir, "manifest.json")
    app = info.get("app") or os.path.basename(info["scanned_folder"])
    rows = build_rows(items)
    used, listed, gone = rows["used"], rows["listed"], rows["left_out"]
    if left_out:
        print("%s: %d names were left out because they are not really used\n" % (app, len(gone)))
        print("  %-30s %-44s %s" % ("NAME", "WHY", "EXAMPLE PLACE"))
        for g in gone[:limit if not everything else len(gone)]:
            print("  %-30s %-44s %s:%s" % (fit(g["name"], 30), fit(g["why"], 44), fit(g["file"], 30), g["line"]))
        return
    if not used and not listed:
        print("No AI model names found in %s. The app may choose its model when it runs, or use none." % app)
        return
    print("%s: %d models used directly in the code, %d only listed in long tables or lists, %d names left out\n" % (app, len(used), len(listed), len(gone)))
    show_rows = used + listed if everything else (used if used else listed)
    print(model_table(show_rows, links_for(info), len(show_rows) if everything else limit, role=everything))
    if not everything and listed and used:
        print("\n  Also %d models only listed in long tables. See them with: %s show %s --all" % (len(listed), command(), run_dir))


def load_packages(run_dir):
    """The AI packages of a finished scan (packages.json), or a clear message when the scan has none to show."""
    path = os.path.join(run_dir, "packages.json")
    if not os.path.exists(path):
        load(run_dir, "manifest.json")  # not a scan at all: say so
        raise SourceError("This scan has no package data: it was made by an older aibom. Scan it again: %s scan <folder or link>" % command())
    return load(run_dir, "packages.json").get("packages", [])


WHY_LEVEL = {"called": "live code calls it", "imported": "live code imports it, but no call to it was found",
             "declared": "it is listed in a dependency file, but no live code imports it"}


def packages_view(run_dir, name=None, everything=False):
    """Print the AI packages of a finished scan with their known vulnerabilities, or one package in detail."""
    packages = load_packages(run_dir)
    info = load(run_dir, "manifest.json")
    app = info.get("app") or os.path.basename(info["scanned_folder"])
    links = links_for(info)
    if name:
        return package_detail(app, packages, name, links)
    rows = package_rows(packages)
    if not rows:
        print("No AI packages found in %s. It may use none, or declare them in a language aibom does not read yet (Python and JavaScript/TypeScript only)." % app)
        return
    sm = package_summary(rows)
    if not ui.pretty():
      print("%s: %d AI packages found%s. %d have known vulnerabilities (%d advisories), %d could not be checked.\n"
          % (app, sm["direct"], ", and %d more only in a lockfile" % sm["transitive"] if sm["transitive"] else "", sm["vulnerable"], sm["advisories"], sm["not_checked"]))
    shown = rows if everything else [r for r in rows if r["direct"] is not False]
    if ui.pretty():
        return screens.packages_pretty(app, rows, sm, shown, len(rows) - len(shown), command(), run_dir, advisory_date())
    room = max(width() - 2 - 24 - 10 - 9 - 9 - 4, 20)
    print("  %-24s %-10s %-9s %-9s %s" % ("PACKAGE", "VERSION", "KIND", "EVIDENCE", "KNOWN VULNERABILITIES"))
    for r in shown:
        evidence = package_level_text(r).replace(" (not in a dependency file)", " *")
        print("  %-24s %-10s %-9s %-9s %s" % (r["name"] if len(r["name"]) <= 24 else r["name"][:23] + "~", fit(r["version"] or "-", 10),
                                              KIND_SHORT.get(r["kind"], r["kind"])[:9], evidence, clip(r["vuln_text"], room)))
    hidden = len(rows) - len(shown)
    if hidden:
        print("\n  ... and %d more only in a lockfile (use --all)" % hidden)
    if any(not r["declared"] for r in shown):
        print("  * imported by the code but not listed in a dependency file")
    print("\nLook closer at one:  %s packages %s PACKAGE" % (command(), run_dir))
    date = advisory_date()
    print("A known vulnerability means this exact version is in an advisory, not that the app reaches the vulnerable code.%s" % (" Advisory data from %s." % date if date else ""))


def vulns_view(run_dir, severity=None, called=False, everything=False):
    """Print the known vulnerabilities of a finished scan, worst first, with a verified fix plan."""
    from .screens import vulns_screen
    packages = load_packages(run_dir)
    info = load(run_dir, "manifest.json")
    app = info.get("app") or os.path.basename(info["scanned_folder"])
    vulns_screen(app, packages, severity, called, everything, advisory_date(), "%s vulns %s" % (command(), run_dir))


def data_line():
    """`models 2026-11-09 · vulnerabilities 2026-11-11`: how fresh the data behind a scan is."""
    try:
        from .db import load_db
        meta = load_db().get("meta") or {}
        return "models %s · vulnerabilities %s" % (meta.get("built", "?"), (meta.get("vulnerabilities") or {}).get("fetched", "?"))
    except Exception:
        return ""


def version_text():
    """`aibom 0.1.0` and the dates of the data it ships with."""
    from . import __version__
    meta = {}
    try:
        from .db import load_db
        meta = load_db().get("meta") or {}
    except Exception:
        pass
    return "aibom %s\n  model data:          %s\n  vulnerability data:  %s" % (
        __version__, meta.get("built", "unknown"), (meta.get("vulnerabilities") or {}).get("fetched", "unknown"))


def package_detail(app, packages, name, links):
    wanted = name.strip().lower()
    hits = [c for c in packages if not c.get("left_out") and c["name"].lower() == wanted]
    if not hits:
        hits = [c for c in packages if not c.get("left_out") and wanted in c["name"].lower()]
    if not hits:
        raise SourceError("I found no AI package called '%s' in %s. List them with: %s packages <scan folder> --all" % (name, app, command()))
    for c in hits:
        row = package_rows([c])[0]
        print("%s %s  (%s%s)" % (c["name"], c.get("version") or "(no exact version)", row["kind"], ", from %s" % c["vendor"] if c.get("vendor") else ""))
        print("  Evidence:        %s: %s" % (package_level_text(row), WHY_LEVEL[c["evidence_level"]]))
        print("  Reachable:       %s" % REACHABILITY_TEXT)
        print("  Needed by:       %s" % {True: "the project itself (declared)", False: "another package (only in a lockfile)", None: "the code (imported, not in a dependency file)"}[c.get("direct")])
        if c.get("purl"):
            print("  Package URL:     %s" % c["purl"])
        for label, key in (("Called", "calls"), ("Imported", "imports"), ("Declared", "evidence")):
            live = [x for x in c.get(key, []) if not x.get("left_out") and x.get("line", 0) > 0]
            if not live:
                continue
            print("  %s in %d place%s:" % (label, len(live), "" if len(live) == 1 else "s"))
            for x in live[:5]:
                print("    %s:%s" % (fit(x["file"], 60), x["line"]))
                snippet = x.get("snippet")
                if snippet:
                    print("        %s" % fit(snippet.strip(), 90))
                url = links.url_for(x["file"], x["line"]) if links else ""
                if url:
                    print("        %s" % url)
            if len(live) > 5:
                print("    ... and %d more" % (len(live) - 5))
        v = c.get("vulnerabilities") or {}
        if v.get("status") != "checked":
            print("  Vulnerabilities: not checked: %s" % (v.get("reason") or "no exact installed version is known"))
        elif not v.get("advisories"):
            print("  Vulnerabilities: none known for this exact version")
        else:
            print("  Vulnerabilities: %d known for this exact version" % len(v["advisories"]))
            for a in v["advisories"]:
                fixed = "fixed in %s" % a["fixed_in"] if a.get("fixed_in") else "no fixed version stated"
                print("    %-8s %-22s %s" % (a["severity"], a["id"], clip(a.get("summary", ""), max(width() - 40, 30))))
                print("             %s  %s" % (fixed, a.get("url", "")))
        print()
    print(PACKAGE_NOTE)


def explain(run_dir, name):
    """Answer 'why is this model here, and how sure are we?' in plain words."""
    items = load(run_dir, "merged.json")
    info = load(run_dir, "manifest.json")
    links = links_for(info)
    rows = build_rows(items)
    q = name.lower()
    allrows = rows["used"] + rows["listed"]
    exact = next((r for r in allrows if q == r["name"].lower() or q in [a.lower() for a in r["also"]]), None)
    gone = next((g for g in rows["left_out"] if q == g["name"].lower()), None)
    hit = exact or (None if gone else next((r for r in allrows if q in r["name"].lower()), None))
    if hit is None:
        gone = gone or next((g for g in rows["left_out"] if q in g["name"].lower()), None)
        if gone:
            print("%s was NOT counted as a model of this app: %s." % (gone["name"], gone["why"]))
            print("  Example place: %s:%s" % (gone["file"], gone["line"]))
            return
        raise SourceError("I found nothing called '%s'. List the models with: %s show %s --all" % (name, command(), run_dir))
    print("%s  (%s, %s)" % (hit["name"], hit["maker"] or "maker unknown", MODE_TEXT.get(hit["mode"], hit["mode"]) or "AI model"))
    print("  How it is used:  %s" % ("set or used directly in the code" if hit["role"] == "used" else "only listed inside a long table or list, not set or called on its own"))
    print("  How sure:        %s" % TIER_LONG[hit["tier"]])
    print("  Evidence:        %s" % LEVEL_LONG[hit["evidence_level"]])
    print("  Reachable:       %s" % REACHABILITY_TEXT)
    if hit["also"]:
        print("  Also written as: %s" % ", ".join(hit["also"][:6]))
    print("  Written in %d place%s in code and settings:" % (len(hit["places"]), "" if len(hit["places"]) == 1 else "s"))
    for p in hit["places"][:8]:
        print("    %s:%s%s" % (fit(p["file"], 60), p["line"], "   (passed into an AI call)" if p.get("called") else ""))
        print("        %s" % fit(p["snippet"], 90)[:90] if len(p["snippet"]) <= 90 else "        %s" % p["snippet"][:87] + "...")
        url = links.url_for(p["file"], p["line"])
        if url:
            print("        %s" % url)
    if len(hit["places"]) > 8:
        print("    ... and %d more" % (len(hit["places"]) - 8))
    if hit["other_places"]:
        print("  Also seen in %d other place%s that do not count (comments, tests, documentation)." % (hit["other_places"], "" if hit["other_places"] == 1 else "s"))


def show_item(run_dir, name):
    """Print one item exactly as it is stored in the AI-BOM file (showing at most 3 proof lines)."""
    bom = load(run_dir, "aibom.cdx.json")
    for c in bom.get("components", []) + bom.get("services", []):
        if c["name"].lower() == name.lower():
            occ = (c.get("evidence") or {}).get("occurrences")
            if occ and len(occ) > 3:
                c = dict(c, evidence={"occurrences": occ[:3]})
                print(json.dumps(c, indent=1, sort_keys=True))
                print("(showing 3 of %d proof lines)" % len(occ))
            else:
                print(json.dumps(c, indent=1, sort_keys=True))
            return
    raise SourceError("There is no model called '%s' in that AI-BOM." % name)


def open_report(run_dir):
    """Open the readable report of a finished run in the web browser."""
    import webbrowser
    path = os.path.abspath(os.path.join(run_dir, "report.html"))
    if not os.path.exists(path):
        raise SourceError("There is no report in '%s' yet. Try: %s rebuild %s" % (run_dir, command(), run_dir))
    print("report:", path)
    webbrowser.open("file:///" + path.replace(os.sep, "/").lstrip("/"))


def load_mcp(run_dir):
    """The MCP servers a scan saved (none for a folder made before MCP servers were read)."""
    path = os.path.join(run_dir, "mcp.json")
    return load(run_dir, "mcp.json") if os.path.exists(path) else {"servers": [], "files": [], "problems": []}


def load_modelfiles(run_dir):
    """The model files and trust_remote_code findings a scan saved (none for a folder made before they were read)."""
    path = os.path.join(run_dir, "modelfiles.json")
    return load(run_dir, "modelfiles.json") if os.path.exists(path) else {"files": [], "problems": [], "remote_code": {"findings": []}}


def load_flags(run_dir):
    """The flags a scan saved (none for a folder made before flags existed)."""
    path = os.path.join(run_dir, "flags.json")
    if not os.path.exists(path):
        return []
    return [flag_rules.Flag.from_dict(d) for d in load(run_dir, "flags.json").get("flags", [])]


def make_pdf(run_dir, output=None):
    """Write the report of a finished scan as a PDF (with the browser that is installed) and return its path."""
    from .pdf import print_to_pdf
    from .report import build_html
    items = load(run_dir, "merged.json")
    info = load(run_dir, "manifest.json")
    app = info.get("app") or os.path.basename(info["scanned_folder"])
    packages = load(run_dir, "packages.json").get("packages", []) if os.path.exists(os.path.join(run_dir, "packages.json")) else []
    meta = {"warnings": info.get("warnings", []), "packages": packages, "flags": load_flags(run_dir), "mcp": load_mcp(run_dir), "model_files": load_modelfiles(run_dir),
            "secrets": info.get("secrets") or {}}
    page = build_html(items, app, info.get("source", ""), links_for(info), meta, pdf=True)
    path = print_to_pdf(page, output or os.path.join(run_dir, "report.pdf"))
    if os.path.abspath(path) == os.path.abspath(os.path.join(run_dir, "report.pdf")):
        rebuild(run_dir)          # the web report now links to the PDF next to it
    return path


def rebuild(run_dir):
    """Rebuild the report, markdown and spreadsheet of a finished scan from its saved data (no re-scan)."""
    from .pipeline import write_readable
    items = load(run_dir, "merged.json")
    info = load(run_dir, "manifest.json")
    links = links_for(info)
    app = info.get("app") or os.path.basename(info["scanned_folder"])
    packages = load(run_dir, "packages.json").get("packages", []) if os.path.exists(os.path.join(run_dir, "packages.json")) else []
    flags = load_flags(run_dir)
    write_readable(run_dir, items, app, info.get("source", ""), links, info.get("warnings", []), packages, flags, load_mcp(run_dir), load_modelfiles(run_dir),
                   info.get("secrets") or {})
    from . import sarif
    sarif.write(os.path.join(run_dir, "aibom.sarif"), flags)
    info.update(links.to_dict() if links.ok else {})
    with safety.open_output(os.path.join(run_dir, "manifest.json")) as f:
        json.dump(info, f, indent=1, sort_keys=True)
    return app, links.ok


def write_sarif(run_dir, prefix="", output=None):
    """Write aibom.sarif for a finished scan, with file paths under `prefix` (the scanned folder inside the repository)."""
    from . import sarif
    if not os.path.exists(os.path.join(run_dir, "manifest.json")):
        raise SourceError("%s is not a finished scan (no manifest.json). Run aibom scan first." % run_dir)
    flags = load_flags(run_dir)
    path = output or os.path.join(run_dir, "aibom.sarif")
    skipped = sarif.write(path, flags, prefix)
    print("sarif: %s (%d results%s)" % (path, len(flags) - skipped, ", %d without a file left out" % skipped if skipped else ""))


def check_tools():
    try:
        import cyclonedx  # noqa: F401
        import jsonschema  # noqa: F401
    except ImportError:
        raise SourceError("Two Python packages are missing. Install aibom with:  python -m pip install .  (from the aibom folder)")


GATE_FAILED = 3   # a scan that ran but found flags at or above --fail-on (a scan that could not run exits 2)
GATE_INCOMPLETE = 4   # with --fail-on: no such flag, but part of the scan did not finish, so it is not a pass


def more_elsewhere(n):
    """What a summary line adds for the findings in tests, examples or documentation, which its count leaves out."""
    return f"; {n} more in tests, examples or documentation" if n else ""


def gate(a, r):
    """--fail-on SEVERITY: exit with GATE_FAILED when the scan has a flag that bad or worse, with GATE_INCOMPLETE when it did not finish."""
    level = getattr(a, "fail_on", None)
    if not level:
        return
    hits = flag_rules.at_least(r.get("flags") or [], level)
    if hits:
        worst = flag_rules.counts(hits)
        print("\nFailed: %d risk flag%s at %s or worse (%s). The fix for each is in the report and in flags.json."
              % (len(hits), "" if len(hits) == 1 else "s", level, ", ".join("%d %s" % (n, s) for s, n in worst.items() if n)), file=sys.stderr)
        sys.exit(GATE_FAILED)
    why = r.get("incomplete")
    if why:
        print("\nFailed: the scan did not finish (%s), so it cannot pass --fail-on. %s"
              % ("; ".join(why), "Scan again with a higher --max-seconds." if r.get("partial") else "See the notes above."), file=sys.stderr)
        sys.exit(GATE_INCOMPLETE)


def do_scan(a):
    from .pipeline import run
    check_tools()
    src = parse(a.source)
    tmp = None
    links = Linker()
    fancy = ui.pretty()  # colour, a live view and a dashboard, only for a person at a terminal
    stages = screens.StageProgress(6 if src["kind"] == "git" else 5) if fancy and not a.quiet else None
    log = stages or ((lambda m: None) if a.quiet else (lambda m: print(m, flush=True)))
    if fancy:
        ui.console().print(ui.banner(__version__, data_line()))
        ui.console().print()
    try:
        if stages:
            stages.__enter__()
        if src["kind"] == "git":
            log("Downloading %s%s ..." % (src["url"], " (" + src["branch"] + ")" if src["branch"] else ""))
            root, tmp = fetch(src)
            links = Linker(src["url"], src.get("commit", ""), src.get("subpath", ""))
            log("  done")
        else:
            root = src["path"]
            links = linker_for_git_folder(root)
        out = a.out or os.path.join("runs", src["name"])
        try:
            r = run(root, out, tuple(x for x in a.finders.split(",") if x), app=src["name"], source=src["source"], log=log, max_seconds=a.max_seconds, links=links)
        except SourceError:  # already says what to do (and may be about the output folder itself: write nothing there)
            raise
        except Exception as e:
            if a.debug:
                raise
            os.makedirs(safety.output_path(out, scanned=root), exist_ok=True)
            with safety.open_output(os.path.join(out, "error.txt")) as f:
                f.write(traceback.format_exc())
            raise SourceError("Something went wrong while scanning (%s: %s). The details are in %s. If you are in the middle of a demo, scan a local folder or use the saved results."
                              % (type(e).__name__, str(e)[:120], os.path.join(out, "error.txt")))
    finally:
        if stages:
            stages.__exit__(*sys.exc_info())
        if tmp and not a.keep:
            cleanup(tmp)
    if fancy:
        try:
            packages = load_packages(out)
        except SourceError:
            packages = []
        # Found on a real scan: a scan cut short by the time limit was shown as "finished: no AI model names found", and a scan with no
        # model names hid its MCP servers, keys and model files. A stopped scan now says so, and the panel shows whatever was found.
        found_any = (r["items"] or packages or r.get("flags") or (r.get("mcp") or {}).get("servers") or (r.get("model_files") or {}).get("files")
                     or (r.get("model_files") or {}).get("other") or (r.get("secrets") or {}).get("keys") or (r.get("secrets") or {}).get("other") or r.get("remote_code"))
        if r["items"] == 0 and r.get("partial"):
            ui.console().print(Text("Stopped at the time limit after %ss, before finding any model names in %s. This is not a final answer: "
                                    "scan again with a higher --max-seconds." % (r["seconds"], r["app"]), style="bold yellow"))
        if found_any:
            screens.dashboard(r, out, packages, links, command(), advisory_date(), __version__)
        elif not r.get("partial"):
            print("Scan finished in %ss: no AI model names found in %s." % (r["seconds"], r["app"]))
        for note in r["warnings"]:
            ui.console().print(Text("Note: " + note, style="yellow"))
        if not r["valid"]:
            raise SourceError("The AI-BOM did not pass the format check: " + str(r["error"]))
        if a.open:
            open_report(out)
        gate(a, r)
        return
    w = width()
    print()
    if r["items"] == 0 and r["partial"]:
        print("Stopped at the time limit after %ss, before finding any model names in %s. This is not a final answer." % (r["seconds"], r["app"]))
    elif r["items"] == 0:
        print("Scan finished in %ss: no AI model names found in %s." % (r["seconds"], r["app"]))
        print("  The app may choose its model when it runs (an environment variable, a settings page, a database), or use none.")
    else:
        print("Scan finished in %ss: %s" % (r["seconds"], r["app"]))
        if links.ok:
            print("Source: %s (version %s)" % (links.url, links.commit[:10]))
        print()
        print("  %-4d models used directly in the code" % r["used"])
        if r["listed"]:
            print("  %-4d more only listed in long tables or lists" % r["listed"])
        if r["left_out"]:
            print("  %-4d names left out (only in comments, messages, tests or docs)" % r["left_out"])
        main = r["rows"]["used"] or r["rows"]["listed"]
        print("\n" + ("The main ones:" if r["rows"]["used"] else "The models found:"))
        print(model_table(main, links, 8))
    ps = r.get("packages") or {}
    if ps.get("ai_packages"):
        print("\n  %-4d AI packages (SDKs, agent frameworks, vector databases, MCP), %d with known vulnerabilities (%d advisories)"
              % (ps["ai_packages"], ps.get("vulnerable_packages", 0), ps.get("advisories", 0)))
        if ps.get("not_checked"):
            print("       %d not checked for vulnerabilities: no exact installed version (a range, or no lockfile)" % ps["not_checked"])
    mf = r.get("model_files") or {}
    if mf.get("files") or mf.get("other"):
        print("\n  %-4d model files (%d use pickle, %d with a dangerous or hidden import, a Lambda layer or a misleading name)%s" % (mf["files"], mf["pickle"], mf["dangerous"], more_elsewhere(mf.get("other", 0))))
    if r.get("remote_code"):
        n = r["remote_code"]
        print("  %-4d %s trust_remote_code on" % (n, "place turns" if n == 1 else "places turn"))
    ks = r.get("secrets") or {}
    if ks.get("keys") or ks.get("other"):
        print("\n  %-4d hardcoded API keys in %d file%s%s (values are never stored; the report lists each file and line)"
              % (ks["keys"], ks["files"], "" if ks["files"] == 1 else "s", more_elsewhere(ks.get("other", 0))))
    mc = r.get("mcp") or {}
    if mc.get("servers"):
        print("\n  %-4d MCP servers declared in the config files (%d local, %d remote)" % (mc["servers"], mc["stdio"], mc["remote"]))
    if r.get("flags"):
        count, text = flag_rules.headline(r["flags"])
        print("\n  %-4d risk flags: %s (the report shows each one; flags.json lists them)" % (count, text))
    for note in r["warnings"]:
        print("  Note: " + note)
    print("\nFiles in %s:" % out)
    print("  report.html     the readable report: open it in a browser (%s report %s)" % (command(), out))
    print("  models.csv      the same list for a spreadsheet")
    print("  aibom.cdx.json  the standard AI-BOM file (%s CycloneDX 1.6)" % ("valid" if r["valid"] else "NOT VALID"))
    print("\nNext:  %s show %s --all      list every model" % (command(), out))
    print("       %s explain %s MODEL   why is this model here?" % (command(), out))
    print("Limits: it cannot see a model chosen when the app runs, and reads Python and JavaScript/TypeScript packages only.")
    if not r["valid"]:
        raise SourceError("The AI-BOM did not pass the format check: " + str(r["error"]))
    if a.open:
        open_report(out)
    gate(a, r)


def main():
    os.environ["NoDefaultCurrentDirectoryInExePath"] = "1"  # Windows: start no program from the current folder, here or in a library
    for s in (sys.stdout, sys.stderr):
        try:
            s.reconfigure(errors="replace")
        except Exception:
            pass
    p = argparse.ArgumentParser(prog=command(), description="Find the AI models and AI packages inside an app and prove each one with a line of code.",
                                epilog="Run %s with no arguments, in a terminal, for a guided menu that shows the command behind every step." % command())
    p.add_argument("--version", action="store_true", help="print the version and the dates of the model and vulnerability data")
    p.add_argument("--plain", action="store_true", help="no colour or boxes, even in a terminal (also: NO_COLOR=1)")
    sub = p.add_subparsers(dest="cmd")
    s = sub.add_parser("scan", help="scan a folder or a GitHub link and write an AI-BOM")
    s.add_argument("source", help="a folder, or a link such as https://github.com/owner/repo (also owner/repo)")
    s.add_argument("--out", help="where to save the results (default: runs/<app name>)")
    s.add_argument("--finders", default="dictionary,context,shapes", help="comma list, default: dictionary,context,shapes")
    s.add_argument("--max-seconds", type=int, default=MAX_SECONDS, help="stop reading files after this many seconds (default %d)" % MAX_SECONDS)
    s.add_argument("--keep", action="store_true", help="keep the downloaded copy of a repository")
    s.add_argument("--open", action="store_true", help="open the report in the browser when done")
    s.add_argument("--quiet", action="store_true", help="no progress lines")
    s.add_argument("--fail-on", choices=list(flag_rules.SEVERITIES), help="exit with code 3 when the scan has a risk flag at this severity or worse (4 when there is none but the scan did not finish; a scan that cannot run exits with 2)")
    s.add_argument("--debug", action="store_true", help="show the full error trace")
    o = sub.add_parser("report", help="open the readable report of a finished scan in the browser, or write it as a PDF (--pdf)")
    o.add_argument("run_dir")
    o.add_argument("--pdf", action="store_true", help="write report.pdf instead of opening the page (needs Chrome, Edge or Chromium)")
    o.add_argument("--output", help="where to write the PDF (default: report.pdf in the scan folder)")
    w = sub.add_parser("show", help="print a finished scan as a plain list")
    w.add_argument("run_dir")
    w.add_argument("--limit", type=int, default=20)
    w.add_argument("--all", action="store_true", help="list every model, including those only listed in long tables")
    w.add_argument("--left-out", action="store_true", help="list the names that were left out, and why")
    w.add_argument("--item", help="print one item as stored in the AI-BOM file")
    x = sub.add_parser("explain", help="why is this model in the result, and how sure are we?")
    x.add_argument("run_dir")
    x.add_argument("model")
    k = sub.add_parser("packages", help="list the AI packages of a finished scan and their known vulnerabilities, or look closer at one")
    k.add_argument("run_dir")
    k.add_argument("package", nargs="?", help="a package name, to see where it is used and its advisories")
    k.add_argument("--all", action="store_true", help="include the packages that are only in a lockfile")
    v = sub.add_parser("vulns", help="list the known vulnerabilities of a finished scan, worst first, with a fix plan")
    v.add_argument("run_dir")
    v.add_argument("--severity", choices=["critical", "high", "medium", "low"], help="show this severity and worse")
    v.add_argument("--called", action="store_true", help="only packages your code calls")
    v.add_argument("--all", action="store_true", help="include the packages that are only in a lockfile")
    f = sub.add_parser("sarif", help="write the risk flags of a finished scan as SARIF, for GitHub code scanning")
    f.add_argument("run_dir")
    f.add_argument("--prefix", default="", help="the folder that was scanned, relative to the repository root, so each file in the SARIF points at the right place (default: the root)")
    f.add_argument("--output", help="where to write it (default: aibom.sarif in the scan folder)")
    b = sub.add_parser("rebuild", help="rebuild the report and spreadsheet of a finished scan, or of every scan in a folder (--all)")
    b.add_argument("run_dir")
    b.add_argument("--all", action="store_true", help="treat run_dir as a folder that holds many scans")
    a = p.parse_args()
    if a.plain:
        from . import ui
        ui.set_plain()
    try:
        if a.version:
            print(version_text())
            return
        if a.cmd is None:
            from . import interactive
            if not interactive.is_interactive():  # a script, a pipe or CI: never wait for a key
                p.print_help()
                return
            sys.exit(interactive.run())
        if a.cmd == "scan":
            do_scan(a)
        elif a.cmd == "report":
            if a.pdf:
                print("pdf:", make_pdf(a.run_dir, a.output))
            else:
                open_report(a.run_dir)
        elif a.cmd == "show":
            show_item(a.run_dir, a.item) if a.item else show(a.run_dir, a.limit, a.all, a.left_out)
        elif a.cmd == "explain":
            explain(a.run_dir, a.model)
        elif a.cmd == "packages":
            packages_view(a.run_dir, a.package, a.all)
        elif a.cmd == "vulns":
            vulns_view(a.run_dir, a.severity, a.called, a.all)
        elif a.cmd == "sarif":
            write_sarif(a.run_dir, a.prefix, a.output)
        elif a.cmd == "rebuild":
            dirs = sorted(os.path.join(a.run_dir, d) for d in os.listdir(a.run_dir) if os.path.exists(os.path.join(a.run_dir, d, "merged.json"))) if a.all else [a.run_dir]
            for d in dirs:
                app, linked = rebuild(d)
                print("rebuilt %-34s %s" % (app, "with links to the code" if linked else "(no web links: local folder)"))
    except SourceError as e:
        print("\nProblem: " + str(e), file=sys.stderr)
        sys.exit(2)
    except KeyboardInterrupt:
        print("\nStopped.", file=sys.stderr)
        sys.exit(130)
    except BrokenPipeError:  # the reader (for example `| head`) closed early: nothing to report
        try:
            sys.stdout = open(os.devnull, "w")
        except OSError:
            pass
        sys.exit(0)
