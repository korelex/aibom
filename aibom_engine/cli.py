"""Command line entry."""
import argparse
import json
import os
import shutil
import sys
import traceback

from .display import build_rows
from .report import CANNOT_SEE, LEVEL_LONG, MODE_TEXT, REACHABILITY_TEXT, TIER_LONG
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


def rebuild(run_dir):
    """Rebuild the report, markdown and spreadsheet of a finished scan from its saved data (no re-scan)."""
    from .pipeline import write_readable
    items = load(run_dir, "merged.json")
    info = load(run_dir, "manifest.json")
    links = links_for(info)
    app = info.get("app") or os.path.basename(info["scanned_folder"])
    write_readable(run_dir, items, app, info.get("source", ""), links, info.get("warnings", []))
    info.update(links.to_dict() if links.ok else {})
    with open(os.path.join(run_dir, "manifest.json"), "w", encoding="utf-8") as f:
        json.dump(info, f, indent=1, sort_keys=True)
    return app, links.ok


def check_tools():
    try:
        import cyclonedx  # noqa: F401
        import jsonschema  # noqa: F401
    except ImportError:
        raise SourceError("Two Python packages are missing. Install aibom with:  python -m pip install .  (from the aibom folder)")


def do_scan(a):
    from .pipeline import run
    check_tools()
    src = parse(a.source)
    tmp = None
    links = Linker()
    log = (lambda m: None) if a.quiet else (lambda m: print(m, flush=True))
    try:
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
        except Exception as e:
            if a.debug:
                raise
            os.makedirs(out, exist_ok=True)
            with open(os.path.join(out, "error.txt"), "w", encoding="utf-8") as f:
                f.write(traceback.format_exc())
            raise SourceError("Something went wrong while scanning (%s: %s). The details are in %s. If you are in the middle of a demo, scan a local folder or use the saved results."
                              % (type(e).__name__, str(e)[:120], os.path.join(out, "error.txt")))
    finally:
        if tmp and not a.keep:
            cleanup(tmp)
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
    for note in r["warnings"]:
        print("  Note: " + note)
    print("\nFiles in %s:" % out)
    print("  report.html     the readable report: open it in a browser (%s report %s)" % (command(), out))
    print("  models.csv      the same list for a spreadsheet")
    print("  aibom.cdx.json  the standard AI-BOM file (%s CycloneDX 1.6)" % ("valid" if r["valid"] else "NOT VALID"))
    print("\nNext:  %s show %s --all      list every model" % (command(), out))
    print("       %s explain %s MODEL   why is this model here?" % (command(), out))
    print("Limits: the reports list AI models only; the AI packages found are in packages.json.")
    print("        It cannot see a model chosen when the app runs.")
    if not r["valid"]:
        raise SourceError("The AI-BOM did not pass the format check: " + str(r["error"]))
    if a.open:
        open_report(out)


def main():
    for s in (sys.stdout, sys.stderr):
        try:
            s.reconfigure(errors="replace")
        except Exception:
            pass
    p = argparse.ArgumentParser(prog=command(), description="Find the AI models inside an app and prove each one with a line of code.")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="scan a folder or a GitHub link and write an AI-BOM")
    s.add_argument("source", help="a folder, or a link such as https://github.com/owner/repo (also owner/repo)")
    s.add_argument("--out", help="where to save the results (default: runs/<app name>)")
    s.add_argument("--finders", default="dictionary,context,shapes", help="comma list, default: dictionary,context,shapes")
    s.add_argument("--max-seconds", type=int, default=120, help="stop reading files after this many seconds (default 120)")
    s.add_argument("--keep", action="store_true", help="keep the downloaded copy of a repository")
    s.add_argument("--open", action="store_true", help="open the report in the browser when done")
    s.add_argument("--quiet", action="store_true", help="no progress lines")
    s.add_argument("--debug", action="store_true", help="show the full error trace")
    o = sub.add_parser("report", help="open the readable report of a finished scan in the browser")
    o.add_argument("run_dir")
    w = sub.add_parser("show", help="print a finished scan as a plain list")
    w.add_argument("run_dir")
    w.add_argument("--limit", type=int, default=20)
    w.add_argument("--all", action="store_true", help="list every model, including those only listed in long tables")
    w.add_argument("--left-out", action="store_true", help="list the names that were left out, and why")
    w.add_argument("--item", help="print one item as stored in the AI-BOM file")
    x = sub.add_parser("explain", help="why is this model in the result, and how sure are we?")
    x.add_argument("run_dir")
    x.add_argument("model")
    b = sub.add_parser("rebuild", help="rebuild the report and spreadsheet of a finished scan, or of every scan in a folder (--all)")
    b.add_argument("run_dir")
    b.add_argument("--all", action="store_true", help="treat run_dir as a folder that holds many scans")
    a = p.parse_args()
    try:
        if a.cmd == "scan":
            do_scan(a)
        elif a.cmd == "report":
            open_report(a.run_dir)
        elif a.cmd == "show":
            show_item(a.run_dir, a.item) if a.item else show(a.run_dir, a.limit, a.all, a.left_out)
        elif a.cmd == "explain":
            explain(a.run_dir, a.model)
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
