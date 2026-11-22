"""What `aibom vulns` and the scan dashboard print: one plain version (pipes, CI, logs, ASCII only) and one drawn with rich
(a real terminal). Both read the same lists from findings.py and report.py, so they say the same thing."""
from rich import box
from rich.console import Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from . import findings as fd
from . import flags as flag_rules
from . import ui

SEVERITY_NOTE = ("Affected is not the same as exploitable: a vulnerability counts when this exact version is in an advisory, and "
                 "aibom does not prove that your app reaches the vulnerable code (reachability is not verified).")
TAG = {"called": "called", "imported": "imported", "declared": "declared"}


def fixed_text(f):
    return "fixed in %s" % f["fixed_in"] if f["fixed_in"] else "no fix stated"


def clip(text, n):
    text = " ".join(str(text).split())
    return text if len(text) <= n else text[: max(n - 3, 0)] + "..."


def tail(text, n):
    """The end of a path with its line number: a long one is cut at the front, because the file and line are what matter."""
    return text if len(text) <= n else "…" + text[-(n - 1):]


def verdict_for(found, filters):
    """The one-line verdict; with a filter on and nothing left, it says the filter matched nothing, not that all is well."""
    if not found and filters:
        return "No known vulnerabilities match this filter."
    return fd.verdict(found)


def plan_line(p):
    """`name 1.2.3 -> 1.4.0` and what it clears, as plain text."""
    if not p["target"]:
        return "%s %s: no fixed version is named by its advisories" % (p["package"], p["version"])
    done = "clears all %d" % p["total"] if not p["remaining"] else "clears %d of %d (still open: %s)" % (p["clears"], p["total"], ", ".join(p["remaining"]))
    return "%s %s -> %s  %s%s" % (p["package"], p["version"], p["target"], done, "  [test your code: %s]" % p["warning"] if p["warning"] else "")


def vulns_plain(app, found, plan, hidden, filters, date, out=print):
    out("%s: %s" % (app, verdict_for(found, filters)))
    if filters:
        out("  Showing: %s." % filters)
    c = fd.counts(found)
    if found:
        out("  " + "   ".join("%s %d" % (s, c[s]) for s in fd.ORDER if s != "unknown" or c[s]))
    room = min(max([len("%s %s" % (f["package"], f["version"])) for f in found] or [0]), 44)
    for sev in fd.ORDER:
        group = [f for f in found if f["severity"] == sev]
        if not group:
            continue
        out("\n%s (%d)" % (ui.severity_label(sev), len(group)))
        for f in group:
            out("  %-22s %-*s %-9s %s" % (f["id"], room, clip("%s %s" % (f["package"], f["version"]), room), TAG[f["level"]], fixed_text(f)))
            out("      %s" % clip(f["summary"], 100))
            if f["url"]:
                out("      %s" % f["url"])
    if plan:
        out("\nFix plan (each target was checked again against the advisories):")
        for p in plan:
            out("  " + plan_line(p))
    if hidden:
        out("\n  %d more in packages that are only in a lockfile (use --all)." % hidden)
    out("\n" + SEVERITY_NOTE + (" Advisory data from %s." % date if date else ""))


def vulns_pretty(app, found, plan, hidden, filters, date, run_cmd):
    con = ui.console()
    w = min(con.width, 110)
    c = fd.counts(found)
    con.print()
    head = Text.assemble((app, "bold"), "  ", (verdict_for(found, filters), ""))
    con.print(head)
    if found:
        con.print(ui.severity_bar(c, min(w - 4, 60)))
        con.print(ui.severity_counts(c))
    if filters:
        con.print(Text("Showing: %s" % filters, style="dim"))
    for sev in fd.ORDER:
        group = [f for f in found if f["severity"] == sev]
        if not group:
            continue
        con.print()
        con.print(Text.assemble(ui.badge(sev), "  %d" % len(group), style=""))
        t = Table(box=box.SIMPLE_HEAD, show_edge=False, pad_edge=False, expand=False, header_style="dim")
        t.add_column("ADVISORY", no_wrap=True)
        t.add_column("PACKAGE", no_wrap=True)
        t.add_column("EVIDENCE", no_wrap=True)
        t.add_column("FIX", no_wrap=True)
        t.add_column("WHAT IT IS")
        for f in group:
            t.add_row(ui.link(f["id"], f["url"]), "%s %s" % (f["package"], f["version"]),
                      Text("● called", style=ui.EVIDENCE["called"]) if f["level"] == "called" else ui.level_text(f["level"], f["declared"]),
                      Text(f["fixed_in"], style="green") if f["fixed_in"] else Text("none stated", style="dim"), clip(f["summary"], 200))
        con.print(t)
    if plan:
        con.print()
        t = Table(title="Fix plan", title_justify="left", title_style="bold", box=box.SIMPLE_HEAD, show_edge=False, pad_edge=False, header_style="dim")
        t.add_column("PACKAGE", no_wrap=True)
        t.add_column("UPGRADE", no_wrap=True)
        t.add_column("CLEARS", no_wrap=True)
        t.add_column("CHECK")
        for p in plan:
            if not p["target"]:
                t.add_row(p["package"], Text("%s  (no fixed version named)" % p["version"], style="dim"), "-", "")
                continue
            clears = Text("%d of %d" % (p["clears"], p["total"]), style="green" if not p["remaining"] else "yellow")
            t.add_row(p["package"], Text.assemble("%s → " % p["version"], (p["target"], "bold green")), clears,
                      Text("test your code: %s" % p["warning"], style="yellow") if p["warning"] else Text("", style=""))
        con.print(t)
        con.print(Text("Each target was checked again against the advisory data before it was listed.", style="dim"))
    if hidden:
        con.print(Text("\n%d more in packages that are only in a lockfile:  %s --all" % (hidden, run_cmd), style="dim"))
    con.print()
    con.print(Panel(Text(SEVERITY_NOTE + (" Advisory data from %s." % date if date else ""), style="dim"), box=box.ROUNDED, border_style="grey37", padding=(0, 1)))
    con.print()


def vulns_screen(app, packages, severity, called, everything, date, run_cmd, db=None):
    """Print the vulnerabilities of a scan, worst first. Returns the findings shown."""
    shown_packages = fd.counted(packages, everything)
    found = fd.filter_findings(fd.collect(shown_packages), severity, called)
    hidden = 0
    if not everything:
        hidden = len(fd.filter_findings(fd.collect(fd.counted(packages, True)), severity, called)) - len(found)
    keys = {(f["package"], f["version"]) for f in found}
    plan = [p for p in fd.fix_plan(shown_packages, db) if (p["package"], p["version"]) in keys]
    filters = []
    if severity:
        filters.append("severity %s or worse" % severity if severity != "critical" else "critical only")
    if called:
        filters.append("only packages your code calls")
    filters = ", ".join(filters)
    if ui.pretty():
        vulns_pretty(app, found, plan, hidden, filters, date, run_cmd)
    else:
        vulns_plain(app, found, plan, hidden, filters, date)
    return found



class StageProgress:
    """The live view of a scan: one line per real stage, with a spinner while it runs, a tick and the time when it is done, and
    the numbers the stage found. It reads the same progress messages the plain log prints (a line that starts a stage, and
    indented lines with its details), so it can only show what the scan is really doing; there is no made-up percentage."""

    def __init__(self, total, con=None):
        self.con = con or ui.console()
        self.total, self.n = total, 0
        self.title, self.details, self.t0 = "", [], 0.0
        self.status = None

    def __enter__(self):
        self.status = self.con.status("", spinner="dots", spinner_style=ui.ACCENT)
        self.status.start()
        return self

    def __exit__(self, *exc):
        self.close(ok=exc[0] is None)
        self.status.stop()

    def __call__(self, message):
        import time
        if message.startswith(" "):  # a detail of the stage that is running
            self.details.append(message.strip())
            return
        self.close()
        self.n += 1
        self.title = message.split(" (")[0].rstrip(" .")  # "Checking every name (live code, ...)" -> "Checking every name"
        self.details, self.t0 = [], time.time()
        self.status.update(Text.assemble((" stage %d of %d  " % (self.n, self.total), "dim"), self.title))

    def close(self, ok=True):
        import time
        if not self.title:
            return
        took = time.time() - self.t0
        mark = Text("\u2714", style="green") if ok else Text("\u2718", style="red")
        room = max(self.con.width - 4 - 34 - 7 - 3, 20)
        detail = clip("; ".join(d for d in self.details if d != "done"), room)
        self.con.print(Text.assemble(mark, "  ", (self.title.ljust(34), ""), ("%5.1fs" % took, "dim"), ("   " + detail if detail else "", "dim")))
        self.title = ""


def _elsewhere(n):
    """What a summary row adds for the findings in tests, examples or documentation, which its count leaves out."""
    return f"; {n} more in tests, examples or documentation" if n else ""


def dashboard(r, out, packages, links, cmd, date, version):
    """The result of a scan, drawn for a terminal: three numbers, the worst of what was found, and what to type next."""
    con = ui.console()
    ps = r.get("packages") or {}
    found = fd.collect(fd.counted(packages))
    later = len(fd.collect(fd.counted(packages, True))) - len(found)
    c = fd.counts(found)
    called = [f for f in found if f["level"] == "called"]
    con.print()
    t = Table.grid(padding=(0, 3))
    t.add_column(justify="right", style="bold")
    t.add_column()
    t.add_row(str(r["used"]), Text("models used directly in the code" + (", %d more only listed in long tables" % r["listed"] if r["listed"] else "")
                                   + (", %d names left out" % r["left_out"] if r["left_out"] else "")))
    pk = ps.get("ai_packages", 0)
    t.add_row(str(pk), Text("AI packages" + (", %d of them called by your code" % ps.get("ai_called", 0) if pk else "")))
    vuln_line = Text("known vulnerabilities")
    if found:
        vuln_line = Text.assemble("known vulnerabilities in %d package%s" % (len({(f["package"], f["version"]) for f in found}),
                                  "" if len({(f["package"], f["version"]) for f in found}) == 1 else "s"), "   ", ui.severity_counts(c, skip_zero=True))
    t.add_row(Text(str(len(found)), style="bold bright_red" if found else "bold green"), vuln_line)
    mf = r.get("model_files") or {}
    if mf.get("files") or mf.get("other"):
        t.add_row(Text(str(mf["files"]), style="bold bright_red" if mf.get("dangerous") else "bold"),
                  Text("model files (%d use pickle, %d with a dangerous or hidden import, a Lambda layer or a misleading name)%s" % (mf["pickle"], mf["dangerous"], _elsewhere(mf.get("other", 0)))))
    if r.get("remote_code"):
        t.add_row(Text(str(r["remote_code"]), style="bold yellow"), Text(("place turns" if r["remote_code"] == 1 else "places turn") + " trust_remote_code on"))
    ks = r.get("secrets") or {}
    if ks.get("keys") or ks.get("other"):
        t.add_row(Text(str(ks["keys"]), style="bold bright_red" if ks.get("keys") else "bold"),
                  Text("hardcoded API keys in %d file%s%s (values are never stored)" % (ks["files"], "" if ks["files"] == 1 else "s", _elsewhere(ks.get("other", 0)))))
    mc = r.get("mcp") or {}
    if mc.get("servers"):
        t.add_row(str(mc["servers"]), Text("MCP servers declared in config files (%d local, %d remote)" % (mc["stdio"], mc["remote"])))
    flags = r.get("flags") or []
    if flags:
        count, shown = flag_rules.headline(flags)
        worst = flags[0].severity  # flags arrive worst first
        t.add_row(Text(str(count), style="bold bright_red" if worst == "high" else "bold yellow" if worst == "medium" else "bold"),
                  Text("risk flags (%s); the report shows each one" % shown))
    body = [t]
    if found:
        body += [Text(""), ui.severity_bar(c, 50),
                 Text("%d in packages your code calls" % len(called) if called else "none in packages your code calls", style="dim")
                 ]
    if later:
        body.append(Text("%d more only in a lockfile (aibom vulns --all)" % later, style="dim"))
    con.print(Panel(Group(*body), title=Text.assemble((" %s " % r["app"], "bold")), title_align="left", subtitle=Text(" scanned in %ss " % r["seconds"], style="dim"),
                    subtitle_align="right", box=box.ROUNDED, border_style=ui.ACCENT, padding=(1, 2)))
    shown = r["rows"]["used"] or r["rows"]["listed"]
    if shown:
        m = Table(title="Models", title_justify="left", title_style="bold", box=box.SIMPLE_HEAD, show_edge=False, pad_edge=False, header_style="dim")
        top6 = shown[:6]
        for h, cap, key in (("MODEL", 42, "name"), ("MADE BY", 16, "maker"), ("TYPE", 22, "mode")):  # these keep their full text; only the path may be cut
            m.add_column(h, no_wrap=True, min_width=min(cap, max([len(h)] + [len(r[key] or "-") for r in top6])))
        m.add_column("WHERE", no_wrap=True)
        room = max(con.width - 4 - sum(min(cap, max([len(h)] + [len(r[key] or "-") for r in top6])) + 2 for h, cap, key in
                                       (("MODEL", 42, "name"), ("MADE BY", 16, "maker"), ("TYPE", 22, "mode"))), 24)
        for row in top6:
            p = row["places"][0] if row["places"] else None
            m.add_row(row["name"], row["maker"] or "-", row["mode"] or "model", tail("%s:%s" % (p["file"], p["line"]), room) if p else "-")
        con.print(m)
        if len(shown) > 6:
            con.print(Text("... and %d more:  %s show %s --all" % (len(shown) - 6, cmd, out), style="dim"))
    top = found[:5]
    if top:
        v = Table(title="Worst vulnerabilities", title_justify="left", title_style="bold", box=box.SIMPLE_HEAD, show_edge=False, pad_edge=False, header_style="dim")
        v.add_column("", no_wrap=True)
        v.add_column("ADVISORY", no_wrap=True)
        v.add_column("PACKAGE", no_wrap=True)
        v.add_column("EVIDENCE", no_wrap=True)
        v.add_column("FIX", no_wrap=True)
        for f in top:
            v.add_row(ui.badge(f["severity"]), ui.link(f["id"], f["url"]), "%s %s" % (f["package"], f["version"]),
                      Text("\u25cf called", style=ui.EVIDENCE["called"]) if f["level"] == "called" else ui.level_text(f["level"], f["declared"]),
                      Text(f["fixed_in"], style="green") if f["fixed_in"] else Text("none stated", style="dim"))
        con.print(v)
    con.print()
    nxt = Table.grid(padding=(0, 2))
    nxt.add_column(style=ui.ACCENT, no_wrap=True)
    nxt.add_column(style="dim")
    if found:
        nxt.add_row("%s vulns %s" % (cmd, out), "every vulnerability, worst first, with a fix plan")
    nxt.add_row("%s report %s" % (cmd, out), "open the full report in your browser")
    nxt.add_row("%s explain %s MODEL" % (cmd, out), "why is a model in the result?")
    con.print(Text("Next", style="bold"))
    con.print(nxt)
    con.print()
    con.print(Text("Limits: it cannot see a model chosen when the app runs; it reads Python and JavaScript/TypeScript packages; "
                   "affected is not exploitable.", style="dim"))
    if links.ok:
        con.print(Text("Source: %s at version %s" % (links.url, links.commit[:10]), style="dim"))
    con.print()


def packages_pretty(app, rows, sm, shown, hidden, cmd, run_dir, date):
    """The AI packages of a scan as a table, worst first, in the colours of the severities and of the evidence."""
    con = ui.console()
    con.print()
    con.print(Text.assemble((app, "bold"), "  %d AI packages%s. %d have known vulnerabilities (%d advisories), %d could not be checked."
                            % (sm["direct"], ", and %d more only in a lockfile" % sm["transitive"] if sm["transitive"] else "", sm["vulnerable"], sm["advisories"], sm["not_checked"])))
    con.print()
    t = Table(box=box.SIMPLE_HEAD, show_edge=False, pad_edge=False, header_style="dim")
    for h in ("PACKAGE", "VERSION", "KIND", "EVIDENCE", "KNOWN VULNERABILITIES"):
        t.add_column(h, no_wrap=True)
    for r in shown:
        if r["vuln_status"] != "checked":
            vuln = Text("not checked", style="dim")
        elif not r["advisories"]:
            vuln = Text("none known", style="green")
        else:
            vuln = Text.assemble(*[p for sev in fd.ORDER for p in ((ui.dot(sev), " %d %s  " % (sum(1 for a in r["advisories"] if a["severity"] == sev), sev))
                                                                   if any(a["severity"] == sev for a in r["advisories"]) else ())])
        t.add_row(r["name"], r["version"] or "-", r["kind"], ui.level_text(r["level"], r["declared"]), vuln)
    con.print(t)
    if hidden:
        con.print(Text("... and %d more only in a lockfile (use --all)" % hidden, style="dim"))
    if any(not r["declared"] for r in shown):
        con.print(Text("* imported by the code but not listed in a dependency file", style="dim"))
    con.print()
    con.print(Text.assemble("Look closer at one:  ", (cmd + " packages " + run_dir + " PACKAGE", ui.ACCENT)))
    con.print(Text("A known vulnerability means this exact version is in an advisory, not that the app reaches the vulnerable code.%s"
                   % (" Advisory data from %s." % date if date else ""), style="dim"))
    con.print()
