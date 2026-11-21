"""The layout of the web report: the order of its sections, the summary at the top, and the findings table."""
import re
import unittest

from aibom_engine.flags import Flag
from aibom_engine.report import FLAGS_SHOWN, build_html


def flag(rule="x.y", severity="low", category="code", **kw):
    base = dict(category=category, title="A title.", subject="thing", fix="Do the thing.", file="src/a.py", line=3)
    base.update(kw)
    return Flag(rule, severity, **base)


def server(name, **kw):
    s = {"name": name, "client": "Cursor", "transport": "stdio", "command": "npx", "args": [], "url": "", "launcher": "npx", "package": name, "ecosystem": "npm",
         "version": "1.0.0", "pinned": True, "env_keys": [], "header_names": [], "url_has_credentials": False, "url_has_query": False, "enabled": True, "note": "",
         "file": ".cursor/mcp.json", "line": 3, "ref": "mcp:" + name, "left_out": ""}
    s.update(kw)
    return s


def model_file(path, **kw):
    r = {"file": path, "size": 10, "extension": ".pkl", "serialization": "pickle", "format": "Python pickle", "pickle_based": True, "status": "scanned", "reason": "",
         "dangerous": [], "unresolved": 0, "pickles": 1, "notes": [], "mislabelled": "", "lambda_layer": False, "location": ""}
    r.update(kw)
    return r


META = {
    "flags": [flag("model.retired", "high", "model", subject="gpt-x"), flag("mcp.shell-command", "high", "mcp", subject="bad", file=".cursor/mcp.json", ref="mcp:bad"),
              flag("model-file.dangerous-call", "high", "model-file", subject="m/b.pkl", file="m/b.pkl", line=0),
              flag("model-file.pickle-format", "medium", "model-file", subject="m/a.pkl", file="m/a.pkl", line=0), flag("code.trust-remote-code", "low", "code"),
              flag("model.license-unknown", "info", "model")],
    "mcp": {"servers": [server("good"), server("bad")], "files": [], "problems": []},
    "model_files": {"files": [model_file("m/a.pkl"), model_file("m/b.pkl", dangerous=[{"module": "os", "name": "system", "severity": "high", "why": "runs commands"}])],
                    "problems": [], "remote_code": {"findings": [{"file": "src/a.py", "line": 3, "how": "keyword", "location": ""}]}},
    "secrets": {"keys": 2, "files": 1, "other": 1},
}


class Order(unittest.TestCase):
    def test_the_sections_come_in_the_order_a_reader_needs(self):
        page = build_html([], "demo", meta=META)
        ids = re.findall(r"<section class='sec' id='(\w+)'>", page)
        self.assertEqual(ids, ["summary", "flags", "models", "mcp", "modelfiles", "scope"])
        self.assertEqual(page.count("<section"), page.count("</section>"))

    def test_the_menu_names_each_section_with_its_count(self):
        nav = re.search(r"<nav class='nav'.*?</nav>", build_html([], "demo", meta=META), re.S).group(0)
        self.assertIn("<a href='#flags'>Findings<span class='n'>6</span></a>", nav)
        self.assertIn("<a href='#mcp'>MCP servers<span class='n'>2</span></a>", nav)
        self.assertIn("<a href='#modelfiles'>Model files<span class='n'>2</span></a>", nav)
        self.assertNotIn("href='#models'", nav)           # no models in this scan

    def test_the_header_says_what_was_scanned_when_and_with_what(self):
        page = build_html([], "demo", "owner/repo", meta=META, today="2026-11-16")
        head = page[page.index("<header"):page.index("</header>")]
        for needle in ("<h1>demo</h1>", "<dt>Source</dt><dd>owner/repo</dd>", "<dt>Report date</dt><dd>2026-11-16</dd>", "<dt>Scanner</dt><dd>aibom 0.", "<dt>Data</dt><dd>models "):
            self.assertIn(needle, head)


class Summary(unittest.TestCase):
    def summary(self, meta):
        page = build_html([], "demo", meta=meta)
        return page[page.index("id='summary'"):page.index("id='flags'")]

    def test_the_banner_says_how_bad_it_is(self):
        self.assertIn("banner bad", self.summary(META))
        self.assertIn("3 high-severity findings need attention", self.summary(META))
        self.assertIn("banner mid", self.summary({"flags": [flag(severity="medium")]}))
        good = self.summary({"flags": [flag(severity="low")]})
        self.assertIn("banner good", good)
        self.assertIn("not proof of safety", good)

    def test_one_tile_per_part_each_linking_to_its_section(self):
        s = self.summary(META)
        for href, label, number in (("flags", "Risk flags", "6"), ("mcp", "MCP servers", "2"), ("modelfiles", "Model files", "2"), ("flags", "Hardcoded API keys", "2"),
                                    ("modelfiles", "trust_remote_code", "1")):
            self.assertRegex(s, f"<a class='card' href='#{href}'><span class='lbl'>{label}</span><b[^>]*>{number}</b>")
        self.assertIn("1 can run code or hide what they are", s)

    def test_the_key_tile_counts_what_the_key_search_found(self):
        # A key in an MCP config is flagged by the MCP rule only, so counting secret flags would miss it.
        s = self.summary({**META, "secrets": {"keys": 5, "files": 3, "other": 0}})
        self.assertIn("<span class='lbl'>Hardcoded API keys</span><b class='hot'>5</b><span>in 3 of the product&#x27;s files", s)
        self.assertNotIn("Hardcoded API keys", self.summary({"flags": []}))


class Findings(unittest.TestCase):
    def test_every_flag_is_in_one_table_worst_first_with_filters(self):
        page = build_html([], "demo", meta=META)
        table = page[page.index("<table class='flags fit'>"):page.index("</table>", page.index("<table class='flags fit'>"))]
        self.assertEqual(table.count("<tr data-sev"), 6)
        self.assertIn("data-cat='model'", table)                  # model flags are in the table too
        self.assertIn("<button type='button' class='fb' data-k='sev' data-v='high' aria-pressed='false'>High (3)</button>", page)
        self.assertIn("data-k='cat' data-v='model-file' aria-pressed='false'>Model file (2)</button>", page)
        self.assertNotIn("id='flmore'", page)                     # few rows: no button

    def test_a_long_table_opens_short_and_a_button_shows_the_rest(self):
        many = {"flags": [flag(severity="low") for _ in range(FLAGS_SHOWN + 5)]}
        self.assertIn(f"<button type='button' class='fb more' id='flmore'>Show all {FLAGS_SHOWN + 5} flags</button>", build_html([], "demo", meta=many))
        self.assertIn("all||n<25", build_html([], "demo", meta=many))     # the script opens on the same number of rows
        self.assertEqual(FLAGS_SHOWN, 25)

    def test_the_pdf_has_no_filters_or_buttons_and_leaves_out_the_info_notes(self):
        page = build_html([], "demo", meta=META, pdf=True)
        self.assertNotIn("class='filters'", page)
        self.assertNotIn("<button", page)
        table = page[page.index("<table class='flags fit'>"):]
        self.assertEqual(table[:table.index("</table>")].count("<tr data-sev"), 5)
        self.assertIn("1 info notes are left out of the PDF", page)


class Inventory(unittest.TestCase):
    def test_each_mcp_server_shows_its_worst_flag(self):
        page = build_html([], "demo", meta=META)
        sec = page[page.index("id='mcp'"):page.index("id='modelfiles'")]
        good, bad = sec.index("<b>good</b>"), sec.index("<b>bad</b>")
        self.assertIn("<span class='none'>none</span>", sec[good:bad])
        self.assertIn("<span class='sev sev-high'>HIGH</span> <span class='cnt'>1 flag</span>", sec[bad:])

    def test_model_files_are_listed_worst_first_with_their_risk(self):
        page = build_html([], "demo", meta=META)
        sec = page[page.index("id='modelfiles'"):page.index("id='scope'")].replace("<wbr>", "")
        self.assertLess(sec.index("m/b.pkl"), sec.index("m/a.pkl"))          # high before medium, whatever the name
        self.assertIn("<h3>trust_remote_code</h3>", sec)
        self.assertIn('<code title="src/a.py:3">a.py:3</code><div class=\'dir\'>src/</div>', sec)

    def test_trust_remote_code_is_a_table_with_every_place(self):
        # Found in review: it was one sentence that listed five places and hid the rest as "and 1 more".
        places = [{"file": f"pkg/eval/run_{i}.py", "line": 10 + i, "how": how, "location": ""}
                  for i, how in enumerate(("keyword", "keyword", "dict", "assignment", "setting", "flag", "keyword"))]
        meta = {**META, "model_files": {**META["model_files"], "remote_code": {"findings": places}}}
        sec = build_html([], "demo", meta=meta)
        sec = sec[sec.index("<h3>trust_remote_code</h3>"):sec.index("id='scope'")].replace("<wbr>", "")
        self.assertIn("<th>Severity</th><th>Where (click to see the line)</th><th>How it is turned on</th>", sec)
        self.assertEqual(sec.count("<tr><td><span class=\"sev sev-medium\">MEDIUM</span></td>"), 7)
        for i in range(7):
            self.assertIn(f'title="pkg/eval/run_{i}.py:{10 + i}">run_{i}.py:{10 + i}</code>', sec)
        for how in ("passed as an argument", "set in a dict of arguments", "set in an assignment", "set in a settings file", "given as a command-line flag"):
            self.assertIn(f"<td>{how}</td>", sec)
        self.assertNotIn("and 1 more", sec)
        self.assertNotIn("and 2 more", sec)

    def test_a_place_shows_its_file_as_the_link_and_its_folder_below(self):
        from aibom_engine.report import place_html
        self.assertEqual(place_html("a/b/c.py:4", "https://x/y").replace("<wbr>", ""),
                         '<a href="https://x/y" target="_blank" rel="noopener" title="a/b/c.py:4">c.py:4</a><div class=\'dir\'>a/b/</div>')
        self.assertEqual(place_html("setup.py:2"), '<code title="setup.py:2">setup.py<wbr>:2</code>')       # no folder: no second line
        self.assertNotIn("<script>", place_html("<script>/x.py:1"))                                         # escaped

    def test_a_project_with_none_of_its_own_says_so(self):
        meta = {"mcp": {"servers": [server("t", left_out="test")], "files": [], "problems": []},
                "model_files": {"files": [model_file("tests/x.pkl", location="test")], "problems": [], "remote_code": {"findings": []}}}
        page = build_html([], "demo", meta=meta)
        self.assertIn("No MCP server is declared in the project's own config files.", page)
        self.assertIn("No model weight file in the project's own files.", page)


class Fit(unittest.TestCase):
    def test_every_table_on_screen_has_column_shares_that_add_up(self):
        # Found in review: tables were wider than their card and the last column ran past the edge. A fixed layout with column
        # shares keeps each table at the width of its card.
        meta = {**META, "packages": []}
        page = build_html([], "demo", meta=meta, files=["flags.csv"])
        tables = re.findall(r"<table class='([^']*)'>(<colgroup>.*?</colgroup>)?", page)
        self.assertTrue(tables)
        for cls, group in tables:
            self.assertIn("fit", cls.split(), cls)
            shares = [int(w) for w in re.findall(r"width:(\d+)%", group)]
            self.assertEqual(sum(shares), 100, (cls, shares))
        self.assertIn("table.fit{table-layout:fixed}", page)
        self.assertNotIn("white-space:nowrap}tbody", page)

    def test_names_and_paths_break_only_at_their_separators(self):
        # Found in review: @huggingface/transformers and file:line paths were cut in the middle of a word.
        from aibom_engine.report import wb, wbc
        self.assertEqual(wb("@huggingface/transformers"), "@huggingface/<wbr>transformers")
        self.assertEqual(wb("app/toolkits/video_toolkit.py:68"), "app/<wbr>toolkits/<wbr>video_<wbr>toolkit.py<wbr>:68")
        self.assertEqual(wb("gpt-4o"), "gpt-4o")
        self.assertEqual(wb("<b>a/b</b>"), "&lt;b&gt;a/<wbr>b&lt;/<wbr>b&gt;")                    # still escaped
        self.assertEqual(wbc("self.config.model = KnowledgeGraphAgent(x)"), "self.<wbr>config.<wbr>model =<wbr> Knowledge<wbr>Graph<wbr>Agent(<wbr>x)")

    def test_labels_wrap_inside_their_cell_and_the_model_table_has_seven_columns(self):
        # Found in review: "Imported (not in a dependency file)" ran into the next column.
        page = build_html([], "demo", meta=META)
        self.assertIn("td .sev,td .ev,td .badge,td .cat{max-width:100%;white-space:normal;vertical-align:top}", page)
        self.assertIn("table.fit{min-width:860px}", page)          # below that width a table scrolls in its own box instead of cutting words
        items = [{"kind": "model", "name": "gpt-4o", "tier": "declared", "role": "used", "evidence": [{"file": "a.py", "line": 1, "use": "live", "snippet": "x"}]}]
        page = build_html(items, "demo", meta=META)
        group = re.search(r'<table class="wide fit"><colgroup>(.*?)</colgroup>', page).group(1)
        self.assertEqual(group.count("<col "), 7)
        head = re.search(r'<table class="wide fit">.*?</tr>', page).group(0)
        self.assertEqual(re.findall(r"<th>([^<]+)</th>", head),
                         ["Model", "Where it is used (click to see the line)", "Confidence", "Status and dates", "Pinned", "Replaced by", "License"])

    def test_the_menu_can_be_hidden_and_brought_back(self):
        page = build_html([], "demo", meta=META)
        self.assertIn("<button type='button' class='navx' id='navhide' aria-controls='nav' title='Hide the menu'>Hide</button>", page)
        self.assertIn("<button type='button' class='navshow' id='navshow' aria-controls='nav'>Contents</button>", page)
        self.assertIn("body.navoff .nav{display:none}", page)
        self.assertNotIn("id='navshow'", build_html([], "demo", meta=META, pdf=True))


class Downloads(unittest.TestCase):
    FILES = ["aibom.cdx.json", "flags.csv", "flags.json", "models.csv"]

    def test_the_header_has_the_download_buttons(self):
        page = build_html([], "demo", meta=META, files=self.FILES + ["report.pdf"])
        actions = page[page.index("<div class='actions'>"):page.index("</header>")]
        for needle in ("<a class='act pri' href='report.pdf' download>Download PDF</a>", "id='dlcsv'>Download findings (CSV)</button>",
                       "href='aibom.cdx.json' download>AI-BOM (CycloneDX)</a>", "href='#downloads'>All files</a>"):
            self.assertIn(needle, actions)

    def test_without_a_pdf_file_the_button_prints_instead(self):
        page = build_html([], "demo", meta=META, files=self.FILES)
        self.assertIn("id='doprint'>Save as PDF</button>", page)
        self.assertNotIn("href='report.pdf'", page)

    def test_the_downloads_section_lists_only_the_files_that_are_there(self):
        page = build_html([], "demo", meta=META, files=self.FILES)
        sec = page[page.index("id='downloads'"):]
        self.assertEqual(re.findall(r"<a href='([^']+)' download>", sec), ["aibom.cdx.json", "flags.csv", "flags.json", "models.csv"])
        self.assertNotIn("id='downloads'", build_html([], "demo", meta=META))       # no files known: no section, no menu entry

    def test_a_pdf_has_no_buttons_and_no_downloads(self):
        page = build_html([], "demo", meta=META, pdf=True, files=self.FILES)
        self.assertNotIn("class='actions'", page)
        self.assertNotIn("id='downloads'", page)
        self.assertNotIn("flagdata", page)

    def test_the_findings_data_in_the_page_cannot_close_its_script(self):
        nasty = {"flags": [flag(subject="</script><script>alert(1)</script>", title="=HYPERLINK(\"x\")")]}
        page = build_html([], "demo", meta=nasty)
        data = page[page.index("id='flagdata'>"):]
        data = data[:data.index("</script>")]
        self.assertNotIn("<", data[len("id='flagdata'>"):])
        import json
        rows = json.loads(data[len("id='flagdata'>"):])["rows"]
        self.assertEqual(rows[0][4], "</script><script>alert(1)</script>")

    def test_the_findings_spreadsheet_has_every_flag_and_no_formulas(self):
        from aibom_engine.report import FLAG_CSV_HEAD, build_flags_csv
        import csv
        import io
        rows = list(csv.reader(io.StringIO(build_flags_csv(META["flags"] + [flag(subject="=cmd|' /C calc'!A0", title="+1", fix="@x", detail="-2")]))))
        self.assertEqual(rows[0], FLAG_CSV_HEAD)
        self.assertEqual(len(rows), len(META["flags"]) + 2)
        last = dict(zip(FLAG_CSV_HEAD, rows[-1]))
        self.assertEqual((last["about"], last["finding"], last["fix"], last["detail"]), ("'=cmd|' /C calc'!A0", "'+1", "'@x", "'-2"))
        self.assertEqual(dict(zip(FLAG_CSV_HEAD, rows[1]))["severity"], "high")

    def test_a_scan_writes_flags_csv_and_its_report_links_to_every_file_it_wrote(self):
        import os
        import subprocess
        import sys
        import tempfile
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        app = os.path.join(root, "tests", "fixtures", "review-app")
        with tempfile.TemporaryDirectory() as out:
            r = subprocess.run([sys.executable, "-m", "aibom_engine", "--plain", "scan", app, "--out", out], cwd=root, capture_output=True, text=True,
                               env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertTrue(os.path.exists(os.path.join(out, "flags.csv")))
            with open(os.path.join(out, "report.html"), encoding="utf-8") as fh:
                page = fh.read()
            linked = re.findall(r"<a href='([^']+)' download>", page[page.index("id='downloads'"):])
            self.assertIn("flags.csv", linked)
            self.assertNotIn("report.pdf", linked)                         # not made by a scan
            for name in linked:
                self.assertTrue(os.path.exists(os.path.join(out, name)), name)


if __name__ == "__main__":
    unittest.main()
