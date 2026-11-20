"""Risk flags (M3.5): the flag type, how flags are ordered and counted, the model flags, and where they land in the outputs."""
import json
import os
import tempfile
import unittest
from unittest import mock

from aibom_engine import flags as F
from aibom_engine.flags import Flag
from aibom_engine.pipeline import run
from aibom_engine.report import risk_summary
from aibom_engine.writer import attach_flags, item_ref, validate

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
APP = os.path.join(ROOT, "tests", "fixtures", "review-app")


def flag(rule="x.y", severity="low", **kw):
    base = dict(category="model", title="A title.", subject="thing", fix="Do the thing.")
    base.update(kw)
    return Flag(rule, severity, **base)


def fake_key():
    """A key-shaped string built at run time, so no key-like text sits in the repository."""
    return "sk-" + "proj" + "-" + "A1b2C3d4" * 4


class FlagType(unittest.TestCase):
    def test_an_unknown_severity_is_refused(self):
        for bad in ("critical", "", "HIGH", None):
            with self.assertRaises(ValueError, msg=repr(bad)):
                flag(severity=bad)

    def test_a_flag_needs_a_rule_a_title_and_a_fix(self):
        for missing in ("title", "fix"):
            with self.assertRaises(ValueError, msg=missing):
                flag(**{missing: ""})
        with self.assertRaises(ValueError):
            flag(rule="")

    def test_a_negative_or_non_number_line_is_refused(self):
        for bad in (-1, "3", None, 1.5):
            with self.assertRaises(ValueError, msg=repr(bad)):
                flag(line=bad)

    def test_windows_paths_are_stored_with_forward_slashes(self):
        self.assertEqual(flag(file="src\\app\\main.py").file, "src/app/main.py")

    def test_a_key_handed_over_by_mistake_never_reaches_any_text_field(self):
        key = fake_key()
        f = flag(title=f"found {key}", subject=f'api_key="{key}"', fix=f"remove {key}", detail=f"line: client(key='{key}')")
        for text in (f.title, f.subject, f.fix, f.detail, json.dumps(f.to_dict()), F.as_property(f)["value"]):
            self.assertNotIn(key, text)
        self.assertIn("*" * len(key), f.title)

    def test_round_trip_through_a_dict(self):
        f = flag(file="a/b.py", line=7, detail="more", ref="model:x")
        self.assertEqual(Flag.from_dict(f.to_dict()), f)
        self.assertEqual(Flag.from_dict({**f.to_dict(), "unknown_future_field": 1}), f)


class Headline(unittest.TestCase):
    def test_info_notes_are_named_apart_and_not_counted(self):
        fl = [flag(severity="high"), flag(severity="low", subject="a"), flag(severity="info", subject="b"), flag(severity="info", subject="c")]
        self.assertEqual(F.headline(fl), (2, "1 high, 1 low; plus 2 info notes"))

    def test_one_info_note_is_singular_and_info_only_says_so(self):
        self.assertEqual(F.headline([flag(severity="info")]), (0, "1 info note only"))
        self.assertEqual(F.headline([flag(severity="medium"), flag(severity="info", subject="z")]), (1, "1 medium; plus 1 info note"))
        self.assertEqual(F.headline([flag(severity="medium")]), (1, "1 medium"))
        self.assertEqual(F.headline([]), (0, ""))


class Ordering(unittest.TestCase):
    def test_worst_first_then_a_stable_order(self):
        a = flag("r.a", "low", subject="b")
        b = flag("r.b", "high", subject="z")
        c = flag("r.c", "medium", subject="a")
        d = flag("r.d", "high", subject="a")
        self.assertEqual([f.rule for f in F.sort_flags([a, b, c, d])], ["r.d", "r.b", "r.c", "r.a"])
        self.assertEqual(F.sort_flags([d, c, b, a]), F.sort_flags([a, b, c, d]))

    def test_the_same_rule_about_the_same_place_is_listed_once(self):
        a = flag("r.a", subject="s", file="f", line=1)
        got = F.collect([a, flag("r.a", subject="s", file="f", line=1)], [flag("r.a", subject="s", file="f", line=2)])
        self.assertEqual(len(got), 2)

    def test_counts_name_every_severity_even_when_zero(self):
        self.assertEqual(F.counts([]), {"high": 0, "medium": 0, "low": 0, "info": 0})
        self.assertEqual(F.counts([flag(severity="high"), flag(severity="high"), flag(severity="info")]),
                         {"high": 2, "medium": 0, "low": 0, "info": 1})

    def test_at_least_includes_the_level_asked_for_and_worse(self):
        fl = [flag(severity=s) for s in F.SEVERITIES]
        self.assertEqual([f.severity for f in F.at_least(fl, "medium")], ["medium", "high"])
        self.assertEqual(len(F.at_least(fl, "info")), 4)
        with self.assertRaises(ValueError):
            F.at_least(fl, "critical")

    def test_the_property_is_the_same_text_every_time(self):
        f = flag(file="a.py", line=3, detail="d")
        p = F.as_property(f)
        self.assertEqual(p["name"], "aibom-engine:flag")
        self.assertEqual(p["value"], F.as_property(Flag.from_dict(f.to_dict()))["value"])
        self.assertEqual(list(json.loads(p["value"])), sorted(json.loads(p["value"])))
        self.assertNotIn("ref", json.loads(p["value"]))


def model(name, **kw):
    it = {"kind": "model", "name": name, "evidence": [{"file": "src/a.py", "line": 4, "use": "live"}],
          "license": "proprietary", "license_restricted": False, "status": "active", "floating": False, "hf_repo": ""}
    it.update(kw)
    return it


REF = lambda it: "model:" + it["name"]  # noqa: E731


class ModelFlags(unittest.TestCase):
    def rules(self, **kw):
        return [f.rule for f in F.model_flags([model("m", **kw)], REF)]

    def test_a_healthy_model_has_no_flags(self):
        self.assertEqual(self.rules(), [])

    def test_retired_is_high_and_names_the_replacement(self):
        f = F.model_flags([model("m", status="retired", replacement="new-model", deprecation_date="2025-01-01", retirement_date="2025-02-01")], REF)[0]
        self.assertEqual((f.rule, f.severity), ("model.retired", "high"))
        self.assertIn("new-model", f.fix)
        self.assertIn("2025-02-01", f.detail)
        self.assertEqual((f.file, f.line, f.ref, f.subject), ("src/a.py", 4, "model:m", "m"))

    def test_deprecated_is_medium_and_gives_the_date_to_act_before(self):
        f = F.model_flags([model("m", status="deprecated", retirement_date="2027-01-14", replacement="r")], REF)[0]
        self.assertEqual((f.rule, f.severity), ("model.deprecated", "medium"))
        self.assertIn("2027-01-14", f.fix)

    def test_a_retired_model_is_not_also_called_deprecated(self):
        self.assertEqual(self.rules(status="retired"), ["model.retired"])

    def test_floating_alias_hf_and_licence_rules(self):
        self.assertEqual(self.rules(floating=True), ["model.floating-alias"])
        self.assertEqual(self.rules(hf_repo="org/m"), ["model.unpinned-hf-repo"])
        self.assertEqual(self.rules(license_restricted=True, license="conditional"), ["model.license-restricted"])
        self.assertEqual(self.rules(license="unknown"), ["model.license-unknown"])
        self.assertEqual(self.rules(license=""), ["model.license-unknown"])

    def test_a_restricted_licence_is_not_also_called_unknown(self):
        self.assertEqual(self.rules(license_restricted=True, license="unknown"), ["model.license-restricted"])

    def test_only_models_get_model_flags_and_the_live_place_is_preferred(self):
        items = [{"kind": "framework", "name": "langchain", "evidence": []},
                 model("m", floating=True, evidence=[{"file": "docs/a.md", "line": 1, "use": "docs"}, {"file": "src/b.py", "line": 9, "use": "live"}])]
        got = F.model_flags(items, REF)
        self.assertEqual([(f.subject, f.file, f.line) for f in got], [("m", "src/b.py", 9)])

    def test_a_model_with_no_known_place_is_still_flagged_without_a_file(self):
        f = F.model_flags([model("m", floating=True, evidence=[])], REF)[0]
        self.assertEqual((f.file, f.line), ("", 0))


class InTheBom(unittest.TestCase):
    def bom(self):
        return {"metadata": {"component": {"bom-ref": "app", "name": "x"}},
                "components": [{"bom-ref": "model:a", "name": "a"}], "services": [{"bom-ref": "service:s", "name": "s"}]}

    def values(self, part):
        return [json.loads(p["value"])["rule"] for p in part.get("properties", []) if p["name"] == F.PROPERTY]

    def test_a_flag_goes_on_its_component_or_service_and_none_is_lost(self):
        bom = self.bom()
        attach_flags(bom, [flag("r.1", ref="model:a"), flag("r.2", ref="service:s"), flag("r.3", ref=""), flag("r.4", ref="model:gone")])
        self.assertEqual(self.values(bom["components"][0]), ["r.1"])
        self.assertEqual(self.values(bom["services"][0]), ["r.2"])
        self.assertEqual(sorted(self.values(bom["metadata"]["component"])), ["r.3", "r.4"])

    def test_no_flags_changes_nothing(self):
        bom = self.bom()
        before = json.dumps(bom, sort_keys=True)
        attach_flags(bom, [])
        self.assertEqual(json.dumps(bom, sort_keys=True), before)


class ReviewApp(unittest.TestCase):
    """The review app through the whole pipeline. The old Risks block and the new flags are computed apart and must agree."""

    @classmethod
    def setUpClass(cls):
        cls.patch = mock.patch.dict(os.environ, {"AIBOM_TODAY": "2026-11-09"})
        cls.patch.start()
        cls.tmp = tempfile.TemporaryDirectory()
        cls.result = run(APP, cls.tmp.name, app="review-app")
        cls.saved = cls.load("flags.json")
        cls.bom = cls.load("aibom.cdx.json")
        cls.manifest = cls.load("manifest.json")

    @classmethod
    def tearDownClass(cls):
        cls.patch.stop()
        cls.tmp.cleanup()

    @classmethod
    def load(cls, name):
        with open(os.path.join(cls.tmp.name, name), encoding="utf-8") as fh:
            return json.load(fh)

    def by_rule(self, rule):
        return sorted(f["subject"] for f in self.saved["flags"] if f["rule"] == rule)

    def test_the_bom_is_still_valid_cyclonedx_1_6(self):
        self.assertIsNone(validate(self.bom))

    def test_the_known_risks_of_the_review_app(self):
        self.assertEqual(self.by_rule("model.retired"), ["claude-3-5-sonnet-20240620"])
        self.assertIn("gpt-4o", self.by_rule("model.deprecated"))
        self.assertIn("gpt-4o", self.by_rule("model.floating-alias"))
        self.assertIn("gpt-4o-mini", self.by_rule("model.floating-alias"))
        self.assertNotIn("text-embedding-3-small", self.by_rule("model.floating-alias"))
        retired = next(f for f in self.saved["flags"] if f["rule"] == "model.retired")
        self.assertIn("claude-sonnet-5-5", retired["fix"])
        self.assertTrue(retired["file"] and retired["line"] > 0)

    def test_the_new_flags_agree_with_the_old_risks_block(self):
        risk = risk_summary(self.result["rows"])
        for rule, key in (("model.retired", "retired"), ("model.deprecated", "deprecated"), ("model.floating-alias", "floating"),
                          ("model.unpinned-hf-repo", "hf"), ("model.license-restricted", "restricted"), ("model.license-unknown", "unknown")):
            self.assertEqual(self.by_rule(rule), sorted(r["name"] for r in risk[key]), rule)

    def test_flags_json_is_worst_first_and_counted(self):
        ranks = [F.RANK[f["severity"]] for f in self.saved["flags"]]
        self.assertEqual(ranks, sorted(ranks, reverse=True))
        self.assertEqual(self.saved["counts"], F.counts([Flag.from_dict(d) for d in self.saved["flags"]]))
        self.assertEqual(self.manifest["flags"], self.saved["counts"])
        self.assertEqual(self.result["flags"][0].severity, "high")

    def test_every_flag_is_in_the_bom_exactly_once(self):
        carried = [json.loads(p["value"]) for part in self.bom["components"] + self.bom.get("services", []) + [self.bom["metadata"]["component"]]
                   for p in part.get("properties", []) if p["name"] == F.PROPERTY]
        self.assertEqual(len(carried), len(self.saved["flags"]))
        retired = next(c for c in self.bom["components"] if c["name"] == "claude-3-5-sonnet-20240620")
        self.assertIn("model.retired", [json.loads(p["value"])["rule"] for p in retired["properties"] if p["name"] == F.PROPERTY])

    def test_the_outputs_are_identical_on_every_run(self):
        with tempfile.TemporaryDirectory() as again:
            run(APP, again, app="review-app")
            for name in ("flags.json", "aibom.cdx.json"):
                with open(os.path.join(again, name), encoding="utf-8") as a, open(os.path.join(self.tmp.name, name), encoding="utf-8") as b:
                    self.assertEqual(a.read(), b.read(), name)

    def test_the_item_ref_of_a_component_is_the_ref_the_flag_uses(self):
        names = {c["bom-ref"] for c in self.bom["components"]}
        for f in self.saved["flags"]:
            if f["ref"]:
                self.assertIn(f["ref"], names)
        self.assertEqual(item_ref({"kind": "model", "name": "GPT 4o"}), "model:gpt-4o")


class Display(unittest.TestCase):
    """What a reader sees. Model lifecycle flags stay in the old Risks block; other flags get their own section."""

    def meta(self, *flags):
        return {"warnings": [], "packages": [], "flags": list(flags)}

    def items(self):
        return [{"kind": "model", "name": "gpt-4o", "tier": "included", "evidence": [], "found_by": ["dictionary"], "aliases": []}]

    def other(self):
        return [flag("mcp.shell-command", "high", category="mcp", title="The server runs a shell | with a pipe", subject="files",
                     file="cfg/mcp.json", line=4, fix="Run a named program, not a shell."),
                flag("secret.api-key", "medium", category="secret", title="A hard-coded key.", subject="<b>x</b>", file="a.py", line=9, fix="Use an env var.")]

    def test_markdown_lists_other_flags_worst_first_with_the_place_and_fix(self):
        from aibom_engine.report import build_markdown
        md = build_markdown([], "demo", meta=self.meta(*self.other()))
        self.assertIn("## Flags", md)
        self.assertLess(md.index("HIGH"), md.index("MEDIUM"))
        self.assertIn("cfg/mcp.json:4", md)
        self.assertIn("Run a named program", md)

    def test_a_pipe_in_a_flag_does_not_break_the_markdown_table(self):
        from aibom_engine.report import build_markdown
        md = build_markdown([], "demo", meta=self.meta(*self.other()))
        row = next(l for l in md.splitlines() if "runs a shell" in l)
        escaped = "\\" + "|"
        self.assertIn("shell " + escaped + " with a pipe", row)
        self.assertEqual(row.replace(escaped, "").count("|"), 6)

    def test_html_escapes_flag_text_and_shows_the_section(self):
        from aibom_engine.report import build_html
        page = build_html([], "demo", meta=self.meta(*self.other()))
        self.assertIn("id='flags'", page)
        self.assertIn("&lt;b&gt;x&lt;/b&gt;", page)
        self.assertNotIn("<b>x</b>", page)
        self.assertIn("<span class='sev sev-high'>HIGH</span>", page)
        self.assertIn("<span class='sev sev-medium'>MEDIUM</span>", page)
        info = build_html([], "demo", meta=self.meta(flag(severity="info", category="mcp")))
        self.assertIn("<span class='sev sev-unknown'>INFO</span>", info)  # the page has no info colour: the neutral one is used, the word stays

    def test_no_section_when_there_are_no_flags_or_only_model_flags(self):
        from aibom_engine.report import build_html, build_markdown
        for meta in (self.meta(), self.meta(flag("model.retired", "high", category="model")), None):
            self.assertNotIn("## Flags", build_markdown([], "demo", meta=meta))
        # The web page always has its Findings section: it says when there is nothing, and model flags are in its table too.
        for meta in (self.meta(), None):
            page = build_html([], "demo", meta=meta)
            self.assertIn("No risk flags were raised by this scan", page)
            self.assertNotIn("table class='flags fit'", page)
        page = build_html([], "demo", meta=self.meta(flag("model.retired", "high", category="model")))
        self.assertIn("table class='flags fit'", page)
        self.assertIn("data-cat='model'", page)

    def test_the_pdf_page_has_the_section_too(self):
        from aibom_engine.report import build_html
        self.assertIn("id='flags'", build_html([], "demo", meta=self.meta(*self.other()), pdf=True))

    def test_the_dashboard_counts_flags_by_severity_and_says_nothing_without_them(self):
        from unittest import mock as m
        from aibom_engine import screens, ui
        from test_ui import drawn, recorded
        r = {"app": "demo", "seconds": 1.0, "used": 0, "listed": 0, "left_out": 0, "rows": {"used": [], "listed": []},
             "packages": {}, "warnings": [], "items": 0, "flags": F.collect(self.other(), [flag(severity="info", subject="z")])}
        try:
            con = recorded()
            screens.dashboard(r, "runs/demo", [], m.Mock(ok=False), "aibom", "", "9.9")
            text = " ".join(drawn(con).split())
            self.assertIn("2 risk flags (1 high, 1 medium; plus 1 info note)", text)
            con = recorded()
            r["flags"] = []
            screens.dashboard(r, "runs/demo", [], m.Mock(ok=False), "aibom", "", "9.9")
            self.assertNotIn("risk flags", drawn(con))
        finally:
            ui.use_console(None)

    def test_the_plain_terminal_summary_names_the_flags(self):
        import subprocess
        import sys
        with tempfile.TemporaryDirectory() as out:
            r = subprocess.run([sys.executable, "-m", "aibom_engine", "scan", APP, "--out", out], cwd=ROOT, capture_output=True, text=True,
                               env={**os.environ, "AIBOM_TODAY": "2026-11-09", "PYTHONDONTWRITEBYTECODE": "1"})
            self.assertEqual(r.returncode, 0, r.stderr)
            with open(os.path.join(out, "flags.json"), encoding="utf-8") as fh:
                saved = json.load(fh)
            line = next(l for l in r.stdout.splitlines() if "risk flags:" in l)
            c = saved["counts"]
            self.assertIn("%d risk flags" % (c["high"] + c["medium"] + c["low"]), " ".join(line.split()))
            self.assertIn("%d high" % c["high"], line)
            self.assertIn("plus %d info note" % c["info"], line)


class ThroughThePipeline(unittest.TestCase):
    """Only model flags exist so far, so a detector for another kind is stood in for: every output must carry what it returns."""

    def test_a_flag_of_another_kind_reaches_every_output(self):
        other = flag("mcp.shell-command", "high", category="mcp", title="The server runs a shell.", subject="files", file="cfg/mcp.json", line=4,
                     fix="Run a named program.")
        with tempfile.TemporaryDirectory() as out, mock.patch("aibom_engine.pipeline.flag_rules.model_flags", return_value=[other]):
            result = run(APP, out, app="review-app")
            read = lambda n, enc="utf-8": open(os.path.join(out, n), encoding=enc).read()  # noqa: E731
            # the review app also declares MCP servers of its own (.cursor/mcp.json), which have their own flags
            self.assertEqual([f.subject for f in result["flags"] if f.subject == "files"], ["files"])
            saved = json.loads(read("flags.json"))
            self.assertEqual(saved["counts"], F.counts(result["flags"]))
            self.assertIn("files", [f["subject"] for f in saved["flags"]])
            self.assertIn("mcp.shell-command", read("aibom.cdx.json"))
            self.assertIn("## Flags", read("report.md"))
            self.assertIn("cfg/mcp.json:4", read("report.md"))
            self.assertIn("id='flags'", read("report.html"))
            self.assertEqual(json.loads(read("manifest.json"))["flags"], saved["counts"])


class Rebuild(unittest.TestCase):
    """`aibom rebuild` and the PDF are made from saved files: they must keep the flags a scan found."""

    def run_cli(self, *args):
        import subprocess
        import sys
        return subprocess.run([sys.executable, "-m", "aibom_engine", *args], cwd=ROOT, capture_output=True, text=True,
                              env={**os.environ, "AIBOM_TODAY": "2026-11-09", "PYTHONDONTWRITEBYTECODE": "1"})

    def test_rebuild_keeps_the_flags_section_and_an_old_folder_without_flags_still_rebuilds(self):
        other = flag("mcp.shell-command", "high", category="mcp", title="The server runs a shell.", subject="files", file="cfg/mcp.json", line=4,
                     fix="Run a named program.")
        with tempfile.TemporaryDirectory() as out:
            self.assertEqual(self.run_cli("scan", APP, "--out", out, "--quiet").returncode, 0)
            path = os.path.join(out, "flags.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump({"flags": [other.to_dict()], "counts": F.counts([other])}, fh)
            r = self.run_cli("rebuild", out)
            self.assertEqual(r.returncode, 0, r.stderr)
            with open(os.path.join(out, "report.md"), encoding="utf-8") as fh:
                self.assertIn("cfg/mcp.json:4", fh.read())
            with open(os.path.join(out, "report.html"), encoding="utf-8") as fh:
                self.assertIn("id='flags'", fh.read())
            os.remove(path)
            r = self.run_cli("rebuild", out)
            self.assertEqual(r.returncode, 0, r.stderr)
            with open(os.path.join(out, "report.md"), encoding="utf-8") as fh:
                self.assertNotIn("## Flags", fh.read())

    def test_load_flags_reads_what_a_scan_saved(self):
        from aibom_engine.cli import load_flags
        with tempfile.TemporaryDirectory() as out:
            self.assertEqual(load_flags(out), [])
            run(APP, out, app="review-app")
            got = load_flags(out)
            self.assertTrue(got and all(isinstance(f, Flag) for f in got))

    def test_the_pdf_page_is_built_with_the_saved_flags(self):
        from aibom_engine.cli import make_pdf
        other = flag("mcp.shell-command", "high", category="mcp", title="The server runs a shell.", subject="files", file="cfg/mcp.json", line=4,
                     fix="Run a named program.")
        with tempfile.TemporaryDirectory() as out:
            run(APP, out, app="review-app")
            with open(os.path.join(out, "flags.json"), "w", encoding="utf-8") as fh:
                json.dump({"flags": [other.to_dict()], "counts": F.counts([other])}, fh)
            with mock.patch("aibom_engine.pdf.print_to_pdf", side_effect=lambda page, path: page) as pdf:
                page = make_pdf(out)
            self.assertEqual(pdf.call_count, 1)
            self.assertIn("id='flags'", page)
            self.assertIn("cfg/mcp.json:4", page.replace("<wbr>", ""))


if __name__ == "__main__":
    unittest.main()
