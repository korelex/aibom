"""The polished terminal (M2.8): when it is drawn, the vulnerability list and fix plan, the live scan view, the dashboard and the
colours in the reports. Vulnerability tests use a small database written here, so they do not change when the real advisory
data is refreshed."""
import contextlib
import io
import os
import re
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from rich.console import Console

from aibom_engine import findings as fd
from aibom_engine import report, screens, ui

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|\x1b\]8;[^\x1b]*\x1b\\")


def adv(id, severity, fixed="", versions=("1.0.0",)):
    """An advisory in the shape of ai_db.json; `fixed` closes the range introduced at 0."""
    events = [{"introduced": "0"}] + ([{"fixed": fixed}] if fixed else [])
    return {"id": id, "aliases": [], "severity": severity, "summary": "summary of " + id, "url": "https://osv.dev/vulnerability/" + id,
            "cvss": "", "versions": [], "ranges": [{"type": "ECOSYSTEM", "events": events}]}


DB = {"vulnerabilities": {
    "pypi:alpha": [adv("A-1", "critical", "1.5.0"), adv("A-2", "high", "1.2.0"), adv("A-3", "low", "2.0.0")],
    "pypi:beta": [adv("B-1", "high", "0.2.0"), adv("B-2", "medium")],
    "pypi:gamma": [adv("G-1", "medium", "3.0.0")],
    "npm:delta": [adv("D-1", "low", "0.4.0")],
}}


def package(name, version, level, severity_ids, eco="pypi", direct=True, declared=True):
    found = [a for a in DB["vulnerabilities"].get("%s:%s" % (eco, name), []) if a["id"] in severity_ids]
    return {"name": name, "version": version, "ecosystem": eco, "evidence_level": level, "declared": declared, "direct": direct,
            "vulnerabilities": {"status": "checked", "reason": "", "advisories": [
                {"id": a["id"], "aliases": [], "severity": a["severity"], "summary": a["summary"], "cvss": "", "fixed_in": next(
                    (e["fixed"] for r in a["ranges"] for e in r["events"] if "fixed" in e), ""), "url": a["url"]} for a in found]}}


PACKAGES = [
    package("alpha", "1.0.0", "declared", {"A-1", "A-2", "A-3"}),
    package("beta", "0.1.0", "called", {"B-1", "B-2"}),
    package("gamma", "2.0.0", "imported", {"G-1"}),
    package("delta", "0.1.0", "declared", {"D-1"}, eco="npm", direct=False),
]


def recorded(width=120):
    con = Console(file=io.StringIO(), force_terminal=True, width=width, record=True, highlight=False, markup=False, emoji=False, color_system="truecolor", legacy_windows=False)
    ui.use_console(con)
    return con


def drawn(con):
    return ANSI.sub("", con.file.getvalue())


class WhenToBePretty(unittest.TestCase):
    def tearDown(self):
        ui.set_plain(False)

    def tty(self):
        return mock.Mock(isatty=lambda: True)

    def test_a_terminal_is_pretty_and_a_pipe_is_not(self):
        with mock.patch.dict(os.environ, {"TERM": "xterm"}, clear=True):
            self.assertTrue(ui.pretty(self.tty()))
            self.assertFalse(ui.pretty(mock.Mock(isatty=lambda: False)))

    def test_the_ways_to_ask_for_plain_text(self):
        for env in ({"NO_COLOR": "1"}, {"AIBOM_PLAIN": "1"}, {"TERM": "dumb"}):
            with mock.patch.dict(os.environ, env, clear=True):
                self.assertFalse(ui.pretty(self.tty()), env)
        with mock.patch.dict(os.environ, {"TERM": "xterm"}, clear=True):
            ui.set_plain()
            self.assertFalse(ui.pretty(self.tty()))

    def test_a_stream_that_cannot_say_defaults_to_plain(self):
        self.assertFalse(ui.pretty(object()))


class Bars(unittest.TestCase):
    def test_widths_add_up_and_every_severity_with_findings_shows(self):
        for counts in ({"critical": 1, "high": 500, "low": 1}, {"high": 3}, {"critical": 2, "high": 2, "medium": 2, "low": 2, "unknown": 1}):
            widths = ui.bar_widths(counts, 40)
            self.assertEqual(sum(widths.values()), 40, counts)
            self.assertEqual(set(widths), {s for s, n in counts.items() if n})
            self.assertTrue(all(w >= 1 for w in widths.values()))

    def test_nothing_to_draw(self):
        self.assertEqual(ui.bar_widths({}, 40), {})
        self.assertEqual(ui.bar_widths({"high": 0}, 40), {})


class Findings(unittest.TestCase):
    def test_worst_first_and_called_packages_first_inside_a_severity(self):
        got = fd.collect(PACKAGES)
        self.assertEqual([f["id"] for f in got], ["A-1", "B-1", "A-2", "B-2", "G-1", "A-3", "D-1"])  # called ones first inside a severity
        again = fd.collect([package("zeta", "1.0.0", "called", set())])  # no findings
        self.assertEqual(again, [])
        high_called = fd.collect([package("alpha", "1.0.0", "declared", {"A-2"}), package("beta", "0.1.0", "called", {"B-1"})])
        self.assertEqual([f["id"] for f in high_called], ["B-1", "A-2"])  # both high: the called one first

    def test_filters(self):
        got = fd.collect(PACKAGES)
        self.assertEqual({f["severity"] for f in fd.filter_findings(got, "high")}, {"critical", "high"})
        self.assertEqual([f["id"] for f in fd.filter_findings(got, called=True)], ["B-1", "B-2"])
        self.assertEqual(fd.filter_findings(got, "critical", True), [])

    def test_left_out_packages_are_not_counted(self):
        p = dict(PACKAGES[0], left_out=True)
        self.assertEqual(fd.collect([p]), [])

    def test_lockfile_only_packages_are_apart_by_default(self):
        self.assertEqual(len(fd.counted(PACKAGES)), 3)
        self.assertEqual(len(fd.counted(PACKAGES, True)), 4)

    def test_the_verdict_counts_packages_and_calls(self):
        self.assertEqual(fd.verdict(fd.collect(PACKAGES)), "7 known vulnerabilities in 4 AI packages, 2 of them in packages your code calls.")
        self.assertEqual(fd.verdict(fd.collect([PACKAGES[1]])), "2 known vulnerabilities in 1 AI package, all in packages your code calls.")
        self.assertEqual(fd.verdict(fd.collect([PACKAGES[0]])), "3 known vulnerabilities in 1 AI package, none in packages your code calls.")
        self.assertIn("No known", fd.verdict([]))


class FixPlan(unittest.TestCase):
    def plan(self, packages=PACKAGES):
        return {p["package"]: p for p in fd.fix_plan(packages, DB)}

    def test_the_target_is_the_highest_fixed_version_and_is_verified(self):
        p = self.plan()["alpha"]
        self.assertEqual((p["target"], p["clears"], p["remaining"]), ("2.0.0", 3, []))

    def test_an_advisory_with_no_fix_stays_open_and_is_named(self):
        p = self.plan()["beta"]  # B-2 names no fixed version, so 0.2.0 fixes B-1 only
        self.assertEqual((p["target"], p["clears"], p["remaining"]), ("0.2.0", 1, ["B-2"]))

    def test_a_package_with_no_named_fix_gets_no_target(self):
        only = package("beta", "0.1.0", "called", {"B-2"})
        self.assertEqual(self.plan([only])["beta"]["target"], "")

    def test_warnings_for_jumps_that_can_break_code(self):
        plans = self.plan()
        self.assertIn("major version jump (1 to 2)", plans["alpha"]["warning"])
        self.assertIn("0.1 to 0.2", plans["beta"]["warning"])
        self.assertEqual(plans["gamma"]["warning"], "major version jump (2 to 3)")
        self.assertEqual(fd._jump("pypi", "1.2.3", "1.4.0"), "")
        self.assertEqual(fd._jump("npm", "1.2.3", "1.2.9"), "")
        self.assertEqual(fd._jump("pypi", "garbage", "1.0"), "")

    def test_worst_packages_come_first(self):
        self.assertEqual([p["package"] for p in fd.fix_plan(PACKAGES, DB)], ["alpha", "beta", "gamma", "delta"])

    def test_a_target_that_is_still_affected_is_not_promised(self):
        # the fix named for G-1 (3.0.0) is itself inside another advisory
        db = {"vulnerabilities": {"pypi:gamma": [adv("G-1", "medium", "3.0.0"), adv("G-9", "high", "4.0.0")]}}
        pk = package("gamma", "2.0.0", "called", set())
        pk["vulnerabilities"]["advisories"] = [{"id": "G-1", "severity": "medium", "fixed_in": "3.0.0", "summary": "", "url": "", "aliases": []}]
        got = fd.fix_plan([pk], db)[0]
        self.assertEqual((got["target"], got["clears"], got["remaining"]), ("3.0.0", 1, ["G-9"]))


class VulnScreens(unittest.TestCase):
    def tearDown(self):
        ui.use_console(None)
        ui.set_plain(False)

    def run_plain(self, **kw):
        buf = io.StringIO()
        with mock.patch.object(ui, "pretty", return_value=False), contextlib.redirect_stdout(buf):
            screens.vulns_screen("app", PACKAGES, kw.get("severity"), kw.get("called", False), kw.get("everything", False), "2026-01-01", "aibom vulns RUN", DB)
        return buf.getvalue()

    def test_plain_is_ascii_sorted_and_complete(self):
        text = self.run_plain()
        text.encode("ascii")
        self.assertLess(text.index("CRITICAL (1)"), text.index("HIGH (2)"))
        self.assertLess(text.index("HIGH (2)"), text.index("MEDIUM (2)"))
        self.assertLess(text.index("MEDIUM (2)"), text.index("LOW (1)"))
        self.assertIn("6 known vulnerabilities in 3 AI packages", text)
        self.assertIn("1 more in packages that are only in a lockfile", text)
        self.assertIn("alpha 1.0.0 -> 2.0.0  clears all 3", text)
        self.assertIn("no fix stated", text)
        self.assertIn("Advisory data from 2026-01-01", text)
        self.assertIn("not the same as exploitable", text)

    def test_all_adds_the_lockfile_packages(self):
        self.assertIn("D-1", self.run_plain(everything=True))
        self.assertNotIn("D-1", self.run_plain())

    def test_the_filters_narrow_the_list_and_the_plan(self):
        text = self.run_plain(severity="high", called=True)
        self.assertIn("B-1", text)
        self.assertNotIn("A-2", text)  # alpha is only declared
        self.assertNotIn("alpha", text.split("Fix plan")[1])
        self.assertIn("Showing: severity high or worse, only packages your code calls.", text)

    def test_a_filter_that_matches_nothing_does_not_say_all_is_well(self):
        text = self.run_plain(severity="critical", called=True)
        self.assertIn("No known vulnerabilities match this filter.", text)
        self.assertNotIn("Fix plan", text)

    def test_pretty_draws_every_severity_worst_first_with_the_fix_plan_last(self):
        con = recorded()
        with mock.patch.object(ui, "pretty", return_value=True):
            screens.vulns_screen("app", PACKAGES, None, False, False, "2026-01-01", "aibom vulns RUN", DB)
        text = drawn(con)
        order = [text.index(w) for w in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "Fix plan", "not the same as exploitable")]
        self.assertEqual(order, sorted(order))
        self.assertIn("● called", text)
        self.assertIn("none stated", text)
        self.assertIn("1.0.0 → 2.0.0", text)
        self.assertIn("major version jump", text)

    def test_pretty_uses_the_severity_colours_and_links_the_advisories(self):
        con = recorded()
        with mock.patch.object(ui, "pretty", return_value=True):
            screens.vulns_screen("app", PACKAGES, None, False, False, "", "aibom vulns RUN", DB)
        raw = con.file.getvalue()
        self.assertIn("\x1b]8;", raw)                          # a link to the advisory
        self.assertIn("https://osv.dev/vulnerability/A-1", raw)
        crit = raw[raw.index("CRITICAL") - 60:raw.index("CRITICAL")]
        self.assertRegex(crit, r"\x1b\[[0-9;]*48;")            # the critical badge has a solid background

    def test_a_long_advisory_text_in_a_narrow_terminal_still_shows_the_worst_first(self):
        con = recorded(70)
        with mock.patch.object(ui, "pretty", return_value=True):
            screens.vulns_screen("app", PACKAGES, None, False, False, "", "aibom vulns RUN", DB)
        self.assertLess(drawn(con).index("CRITICAL"), drawn(con).index("LOW"))


class LiveScan(unittest.TestCase):
    def tearDown(self):
        ui.use_console(None)

    def test_one_line_per_stage_with_its_details_and_no_percentage(self):
        con = recorded()
        with screens.StageProgress(3, con) as log:
            log("Sorting the files ...")
            log("  7 files: 2 code")
            log("Checking every name (live code, comment, message, test, docs) ...")
            log("Writing the AI-BOM and the report ...")
        lines = [l for l in drawn(con).splitlines() if "✔" in l]
        self.assertEqual(len(lines), 3)
        self.assertIn("7 files: 2 code", lines[0])
        self.assertIn("Checking every name ", lines[1])
        self.assertNotIn("(live code", drawn(con))
        self.assertNotIn("%", drawn(con))

    def test_a_scan_that_fails_marks_the_running_stage_failed(self):
        con = recorded()
        with self.assertRaises(RuntimeError):
            with screens.StageProgress(2, con) as log:
                log("Sorting the files ...")
                raise RuntimeError("boom")
        self.assertIn("✘", drawn(con))
        self.assertNotIn("✔", drawn(con))


class Dashboard(unittest.TestCase):
    def tearDown(self):
        ui.use_console(None)

    def result(self):
        row = {"name": "gpt-4o", "maker": "OpenAI", "mode": "chat model", "places": [{"file": "src/a.py", "line": 3}]}
        return {"app": "demo", "seconds": 1.5, "used": 1, "listed": 0, "left_out": 2, "rows": {"used": [row], "listed": []},
                "packages": {"ai_packages": 4, "ai_called": 1}, "warnings": [], "items": 1}

    def test_it_shows_the_three_numbers_the_worst_findings_and_what_to_type_next(self):
        con = recorded()
        links = mock.Mock(ok=False)
        screens.dashboard(self.result(), "runs/demo", PACKAGES, links, "aibom", "", "9.9")
        text = " ".join(drawn(con).split())
        for needle in ("demo", "models used directly", "4", "AI packages", "1 of them called", "known vulnerabilities in 3 packages",
                       "CRITICAL", "A-1", "gpt-4o", "aibom vulns runs/demo", "aibom report runs/demo", "affected is not exploitable",
                       "1 more only in a lockfile"):
            self.assertIn(needle, text)
        self.assertLess(text.index("A-1"), text.index("G-1"))  # the top five only: the low one is not shown

    def test_a_long_path_is_cut_at_the_front_so_the_line_number_stays_and_names_stay_whole(self):
        r = self.result()
        r["rows"]["used"][0].update(name="claude-3-5-sonnet-20240620", mode="speech-to-text model",
                                    places=[{"file": "a/very/deep/folder/" * 6 + "agent.py", "line": 4321}])
        con = recorded(100)
        screens.dashboard(r, "runs/demo", [], mock.Mock(ok=False), "aibom", "", "9.9")
        text = drawn(con)
        self.assertIn("agent.py:4321", text)
        self.assertIn("claude-3-5-sonnet-20240620", text)
        self.assertIn("speech-to-text model", text)
        self.assertEqual(screens.tail("abcdef", 4), "…def")
        self.assertEqual(screens.tail("abc", 4), "abc")

    def test_no_vulnerabilities_is_shown_as_good_news_without_a_vulns_hint(self):
        con = recorded()
        screens.dashboard(self.result(), "runs/demo", [], mock.Mock(ok=False), "aibom", "", "9.9")
        text = drawn(con)
        self.assertNotIn("aibom vulns", text)
        self.assertNotIn("Worst vulnerabilities", text)


class Reports(unittest.TestCase):
    META = {"packages": PACKAGES}

    def make(self):
        return report.build_html([], "demo", meta=self.META), report.build_markdown([], "demo", meta=self.META)

    def setUp(self):
        self.patch = mock.patch("aibom_engine.findings.database.load_db", return_value=DB)
        self.patch.start()
        self.html, self.md = self.make()

    def tearDown(self):
        self.patch.stop()

    def test_html_has_coloured_severity_labels_that_also_say_the_word(self):
        for sev in ("critical", "high", "medium", "low"):
            self.assertIn('class="sev sev-%s">%s</span>' % (sev, sev.upper()), self.html)
        self.assertIn('class="sevbar"', self.html)

    def test_html_lists_advisories_worst_first_and_ends_the_packages_with_the_fix_plan(self):
        h = self.html
        self.assertLess(h.index("A-1"), h.index("A-2"))
        self.assertLess(h.index("A-2"), h.index("A-3"))
        self.assertLess(h.index("<h2>AI packages</h2>"), h.index("<h3>Fix plan</h3>"))
        self.assertIn("upgrade to 2.0.0: clears all 3", h)

    def test_markdown_has_the_same_order_and_plan(self):
        m = self.md
        self.assertLess(m.index("**CRITICAL**"), m.index("**LOW**"))
        self.assertIn("### Fix plan", m)
        self.assertIn("| alpha | 1.0.0 | CRITICAL | upgrade to 2.0.0: clears all 3", m)
        self.assertLess(m.index("### Fix plan"), m.index("## What this scan cannot see"))

    def test_the_reports_do_not_change_between_builds(self):
        self.assertEqual(self.make(), (self.html, self.md))

    def test_advisories_are_sorted_even_when_the_data_is_stored_in_another_order(self):
        scrambled = dict(PACKAGES[0])
        scrambled["vulnerabilities"] = {"status": "checked", "reason": "", "advisories": list(reversed(PACKAGES[0]["vulnerabilities"]["advisories"]))}
        meta = {"packages": [scrambled]}
        for page in (report.build_html([], "demo", meta=meta), report.build_markdown([], "demo", meta=meta)):
            self.assertLess(page.index("A-1"), page.index("A-3"), "critical before low")

    def test_a_scan_without_vulnerabilities_has_no_fix_plan(self):
        clean = {"packages": [package("gamma", "9.0.0", "called", set())]}
        self.assertNotIn("Fix plan", report.build_html([], "demo", meta=clean))

    def test_a_broken_plan_never_stops_the_report(self):
        with mock.patch("aibom_engine.findings.fix_plan", side_effect=RuntimeError("x")):
            self.assertNotIn("Fix plan", report.build_html([], "demo", meta=self.META))


class AtATerminal(unittest.TestCase):
    """A real terminal is simulated: stdout says it is one. `--plain` must still give plain text there, and without it the same
    command is drawn with colour (so the test proves it can tell the difference)."""

    class Tty(io.StringIO):
        def isatty(self):
            return True

    def run_main(self, *args):
        from aibom_engine import cli
        out = self.Tty()
        env = {k: v for k, v in os.environ.items() if k not in ("NO_COLOR", "AIBOM_PLAIN")}
        env["TERM"] = "xterm-256color"
        with mock.patch.dict(os.environ, env, clear=True), mock.patch.object(sys, "argv", ["aibom"] + list(args)),                 contextlib.redirect_stdout(out):
            try:
                cli.main()
            finally:
                ui.set_plain(False)
        return out.getvalue()

    @classmethod
    def setUpClass(cls):
        cls.dir = os.path.join(tempfile.mkdtemp(), "review")
        done = subprocess.run([sys.executable, "-m", "aibom_engine", "scan", os.path.join(ROOT, "tests", "fixtures", "review-app"), "--out", cls.dir, "--quiet"],
                              cwd=ROOT, capture_output=True, text=True, timeout=300)
        assert done.returncode == 0, done.stderr

    def test_a_terminal_gets_colour_and_the_plain_option_turns_it_off(self):
        self.assertIn("[", self.run_main("vulns", self.dir))
        self.assertNotIn("", self.run_main("--plain", "vulns", self.dir))
        self.assertNotIn("", self.run_main("--plain", "packages", self.dir))


class Commands(unittest.TestCase):
    """The real command, run as a person's shell would: output goes to a pipe, so it must stay plain."""

    def run_cli(self, *args, **env):
        e = dict(os.environ, PYTHONIOENCODING="utf-8", **env)
        return subprocess.run([sys.executable, "-m", "aibom_engine"] + list(args), cwd=ROOT, capture_output=True, text=True, env=e, timeout=120)

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.out = os.path.join(cls.tmp, "review")
        done = subprocess.run([sys.executable, "-m", "aibom_engine", "scan", os.path.join(ROOT, "tests", "fixtures", "review-app"), "--out", cls.out, "--quiet"],
                              cwd=ROOT, capture_output=True, text=True, timeout=300)
        assert done.returncode == 0, done.stderr

    def test_version_says_the_version_and_how_fresh_the_data_is(self):
        done = self.run_cli("--version")
        self.assertEqual(done.returncode, 0)
        self.assertRegex(done.stdout, r"aibom \d+\.\d+\.\d+")
        self.assertRegex(done.stdout, r"model data:\s+\d{4}-\d\d-\d\d")
        self.assertRegex(done.stdout, r"vulnerability data:\s+\d{4}-\d\d-\d\d")

    def test_vulns_in_a_pipe_is_plain_ascii_with_no_escape_codes(self):
        done = self.run_cli("vulns", self.out)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertNotIn("\x1b", done.stdout)
        done.stdout.encode("ascii")
        self.assertIn("CRITICAL (", done.stdout)
        self.assertLess(done.stdout.index("CRITICAL ("), done.stdout.index("HIGH ("))
        self.assertIn("Fix plan", done.stdout)

    def test_severity_filter_and_bad_values(self):
        done = self.run_cli("vulns", self.out, "--severity", "critical")
        self.assertEqual(done.returncode, 0)
        self.assertNotIn("HIGH (", done.stdout)
        bad = self.run_cli("vulns", self.out, "--severity", "urgent")
        self.assertEqual(bad.returncode, 2)

    def test_a_folder_that_is_not_a_scan_gets_a_clear_message(self):
        done = self.run_cli("vulns", self.tmp)
        self.assertEqual(done.returncode, 2)
        self.assertIn("Problem:", done.stderr)

    def test_plain_flag_and_no_color_keep_a_scan_free_of_escape_codes(self):
        done = self.run_cli("--plain", "packages", self.out)
        self.assertEqual(done.returncode, 0)
        self.assertNotIn("\x1b", done.stdout)


if __name__ == "__main__":
    unittest.main()
