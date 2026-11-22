"""A scanned repository is untrusted: aibom must not run anything from it, read or write outside it through it, or call an
unfinished scan a pass. Each test builds a hostile folder and checks what really happened on disk."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MARK = "outside-marker-7781"
GIT = shutil.which("git")
WINDOWS = os.name == "nt"
CSC = os.path.join(os.environ.get("SystemRoot", ""), "Microsoft.NET", "Framework64", "v4.0.30319", "csc.exe")


def put(base, rel, text=""):
    path = os.path.join(base, *rel.split("/"))
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)
    return path


def slashes(path):
    return path.replace("\\", "/")


def aibom(args, cwd, env=None):
    """The command as installed: the package is importable, the current folder is not on the import path."""
    code = "import sys; sys.path[0] = %r; from aibom_engine.cli import main; main()" % ROOT
    e = {k: v for k, v in os.environ.items() if k.upper() != "NODEFAULTCURRENTDIRECTORYINEXEPATH"}
    e.update({"PYTHONDONTWRITEBYTECODE": "1", "PYTHONIOENCODING": "utf-8"})
    e.update(env or {})
    return subprocess.run([sys.executable, "-c", code, "--plain"] + args, cwd=cwd, env=e, capture_output=True, text=True, encoding="utf-8", timeout=180)


def all_output(folder):
    text = ""
    for base, _, names in os.walk(folder):
        for n in names:
            with open(os.path.join(base, n), encoding="utf-8", errors="replace") as fh:
                text += fh.read()
    return text


class Hostile(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True) if sys.version_info >= (3, 10) else tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.top = os.path.realpath(tmp.name)
        self.repo = os.path.join(self.top, "repo")
        os.makedirs(self.repo)
        self.out = os.path.join(self.top, "out")
        self.marker = os.path.join(self.top, "RAN")

    def scan(self, *extra, **kw):
        return aibom(["scan", ".", "--out", kw.get("out", self.out)] + list(extra), self.repo)

    def link(self, target, rel, directory=False):
        path = os.path.join(self.repo, *rel.split("/"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        try:
            os.symlink(target, path, target_is_directory=directory)
        except OSError as e:
            self.skipTest("this computer cannot make symlinks: %s" % e)
        return path


class NothingFromTheRepositoryRuns(Hostile):
    @unittest.skipUnless(WINDOWS and os.path.isfile(CSC) and GIT, "needs Windows, its C# compiler and git")
    def test_a_git_exe_in_the_scanned_folder_is_not_run(self):
        src = put(self.top, "p.cs", 'class P{static int Main(){System.IO.File.WriteAllText(@"%s","x");return 1;}}' % self.marker)
        subprocess.run([CSC, "/nologo", "/out:" + os.path.join(self.repo, "git.exe"), src], check=True, capture_output=True)
        self.assertEqual(self.scan().returncode, 0)
        self.assertFalse(os.path.exists(self.marker))

    def test_a_program_is_looked_up_on_absolute_path_entries_only(self):
        from aibom_engine import safety
        name = "aibomprobe.exe" if WINDOWS else "aibomprobe"
        for folder in (self.repo, os.path.join(self.top, "bin")):
            os.chmod(put(folder, name), 0o755)
        here = os.getcwd()
        os.chdir(self.repo)
        self.addCleanup(os.chdir, here)
        real = os.path.join(self.top, "bin")
        with mock.patch.dict(os.environ, {"PATH": os.pathsep.join(["", "."])}):
            self.assertIsNone(safety.find_program("aibomprobe"))
        with mock.patch.dict(os.environ, {"PATH": os.pathsep.join(["", ".", self.repo, real])}):
            self.assertEqual(os.path.normcase(safety.find_program("aibomprobe", avoid=self.repo)), os.path.normcase(os.path.join(real, name)))

    def git(self, *args):
        subprocess.run([GIT, "-C", self.repo, "-c", "user.name=t", "-c", "user.email=t@example.invalid"] + list(args), check=True, capture_output=True)

    def committed(self, files):
        self.git("init", "-q")
        self.git("config", "core.autocrlf", "false")
        for rel, text in files.items():
            put(self.repo, rel, text)
        self.git("add", "-A")
        self.git("commit", "-qm", "x")
        self.git("remote", "add", "origin", "https://github.com/example/app.git")  # git status only runs for a folder that can be linked

    def command(self):
        return "echo x > '%s'; cat" % slashes(self.marker)

    def assert_scan_runs_nothing(self):
        if os.path.exists(self.marker):
            os.remove(self.marker)
        self.assertEqual(self.scan().returncode, 0)
        self.assertFalse(os.path.exists(self.marker))

    @unittest.skipUnless(GIT, "git is not installed")
    def test_core_fsmonitor_in_the_folders_git_config_is_not_run(self):
        self.committed({"app.py": "x = 1\n"})
        self.git("config", "core.fsmonitor", put(self.top, "hook.sh", "#!/bin/sh\n" + self.command() + "\n").replace("\\", "/"))
        os.chmod(os.path.join(self.top, "hook.sh"), 0o755)
        self.assert_scan_runs_nothing()

    @unittest.skipUnless(GIT, "git is not installed")
    def test_a_clean_filter_is_not_run(self):
        self.committed({"app.py": "x = 1\n", ".gitattributes": "*.py filter=evil\n"})
        self.git("config", "filter.evil.clean", self.command())
        put(self.repo, "app.py", "x = 1\n")  # a new time stamp makes git read the file again
        os.utime(os.path.join(self.repo, "app.py"), (1700000000, 1700000000))
        self.assert_scan_runs_nothing()

    @unittest.skipUnless(GIT, "git is not installed")
    def test_a_git_hook_is_not_run(self):
        self.committed({"app.py": "x = 1\n"})
        os.chmod(put(self.repo, ".git/hooks/post-index-change", "#!/bin/sh\necho x > '%s'\n" % slashes(self.marker)), 0o755)
        os.utime(os.path.join(self.repo, "app.py"), (1700000000, 1700000000))
        self.assert_scan_runs_nothing()

    @unittest.skipUnless(GIT, "git is not installed")
    def test_links_to_the_code_still_work_and_stop_when_the_folder_changed(self):
        from aibom_engine.source import linker_for_git_folder
        self.committed({"sub/app.py": "x = 1\n"})
        self.git("remote", "set-url", "origin", "https://user:s3cret@github.com/example/app.git")
        links = linker_for_git_folder(os.path.join(self.repo, "sub"))
        self.assertTrue(links.ok)
        self.assertEqual(links.url, "https://github.com/example/app")
        self.assertTrue(links.url_for("app.py", 1).endswith("/sub/app.py#L1"))
        put(self.repo, "sub/app.py", "x = 2\n")
        self.assertFalse(linker_for_git_folder(self.repo).ok)

    def test_python_dash_m_does_not_import_modules_from_the_current_folder(self):
        put(self.repo, "argparse.py", "open(%r, 'w').write('x')\nraise SystemExit(0)\n" % self.marker)
        env = {**os.environ, "PYTHONPATH": ROOT, "PYTHONDONTWRITEBYTECODE": "1"}
        subprocess.run([sys.executable, "-m", "aibom_engine", "--version"], cwd=self.repo, env=env, capture_output=True, timeout=60)
        self.assertFalse(os.path.exists(self.marker))


class NothingOutsideIsRead(Hostile):
    def assert_not_read(self):
        r = self.scan()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn(MARK, all_output(self.out) + r.stdout + r.stderr)

    def test_a_linked_file(self):
        self.link(put(self.top, "private.py", 'model = "%s"\n' % MARK), "config.py")
        self.assert_not_read()

    def test_a_linked_dependency_file(self):
        self.link(put(self.top, "reqs.txt", "langchain-%s==1.0.0\n" % MARK), "requirements.txt")
        self.assert_not_read()

    def test_a_linked_folder(self):
        put(self.top, "private/app.py", 'model = "%s"\n' % MARK)
        self.link(os.path.join(self.top, "private"), "lib", directory=True)
        self.assert_not_read()

    @unittest.skipUnless(WINDOWS, "junctions are a Windows feature")
    def test_a_junction(self):
        import _winapi
        put(self.top, "private/app.py", 'model = "%s"\n' % MARK)
        put(self.top, "private/.mcp.json", json.dumps({"mcpServers": {MARK: {"command": "node"}}}))
        _winapi.CreateJunction(os.path.join(self.top, "private"), os.path.join(self.repo, "lib"))
        self.addCleanup(os.rmdir, os.path.join(self.repo, "lib"))
        self.assert_not_read()

    def test_requirements_cannot_include_a_file_outside(self):
        outside = put(self.top, "reqs.txt", "langchain-openai==9.8.7781\n")
        for target in ("../reqs.txt", slashes(outside)):
            put(self.repo, "requirements.txt", "-r %s\n" % target)
            self.assertEqual(self.scan().returncode, 0)
            self.assertNotIn("9.8.7781", all_output(self.out), target)

    def test_requirements_can_still_include_a_file_inside(self):
        put(self.repo, "deps/base.in", "langchain-openai==9.8.7781\n")
        put(self.repo, "app/requirements.txt", "-r ../deps/base.in\n")
        self.assertEqual(self.scan().returncode, 0)
        self.assertIn("9.8.7781", all_output(self.out))

    @unittest.skipIf(WINDOWS, "named pipes in a folder are a POSIX feature")
    def test_a_named_pipe_does_not_hang_the_scan(self):
        os.mkfifo(os.path.join(self.repo, "app.py"))
        os.mkfifo(os.path.join(self.repo, ".mcp.json"))
        self.assertEqual(self.scan().returncode, 0)

    def test_the_readers_refuse_paths_that_leave_the_folder(self):
        from aibom_engine import safety
        put(self.top, "x.txt", "x")
        put(self.repo, "ok.txt", "x")
        self.assertTrue(safety.inside_file(self.repo, "ok.txt"))
        for rel in ("../x.txt", slashes(os.path.join(self.top, "x.txt")), "a/../../x.txt", "", "."):
            self.assertIsNone(safety.inside_file(self.repo, rel), rel)
        if WINDOWS:
            for rel in (r"\\host\share\x", "C:x.txt", "ok.txt:stream"):
                self.assertIsNone(safety.inside_file(self.repo, rel), rel)

    def test_a_linked_subfolder_of_a_downloaded_repository_is_refused(self):
        from aibom_engine import source
        dest = os.path.join(self.top, "clone")
        os.makedirs(dest)
        with self.assertRaises(source.SourceError):
            source.folder_in_clone(dest, "../repo")
        try:
            os.symlink(self.repo, os.path.join(dest, "sub"), target_is_directory=True)
        except OSError:
            return
        with self.assertRaises(source.SourceError):
            source.folder_in_clone(dest, "sub")


class NothingOutsideIsWritten(Hostile):
    def test_a_linked_result_file(self):
        victim = put(self.top, "victim.txt", "original")
        self.link(victim, "results/report.md")
        r = self.scan(out="results")
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        with open(victim) as fh:
            self.assertEqual(fh.read(), "original")

    def test_a_hard_linked_result_file(self):
        victim = put(self.top, "victim.txt", "original")
        os.makedirs(os.path.join(self.repo, "results"))
        os.link(victim, os.path.join(self.repo, "results", "flags.json"))
        self.assertEqual(self.scan(out="results").returncode, 2)
        with open(victim) as fh:
            self.assertEqual(fh.read(), "original")

    def test_a_linked_results_folder_and_a_linked_parent_of_it(self):
        target = os.path.join(self.top, "elsewhere")
        os.makedirs(target)
        self.link(target, "runs", directory=True)
        for out in ("runs", os.path.join("runs", "app")):
            self.assertEqual(self.scan(out=out).returncode, 2, out)
        self.assertEqual(os.listdir(target), [])

    @unittest.skipUnless(WINDOWS, "junctions are a Windows feature")
    def test_a_results_folder_that_is_a_junction(self):
        import _winapi
        target = os.path.join(self.top, "elsewhere")
        os.makedirs(target)
        _winapi.CreateJunction(target, os.path.join(self.repo, "runs"))
        self.addCleanup(os.rmdir, os.path.join(self.repo, "runs"))
        self.assertEqual(self.scan(out="runs").returncode, 2)
        self.assertEqual(os.listdir(target), [])

    def test_rebuild_and_sarif_do_not_write_through_a_link(self):
        self.assertEqual(self.scan().returncode, 0)
        victim = put(self.top, "victim.txt", "original")
        path = os.path.join(self.out, "aibom.sarif")
        os.remove(path)
        try:
            os.symlink(victim, path)
        except OSError as e:
            self.skipTest("this computer cannot make symlinks: %s" % e)
        for cmd in ("rebuild", "sarif"):
            self.assertEqual(aibom([cmd, self.out], self.top).returncode, 2, cmd)
        with open(victim) as fh:
            self.assertEqual(fh.read(), "original")


class AnUnfinishedScanIsNotAPass(Hostile):
    def test_time_limit_fails_the_gate_with_its_own_exit_code(self):
        put(self.repo, "app.py", "x = 1\n")
        r = self.scan("--max-seconds", "-1", "--fail-on", "high")
        self.assertEqual(r.returncode, 4, r.stdout + r.stderr)
        self.assertIn("did not finish", r.stderr)
        with open(os.path.join(self.out, "manifest.json")) as fh:
            self.assertTrue(json.load(fh)["incomplete"])

    def test_without_fail_on_it_warns_and_keeps_exit_0(self):
        put(self.repo, "app.py", "x = 1\n")
        r = self.scan("--max-seconds", "-1")
        self.assertEqual(r.returncode, 0)
        self.assertIn("time limit", r.stdout.lower())

    def test_a_finished_scan_passes(self):
        put(self.repo, "app.py", "x = 1\n")
        self.assertEqual(self.scan("--fail-on", "low").returncode, 0)
        with open(os.path.join(self.out, "manifest.json")) as fh:
            self.assertEqual(json.load(fh)["incomplete"], [])

    def reasons(self, module, value):
        from aibom_engine import pipeline
        put(self.repo, "app.py", "x = 1\n")
        with mock.patch.object(getattr(pipeline, module), "find", **value):
            return pipeline.run(self.repo, self.out)["incomplete"]

    def test_a_crashed_check_is_incomplete(self):
        for module in ("mcp_finder", "credential_finder", "modelfile_finder", "remote_code_finder", "package_finder"):
            self.assertTrue(self.reasons(module, {"side_effect": RuntimeError("broken")}), module)

    def test_a_crashed_name_finder_is_incomplete(self):
        from aibom_engine import pipeline
        with mock.patch.dict(pipeline.FINDERS, {"context": mock.Mock(side_effect=RuntimeError("broken"))}):
            self.assertTrue(pipeline.run(self.repo, self.out)["incomplete"])

    def test_a_list_cut_at_its_overall_cap_is_incomplete(self):
        cut = {"findings": [], "files_scanned": 1, "problems": [], "partial": False, "truncated": True, "capped": True}
        self.assertTrue(self.reasons("credential_finder", {"return_value": cut}))
        cut = {"files": [], "problems": [], "partial": False, "truncated": True}
        self.assertTrue(self.reasons("modelfile_finder", {"return_value": cut}))
        cut = {"findings": [], "files_scanned": 1, "partial": False, "truncated": True, "capped": True}
        self.assertTrue(self.reasons("remote_code_finder", {"return_value": cut}))

    def test_a_flag_outranks_incomplete(self):
        import argparse
        from aibom_engine import cli, flags
        a = argparse.Namespace(fail_on="high")
        with mock.patch.object(flags, "at_least", return_value=[mock.Mock(severity="high")]), mock.patch.object(flags, "counts", return_value={"high": 1}):
            with self.assertRaises(SystemExit) as done:
                cli.gate(a, {"flags": [object()], "incomplete": ["the time limit was reached"]})
        self.assertEqual(done.exception.code, 3)


class TheAction(unittest.TestCase):
    def setUp(self):
        import yaml
        with open(os.path.join(ROOT, "action.yml"), encoding="utf-8") as fh:
            self.steps = {s.get("name", "setup"): s for s in yaml.safe_load(fh)["runs"]["steps"]}

    def test_every_python_it_starts_ignores_the_checkout(self):
        starts = 0
        for step in self.steps.values():
            for line in step.get("run", "").splitlines():
                if "python " in line and not line.strip().startswith("#"):
                    starts += 1
                    self.assertIn("python -I", line)
        self.assertGreaterEqual(starts, 1)

    def test_it_uploads_named_files_and_only_after_a_scan_wrote_them(self):
        keep = self.steps["Keep the results"]
        self.assertIn("steps.scan.outputs.written", keep["if"])
        paths = keep["with"]["path"].splitlines()
        self.assertIn("${{ inputs.output }}/aibom.cdx.json", paths)
        self.assertNotIn("${{ inputs.output }}", paths)

    def test_it_uploads_every_file_a_scan_writes(self):
        from aibom_engine import pipeline
        with tempfile.TemporaryDirectory() as d:
            put(d, "app/app.py", "x = 1\n")
            out = os.path.join(d, "out")
            pipeline.run(os.path.join(d, "app"), out)
            kept = {p.rsplit("/", 1)[-1] for p in self.steps["Keep the results"]["with"]["path"].splitlines()}
            self.assertEqual(kept, set(os.listdir(out)))


if __name__ == "__main__":
    unittest.main()
