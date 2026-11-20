"""MCP servers declared in config files (M3.1): finding the files, reading every documented format, how a server is started,
what is kept (never a secret), and where the servers show up in the outputs."""
import csv
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from aibom_engine import mcp
from aibom_engine.pipeline import run
from aibom_engine.report import build_html, build_markdown, build_mcp_csv
from aibom_engine.writer import mcp_parts, validate

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")


def make(files):
    tmp = tempfile.TemporaryDirectory()
    for rel, text in files.items():
        path = os.path.join(tmp.name, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
    return tmp


def servers(files):
    with make(files) as d:
        return mcp.find(d)


def one(rel, text):
    got = servers({rel: text})["servers"]
    assert len(got) == 1, got
    return got[0]


# Secrets are built from pieces so no key-shaped text sits in the repository.
KEY = "sk-" + "ant-" + "Zq9x" * 8
TOKEN = "ghp_" + "A1b2C3d4E5" * 4
PASSWORD = "hunter2" + "hunter2"


class Formats(unittest.TestCase):
    """Each example is the shape the tool's own documentation shows."""

    def test_claude_code_project_file_with_all_three_transports(self):
        got = servers({".mcp.json": '''{
  "mcpServers": {
    "airtable": {"command": "npx", "args": ["-y", "airtable-mcp-server"], "env": {"AIRTABLE_API_KEY": "YOUR_KEY"}},
    "notion": {"type": "http", "url": "https://mcp.notion.com/mcp", "headers": {"Authorization": "Bearer your-token"}},
    "asana": {"type": "sse", "url": "https://mcp.asana.com/sse"}
  }
}'''})["servers"]
        by = {s["name"]: s for s in got}
        self.assertEqual({k: (v["transport"], v["line"], v["client"]) for k, v in by.items()},
                         {"airtable": ("stdio", 3, "Claude Code or VS Code"), "notion": ("http", 4, "Claude Code or VS Code"), "asana": ("sse", 5, "Claude Code or VS Code")})
        self.assertEqual(by["airtable"]["env_keys"], ["AIRTABLE_API_KEY"])
        self.assertEqual(by["notion"]["header_names"], ["Authorization"])
        self.assertEqual(by["notion"]["url"], "https://mcp.notion.com/mcp")

    def test_cursor_file(self):
        s = one(".cursor/mcp.json", '{"mcpServers": {"server-name": {"command": "python", "args": ["mcp-server.py"], "env": {"API_KEY": "value"}}}}')
        self.assertEqual((s["client"], s["transport"], s["command"], s["args"], s["env_keys"]), ("Cursor", "stdio", "python", ["mcp-server.py"], ["API_KEY"]))

    def test_a_cursor_remote_server_with_no_type_is_a_remote_service(self):
        s = one(".cursor/mcp.json", '{"mcpServers": {"r": {"url": "http://localhost:3000/mcp", "headers": {"API_KEY": "value"}}}}')
        self.assertEqual((s["transport"], s["url"], s["header_names"]), ("remote", "http://localhost:3000/mcp", ["API_KEY"]))

    def test_vscode_uses_the_servers_key_and_allows_comments(self):
        s = one(".vscode/mcp.json", '''{
  // VS Code writes comments here
  "inputs": [{"id": "token", "type": "promptString", "password": true}],
  "servers": {
    "pw": {"type": "stdio", "command": "npx", "args": ["-y", "@playwright/mcp@1.0.0"],},
  },
}''')
        self.assertEqual((s["client"], s["name"], s["line"], s["package"], s["version"], s["pinned"]), ("VS Code", "pw", 5, "@playwright/mcp", "1.0.0", True))

    def test_vscode_mcp_json_is_read_although_the_scan_skips_dot_vscode_elsewhere(self):
        got = servers({".vscode/mcp.json": '{"servers": {"a": {"command": "x"}}}', ".vscode/settings.json": '{"mcpServers": {"b": {"command": "y"}}}'})
        self.assertEqual([s["name"] for s in got["servers"]], ["a"])

    def test_gemini_url_is_sse_and_httpurl_is_http(self):
        got = {s["name"]: s for s in servers({".gemini/settings.json": '''{
  "theme": "dark",
  "mcpServers": {
    "localServer": {"command": "python", "args": ["-m", "my_mcp_server"], "cwd": "./mcp-servers/python", "env": {"API_KEY": "$MY_API_TOKEN"}, "trust": false},
    "remoteServer": {"httpUrl": "http://localhost:3000/mcp", "headers": {"Authorization": "Bearer your-api-token"}},
    "sseServer": {"url": "https://example.com/sse"}
  }
}'''})["servers"]}
        self.assertEqual({k: v["transport"] for k, v in got.items()}, {"localServer": "stdio", "remoteServer": "http", "sseServer": "sse"})
        self.assertEqual(got["remoteServer"]["url"], "http://localhost:3000/mcp")

    def test_codex_toml_tables_with_lines_env_and_bearer_variable(self):
        text = '''model = "gpt-5"

[mcp_servers.context7]
command = "npx"
args = ["-y", "@upstash/context7-mcp"]

[mcp_servers.context7.env]
MY_ENV_VAR = "MY_ENV_VALUE"

[mcp_servers.figma]
url = "https://mcp.figma.com/mcp"
bearer_token_env_var = "FIGMA_OAUTH_TOKEN"
http_headers = { "X-Figma-Region" = "us-east-1" }

[mcp_servers."chrome.devtools"]
url = "http://localhost:3000/mcp"
enabled = false
'''
        lines = text.splitlines()
        at = lambda header: next(i + 1 for i, l in enumerate(lines) if l.strip() == header)  # noqa: E731  (counted from the text, not from the code under test)
        got = {s["name"]: s for s in servers({".codex/config.toml": text})["servers"]}
        self.assertEqual((got["context7"]["line"], got["context7"]["env_keys"], got["context7"]["package"]), (at("[mcp_servers.context7]"), ["MY_ENV_VAR"], "@upstash/context7-mcp"))
        self.assertEqual((got["figma"]["transport"], got["figma"]["line"], got["figma"]["header_names"]), ("http", at("[mcp_servers.figma]"), ["Authorization", "X-Figma-Region"]))
        self.assertEqual((got["chrome.devtools"]["line"], got["chrome.devtools"]["enabled"]), (at('[mcp_servers."chrome.devtools"]'), False))
        self.assertEqual(sorted(g["line"] for g in got.values()), [3, 10, 15])  # and the three counted by hand

    def test_claude_desktop_file(self):
        s = one("claude_desktop_config.json", '{"mcpServers": {"filesystem": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/Users/username/Desktop"]}}}')
        self.assertEqual((s["client"], s["package"], s["args"][-1]), ("Claude Desktop", "@modelcontextprotocol/server-filesystem", "/Users/username/Desktop"))

    def test_any_json_with_mcp_in_its_name_if_it_holds_server_like_entries(self):
        self.assertEqual(one("config/my-mcp-config.json", '{"mcpServers": {"a": {"command": "x"}}}')["client"], "an MCP config")
        self.assertEqual(one("mcp.json", '{"servers": {"a": {"url": "https://x.y/z"}}}')["transport"], "remote")

    def test_json_with_mcp_in_its_name_that_is_something_else_is_ignored_quietly(self):
        got = servers({"mcp-notes.json": '{"servers": {"a": "just text", "b": {"owner": "me"}}}', "mcp-broken.json": "{not json", "mcp-list.json": "[1, 2]"})
        self.assertEqual((got["servers"], got["problems"]), ([], []))

    def test_an_ordinary_json_file_is_never_read(self):
        self.assertEqual(servers({"package.json": '{"mcpServers": {"a": {"command": "x"}}}', "settings.json": '{"servers": {"a": {"command": "x"}}}'})["servers"], [])

    def test_a_gemini_settings_file_without_mcp_servers_gives_nothing(self):
        self.assertEqual(servers({".gemini/settings.json": '{"theme": "dark"}'}), {"servers": [], "files": [], "problems": [], "partial": False})

    def test_the_same_server_in_two_files_is_listed_twice_with_each_place(self):
        got = servers({".mcp.json": '{"mcpServers": {"a": {"command": "x"}}}', ".cursor/mcp.json": '{"mcpServers": {"a": {"command": "x"}}}'})["servers"]
        self.assertEqual(sorted(s["file"] for s in got), [".cursor/mcp.json", ".mcp.json"])


class Transport(unittest.TestCase):
    def kind(self, entry, rel=".mcp.json"):
        return one(rel, json.dumps({"mcpServers": {"s": entry}}))["transport"]

    def test_explicit_types_and_aliases(self):
        self.assertEqual(self.kind({"type": "stdio", "command": "x"}), "stdio")
        self.assertEqual(self.kind({"type": "streamable-http", "url": "https://a/b"}), "http")
        self.assertEqual(self.kind({"type": "SSE", "url": "https://a/b"}), "sse")
        self.assertEqual(self.kind({"type": "websocket", "url": "wss://a/b"}), "websocket")

    def test_inferred_from_the_fields(self):
        self.assertEqual(self.kind({"command": "x"}), "stdio")
        self.assertEqual(self.kind({"url": "https://a/b"}), "remote")
        self.assertEqual(self.kind({"httpUrl": "https://a/b"}), "http")

    def test_an_entry_with_nothing_to_run_says_so(self):
        s = one(".mcp.json", '{"mcpServers": {"s": {"description": "nothing here"}}}')
        self.assertEqual((s["transport"], s["note"]), ("unknown", "the entry has neither a command nor a URL"))

    def test_entries_that_are_not_objects_are_skipped(self):
        got = servers({".mcp.json": '{"mcpServers": {"a": "text", "b": null, "c": [1], "d": {"command": "x"}}}'})["servers"]
        self.assertEqual([s["name"] for s in got], ["d"])

    def test_a_disabled_flag_is_recorded(self):
        self.assertIs(one(".mcp.json", '{"mcpServers": {"s": {"command": "x", "disabled": true}}}')["enabled"], False)
        self.assertIsNone(one(".mcp.json", '{"mcpServers": {"s": {"command": "x"}}}')["enabled"])


class Launcher(unittest.TestCase):
    """How a stdio server is started. Where the package cannot be told, it stays empty: a guess would be a false claim."""

    def p(self, command, *args):
        r = mcp.parse_launcher(command, list(args))
        return r["launcher"], r["package"], r["ecosystem"], r["version"], r["pinned"]

    def test_npx_forms(self):
        self.assertEqual(self.p("npx", "-y", "airtable-mcp-server"), ("npx", "airtable-mcp-server", "npm", "", False))
        self.assertEqual(self.p("npx", "-y", "@scope/pkg@1.2.3", "/x"), ("npx", "@scope/pkg", "npm", "1.2.3", True))
        self.assertEqual(self.p("npx", "pkg@latest"), ("npx", "pkg", "npm", "latest", False))
        self.assertEqual(self.p("npx", "pkg@^1.2.0"), ("npx", "pkg", "npm", "^1.2.0", False))
        self.assertEqual(self.p("npx", "pkg@1.2"), ("npx", "pkg", "npm", "1.2", False))
        self.assertEqual(self.p("npx", "pkg@1.2.3-beta.1"), ("npx", "pkg", "npm", "1.2.3-beta.1", True))
        self.assertEqual(self.p("npx", "--yes", "--registry", "https://r.example", "pkg@2.0.0"), ("npx", "pkg", "npm", "2.0.0", True))
        self.assertEqual(self.p("npx", "-p", "@scope/real@3.0.0", "bin-name"), ("npx", "@scope/real", "npm", "3.0.0", True))
        self.assertEqual(self.p("npx", "--package=pkg@1.0.0", "bin"), ("npx", "pkg", "npm", "1.0.0", True))

    def test_other_node_launchers(self):
        self.assertEqual(self.p("bunx", "pkg@1.0.0"), ("bunx", "pkg", "npm", "1.0.0", True))
        self.assertEqual(self.p("pnpx", "pkg"), ("pnpx", "pkg", "npm", "", False))
        self.assertEqual(self.p("pnpm", "dlx", "pkg@1.0.0"), ("pnpm dlx", "pkg", "npm", "1.0.0", True))
        self.assertEqual(self.p("yarn", "dlx", "-p", "pkg@1.0.0", "bin"), ("yarn dlx", "pkg", "npm", "1.0.0", True))

    def test_windows_cmd_wrapper_and_executable_suffixes(self):
        self.assertEqual(self.p("cmd", "/c", "npx", "-y", "@playwright/mcp@latest"), ("npx", "@playwright/mcp", "npm", "latest", False))
        self.assertEqual(self.p("C:\\Program Files\\nodejs\\npx.cmd", "-y", "pkg@1.0.0"), ("npx", "pkg", "npm", "1.0.0", True))
        self.assertEqual(self.p("/usr/local/bin/uvx", "pkg"), ("uvx", "pkg", "pypi", "", False))

    def test_a_package_from_a_url_or_path_is_marked_as_source(self):
        self.assertEqual(self.p("npx", "github:user/repo")[2:], ("source", "", False))
        self.assertEqual(self.p("npx", "git+https://github.com/u/r.git")[2:], ("source", "", False))
        self.assertEqual(self.p("npx", "./local-server")[2:], ("source", "", False))
        self.assertEqual(self.p("uvx", "git+https://github.com/u/r.git@main")[2:], ("source", "", False))

    def test_unknown_options_give_no_package_instead_of_a_guess(self):
        self.assertEqual(self.p("npx", "--mystery", "pkg"), ("npx", "", "", "", None))
        self.assertEqual(self.p("uvx", "--another-flag", "value", "pkg"), ("uvx", "", "", "", None))
        self.assertEqual(self.p("docker", "run", "--new-flag", "image"), ("docker", "", "", "", None))

    def test_npx_with_a_shell_string_has_no_package(self):
        self.assertEqual(self.p("npx", "-c", "some-command && other"), ("npx", "", "", "", None))

    def test_uvx_pipx_and_uv_tool_run(self):
        self.assertEqual(self.p("uvx", "mcp-server-git"), ("uvx", "mcp-server-git", "pypi", "", False))
        self.assertEqual(self.p("uvx", "mcp-server-git==1.2.3"), ("uvx", "mcp-server-git", "pypi", "1.2.3", True))
        self.assertEqual(self.p("uvx", "mcp-server-git@1.2.3"), ("uvx", "mcp-server-git", "pypi", "1.2.3", True))
        self.assertEqual(self.p("uvx", "mcp-server-git@latest"), ("uvx", "mcp-server-git", "pypi", "latest", False))
        self.assertEqual(self.p("uvx", "mcp-server-git>=1.0"), ("uvx", "mcp-server-git", "pypi", "1.0", False))
        self.assertEqual(self.p("uvx", "mcp-server-git==1.*"), ("uvx", "mcp-server-git", "pypi", "1.*", False))
        self.assertEqual(self.p("uvx", "Mcp_Server.Git==1.0"), ("uvx", "mcp-server-git", "pypi", "1.0", True))
        self.assertEqual(self.p("uvx", "--python", "3.12", "--from", "real-pkg==2.0.0", "tool-name"), ("uvx", "real-pkg", "pypi", "2.0.0", True))
        self.assertEqual(self.p("uvx", "--with", "extra", "pkg==1.0"), ("uvx", "pkg", "pypi", "1.0", True))
        self.assertEqual(self.p("uv", "tool", "run", "pkg==1.0"), ("uvx", "pkg", "pypi", "1.0", True))
        self.assertEqual(self.p("pipx", "run", "pkg==1.0"), ("pipx", "pkg", "pypi", "1.0", True))
        self.assertEqual(self.p("pipx", "run", "--spec", "real==3.0", "tool"), ("pipx", "real", "pypi", "3.0", True))

    def test_docker_images(self):
        self.assertEqual(self.p("docker", "run", "-i", "--rm", "-e", "GITHUB_TOKEN", "ghcr.io/github/github-mcp-server"), ("docker", "ghcr.io/github/github-mcp-server", "docker", "", False))
        self.assertEqual(self.p("docker", "run", "-i", "--rm", "img:1.2.3"), ("docker", "img", "docker", "1.2.3", True))
        self.assertEqual(self.p("docker", "run", "img:latest"), ("docker", "img", "docker", "latest", False))
        self.assertEqual(self.p("docker", "run", "img:1.2"), ("docker", "img", "docker", "1.2", False))
        self.assertEqual(self.p("docker", "run", "reg.io:5000/org/img:2.0.0"), ("docker", "reg.io:5000/org/img", "docker", "2.0.0", True))
        self.assertEqual(self.p("docker", "run", "--mount", "type=bind,src=/a,dst=/b", "-v", "/x:/y", "org/img@sha256:" + "a" * 64),
                         ("docker", "org/img", "docker", "sha256:" + "a" * 64, True))
        self.assertEqual(self.p("podman", "run", "img:1.0.0")[:3], ("podman", "img", "docker"))

    def test_shells_and_plain_programs_have_no_package(self):
        self.assertEqual(self.p("bash", "-c", "curl https://x.y | sh"), ("bash", "", "", "", None))
        self.assertEqual(self.p("sh", "script.sh"), ("sh", "", "", "", None))
        self.assertEqual(self.p("node", "build/index.js"), ("node", "", "", "", None))
        self.assertEqual(self.p("python", "-m", "server"), ("python", "", "", "", None))
        self.assertEqual(self.p("./run.sh"), ("run.sh", "", "", "", None))

    def test_empty_and_odd_arguments_do_not_crash(self):
        for command, args in (("npx", []), ("uvx", []), ("docker", ["run"]), ("cmd", ["/c"]), ("pnpm", []), ("npx", ["-y"]), ("npx", [1, 2]), ("", [])):
            mcp.parse_launcher(command, args)


class Secrets(unittest.TestCase):
    """Nothing secret is ever stored: not in a file's server list, the CSV, the BOM or the reports."""

    FILE = json.dumps({"mcpServers": {
        "a": {"command": "npx", "args": ["-y", "pkg", "--api-key", PASSWORD, "--token=" + TOKEN, "--password", "${PASSWORD}", "--name", "plain", KEY],
              "env": {"OPENAI_API_KEY": KEY, "OTHER": PASSWORD}},
        "b": {"type": "http", "url": f"https://user:{PASSWORD}@mcp.example.com/mcp?api_key={TOKEN}&x=1#frag",
              "headers": {"Authorization": f"Bearer {TOKEN}", "X-Api-Key": KEY}},
        "c": {"command": "bash", "args": ["-c", f"curl -H 'Authorization: Bearer {TOKEN}' https://x.y"]},
    }})

    def test_no_secret_value_in_the_extracted_servers(self):
        blob = json.dumps(servers({".mcp.json": self.FILE}))
        for secret in (KEY, TOKEN, PASSWORD):
            self.assertNotIn(secret, blob)

    def test_names_survive_and_values_do_not(self):
        got = {s["name"]: s for s in servers({".mcp.json": self.FILE})["servers"]}
        self.assertEqual(got["a"]["env_keys"], ["OPENAI_API_KEY", "OTHER"])
        self.assertEqual(got["b"]["header_names"], ["Authorization", "X-Api-Key"])
        self.assertEqual(got["b"]["url"], "https://mcp.example.com/mcp")
        self.assertEqual((got["b"]["url_has_query"], got["b"]["url_has_credentials"]), (True, True))

    def test_the_value_after_a_secret_flag_is_masked_and_other_arguments_stay(self):
        args = mcp.scrub_args(["-y", "pkg", "--api-key", PASSWORD, "--password", "${PASSWORD}", "--name", "plain", "--token=" + PASSWORD, "--keyfile=/path/a.pem"])
        self.assertEqual(args[:2], ["-y", "pkg"])
        self.assertEqual(args[3], "*" * len(PASSWORD))
        self.assertEqual(args[4:7], ["--password", "${PASSWORD}", "--name"])  # a placeholder is not a secret
        self.assertEqual(args[7], "plain")
        self.assertEqual(args[8], "--token=" + "*" * len(PASSWORD))
        self.assertEqual(args[9], "--keyfile=" + "*" * len("/path/a.pem"))  # a flag that says "key" is masked even if the value is a path: over-masking is the safe side

    def test_masking_twice_changes_nothing(self):
        once = mcp.scrub_args(["--token", PASSWORD])
        self.assertEqual(mcp.scrub_args(once), once)

    def test_url_cleaning(self):
        self.assertEqual(mcp.safe_url("https://u:p@Host.Example:8080/a/b?x=1#f"), ("https://Host.Example:8080/a/b", True, True))
        self.assertEqual(mcp.safe_url("https://only-user@host/x"), ("https://host/x", False, True))
        self.assertEqual(mcp.safe_url("https://a@b@host/x"), ("https://host/x", False, True))
        self.assertEqual(mcp.safe_url("https://host/x?"), ("https://host/x", False, False))
        self.assertEqual(mcp.safe_url("http://[::1]:3000/mcp"), ("http://[::1]:3000/mcp", False, False))
        self.assertEqual(mcp.safe_url("${API_BASE_URL:-https://api.example.com}/mcp"), ("${API_BASE_URL:-https://api.example.com}/mcp", False, False))
        self.assertEqual(mcp.safe_url("not a url?secret=1")[0], "not a url")
        self.assertEqual(mcp.safe_url("http://host:notaport/x")[0], "http://host:notaport/x")

    def test_the_outputs_never_hold_a_secret(self):
        with make({".mcp.json": self.FILE, "app.py": 'from openai import OpenAI\nOpenAI().chat.completions.create(model="gpt-4o-2024-08-06", messages=[])\n'}) as d, \
                tempfile.TemporaryDirectory() as out:
            run(d, out, app="demo")
            for name in os.listdir(out):
                with open(os.path.join(out, name), encoding="utf-8-sig", errors="replace") as fh:
                    text = fh.read()
                for secret in (KEY, TOKEN, PASSWORD):
                    self.assertNotIn(secret, text, name)


class FindingFiles(unittest.TestCase):
    def test_servers_in_tests_examples_docs_and_vendored_folders_are_left_out_with_the_reason(self):
        cfg = '{"mcpServers": {"s": {"command": "x"}}}'
        got = servers({".mcp.json": cfg, "tests/.mcp.json": cfg, "examples/demo/.cursor/mcp.json": cfg, "docs/mcp.json": cfg, "vendor/x/.mcp.json": cfg})
        self.assertEqual({s["file"]: s["left_out"] for s in got["servers"]},
                         {".mcp.json": "", "tests/.mcp.json": "test", "examples/demo/.cursor/mcp.json": "example", "docs/mcp.json": "docs", "vendor/x/.mcp.json": "vendored"})
        self.assertEqual(got["servers"][0]["left_out"], "")  # the product's own servers come first
        self.assertEqual(mcp.summary(got), {"servers": 1, "stdio": 1, "remote": 0, "config_files": 1, "left_out": 4})

    def test_the_products_own_servers_come_first_even_when_a_left_out_file_sorts_earlier(self):
        cfg = '{"mcpServers": {"s": {"command": "x"}}}'
        got = servers({"docs/mcp.json": cfg, "examples/mcp.json": cfg, "src/mcp.json": cfg})["servers"]
        self.assertEqual([(s["file"], s["left_out"]) for s in got], [("src/mcp.json", ""), ("docs/mcp.json", "docs"), ("examples/mcp.json", "example")])

    def test_the_summary_counts_a_url_with_no_stated_type_as_remote(self):
        got = servers({".mcp.json": '{"mcpServers": {"a": {"url": "https://a.b/c"}, "b": {"type": "sse", "url": "https://a.b/d"}, "c": {"type": "http", "url": "https://a.b/e"}, "d": {"command": "x"}}}'})
        self.assertEqual(mcp.summary(got), {"servers": 4, "stdio": 1, "remote": 3, "config_files": 1, "left_out": 0})

    def test_dependency_and_build_folders_are_not_walked(self):
        cfg = '{"mcpServers": {"s": {"command": "x"}}}'
        got = servers({"node_modules/pkg/.mcp.json": cfg, ".git/mcp.json": cfg, "dist/mcp.json": cfg, "venv/mcp.json": cfg, "src/mcp.json": cfg})
        self.assertEqual([s["file"] for s in got["servers"]], ["src/mcp.json"])

    def test_a_broken_known_file_is_a_problem_and_the_scan_goes_on(self):
        got = servers({".mcp.json": '{"mcpServers": {"a": {"command": "x"},}', ".cursor/mcp.json": '{"mcpServers": {"b": {"command": "y"}}}', ".codex/config.toml": "[mcp_servers.c\ncommand = "})
        self.assertEqual([s["name"] for s in got["servers"]], ["b"])
        self.assertEqual(sorted(p["file"] for p in got["problems"]), [".codex/config.toml", ".mcp.json"])
        self.assertTrue(all(p["error"] for p in got["problems"]))

    def test_a_broken_file_named_exactly_like_an_mcp_config_is_a_problem_too(self):
        # Found on a real repository: .codex/mcp.json and .aider/mcp.json had git conflict markers and were skipped without a word.
        conflict = '{\n  "mcpServers": {\n<<<<<<< HEAD\n    "a": {"command": "x"}\n=======\n    "a": {"command": "y"}\n>>>>>>> branch\n  }\n}\n'
        got = servers({".codex/mcp.json": conflict, "tools/.aider/mcp.json": '{"mcpServers": {"srv" {"command" "julia"}}}', "deep/x/.mcp.json": "{",
                       "mcp-broken.json": "{not json", "notes/mcp-ideas.json": "[1,"})
        self.assertEqual(sorted(p["file"] for p in got["problems"]), [".codex/mcp.json", "deep/x/.mcp.json", "tools/.aider/mcp.json"])
        self.assertTrue(all(p["error"] for p in got["problems"]))
        self.assertEqual(got["servers"], [])

    def test_a_huge_file_is_not_read(self):
        got = servers({".mcp.json": '{"mcpServers": {"a": {"command": "x", "pad": "' + "x" * 1_600_000 + '"}}}'})
        self.assertEqual(got["servers"], [])
        self.assertIn("larger than", got["problems"][0]["error"])

    def test_a_non_utf8_file_does_not_crash(self):
        with make({}) as d:
            with open(os.path.join(d, ".mcp.json"), "wb") as fh:
                fh.write(b'{"mcpServers": {"caf\xe9": {"command": "x"}}}')
            self.assertEqual(len(mcp.find(d)["servers"]), 1)

    def test_a_file_with_a_byte_order_mark_is_read(self):
        with make({}) as d:
            with open(os.path.join(d, ".mcp.json"), "wb") as fh:
                fh.write(b'\xef\xbb\xbf{"mcpServers": {"a": {"command": "x"}}}')
            self.assertEqual([s["name"] for s in mcp.find(d)["servers"]], ["a"])

    def test_a_symbolic_link_is_not_followed(self):
        with make({"real/.mcp.json": '{"mcpServers": {"a": {"command": "x"}}}'}) as d:
            link = os.path.join(d, ".mcp.json")
            try:
                os.symlink(os.path.join(d, "real", ".mcp.json"), link)
            except (OSError, NotImplementedError):
                self.skipTest("symbolic links are not available here")
            self.assertEqual([s["file"] for s in mcp.find(d)["servers"]], ["real/.mcp.json"])

    def test_a_file_the_system_reports_as_a_link_is_skipped_even_where_links_cannot_be_made(self):
        with make({".mcp.json": '{"mcpServers": {"a": {"command": "x"}}}'}) as d:
            with mock.patch("aibom_engine.mcp.os.path.islink", return_value=True):
                self.assertEqual(mcp.find(d)["servers"], [])

    def test_an_empty_folder_and_a_missing_deadline_work(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(mcp.find(d), {"servers": [], "files": [], "problems": [], "partial": False})

    def test_the_time_limit_stops_the_walk_and_says_so(self):
        with make({"a/.mcp.json": '{"mcpServers": {"a": {"command": "x"}}}'}) as d:
            got = mcp.find(d, deadline=1)
            self.assertEqual((got["servers"], got["partial"]), ([], True))
            self.assertIs(mcp.find(d)["partial"], False)

    def test_the_summary_of_nothing(self):
        self.assertEqual(mcp.summary({"servers": [], "files": [], "problems": []}), {"servers": 0, "stdio": 0, "remote": 0, "config_files": 0, "left_out": 0})

    def test_every_server_dict_has_the_same_keys_and_is_json_safe(self):
        got = servers({".mcp.json": '{"mcpServers": {"a": {"command": "npx", "args": ["pkg"]}, "b": {"url": "https://x/y"}}}'})
        self.assertEqual(len({tuple(sorted(s)) for s in got["servers"]}), 1)
        json.dumps(got)


class InTheBom(unittest.TestCase):
    def parts(self, files):
        return mcp_parts(servers(files)["servers"])

    def test_a_local_server_is_an_application_with_a_purl_and_its_place(self):
        comps, services = self.parts({".mcp.json": '{\n"mcpServers": {"fs": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem@1.2.3", "/x"], "env": {"K": "v"}}}}'})
        self.assertEqual(services, [])
        c = comps[0]
        self.assertEqual((c["type"], c["name"], c["purl"], c["version"]), ("application", "fs", "pkg:npm/%40modelcontextprotocol/server-filesystem@1.2.3", "1.2.3"))
        self.assertEqual(c["evidence"]["occurrences"], [{"location": ".mcp.json", "line": 2, "additionalContext": "declared in a Claude Code or VS Code config"}])
        props = [(p["name"], p["value"]) for p in c["properties"]]
        self.assertIn(("aibom-engine:kind", "mcp-server"), props)
        self.assertIn(("aibom-engine:environment-name", "K"), props)
        self.assertIn(("aibom-engine:pinned", "true"), props)
        self.assertNotIn("v", [v for n, v in props if n.endswith("environment-name") or n.endswith("header-name")])

    def test_an_unpinned_package_has_a_purl_without_a_version(self):
        c = self.parts({".mcp.json": '{"mcpServers": {"a": {"command": "uvx", "args": ["mcp-server-git"]}}}'})[0][0]
        self.assertEqual(c["purl"], "pkg:pypi/mcp-server-git")
        self.assertNotIn("version", c)

    def test_a_docker_or_script_server_has_no_purl(self):
        for cmd, args in (("docker", ["run", "img:1.0.0"]), ("node", ["server.js"])):
            c = self.parts({".mcp.json": json.dumps({"mcpServers": {"a": {"command": cmd, "args": args}}})})[0][0]
            self.assertNotIn("purl", c)

    def test_a_remote_server_is_a_service_with_an_endpoint_and_authenticated_when_it_sends_authorization(self):
        _, services = self.parts({".mcp.json": '{"mcpServers": {"n": {"type": "http", "url": "https://mcp.notion.com/mcp", "headers": {"Authorization": "Bearer x"}}, "o": {"url": "https://a.b/sse"}}}'})
        by = {s["name"]: s for s in services}
        self.assertEqual(by["n"]["endpoints"], ["https://mcp.notion.com/mcp"])
        self.assertIs(by["n"]["authenticated"], True)
        self.assertNotIn("authenticated", by["o"])
        self.assertIn(("aibom-engine:declared-in", ".mcp.json:1"), [(p["name"], p["value"]) for p in by["n"]["properties"]])

    def test_a_url_with_a_placeholder_is_a_property_not_an_endpoint(self):
        for url in ("${API_BASE}/mcp", "https://${HOST}/mcp", "https://host/{tenant}/mcp"):
            _, services = self.parts({".mcp.json": json.dumps({"mcpServers": {"n": {"url": url}}})})
            self.assertNotIn("endpoints", services[0], url)
            self.assertIn(("aibom-engine:url", url), [(p["name"], p["value"]) for p in services[0]["properties"]], url)

    def test_a_package_with_a_floating_version_has_no_version_in_the_bom(self):
        c = self.parts({".mcp.json": '{"mcpServers": {"a": {"command": "npx", "args": ["pkg@latest"]}, "b": {"command": "npx", "args": ["pkg2@^1.0.0"]}}}'})[0]
        for comp in c:
            self.assertNotIn("version", comp)
            self.assertNotIn("@", comp["purl"].split("/")[-1])
        self.assertEqual(sorted(x["purl"] for x in c), ["pkg:npm/pkg", "pkg:npm/pkg2"])

    def test_left_out_servers_are_not_in_the_bom_and_references_are_unique(self):
        files = {"tests/.mcp.json": '{"mcpServers": {"t": {"command": "x"}}}', ".vscode/mcp.json": '{"mcpServers": {"a": {"command": "x"}}, "servers": {"a": {"command": "y"}}}'}
        comps, services = self.parts(files)
        refs = [c["bom-ref"] for c in comps + services]
        self.assertEqual(len(refs), 2)
        self.assertEqual(len(set(refs)), 2)

    def test_the_whole_bom_is_valid_cyclonedx_with_every_kind_of_server(self):
        files = {".mcp.json": '{"mcpServers": {"a": {"command": "npx", "args": ["-y", "pkg@1.0.0"]}, "b": {"type": "sse", "url": "https://a.b/sse", "headers": {"Authorization": "x"}}, "c": {"url": "${X}/y"}, "d": {"x": 1, "command": "bash", "args": ["-c", "ls"]}}}',
                 ".codex/config.toml": '[mcp_servers.z]\nurl = "https://z.y/mcp"\nenabled = false\n', "app.py": 'from openai import OpenAI\n'}
        with make(files) as d, tempfile.TemporaryDirectory() as out:
            run(d, out, app="demo")
            with open(os.path.join(out, "aibom.cdx.json"), encoding="utf-8") as fh:
                bom = json.load(fh)
            self.assertIsNone(validate(bom))
            names = {c["name"] for c in bom["components"]} | {s["name"] for s in bom.get("services", [])}
            self.assertTrue({"a", "b", "c", "d", "z"} <= names)


class Outputs(unittest.TestCase):
    FILES = {".mcp.json": '{\n  "mcpServers": {\n    "fs": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem@1.2.3", "/data"]},\n'
                          '    "web|<b>x</b>": {"type": "http", "url": "https://mcp.example.com/mcp", "headers": {"Authorization": "Bearer x"}}\n  }\n}',
             "examples/.mcp.json": '{"mcpServers": {"demo": {"command": "x"}}}',
             "app.py": 'from openai import OpenAI\nOpenAI().chat.completions.create(model="gpt-4o-2024-08-06", messages=[])\n'}

    @classmethod
    def setUpClass(cls):
        cls.repo = make(cls.FILES)
        cls.out = tempfile.TemporaryDirectory()
        cls.result = run(cls.repo.name, cls.out.name, app="demo")

    @classmethod
    def tearDownClass(cls):
        cls.repo.cleanup()
        cls.out.cleanup()

    def read(self, name):
        with open(os.path.join(self.out.name, name), encoding="utf-8-sig") as fh:
            return fh.read()

    def test_mcp_json_manifest_and_result_agree(self):
        saved = json.loads(self.read("mcp.json"))
        self.assertEqual(len(saved["servers"]), 3)
        summary = {"servers": 2, "stdio": 1, "remote": 1, "config_files": 1, "left_out": 1}
        self.assertEqual(json.loads(self.read("manifest.json"))["mcp"], summary)
        self.assertEqual(self.result["mcp"], summary)

    def test_markdown_section_with_the_place_the_pin_and_an_escaped_pipe(self):
        md = self.read("report.md")
        self.assertIn("## MCP servers", md)
        self.assertIn("npx @modelcontextprotocol/server-filesystem@1.2.3", md)
        self.assertIn(".mcp.json:3", md)
        self.assertIn("version pinned", md)
        self.assertIn("1 more declared only in tests, examples or documentation, left out.", md)
        row = next(l for l in md.splitlines() if "web" in l and "remote service" in l)
        escaped = "\\" + "|"
        self.assertEqual(row.replace(escaped, "").count("|"), 6)

    def test_html_section_escapes_names(self):
        page = self.read("report.html")
        self.assertIn("<h2>MCP servers</h2>", page)
        self.assertIn("&lt;b&gt;x&lt;/b&gt;", page)
        self.assertNotIn("<b>x</b></b>", page)

    def test_csv_has_one_row_per_server_with_left_out_ones_marked(self):
        rows = list(csv.DictReader(io.StringIO(self.read("mcp.csv"))))
        self.assertEqual(len(rows), 3)
        by = {r["server"]: r for r in rows}
        self.assertEqual((by["fs"]["package"], by["fs"]["pinned"], by["fs"]["line"], by["fs"]["left_out"]), ("@modelcontextprotocol/server-filesystem", "yes", "3", ""))
        self.assertEqual(by["demo"]["left_out"], "example")

    def test_no_section_and_an_empty_csv_when_there_are_no_servers(self):
        with make({"app.py": 'from openai import OpenAI\n'}) as d, tempfile.TemporaryDirectory() as out:
            run(d, out, app="demo")
            with open(os.path.join(out, "report.md"), encoding="utf-8") as fh:
                self.assertNotIn("## MCP servers", fh.read())
            with open(os.path.join(out, "report.html"), encoding="utf-8") as fh:
                self.assertNotIn("MCP servers</h2>", fh.read())
            with open(os.path.join(out, "mcp.csv"), encoding="utf-8-sig") as fh:
                self.assertEqual(len(fh.read().strip().splitlines()), 1)
            with open(os.path.join(out, "manifest.json"), encoding="utf-8") as fh:
                self.assertEqual(json.load(fh)["mcp"]["servers"], 0)

    def test_only_left_out_servers_say_so_without_an_empty_table(self):
        md = build_markdown([], "demo", meta={"mcp": {"servers": [dict(servers({"examples/.mcp.json": '{"mcpServers": {"a": {"command": "x"}}}'})["servers"][0])]}})
        self.assertIn("1 more declared only in tests", md)
        self.assertNotIn("| Server |", md)

    def test_the_limits_text_no_longer_says_mcp_servers_are_not_covered(self):
        from aibom_engine.report import CANNOT_SEE
        text = " ".join(CANNOT_SEE)
        self.assertNotIn("MCP servers, datasets, secrets and weight files are not covered", text)
        self.assertIn("No server is started", text)

    def test_the_pdf_page_and_a_rebuild_keep_the_servers(self):
        from aibom_engine.cli import make_pdf
        with mock.patch("aibom_engine.pdf.print_to_pdf", side_effect=lambda page, path: page):
            self.assertIn("MCP servers</h2>", make_pdf(self.out.name))
        for name in ("report.md", "report.html", "mcp.csv"):
            os.remove(os.path.join(self.out.name, name))
        r = subprocess.run([sys.executable, "-m", "aibom_engine", "rebuild", self.out.name], cwd=ROOT, capture_output=True, text=True,
                           env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("## MCP servers", self.read("report.md"))
        self.assertEqual(len(self.read("mcp.csv").strip().splitlines()), 4)

    def test_a_run_folder_made_before_mcp_servers_were_read_still_rebuilds(self):
        with make({"app.py": 'from openai import OpenAI\n'}) as d, tempfile.TemporaryDirectory() as out:
            run(d, out, app="demo")
            os.remove(os.path.join(out, "mcp.json"))
            r = subprocess.run([sys.executable, "-m", "aibom_engine", "rebuild", out], cwd=ROOT, capture_output=True, text=True,
                               env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
            self.assertEqual(r.returncode, 0, r.stderr)

    def test_the_terminal_summary_and_dashboard_count_the_servers(self):
        from aibom_engine import screens, ui
        from test_ui import drawn, recorded
        with tempfile.TemporaryDirectory() as out:
            r = subprocess.run([sys.executable, "-m", "aibom_engine", "scan", self.repo.name, "--out", out], cwd=ROOT, capture_output=True, text=True,
                               env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
            self.assertEqual(r.returncode, 0, r.stderr)
            line = next(l for l in r.stdout.splitlines() if "declared in the config files" in l)
            self.assertEqual(" ".join(line.split()), "2 MCP servers declared in the config files (1 local, 1 remote)")
        many = {".mcp.json": json.dumps({"mcpServers": {"a": {"command": "x"}, "b": {"command": "y"}, "c": {"command": "z"}, "d": {"url": "https://a.b/c"}}})}
        with make(many) as repo, tempfile.TemporaryDirectory() as out:
            r = subprocess.run([sys.executable, "-m", "aibom_engine", "scan", repo, "--out", out], cwd=ROOT, capture_output=True, text=True,
                               env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
            line = next(l for l in r.stdout.splitlines() if "declared in the config files" in l)
            self.assertEqual(" ".join(line.split()), "4 MCP servers declared in the config files (3 local, 1 remote)")
        result = {"app": "demo", "seconds": 1.0, "used": 0, "listed": 0, "left_out": 0, "rows": {"used": [], "listed": []}, "packages": {}, "warnings": [], "items": 0,
                  "mcp": {"servers": 4, "stdio": 3, "remote": 1}}
        try:
            con = recorded()
            screens.dashboard(result, "runs/demo", [], mock.Mock(ok=False), "aibom", "", "9.9")
            self.assertIn("MCP servers declared in config files (3 local, 1 remote)", " ".join(drawn(con).split()))
            con = recorded()
            result["mcp"] = {"servers": 0, "stdio": 0, "remote": 0}
            screens.dashboard(result, "runs/demo", [], mock.Mock(ok=False), "aibom", "", "9.9")
            self.assertNotIn("MCP servers", drawn(con))
        finally:
            ui.use_console(None)

    def test_the_mcp_step_runs_before_the_slow_steps_so_they_cannot_use_up_its_time(self):
        # Found on real repositories: after a long package step the time limit had passed, the search found nothing and said nothing.
        lines = []
        with make({".mcp.json": '{"mcpServers": {"a": {"command": "x"}}}', "app.py": 'from openai import OpenAI'}) as d, tempfile.TemporaryDirectory() as out:
            run(d, out, app="demo", log=lines.append)
        text = [l.strip() for l in lines]
        self.assertLess(text.index("Reading MCP config files ..."), text.index("Reading dependency files ..."))
        self.assertLess(text.index("Reading MCP config files ..."), text.index("Looking for model names ..."))

    def test_a_search_cut_short_by_the_time_limit_is_a_warning(self):
        cut = {"servers": [], "files": [], "problems": [], "partial": True}
        with make({"app.py": 'from openai import OpenAI'}) as d, tempfile.TemporaryDirectory() as out:
            with mock.patch("aibom_engine.pipeline.mcp_finder.find", return_value=cut):
                result = run(d, out, app="demo")
            self.assertTrue(any("looking for MCP config files" in w and "some may be missing" in w for w in result["warnings"]))
            result = run(d, out, app="demo")
            self.assertFalse(any("looking for MCP config files" in w for w in result["warnings"]))

    def test_a_failure_in_the_mcp_step_never_stops_the_scan(self):
        with make({"app.py": 'from openai import OpenAI\nOpenAI().chat.completions.create(model="gpt-4o-2024-08-06", messages=[])\n'}) as d, tempfile.TemporaryDirectory() as out:
            with mock.patch("aibom_engine.pipeline.mcp_finder.find", side_effect=RuntimeError("boom")):
                result = run(d, out, app="demo")
            self.assertTrue(result["valid"])
            self.assertTrue(any("MCP config files could not be read" in w for w in result["warnings"]))
            self.assertGreaterEqual(result["used"], 1)

    def test_a_broken_config_file_becomes_a_warning(self):
        with make({".mcp.json": "{broken", "app.py": 'from openai import OpenAI\n'}) as d, tempfile.TemporaryDirectory() as out:
            result = run(d, out, app="demo")
            self.assertTrue(any(".mcp.json" in w and "MCP config file" in w for w in result["warnings"]))

    def test_the_csv_builder_handles_none(self):
        self.assertEqual(build_mcp_csv(None).strip().split(",")[0], "server")

    def test_the_html_builder_alone_shows_the_section(self):
        found = servers({".mcp.json": '{"mcpServers": {"a": {"command": "x"}}}'})
        self.assertIn("MCP servers</h2>", build_html([], "demo", meta={"mcp": found}))


class Determinism(unittest.TestCase):
    def test_the_same_files_give_the_same_servers_in_the_same_order(self):
        files = {f"p{i}/.mcp.json": '{"mcpServers": {"b": {"command": "x"}, "a": {"command": "y"}}}' for i in range(4)}
        self.assertEqual(json.dumps(servers(files)), json.dumps(servers(dict(reversed(list(files.items()))))))


if __name__ == "__main__":
    unittest.main()
