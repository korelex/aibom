"""Risk flags for MCP servers (M3.2): credentials written in a config file, shell strings, unpinned packages, broad file system access."""
import json
import os
import tempfile
import unittest

from aibom_engine import flags as F
from aibom_engine import mcp, mcp_flags
from aibom_engine.mcp_flags import broad_path, inline_code, path_arguments
from aibom_engine.pipeline import run
from aibom_engine.writer import validate
from test_mcp import make

# Secrets are built from pieces so no key-shaped text sits in the repository.
KEY = "sk-" + "ant-" + "Zq9x" * 8
GH = "ghp_" + "A1b2C3d4E5" * 4
LIT = "abcdef" + "1234567890"       # a plain secret value
PW = "hunter2" + "hunter2"


def flags_of(config, rel=".mcp.json", extra=None):
    files = {rel: config if isinstance(config, str) else json.dumps(config, indent=1)}
    files.update(extra or {})
    with make(files) as d:
        found = mcp.find(d)
    return mcp_flags.mcp_flags(found["servers"]), found


def rules(config, **kw):
    return sorted(f.rule for f in flags_of(config, **kw)[0])


def entry(command, *args, **extra):
    return {"mcpServers": {"s": {"command": command, "args": list(args), **extra}}}


class SecretKinds(unittest.TestCase):
    def test_what_counts_as_a_credential(self):
        for name, value, want in [
            ("OPENAI_API_KEY", KEY, "provider-key"), ("GITHUB_TOKEN", GH, "provider-key"), ("Authorization", "Bearer " + KEY, "provider-key"),
            ("API_KEY", LIT, "literal"), ("PASSWORD", PW, "literal"), ("X-Api-Key", "abc123def456ghi", "literal"), ("client_secret", "s3cr3tvalue99", "literal"),
            ("OPENAI_API_KEY", "${OPENAI_API_KEY}", ""), ("API_KEY", "$API_KEY", ""), ("API_KEY", "%API_KEY%", ""), ("API_KEY", "{{ secrets.key }}", ""),
            ("API_KEY", "YOUR_KEY", ""), ("API_KEY", "your-api-key-here", ""), ("API_KEY", "<token>", ""), ("API_KEY", "xxxxxxxxxxxx", ""),
            ("API_KEY", "changeme", ""), ("API_KEY", "example-key-123", ""), ("Authorization", "Bearer ${TOKEN}", ""), ("Authorization", "Bearer <token>", ""),
            ("KEY_FILE", "/etc/ssl/key.pem", ""), ("KEY_FILE", "./key.pem", ""), ("KEY_FILE", "C:/keys/a.pem", ""), ("TOKEN_URL", "https://auth.example.org/token", ""),
            ("TOKEN_ENV", "MY_API_TOKEN", ""), ("AUTH_MODE", "oauth", ""), ("DEBUG", "true", ""), ("LOG_LEVEL", "ERROR", ""), ("PORT", "8080", ""),
            ("API_KEY", "short", ""), ("NOTE", "a long sentence that is not a secret", ""), ("API_KEY", "two words here", ""), ("API_KEY", "", ""),
            ("TOKEN", 12345678, ""), ("TOKEN", None, ""), ("TOKEN", True, ""), ("TOKEN", ["a"], ""),
            # a key-shaped prefix on a value made only of words is a documented placeholder; random letters and digits are a key
            ("DEMO_API_KEY", "sk-demo-dev-local-development-key", ""), ("API_KEY", "sk-this-is-a-fake-key-for-docs", ""),
            ("API_KEY", "sk-proj-" + "Ab3dE6gH9jK2mN5p", "provider-key"), ("API_KEY", "sk-" + "abcdefghijklmnopqrstuvwxyz", "provider-key"),
            ("API_KEY", "ctx7sk-" + "9f3a1c2e-77b4-4d1a-9a6e-1b2c3d4e5f60", "provider-key"),
            ("API_KEY", "sk-proj-" + "AbCdEfGhIjKlMnOpQrSt", "provider-key"),   # letters only but mixed case: random, so a key
            ("API_KEY", "sk-Dev-Local-Development-Key", "provider-key"),          # capitals make it unlike a plain placeholder: err on the side of reporting
            ("PASSWORD", "correct-horse-battery-staple", "literal")]:
            self.assertEqual(mcp._secret_kind(name, value), want, (name, value))

    def test_a_key_shape_is_a_credential_whatever_the_name(self):
        self.assertEqual(mcp._secret_kind("NOTE", KEY), "provider-key")
        self.assertEqual(mcp._secret_kind("", GH), "provider-key")


class WhereSecretsAre(unittest.TestCase):
    def secrets(self, entry_dict):
        return flags_of({"mcpServers": {"s": entry_dict}})[1]["servers"][0]["secrets"]

    def test_env_header_url_and_arguments(self):
        got = self.secrets({"command": "x", "args": ["--token", LIT, "--api-key=" + LIT, "-e", "SECRET=" + LIT, "--header", "Authorization: Bearer " + LIT, GH],
                            "env": {"OPENAI_API_KEY": KEY, "LOG": "x", "OK": "${OK}"}, "headers": {"X-Api-Key": LIT, "Accept": "json"}})
        pairs = sorted((s["in"], s["name"], s["kind"]) for s in got)
        self.assertEqual(pairs, sorted([("env", "OPENAI_API_KEY", "provider-key"), ("header", "X-Api-Key", "literal"), ("arg", "--token", "literal"),
                                        ("arg", "--api-key", "literal"), ("arg", "SECRET", "literal"), ("arg", "Authorization", "literal"), ("arg", "(argument)", "provider-key")]))

    def test_a_url_with_a_password_or_a_token_in_the_query(self):
        got = self.secrets({"url": f"https://user:{PW}@h.example/mcp?api_key={LIT}&mode=x&token=${{TOKEN}}"})
        self.assertEqual(sorted((s["in"], s["name"], s["kind"]) for s in got), [("url", "", "credentials"), ("url-query", "api_key", "literal")])

    def test_one_secret_is_reported_once_even_when_it_has_a_key_shape(self):
        for args in (["--token", GH], ["--token=" + GH], ["-e", "TOKEN=" + GH], ["--header", "Authorization: Bearer " + GH]):
            got = flags_of({"mcpServers": {"s": {"command": "x", "args": args}}})[1]["servers"][0]["secrets"]
            self.assertEqual(len(got), 1, args)

    def test_a_token_in_the_user_name_part_of_a_url(self):
        self.assertEqual([(s["in"], s["kind"]) for s in self.secrets({"url": f"https://{GH}@h.example/x"})], [("url", "provider-key")])
        self.assertEqual(self.secrets({"url": "https://user@h.example/x"}), [])
        self.assertEqual(self.secrets({"url": "https://user:${PW}@h.example/x"}), [])

    def test_the_line_is_the_line_of_the_key_when_the_file_is_json(self):
        got = self.secrets({"command": "x", "env": {"A": "1", "OPENAI_API_KEY": KEY}})
        text = json.dumps({"mcpServers": {"s": {"command": "x", "env": {"A": "1", "OPENAI_API_KEY": KEY}}}}, indent=1).splitlines()
        want = next(i + 1 for i, l in enumerate(text) if "OPENAI_API_KEY" in l)
        self.assertEqual(got[0]["line"], want)

    def test_values_are_never_stored(self):
        blob = json.dumps(flags_of({"mcpServers": {"s": {"command": "x", "args": ["--token", LIT, "-e", "PASSWORD=" + PW, "--header", "Authorization: Bearer " + LIT],
                                                          "env": {"OPENAI_API_KEY": KEY}, "headers": {"X-Api-Key": GH}}}})[1])
        for secret in (KEY, GH, LIT, PW):
            self.assertNotIn(secret, blob)

    def test_toml_env_secrets_use_the_servers_line(self):
        got = flags_of('[mcp_servers.s]\ncommand = "x"\n[mcp_servers.s.env]\nOPENAI_API_KEY = "' + KEY + '"\n', rel=".codex/config.toml")[1]["servers"][0]
        self.assertEqual([(s["in"], s["name"], s["line"]) for s in got["secrets"]], [("env", "OPENAI_API_KEY", 1)])
        self.assertNotIn(KEY, json.dumps(got))

    def test_there_is_a_cap_on_how_many_are_kept(self):
        env = {f"KEY_{i}": LIT + str(i) for i in range(200)}
        self.assertEqual(len(self.secrets({"command": "x", "env": env})), mcp.MAX_SECRETS)


class PlaintextSecretFlags(unittest.TestCase):
    def test_a_key_shape_or_a_url_password_is_high_and_a_plain_value_is_medium(self):
        got = {f.subject: f for f in flags_of({"mcpServers": {"s": {"command": "x", "env": {"A_KEY": KEY, "B_KEY": LIT}, "url": f"https://u:{PW}@h/x"}}})[0]
               if f.rule == "mcp.plaintext-secret"}
        self.assertEqual({k: v.severity for k, v in got.items()}, {"s: A_KEY": "high", "s: B_KEY": "medium", "s": "high"})
        flag = got["s: A_KEY"]
        self.assertEqual((flag.category, flag.file, flag.ref), ("mcp", ".mcp.json", "mcp:.mcp.json:s"))
        self.assertIn("MCP01", flag.detail)
        self.assertIn("environment variable A_KEY", flag.detail)
        self.assertIn("rotate", flag.fix)

    def test_placeholders_and_documentation_examples_are_not_flagged(self):
        self.assertEqual(rules({"mcpServers": {"s": {"command": "x", "env": {"OPENAI_API_KEY": "${OPENAI_API_KEY}", "AIRTABLE_API_KEY": "YOUR_KEY", "K": "<token>"},
                                                     "headers": {"Authorization": "Bearer ${TOKEN}"}}}}), [])

    def test_a_disabled_server_still_has_its_secrets_flagged_but_nothing_else(self):
        got = rules({"mcpServers": {"s": {"command": "npx", "args": ["pkg"], "env": {"A_KEY": KEY}, "disabled": True}}})
        self.assertEqual(got, ["mcp.plaintext-secret"])

    def test_no_flags_for_servers_in_tests_examples_or_docs(self):
        cfg = json.dumps({"mcpServers": {"s": {"command": "bash", "args": ["-c", "ls"], "env": {"A_KEY": KEY}}}})
        for rel in ("tests/.mcp.json", "examples/x/.mcp.json", "docs/mcp.json"):
            self.assertEqual(rules(cfg, rel=rel), [], rel)

    def test_the_flag_text_never_holds_the_secret(self):
        flags, _ = flags_of({"mcpServers": {"s": {"command": "bash", "args": ["-c", "echo " + GH], "env": {"A_KEY": KEY}, "url": f"https://u:{PW}@h/x?token={LIT}"}}})
        blob = json.dumps([f.to_dict() for f in flags])
        for secret in (KEY, GH, LIT, PW):
            self.assertNotIn(secret, blob)


class ShellFlags(unittest.TestCase):
    def test_inline_code_forms(self):
        self.assertEqual(inline_code("bash", ["-c", "ls -la"]), "ls -la")
        self.assertEqual(inline_code("/bin/sh", ["-lc", "run it"]), "run it")
        self.assertEqual(inline_code("zsh", ["-c", "a", "b"]), "a b")
        self.assertEqual(inline_code("pwsh", ["-Command", "Get-Date"]), "Get-Date")
        self.assertEqual(inline_code("powershell.exe", ["-EncodedCommand", "AAAA"]), "AAAA")
        self.assertEqual(inline_code("cmd", ["/c", "dir C:\\"]), "dir C:\\")
        self.assertEqual(inline_code("python3", ["-c", "import os"]), "import os")
        self.assertEqual(inline_code("python", ["-c", "import os"]), "import os")
        self.assertEqual(inline_code("py", ["-c", "x"]), "x")
        self.assertEqual(inline_code("node", ["-e", "run()"]), "run()")
        self.assertEqual(inline_code("deno", ["eval", "1+1"]), "1+1")
        self.assertEqual(inline_code("bash", ["-c"]), "")
        # more languages that run code given on the command line (julia was missed on a real repository)
        self.assertEqual(inline_code("julia", ["--project=@srv", "-e", "using Server; Server.serve()"]), "using Server; Server.serve()")
        self.assertEqual(inline_code("julia", ["--eval", "x()"]), "x()")
        self.assertEqual(inline_code("Rscript", ["-e", "source('x.R')"]), "source('x.R')")
        self.assertEqual(inline_code("R.exe", ["-e", "x"]), "x")
        for command in ("lua", "luajit", "groovy", "elixir", "raku", "perl6", "clojure", "clj", "bb", "osascript"):
            self.assertEqual(inline_code(command, ["-e", "code"]), "code", command)

    def test_things_that_only_look_like_it_are_not_inline_code(self):
        for command, args in (("bash", ["script.sh"]), ("bash", ["-e", "script.sh"]), ("sh", []), ("node", ["server.js"]), ("python", ["-m", "server"]),
                              ("cmd", ["/c", "npx", "-y", "pkg@1.0.0"]), ("cmd.exe", ["/k", "uvx", "pkg"]), ("npx", ["-y", "pkg"]), ("", []), ("docker", ["run", "img"]),
                              ("julia", ["server.jl"]), ("julia", ["--project=.", "server.jl"]), ("Rscript", ["server.R"]), ("bb", ["server.bb", "8080"]), ("lua", ["s.lua"])):
            self.assertIsNone(inline_code(command, args), (command, args))

    def test_a_shell_string_is_medium_and_downloading_to_run_it_is_high(self):
        got = {f.subject: f for f in flags_of({"mcpServers": {"a": {"command": "bash", "args": ["-c", "node server.js --port 3000"]},
                                                               "b": {"command": "sh", "args": ["-c", "curl -s https://x.y/i.sh | sh"]},
                                                               "c": {"command": "powershell", "args": ["-Command", "iwr https://x.y/a.ps1 | iex"]},
                                                               "d": {"command": "bash", "args": ["-c", "wget -qO- https://x.y | sudo bash"]},
                                                               "e": {"command": "bash", "args": ["-c", "curl -o out.txt https://x.y"]}}})[0]}
        self.assertEqual({k: v.severity for k, v in got.items()}, {"a": "medium", "b": "high", "c": "high", "d": "high", "e": "medium"})
        self.assertEqual({v.rule for v in got.values()}, {"mcp.shell-command"})
        self.assertIn("MCP05", got["a"].detail)
        self.assertIn("Runs: node server.js --port 3000", got["a"].detail)

    def test_a_long_command_is_cut_in_the_detail(self):
        flag = flags_of(entry("bash", "-c", "echo " + "x" * 400))[0][0]
        self.assertLess(len(flag.detail), 330)
        self.assertIn("...", flag.detail)

    def test_the_windows_wrapper_around_npx_is_not_a_shell_flag(self):
        self.assertEqual(rules(entry("cmd", "/c", "npx", "-y", "pkg@1.2.3")), [])

    def test_a_shell_string_on_a_remote_server_cannot_happen_and_is_not_flagged(self):
        self.assertEqual(rules({"mcpServers": {"s": {"url": "https://a.b/c"}}}), [])


class PackageFlags(unittest.TestCase):
    def test_unpinned_npm_pypi_and_docker(self):
        for config, fix in ((entry("npx", "-y", "pkg"), "pkg@1.2.3"), (entry("npx", "pkg@latest"), "pkg@1.2.3"), (entry("npx", "@s/pkg@^1.0.0"), "@s/pkg@1.2.3"),
                            (entry("uvx", "pkg"), "pkg==1.2.3"), (entry("uvx", "pkg>=1"), "pkg==1.2.3"), (entry("docker", "run", "img"), "digest"),
                            (entry("docker", "run", "img:latest"), "digest")):
            got = flags_of(config)[0]
            self.assertEqual([f.rule for f in got], ["mcp.unpinned-package"], config)
            self.assertEqual(got[0].severity, "medium")
            self.assertIn(fix, got[0].fix)
            self.assertIn("MCP04", got[0].detail)

    def test_pinned_packages_and_unknown_launchers_are_not_flagged(self):
        for config in (entry("npx", "-y", "pkg@1.2.3"), entry("uvx", "pkg==1.2.3"), entry("uvx", "pkg@1.2.3"), entry("docker", "run", "img:1.2.3"),
                       entry("docker", "run", "img@sha256:" + "a" * 64), entry("node", "server.js"), entry("python", "-m", "x"), entry("my-binary"), entry("npx", "--mystery", "pkg")):
            self.assertEqual(rules(config), [], config)

    def test_code_fetched_from_a_url_or_git_address(self):
        for spec in ("git+https://github.com/u/r.git", "github:user/repo", "https://example.org/pkg.tgz", "git+ssh://git@h/r.git"):
            got = flags_of(entry("npx", spec))[0]
            self.assertEqual([f.rule for f in got], ["mcp.package-from-url"], spec)
        self.assertEqual(rules(entry("npx", "./local-server")), [])
        self.assertEqual(rules(entry("uvx", "/opt/tools/server")), [])

    def test_the_server_name_file_line_and_reference_say_exactly_where(self):
        cfg = '{\n  "mcpServers": {\n    "ok": {"command": "node", "args": ["a.js"]},\n    "bad": {"command": "npx", "args": ["pkg"]}\n  }\n}'
        f = flags_of(cfg)[0][0]
        self.assertEqual((f.subject, f.file, f.line, f.ref), ("bad", ".mcp.json", 4, "mcp:.mcp.json:bad"))


class Paths(unittest.TestCase):
    def test_what_is_a_broad_path(self):
        for path, want in [("/", "root"), ("//", "root"), ("C:\\", "root"), ("c:/", "root"), ("D:", "root"), ("/etc", "system"), ("/etc/", "system"), ("/var", "system"),
                           ("C:\\Windows", "system"), ("/root", "system"), ("~", "home"), ("~/", "home"), ("$HOME", "home"), ("${HOME}", "home"), ("%USERPROFILE%", "home"),
                           ("${userHome}", "home"), ("/Users/bob", "home"), ("/Users/bob/", "home"), ("/home/bob", "home"), ("C:\\Users\\bob", "home"), ("C:/Users/bob/", "home"),
                           ("/Users", "home"), ('"/"', "root"), ("/Users/bob/Desktop", ""), ("/home/bob/project", ""), ("~/project", ""), ("./", ""), (".", ""), ("src", ""),
                           ("/usr/local/share/app", ""), ("${workspaceFolder}", ""), ("C:\\Users\\bob\\proj", ""), ("", ""), ("/a\n/b", ""), ("https://x.y/", "")]:
            self.assertEqual(broad_path(path), want, path)

    def test_which_arguments_name_a_place(self):
        self.assertEqual(path_arguments(["-y", "pkg", "/Users/bob", "--root=/", "--dir", "/data"]), ["pkg", "/Users/bob", "/", "/data"])
        self.assertEqual(path_arguments(["run", "-v", "/:/host:ro", "img"]), ["run", "/", "img"])
        self.assertEqual(path_arguments(["run", "--volume=/home/bob:/h", "img"]), ["run", "/home/bob", "img"])
        self.assertEqual(path_arguments(["run", "-v", "C:\\Users\\bob:/home", "img"]), ["run", "C:\\Users\\bob", "img"])
        self.assertEqual(path_arguments(["run", "--mount", "type=bind,src=/,dst=/x", "img"]), ["run", "/", "img"])
        self.assertEqual(path_arguments(["run", "--mount=type=bind,source=/etc,target=/x", "img"]), ["run", "/etc", "img"])
        self.assertEqual(path_arguments(["run", "-v", "namedvolume", "img"]), ["run", "namedvolume", "img"])

    def test_severity_by_how_broad(self):
        got = {f.detail.split(".")[0]: f.severity for f in flags_of(entry("npx", "-y", "@modelcontextprotocol/server-filesystem@1.0.0", "/", "/etc", "/Users/bob", "/Users/bob/project"))[0]
               if f.rule == "mcp.broad-filesystem-path"}
        self.assertEqual(got, {"Path: /": "high", "Path: /etc": "high", "Path: /Users/bob": "medium"})

    def test_a_narrow_folder_is_fine_and_each_broad_path_is_flagged_once(self):
        self.assertEqual(rules(entry("npx", "-y", "@modelcontextprotocol/server-filesystem@1.0.0", "/Users/bob/Desktop", "/Users/bob/Downloads")), [])
        got = flags_of(entry("npx", "-y", "pkg@1.0.0", "/", "/", "--root=/"))[0]
        self.assertEqual(len([f for f in got if f.rule == "mcp.broad-filesystem-path"]), 1)

    def test_docker_mounts_of_the_root_or_home(self):
        got = flags_of(entry("docker", "run", "-i", "--rm", "-v", "/:/host", "--mount", "type=bind,src=/home/bob,dst=/h", "img:1.0.0"))[0]
        self.assertEqual(sorted((f.severity, f.detail.split(".")[0]) for f in got), [("high", "Path: /"), ("medium", "Path: /home/bob")])

    def test_references_are_the_published_owasp_ones_and_no_baseline_is_claimed(self):
        flags, _ = flags_of({"mcpServers": {"a": {"command": "bash", "args": ["-c", "ls", "/"], "env": {"A_KEY": KEY}}, "b": {"command": "npx", "args": ["pkg", "~"]}}})
        text = " ".join(f.detail + f.title + f.fix for f in flags)
        for ref in ("MCP01", "MCP02", "MCP04", "MCP05", "OWASP MCP Top 10"):
            self.assertIn(ref, text)
        self.assertNotIn("Baseline", text)
        self.assertNotIn("CSA", text)


class Everywhere(unittest.TestCase):
    CONFIG = {"mcpServers": {"fs": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/"], "env": {"OPENAI_API_KEY": KEY}},
                             "sh": {"command": "bash", "args": ["-c", "curl -s https://x.y/i.sh | sh"]},
                             "ok": {"command": "npx", "args": ["-y", "pkg@1.2.3", "/Users/bob/project"]},
                             "remote": {"type": "http", "url": "https://mcp.example.com/mcp", "headers": {"Authorization": "Bearer " + GH}}}}

    @classmethod
    def setUpClass(cls):
        cls.repo = make({".mcp.json": json.dumps(cls.CONFIG, indent=1), "app.py": "from openai import OpenAI"})
        cls.out = tempfile.TemporaryDirectory()
        cls.result = run(cls.repo.name, cls.out.name, app="demo")

    @classmethod
    def tearDownClass(cls):
        cls.repo.cleanup()
        cls.out.cleanup()

    def read(self, name):
        with open(os.path.join(self.out.name, name), encoding="utf-8-sig") as fh:
            return fh.read()

    def test_the_flags_are_in_the_result_flags_json_and_the_manifest_worst_first(self):
        saved = json.loads(self.read("flags.json"))
        mcp_rules = [(f["severity"], f["rule"], f["subject"]) for f in saved["flags"] if f["category"] == "mcp"]
        self.assertEqual(sorted(mcp_rules), sorted([("high", "mcp.plaintext-secret", "fs: OPENAI_API_KEY"), ("high", "mcp.plaintext-secret", "remote: Authorization"),
                                                    ("high", "mcp.broad-filesystem-path", "fs"), ("medium", "mcp.unpinned-package", "fs"), ("high", "mcp.shell-command", "sh")]))
        ranks = [F.RANK[f["severity"]] for f in saved["flags"]]
        self.assertEqual(ranks, sorted(ranks, reverse=True))
        self.assertEqual(json.loads(self.read("manifest.json"))["flags"], saved["counts"])
        self.assertEqual(len(self.result["flags"]), len(saved["flags"]))

    def test_each_flag_sits_on_its_component_or_service_in_the_bom(self):
        bom = json.loads(self.read("aibom.cdx.json"))
        self.assertIsNone(validate(bom))
        parts = {p["bom-ref"]: p for p in bom["components"] + bom.get("services", [])}
        on = {ref: sorted(json.loads(p["value"])["rule"] for p in part.get("properties", []) if p["name"] == F.PROPERTY) for ref, part in parts.items()}
        self.assertEqual(on["mcp:.mcp.json:fs"], ["mcp.broad-filesystem-path", "mcp.plaintext-secret", "mcp.unpinned-package"])
        self.assertEqual(on["mcp:.mcp.json:sh"], ["mcp.shell-command"])
        self.assertEqual(on["mcp:.mcp.json:ok"], [])
        self.assertEqual(on["mcp:.mcp.json:remote"], ["mcp.plaintext-secret"])
        carried = sum(1 for part in bom["components"] + bom.get("services", []) + [bom["metadata"]["component"]] for p in part.get("properties", []) if p["name"] == F.PROPERTY)
        self.assertEqual(carried, len(json.loads(self.read("flags.json"))["flags"]))

    def test_the_report_lists_them_in_a_flags_section_worst_first(self):
        md = self.read("report.md")
        self.assertIn("## Flags", md)
        flags_block = md.split("## Flags")[1].split("\n## ")[0]
        self.assertLess(flags_block.index("HIGH"), flags_block.index("MEDIUM"))
        self.assertIn(".mcp.json:", flags_block)
        self.assertIn("id='flags'", self.read("report.html"))

    def test_no_secret_reaches_any_output_file(self):
        for name in os.listdir(self.out.name):
            text = self.read(name)
            for secret in (KEY, GH):
                self.assertNotIn(secret, text, name)

    def test_the_terminal_headline_counts_them(self):
        count, text = F.headline(self.result["flags"])
        self.assertGreaterEqual(count, 5)
        self.assertIn("high", text)

    def test_the_run_is_the_same_every_time(self):
        with tempfile.TemporaryDirectory() as again:
            run(self.repo.name, again, app="demo")
            for name in ("flags.json", "aibom.cdx.json", "mcp.json"):
                with open(os.path.join(again, name), encoding="utf-8") as a, open(os.path.join(self.out.name, name), encoding="utf-8") as b:
                    self.assertEqual(a.read(), b.read(), name)


class Masking(unittest.TestCase):
    """Arguments are stored as text, so a secret inside one must be masked in every form it can take."""

    def test_forms_that_carry_a_secret(self):
        cases = {("run", "-e", "TOKEN=" + LIT, "img"): ["run", "-e", "TOKEN=" + "*" * len(LIT), "img"],
                 ("--env=API_KEY=" + LIT,): ["--env=API_KEY=" + "*" * len(LIT)],
                 ("--header", "Authorization: Bearer " + LIT): ["--header", "Authorization: " + "*" * (len("Bearer ") + len(LIT))],
                 ("-H", "X-Api-Key:" + LIT): ["-H", "X-Api-Key:" + "*" * len(LIT)],
                 ("--set", "apiKey=" + LIT): ["--set", "apiKey=" + "*" * len(LIT)],
                 ("--token", LIT): ["--token", "*" * len(LIT)],
                 ("--api-key=" + LIT,): ["--api-key=" + "*" * len(LIT)],
                 ("--header", "Authorization", "Bearer " + LIT): ["--header", "Authorization", "Bearer " + "*" * len(LIT)]}
        for args, want in cases.items():
            self.assertEqual(mcp.scrub_args(list(args)), want, args)

    def test_whatever_the_detector_finds_is_masked_in_the_stored_arguments(self):
        # The safety-critical rule: a value that is reported as a credential must not survive in the arguments that are saved.
        names = ["TOKEN", "API_KEY", "PASSWORD", "client_secret", "apiKey", "X-Api-Key", "Authorization", "SESSION_COOKIE", "private-key", "AUTH_TOKEN"]
        forms = [lambda n, v: ["-e", f"{n}={v}"], lambda n, v: [f"--env={n}={v}"], lambda n, v: ["--header", f"{n}: {v}"], lambda n, v: ["-H", f"{n}:{v}"],
                 lambda n, v: ["--set", f"{n}={v}"], lambda n, v: [f"--{n}={v}"], lambda n, v: [f"--{n}", v], lambda n, v: [f"{n}={v}"],
                 lambda n, v: ["--header", n, f"Bearer {v}"], lambda n, v: ["--header", f"{n}: Bearer {v}"], lambda n, v: ["--define", f"{n}={v}"]]
        for name in names:
            for build in forms:
                args = build(name, LIT)
                scrubbed = " ".join(mcp.scrub_args(list(args)))
                found = mcp.find_secrets({}, list(args), 1, "")
                self.assertNotIn(LIT, scrubbed, (name, args))
                self.assertTrue(found, (name, args))

    def test_forms_that_must_stay_readable(self):
        for args in (["-e", "TOKEN=${TOKEN}"], ["-e", "MODE=fast"], ["--env=MODE=fast"], ["--header", "Authorization:Bearer ${TOKEN}"], ["https://x.y/z?a=b"], ["--mount", "type=bind,src=/a,dst=/b"],
                     ["--name", "plain"], ["run", "-i", "--rm", "img:1.0.0"], ["--port=8080"], ["-y", "@scope/pkg@1.0.0"]):
            self.assertEqual(mcp.scrub_args(list(args)), list(args), args)

    def test_no_secret_in_any_of_those_forms_reaches_the_server_record_or_the_outputs(self):
        args = ["run", "-e", "TOKEN=" + LIT, "--env=API_KEY=" + PW, "--header", "Authorization: Bearer " + LIT, "-H", "X-Api-Key:" + PW, "img"]
        with make({".mcp.json": json.dumps({"mcpServers": {"s": {"command": "docker", "args": args}}}), "app.py": "from openai import OpenAI"}) as d, tempfile.TemporaryDirectory() as out:
            run(d, out, app="demo")
            for name in os.listdir(out):
                with open(os.path.join(out, name), encoding="utf-8-sig") as fh:
                    text = fh.read()
                for secret in (LIT, PW):
                    self.assertNotIn(secret, text, name)


class CommandLineInTheCommandField(unittest.TestCase):
    """Real configs often write the whole command line in `command` and leave `args` empty."""

    def test_the_split(self):
        for command, args, want in [
            ("npx @playwright/mcp@latest", [], ("npx", ["@playwright/mcp@latest"])),
            ("npx -y pkg@1.0.0 --flag", [], ("npx", ["-y", "pkg@1.0.0", "--flag"])),
            ('bash -c "curl https://x.y | sh"', [], ("bash", ["-c", "curl https://x.y | sh"])),
            ("docker run -i --rm img:1.0.0", [], ("docker", ["run", "-i", "--rm", "img:1.0.0"])),
            ("uvx pkg==1.0 'a b'", [], ("uvx", ["pkg==1.0", "a b"])),
            (r"C:\tools\npx.cmd -y pkg", [], (r"C:\tools\npx.cmd", ["-y", "pkg"])),
            ("npx", [], ("npx", [])),
            ("npx @playwright/mcp@latest", ["--headless"], ("npx @playwright/mcp@latest", ["--headless"])),   # args given: the command is left alone
            ("C:/Program Files/nodejs/node.exe", [], ("C:/Program Files/nodejs/node.exe", [])),            # a path with a space is not a command line
            ("my-tool --flag", [], ("my-tool --flag", [])),                                              # not a program known to take arguments
            ('npx "unclosed', [], ("npx", ['"unclosed'])),
            ("", [], ("", [])),
            ("  npx   pkg  ", [], ("npx", ["pkg"]))]:
            self.assertEqual(mcp.split_command_line(command, list(args)), (want[0], want[1]), (command, args))

    def test_a_whole_command_line_in_command_is_read_as_a_package_and_flagged_like_any_other(self):
        got, found = flags_of({"mcpServers": {"pw": {"command": "npx @playwright/mcp@latest"}, "pinned": {"command": "npx @playwright/mcp@1.2.3"}}})
        by = {s["name"]: s for s in found["servers"]}
        self.assertEqual((by["pw"]["command"], by["pw"]["args"], by["pw"]["launcher"], by["pw"]["package"], by["pw"]["version"], by["pw"]["pinned"]),
                         ("npx", ["@playwright/mcp@latest"], "npx", "@playwright/mcp", "latest", False))
        self.assertEqual(by["pinned"]["pinned"], True)
        self.assertEqual([(f.rule, f.subject) for f in got], [("mcp.unpinned-package", "pw")])

    def test_a_shell_string_and_a_broad_path_in_the_command_field_are_flagged(self):
        got = flags_of({"mcpServers": {"a": {"command": 'bash -c "curl -s https://x.y | sh"'}, "b": {"command": "npx -y @modelcontextprotocol/server-filesystem@1.0.0 /"}}})[0]
        self.assertEqual(sorted((f.subject, f.rule, f.severity) for f in got), [("a", "mcp.shell-command", "high"), ("b", "mcp.broad-filesystem-path", "high")])

    def test_a_secret_written_in_the_command_field_is_masked_and_reported(self):
        got, found = flags_of({"mcpServers": {"s": {"command": f"npx -y pkg@1.0.0 --token {LIT} -e API_KEY={PW}"}}})
        self.assertNotIn(LIT, json.dumps(found))
        self.assertNotIn(PW, json.dumps(found))
        self.assertEqual(sorted(f.subject for f in got), ["s: --token", "s: API_KEY"])

    def test_toml_command_lines_too(self):
        got = flags_of('[mcp_servers.s]\ncommand = "npx @codemcp/workflows@latest"\n', rel=".codex/config.toml")[0]
        self.assertEqual([f.rule for f in got], ["mcp.unpinned-package"])


class ReviewAppFixture(unittest.TestCase):
    """tests/fixtures/review-app has an .cursor/mcp.json that was written to be unsafe: the flags it should raise are known."""

    def test_its_two_servers_raise_exactly_these_flags(self):
        app = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "review-app")
        found = mcp.find(app)
        got = sorted((f.subject, f.rule, f.severity, f.file, f.line) for f in mcp_flags.mcp_flags(found["servers"]))
        self.assertEqual(got, [("filesystem-root", "mcp.broad-filesystem-path", "high", ".cursor/mcp.json", 3),
                               ("filesystem-root", "mcp.unpinned-package", "medium", ".cursor/mcp.json", 3),
                               ("shell-fetch", "mcp.shell-command", "high", ".cursor/mcp.json", 7)])


if __name__ == "__main__":
    unittest.main()
