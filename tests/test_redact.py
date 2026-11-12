"""A key on the same line as a model name must never reach the AI-BOM, the JSON files or the reports."""
import os
import subprocess
import sys
import tempfile
import unittest

from aibom_engine.finding import Finding
from aibom_engine.redact import redact

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
KEYS = {
    "openai": "sk-proj-AbCdEfGh1234567890abcdefXYZ",
    "anthropic": "sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789",
    "aws": "AKIAIOSFODNN7EXAMPLE",
    "github": "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
    "huggingface": "hf_abcdefghijklmnopqrstuvwxyzABCDEFGH",
    "google": "AIzaSyA-1234567890abcdefghijklmnopqrstuv",
    "slack": "xoxb-1234567890-abcdefghijkl",
    "jwt": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnop",
}


class Secrets(unittest.TestCase):
    def test_well_known_key_formats_are_masked(self):
        for name, key in KEYS.items():
            line = 'client = Client(name="%s", model="gpt-4o")' % key  # no "key" or "secret" in the name: only the format can give it away
            out = redact(line)
            self.assertNotIn(key, out, name)
            self.assertNotIn(key[6:], out, name)
            self.assertIn('model="gpt-4o"', out, name)

    def test_a_value_given_to_a_name_that_says_it_is_secret(self):
        for line in ('api_key = "abcd1234efgh"', "api_key='abcd1234efgh'", 'cfg = {"token": "abcd1234efgh"}', 'password = "hunter2hunter2"',
                     'headers = {"Authorization": "Bearer abcdefghijklmnopqrstuvwx"}', "client_secret: 'abcd1234efgh'", "OPENAI_API_KEY=\"abcd1234efgh\""):
            out = redact(line)
            self.assertNotRegex(out, r"abcd1234efgh|hunter2hunter2|abcdefghijklmnopqrstuvwx", line)

    def test_a_password_in_a_url_is_masked_and_the_rest_of_the_url_stays(self):
        out = redact('url = "https://deploy:s3cretpass@registry.example.com/simple"')
        self.assertNotIn("s3cretpass", out)
        self.assertIn("https://deploy:", out)
        self.assertIn("@registry.example.com", out)

    def test_a_private_key_block_is_masked(self):
        out = redact("k = '-----BEGIN RSA PRIVATE KEY-----MIIEowIBAAKCAQEAxyz-----END RSA PRIVATE KEY-----'")
        self.assertNotIn("MIIEow", out)

    def test_the_line_keeps_its_length_so_the_column_of_the_model_stays_right(self):
        line = 'OpenAI(api_key="%s"); model="gpt-4o"' % KEYS["openai"]
        out = redact(line)
        self.assertEqual(len(out), len(line))
        self.assertEqual(out.index('model="gpt-4o"'), line.index('model="gpt-4o"'))

    def test_things_that_are_not_secrets_are_left_alone(self):
        for line in ('model="gpt-4o-2024-08-06"', 'api_key=os.environ["OPENAI_API_KEY"]', 'api_key="your-api-key-here"', 'api_key=""', "max_tokens = 4096",
                     'tokenizer="cl100k_base"', 'token_limit = "8192"', 'password_field = "password"', "from openai import OpenAI",
                     'client = OpenAI(api_key="${OPENAI_API_KEY}")', "api_key='<your key>'", 'embedding_model: "text-embedding-3-small"',
                     "const key = process.env.OPENAI_API_KEY", "ssh://git@github.com/owner/repo.git", "https://example.com/a:b/c"):
            self.assertEqual(redact(line), line)

    def test_empty_and_short_text(self):
        self.assertEqual(redact(""), "")
        self.assertEqual(redact(None), None)
        self.assertEqual(redact("x=1"), "x=1")

    def test_a_finding_masks_its_own_line(self):
        f = Finding(tool="context", kind="model", name="gpt-4o", snippet='OpenAI(api_key="%s", model="gpt-4o")' % KEYS["openai"])
        self.assertNotIn(KEYS["openai"], f.snippet)
        self.assertNotIn(KEYS["openai"], str(f.to_dict()))


class WholeScan(unittest.TestCase):
    """A real scan of an app that has keys next to its model names: no output file may hold a key."""

    def test_no_output_file_holds_a_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            app = os.path.join(tmp, "app")
            os.makedirs(os.path.join(app, "src"))
            with open(os.path.join(app, "src", "main.py"), "w", encoding="utf-8") as f:
                f.write('from openai import OpenAI; boot = OpenAI(api_key="%s")\n' % KEYS["anthropic"])  # an import line that also holds a key
                f.write("from openai import OpenAI\n"
                        'client = OpenAI(api_key="%s"); r = client.chat.completions.create(model="gpt-4o", messages=[])\n' % KEYS["openai"])
            with open(os.path.join(app, "src", "chat.js"), "w", encoding="utf-8") as f:
                f.write('import OpenAI from "openai"; const first = new OpenAI({ apiKey: "%s" });\n' % KEYS["slack"])
                f.write('import OpenAI from "openai";\nconst c = new OpenAI({ apiKey: "%s" }); c.chat.completions.create({ model: "gpt-4o-mini" });\n' % KEYS["github"])
            out = os.path.join(tmp, "out")
            done = subprocess.run([sys.executable, "-m", "aibom_engine", "scan", app, "--out", out, "--quiet"], cwd=ROOT, capture_output=True, text=True, timeout=300)
            self.assertEqual(done.returncode, 0, done.stderr)
            seen = 0
            for name in os.listdir(out):
                with open(os.path.join(out, name), encoding="utf-8-sig", errors="replace") as f:
                    text = f.read()
                seen += 1
                for key in (KEYS["openai"], KEYS["github"], KEYS["anthropic"], KEYS["slack"], KEYS["openai"][3:]):
                    self.assertNotIn(key, text, "%s holds a key" % name)
            self.assertGreater(seen, 8)
            with open(os.path.join(out, "findings.json"), encoding="utf-8") as f:
                self.assertIn('model=\\"gpt-4o\\"', f.read())  # the proof line is still there


if __name__ == "__main__":
    unittest.main()
