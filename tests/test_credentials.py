"""Hardcoded AI provider API keys (M3.3): what is recognised, what is not, where, how serious, and that no key ever reaches an output."""
import json
import os
import random
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from aibom_engine import credentials as C
from aibom_engine import flags as F
from aibom_engine.pipeline import run
from aibom_engine.redact import redact
from aibom_engine.triage import FileInfo
from test_mcp import make

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
LETTERS = ALNUM[:52]
HEX = "0123456789abcdef"
B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"


def pick(seed, n, alphabet=ALNUM):
    """Random-looking text built at run time from a fixed seed, so no key-shaped text sits in the repository."""
    rnd = random.Random(seed)
    return "".join(rnd.choice(alphabet) for _ in range(n))


# provider key name -> (a key with that format, rule id, provider)
KEYS = {
    "anthropic": ("sk-ant-api03-" + pick(1, 93, ALNUM + "_-"), "anthropic-api-key", "Anthropic"),
    "anthropic-admin": ("sk-ant-admin01-" + pick(2, 93, ALNUM + "_-"), "anthropic-api-key", "Anthropic"),
    "openai-project": ("sk-proj-" + pick(3, 74, ALNUM + "_-"), "openai-project-key", "OpenAI"),
    "openai-service": ("sk-svcacct-" + pick(4, 58, ALNUM + "_-"), "openai-project-key", "OpenAI"),
    "openai-legacy": ("sk-" + pick(5, 20) + "T3BlbkFJ" + pick(6, 20), "openai-key", "OpenAI"),
    "openrouter": ("sk-or-v1-" + pick(7, 64, HEX), "openrouter-key", "OpenRouter"),
    "huggingface": ("hf_" + pick(8, 34, LETTERS), "huggingface-token", "Hugging Face"),
    "huggingface-org": ("api_org_" + pick(9, 34, LETTERS), "huggingface-org-token", "Hugging Face"),
    "google": ("AIza" + pick(10, 35, ALNUM + "_-"), "google-api-key", "Google"),
    "groq": ("gsk_" + pick(11, 52), "groq-key", "Groq"),
    "xai": ("xai-" + pick(12, 80), "xai-key", "xAI"),
    "perplexity": ("pplx-" + pick(13, 48), "perplexity-key", "Perplexity"),
    "replicate": ("r8_" + pick(14, 37), "replicate-token", "Replicate"),
    "aws": ("AKIA" + pick(15, 16, B32), "aws-access-key", "AWS"),
    "aws-temporary": ("ASIA" + pick(16, 16, B32), "aws-access-key", "AWS"),
    "bedrock": ("ABSK" + pick(17, 120, ALNUM + "+/"), "bedrock-api-key", "Amazon Bedrock"),
}


def scan(text, rel="src/app.py", location=""):
    return C._scan_text(text, rel, location)


def rules(text, **kw):
    return [(f["rule"], f["line"]) for f in scan(text, **kw)]


class Formats(unittest.TestCase):
    def test_every_format_is_recognised_with_its_provider_and_rule(self):
        for name, (key, rule, provider) in KEYS.items():
            got = scan(f'client = Client(api_key="{key}")\n')
            self.assertEqual([(f["rule"], f["provider"], f["how"], f["line"], f["length"]) for f in got], [(rule, provider, "format", 1, len(key))], name)

    def test_in_every_kind_of_file_and_around_every_kind_of_punctuation(self):
        key = KEYS["anthropic"][0]
        for text in (f'ANTHROPIC_API_KEY="{key}"', f"export K={key}", f"key: {key}", f'{{"k": "{key}"}}', f"curl -H 'x-api-key: {key}' https://a.b", f"`{key}`",
                     f"({key})", f"[{key}]", f"<{key}>", f"{key},", f"{key};", f"= {key}", f"# {key}", f"// {key}", f"'{key}'", f"Bearer {key}", f"{key}\n", f"{key}\r\n"):
            self.assertEqual([r for r, _ in rules(text)], ["anthropic-api-key"], text[:30])

    def test_line_numbers_are_the_line_of_the_key_whatever_the_line_ending(self):
        a, b, c = KEYS["openai-project"][0], KEYS["groq"][0], KEYS["xai"][0]
        for eol in ("\n", "\r\n"):
            text = eol.join(["# header", "", f"a = '{a}'", "x = 1", f"b = '{b}'", "", "", f"c = '{c}'"])
            self.assertEqual(rules(text), [("openai-project-key", 3), ("groq-key", 5), ("xai-key", 8)], repr(eol))

    def test_a_key_on_the_first_line_or_the_last_without_a_newline(self):
        key = KEYS["groq"][0]
        self.assertEqual(rules(key), [("groq-key", 1)])
        self.assertEqual(rules("\n\n\n" + key), [("groq-key", 4)])

    def test_two_keys_on_one_line_are_two_findings_on_the_same_line(self):
        a, b = KEYS["groq"][0], KEYS["xai"][0]
        self.assertEqual(rules(f"{a} {b}"), [("groq-key", 1), ("xai-key", 1)])

    def test_a_notebook_and_a_json_file_are_read_as_text(self):
        key = KEYS["huggingface"][0]
        text = json.dumps({"cells": [{"source": [f"os.environ['HF'] = '{key}'"]}]}, indent=1)
        self.assertEqual([r for r, _ in rules(text)], ["huggingface-token"])


class Prefilter(unittest.TestCase):
    def test_every_format_starts_with_a_prefix_the_prefilter_looks_for(self):
        for name, (key, _, _) in KEYS.items():
            self.assertTrue(key.startswith(C.PREFIXES), name)
        self.assertEqual(sorted(C.PREFIXES), sorted({p for p in C.PREFIXES if any(key.startswith(p) for key, _, _ in KEYS.values())}))

    def test_a_text_with_no_prefix_is_not_run_through_the_patterns(self):
        with mock.patch.object(C, "FORMAT_RE") as pattern:
            self.assertEqual(scan("nothing to see here, just words and numbers 12345"), [])
            pattern.finditer.assert_not_called()
            scan("task-runner sk-")
            pattern.finditer.assert_called()


class NotKeys(unittest.TestCase):
    """What a false alarm would look like: each of these must not be reported."""

    def test_an_empty_value_does_not_borrow_the_next_line(self):
        # `OPENAI_API_KEY=` with nothing after it, followed by another setting: the next line is not the key (found on a real .env.example).
        for eol in ("\n", "\r\n"):
            text = "SERPER_API_KEY=" + eol + "OPENAI_API_KEY=" + eol + "OPENAI_MODEL_NAME=gpt-4o" + eol
            self.assertEqual(rules(text, rel=".env.example"), [], repr(eol))
        self.assertEqual(rules("openai_api_key:\n  other_setting_name_1234567890\n", rel="c.yaml"), [])
        self.assertEqual(rules("api_key =\nOTHER_SETTING=value123456789012345\n"), [])

    def test_a_longer_token_that_merely_contains_a_key_shape(self):
        for key in (KEYS["groq"][0], KEYS["huggingface"][0], KEYS["google"][0], KEYS["perplexity"][0]):
            self.assertEqual(rules("a" + key), [], key[:6] + " with a letter before")
            self.assertEqual(rules("_" + key), [], key[:6] + " with an underscore before")
            if key not in (KEYS["groq"][0],):  # Groq's length is open-ended on purpose, so a longer string is still a Groq-shaped key
                self.assertEqual(rules(key + "Z9"), [], key[:6] + " with more after")

    def test_wrong_lengths(self):
        cases = ["hf_" + pick(1, 33, LETTERS), "hf_" + pick(1, 35, LETTERS), "pplx-" + pick(2, 47), "pplx-" + pick(2, 49), "r8_" + pick(3, 36), "r8_" + pick(3, 38),
                 "sk-or-v1-" + pick(4, 63, HEX), "AIza" + pick(5, 34), "AIza" + pick(5, 36), "gsk_" + pick(6, 39), "xai-" + pick(7, 39), "AKIA" + pick(8, 15, B32),
                 "sk-ant-api03-" + pick(9, 79), "sk-proj-" + pick(10, 39), "ABSK" + pick(11, 100, ALNUM + "+/")]
        for key in cases:
            self.assertEqual(rules(f'k = "{key}"'), [], key[:14] + f" ({len(key)})")

    def test_wrong_character_sets(self):
        for key in ("hf_" + pick(1, 33, LETTERS) + "1", "sk-or-v1-" + pick(2, 64, HEX.upper()), "AKIA" + pick(3, 16, "ABCDEFGHIJKLMNOPQRSTUVWXYZ019"), "r8_" + pick(4, 18) + "-" + pick(5, 18),
                    "sk-" + pick(5, 20) + "T3Blbkfj" + pick(6, 20)):
            self.assertEqual(rules(f'k = "{key}"'), [], key[:14])

    def test_examples_and_placeholders(self):
        for key in ("sk-proj-" + "x" * 60, "sk-proj-" + "a" * 60, "sk-proj-" + "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJ", "sk-proj-" + "0123456789" * 5,
                    "sk-proj-your-key-here-" + pick(1, 30), "sk-proj-EXAMPLE" + pick(2, 40), "sk-proj-" + pick(3, 20) + "placeholder" + pick(4, 20), "sk-proj-" + pick(5, 20) + "dummy" + pick(6, 20),
                    "sk-ant-api03-" + "x" * 90, "sk-ant-api03-" + "..." + "x" * 80, "hf_" + "a" * 34, "hf_" + "abcdefghijklmnopqrstuvwxyzABCDEFGH", "gsk_" + "1234567890" * 5,
                    "gsk_" + pick(1, 20) + "fake" + pick(2, 25), "AIza" + "x" * 35, "AIza" + "Sy" + "A" * 33, "r8_" + pick(1, 18) + "sample" + pick(2, 13),
                    "pplx-" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuv", "AKIAIOSFODNN7EXAMPLE", "xai-" + pick(1, 20) + "redacted" + pick(2, 20)):
            self.assertEqual(rules(f'k = "{key}"'), [], key[:24])

    def test_low_entropy_repeated_and_counting_values_that_have_many_distinct_characters(self):
        for key in ("gsk_" + "qzxkvmwjh" * 6, "xai-" + "qzxkvmwjh" * 9, "pplx-" + "qzxkvmwjh" * 5 + "qzx",                            # nine distinct characters: entropy too low
                    "sk-proj-" + pick(1, 30) + "aaaaaaaa" + pick(2, 30), "sk-ant-api03-" + pick(3, 40) + "ZZZZZZZZ" + pick(4, 40),             # a run of one character
                    "sk-proj-" + pick(5, 30) + "012345678" + pick(6, 30), "gsk_" + pick(7, 25) + "abcdefghi" + pick(8, 25),                    # counting
                    "sk-proj-your-" + pick(9, 55), "sk-proj-my-" + pick(10, 55), "xai-" + pick(11, 40) + "REDACTED" + pick(12, 40)):
            self.assertEqual(rules(f'k = "{key}"'), [], key[:30])

    def test_the_entropy_threshold_is_what_rejects_a_value_that_looks_random_enough_otherwise(self):
        low = "gsk_" + "qzxkvmwjh" * 6
        self.assertFalse(C.looks_fake(low))
        self.assertLess(C.entropy(low), 3.5)

    def test_documentation_forms_with_an_ellipsis_or_angle_brackets(self):
        for text in ("OPENAI_API_KEY=sk-proj-...", "key = sk-ant-api03-<your key>", "sk-proj-xxxxxxxx", "export HF_TOKEN=hf_" + "x" * 34, "AIza... (39 characters)"):
            self.assertEqual(rules(text), [], text)

    def test_ordinary_words_and_identifiers(self):
        for text in ("task-manager-running-in-production", "disk-usage-report-for-all-users-on-the-system", "mask-ant-api03-notakey", "AKIA is a prefix", "hf_ is a prefix", "sk-"):
            self.assertEqual(rules(text), [], text)

    def test_entropy_and_looks_fake(self):
        self.assertEqual(C.entropy(""), 0.0)
        self.assertEqual(C.entropy("aaaa"), 0.0)
        self.assertAlmostEqual(C.entropy("abcd"), 2.0)
        self.assertGreater(C.entropy(pick(1, 60)), 4.5)
        for fake in ("sk-" + "x" * 40, "key-0000000000-abc", "abcdefghijklmnopqrstu", "ZYXabcdefghijkl", "my-key-here", "sk-your-key-1234567890abcdef", "a" * 30, "ab" * 20, "12345678901234567890"):
            self.assertTrue(C.looks_fake(fake), fake)
        for real in (KEYS["anthropic"][0], KEYS["groq"][0], KEYS["xai"][0], pick(5, 40), pick(6, 32, HEX)):
            self.assertFalse(C.looks_fake(real), real[:10])


class NamedKeys(unittest.TestCase):
    """Mistral, Cohere and Azure OpenAI keys have no distinctive format: they are reported only under a provider-named name."""

    def named(self, text):
        return [(f["provider"], f["rule"], f["how"], f["line"]) for f in scan(text)]

    def test_provider_named_settings_with_a_literal_value(self):
        mistral, cohere, azure = pick(1, 32), pick(2, 40), pick(3, 32, HEX)
        for text, want in ((f'MISTRAL_API_KEY="{mistral}"', "Mistral"), (f"COHERE_API_KEY={cohere}", "Cohere"), (f'export AZURE_OPENAI_API_KEY="{azure}"', "OpenAI"),
                           (f'"mistralApiKey": "{mistral}"', "Mistral"), (f"cohere_token: {cohere}", "Cohere"), (f"mistral_api_key = '{mistral}'", "Mistral"),
                           (f'client = Mistral(mistral_api_key="{mistral}")', "Mistral"), (f"  TOGETHER_API_KEY: '{cohere}'", "Together"),
                           (f'DEEPSEEK_API_KEY = "{mistral}"', "DeepSeek"), (f'os.environ["GROQ_API_KEY"] = "{mistral}"', "Groq"), (f"LANGSMITH_API_KEY={mistral}", "LangSmith")):
            self.assertEqual(self.named(text), [(want, "named-key", "name", 1)], text)

    def test_the_same_value_under_an_unrelated_name_is_not_reported(self):
        value = pick(1, 40)
        for text in (f'API_KEY="{value}"', f'SECRET_KEY="{value}"', f'DATABASE_TOKEN="{value}"', f'session_token = "{value}"', f'hash = "{value}"', f'FOO_KEY="{value}"'):
            self.assertEqual(self.named(text), [], text)

    def test_lookups_placeholders_and_non_secrets_are_not_reported(self):
        for value in ("${MISTRAL_API_KEY}", "$MISTRAL_API_KEY", "%MISTRAL_API_KEY%", "{{ secrets.mistral }}", "<your-mistral-key-here-12345>", "YOUR_MISTRAL_API_KEY_HERE", "os.getenv('MISTRAL_API_KEY')",
                      "process.env.MISTRAL_API_KEY", "MISTRAL_API_KEY_VALUE_FROM_ENV", "https://api.mistral.ai/v1/chat/completions", "/etc/secrets/mistral_api_key", "C:\\keys\\mistral.key",
                      "mistral-api-key-from-the-vault-1", pick(1, 19), pick(2, 40, LETTERS), pick(3, 40, "0123456789"), "a" * 40, "x1" * 20, "replace-with-your-key-123456", "changeme-please-1234567890",
                      "sample-mistral-key-1234567890", "true", "12345678901234567890"):
            self.assertEqual(self.named(f'MISTRAL_API_KEY = "{value}"'), [], value)
            self.assertEqual(self.named(f"MISTRAL_API_KEY={value}"), [], value)

    def test_values_the_name_rule_refuses_for_their_own_reasons(self):
        for value in ("Ab3dE6gH9jK2...mN5pQ8sT1vW4", "7f3a9c1e5b" * 3 + "7f", "MISTRAL_KEY_V2_FROM_ENV_PROD_01", "Ab3dE6gH9jK2mN5pQ8sT1vW4yZ" + "..." + "x"):
            self.assertEqual(self.named(f'MISTRAL_API_KEY = "{value}"'), [], value)
        self.assertFalse(C._literal_key(pick(1, 19)))
        self.assertFalse(C._literal_key("7f3a9c1e5b" * 3 + "7f"))
        self.assertFalse(C._literal_key("MISTRAL_KEY_V2_FROM_ENV_PROD_01"))
        self.assertTrue(C._literal_key(pick(2, 32)))

    def test_every_provider_word_is_recognised_in_a_name(self):
        value = pick(3, 36)
        expected = {"openai": "OpenAI", "anthropic": "Anthropic", "mistral": "Mistral", "cohere": "Cohere", "groq": "Groq", "gemini": "Google", "google": "Google", "together": "Together",
                    "replicate": "Replicate", "hugging": "Hugging Face", "huggingface": "Hugging Face", "deepseek": "DeepSeek", "openrouter": "OpenRouter", "fireworks": "Fireworks",
                    "perplexity": "Perplexity", "pplx": "Perplexity", "voyage": "Voyage", "elevenlabs": "ElevenLabs", "eleven_labs": "ElevenLabs", "langsmith": "LangSmith",
                    "langchain": "LangSmith", "tavily": "Tavily", "pinecone": "Pinecone", "xai": "xAI", "grok": "xAI", "cerebras": "Cerebras", "nvidia": "NVIDIA", "jina": "Jina",
                    "stability": "Stability AI", "assemblyai": "AssemblyAI", "deepgram": "Deepgram", "sambanova": "SambaNova"}
        self.assertEqual(dict(C.PROVIDER_WORDS), expected)  # the table is pinned here on purpose: dropping a provider must fail a test
        for word, provider in expected.items():
            self.assertEqual(self.named(f'{word.upper()}_API_KEY="{value}"'), [(provider, "named-key", "name", 1)], word)

    def test_a_provider_named_setting_that_is_not_a_key_is_not_reported(self):
        for text in ('openai_model = "gpt-4o-2024-08-06-extra-long-name-123"', 'MISTRAL_BASE_URL = "https://eu.api.mistral.ai/v1/xyz123456"', 'cohere_model: "command-r-plus-08-2024-abc123"',
                     'OPENAI_ORG_ID = "org-AbCdEfGhIjKlMnOpQrStUv123"', 'groq_timeout = "30000000000000000000000"'):
            self.assertEqual(self.named(text), [], text)

    def test_a_format_match_under_a_provider_name_is_one_finding_not_two(self):
        key = KEYS["groq"][0]
        self.assertEqual(self.named(f'GROQ_API_KEY = "{key}"'), [("Groq", "groq-key", "format", 1)])
        a, b = KEYS["openai-project"][0], pick(5, 40)
        self.assertEqual(self.named(f'OPENAI_API_KEY="{a}"\nMISTRAL_API_KEY="{b}"'), [("OpenAI", "openai-project-key", "format", 1), ("Mistral", "named-key", "name", 2)])

    def test_the_name_rule_does_not_hang_on_long_or_odd_lines(self):
        import time
        for text in ("token = " + "A" * 2_000_000, "openai_key_x" * 200_000, "a" * 500_000 + "_key=", "key=" * 200_000, ("MISTRAL_API_KEY=" + "9" * 30 + "\n") * 5000):
            t = time.time()
            scan(text)
            self.assertLess(time.time() - t, 5, text[:20])


class Placement(unittest.TestCase):
    def test_where_a_file_sits(self):
        for rel, category, want in (("src/app.py", "code", ""), (".env", "config", ""), ("config/settings.yaml", "config", ""), ("tests/test_a.py", "test", "test"),
                                    ("examples/demo/app.py", "code", "example"), ("docs/guide.md", "docs", "docs"), ("README.md", "docs", "docs"), (".env.example", "config", "example"),
                                    ("config/app.sample.json", "config", "example"), (".env.template", "config", "example"), ("vendor/lib/a.py", "code", "vendored"),
                                    ("results/run1.json", "data", "data"), ("notebooks/a.ipynb", "notebook", ""), ("deploy/Dockerfile", "config", ""), ("src/__tests__/a.ts", "test", "test")):
            self.assertEqual(C.location_of(rel, category), want, rel)

    def test_severity_by_how_it_was_recognised_and_where(self):
        live_format = {"provider": "OpenAI", "rule": "openai-project-key", "how": "format", "file": "a.py", "line": 3, "length": 80, "location": ""}
        live_name = {**live_format, "provider": "Mistral", "rule": "named-key", "how": "name"}
        in_test = {**live_format, "location": "test"}
        got = C.credential_flags([live_format, live_name, in_test, {**live_name, "location": "example", "file": ".env.example"}])
        self.assertEqual([(f.severity, f.subject, f.file, f.rule, f.category, f.ref) for f in got],
                         [("high", "OpenAI", "a.py", "secret.api-key", "secret", ""), ("medium", "Mistral", "a.py", "secret.api-key", "secret", ""),
                          ("low", "OpenAI", "a.py", "secret.api-key", "secret", ""), ("low", "Mistral", ".env.example", "secret.api-key", "secret", "")])
        self.assertIn("rotate", got[0].fix)
        self.assertIn("80 characters", got[0].detail)
        covered = C.credential_flags([live_format, {**live_name, "line": 9}], covered={(live_format["file"], live_format["line"])})
        self.assertEqual([f.subject for f in covered], ["Mistral"])          # a place another flag reports is not flagged again
        self.assertIn("not stored", got[0].detail)
        self.assertIn("may be a sample", got[2].detail)
        self.assertNotIn("may be a sample", got[0].detail)
        self.assertEqual((got[0].line, got[0].title), (3, "A OpenAI API key is written in this file."))

    def test_the_summary_counts_the_products_own_files_apart(self):
        found = {"findings": [{"location": "", "file": "a"}, {"location": "", "file": "a"}, {"location": "", "file": "b"}, {"location": "test", "file": "t"}], "files_scanned": 9}
        self.assertEqual(C.summary(found), {"keys": 3, "files": 2, "other": 1, "scanned": 9})
        self.assertEqual(C.summary({"findings": [], "files_scanned": 0}), {"keys": 0, "files": 0, "other": 0, "scanned": 0})


class Files(unittest.TestCase):
    KEY = KEYS["openai-project"][0]

    def found(self, files, **kw):
        with make(files) as d:
            from aibom_engine.triage import triage
            return C.find(d, triage(d), **kw)

    def test_the_products_files_and_hidden_config_files_are_read(self):
        got = self.found({"src/a.py": f'k = "{self.KEY}"', ".env": f"OPENAI_API_KEY={self.KEY}", "deploy/Dockerfile": f"ENV K={self.KEY}", "app.config.json": f'{{"k": "{self.KEY}"}}'})
        self.assertEqual(sorted(f["file"] for f in got["findings"]), [".env", "app.config.json", "deploy/Dockerfile", "src/a.py"])
        self.assertTrue(all(f["location"] == "" for f in got["findings"]))

    def test_locks_minified_translations_and_dependency_folders_are_skipped(self):
        got = self.found({"package-lock.json": self.KEY, "yarn.lock": self.KEY, "dist/app.min.js": self.KEY, "i18n/en.json": self.KEY, "node_modules/p/i.js": self.KEY, ".git/config": self.KEY,
                          "locales/fr.json": self.KEY})
        self.assertEqual(got["findings"], [])

    def test_binary_empty_and_oversized_files_are_skipped_and_odd_text_is_read(self):
        with make({"a.txt": "", "big.py": "x" * 10}) as d:
            with open(os.path.join(d, "bin.dat"), "wb") as fh:
                fh.write(b"\x00\x01" + self.KEY.encode() + b"\x00")
            with open(os.path.join(d, "latin.py"), "wb") as fh:
                fh.write(b"# caf\xe9\nk = '" + self.KEY.encode() + b"'\n")
            with open(os.path.join(d, "huge.py"), "w") as fh:
                fh.write(self.KEY + "\n" + "#" * 1_600_000)
            from aibom_engine.triage import triage
            got = C.find(d, triage(d))
        self.assertEqual([(f["file"], f["line"]) for f in got["findings"]], [("latin.py", 2)])
        self.assertEqual(got["problems"], [])

    def test_a_symbolic_link_is_not_followed(self):
        with make({"real.py": f'k = "{self.KEY}"'}) as d:
            from aibom_engine.triage import triage
            files = triage(d)
            with mock.patch("aibom_engine.credentials.os.path.islink", return_value=True):
                self.assertEqual(C.find(d, files)["findings"], [])

    def test_an_unreadable_file_is_a_problem_and_the_rest_are_still_read(self):
        with make({"a.py": f'k = "{self.KEY}"', "b.py": "x = 1"}) as d:
            from aibom_engine.triage import triage
            files = triage(d)
            real = open

            def flaky(path, *a, **k):
                if str(path).endswith("b.py"):
                    raise OSError("denied")
                return real(path, *a, **k)
            with mock.patch("builtins.open", side_effect=flaky):
                got = C.find(d, files)
        self.assertEqual([f["file"] for f in got["findings"]], ["a.py"])
        self.assertEqual([p["file"] for p in got["problems"]], ["b.py"])

    def test_findings_are_ordered_live_first_then_by_file_and_line(self):
        got = self.found({"tests/t.py": f'k = "{self.KEY}"', "z.py": f'k = "{self.KEY}"\nj = "{self.KEY}"', "a.py": f'k = "{self.KEY}"'})
        self.assertEqual([(f["file"], f["line"], f["location"]) for f in got["findings"]], [("a.py", 1, ""), ("z.py", 1, ""), ("z.py", 2, ""), ("tests/t.py", 1, "test")])

    def test_caps_per_file_and_in_total_and_the_time_limit(self):
        many = "\n".join(f'k{i} = "{pick(i, 74, ALNUM)}"' for i in range(60))
        text = "\n".join(f'k{i} = "sk-proj-{pick(i, 74, ALNUM)}"' for i in range(60))
        self.assertEqual(len(scan(text)), 60)  # scanning a text reports every key; the cap is applied per file and in all by find()
        self.assertEqual(scan(many), [])
        one = self.found({"a.py": text})
        self.assertEqual((len(one["findings"]), one["truncated"]), (C.MAX_PER_FILE, True))   # one file full of keys cannot bury the rest
        few = self.found({"a.py": "\n".join(text.splitlines()[:3])})
        self.assertEqual((len(few["findings"]), few["truncated"]), (3, False))
        got = self.found({f"f{i}.py": text for i in range(30)})
        self.assertEqual((len(got["findings"]), got["truncated"]), (C.MAX_FINDINGS, True))
        self.assertTrue(self.found({"a.py": f'k = "{self.KEY}"'}, deadline=1)["partial"])
        self.assertFalse(self.found({"a.py": f'k = "{self.KEY}"'})["partial"])

    def test_the_same_files_give_the_same_findings(self):
        files = {f"p{i}/a.py": f'k = "{self.KEY}"' for i in range(5)}
        self.assertEqual(json.dumps(self.found(files)), json.dumps(self.found(dict(reversed(list(files.items()))))))

    def test_a_finding_holds_no_part_of_the_key(self):
        got = self.found({"a.py": f'k = "{self.KEY}"'})
        blob = json.dumps(got)
        for piece in (self.KEY, self.KEY[8:30], self.KEY[-20:]):
            self.assertNotIn(piece, blob)
        self.assertEqual(sorted(got["findings"][0]), ["file", "how", "length", "line", "location", "provider", "rule"])


class Masking(unittest.TestCase):
    def test_every_format_is_masked_by_redact_wherever_it_appears(self):
        for name, (key, _, _) in KEYS.items():
            for text in (f"see {key} here, model gpt-4o", f"Authorization: {key}", f"x = [{key}, 'gpt-4o']"):  # bare: no key= name to give it away
                out = redact(text)
                self.assertNotIn(key, out, (name, text))
                self.assertTrue(out.startswith(text.split(key)[0]), (name, text))        # the text around the key is kept
                self.assertEqual(out.endswith("gpt-4o"), text.endswith("gpt-4o"))
                self.assertIn("*" * len(key), out, (name, text))

    def test_the_new_formats_are_masked_and_ordinary_text_is_not(self):
        for text in ("gsk-is-a-prefix", "xai-model-name", "pplx-api", "r8_", "ABSKx", "the task-runner", "ASIAN markets"):
            self.assertEqual(redact(text), text, text)


class Everywhere(unittest.TestCase):
    """The whole scan: every output carries the finding and none carries a key."""

    LIVE = {"openai": KEYS["openai-project"][0], "anthropic": KEYS["anthropic"][0], "google": KEYS["google"][0], "mistral": pick(77, 32),
            "mcp": "sk-proj-" + pick(78, 74, ALNUM + "_-")}
    FILES = {
        "src/client.py": f'from openai import OpenAI\nclient = OpenAI(api_key="{LIVE["openai"]}")\nclient.chat.completions.create(model="gpt-4o-2024-08-06", messages=[])\n',
        ".env": f'ANTHROPIC_API_KEY={LIVE["anthropic"]}\nMISTRAL_API_KEY={LIVE["mistral"]}\nGOOGLE_API_KEY=${{GOOGLE_API_KEY}}\n',
        "config/app.yaml": f"google:\n  key: {LIVE['google']}\n",
        "tests/test_client.py": f'KEY = "{KEYS["groq"][0]}"\n',
        ".env.example": "OPENAI_API_KEY=sk-proj-your-key-here\nANTHROPIC_API_KEY=\n",
        "src/line.py": f'x = OpenAI(api_key="{KEYS["xai"][0]}", model="gpt-4o-mini")\n',
        "docs/guide.md": "Set OPENAI_API_KEY=sk-proj-... in your shell.\n",
        ".mcp.json": '{"mcpServers": {"s": {"command": "npx", "args": ["-y", "s-mcp@1.0.0"],\n  "env": {"OPENAI_API_KEY": "' + LIVE["mcp"] + '"}}}}\n',
    }

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

    def secret_values(self):
        values = list(self.LIVE.values()) + [KEYS["groq"][0], KEYS["xai"][0]]
        return values + [v[len(v) // 3: len(v) // 3 + 24] for v in values]  # the key, and a piece from the middle of it

    def test_no_output_file_holds_any_key_or_piece_of_one(self):
        for name in os.listdir(self.out.name):
            text = self.read(name)
            for secret in self.secret_values():
                self.assertNotIn(secret, text, name)

    def test_credentials_json_manifest_and_result_agree(self):
        saved = json.loads(self.read("credentials.json"))
        got = sorted((f["file"], f["line"], f["provider"], f["how"], f["location"]) for f in saved["findings"])
        self.assertEqual(got, sorted([("src/client.py", 2, "OpenAI", "format", ""), (".env", 1, "Anthropic", "format", ""), (".env", 2, "Mistral", "name", ""),
                                      ("config/app.yaml", 2, "Google", "format", ""), ("src/line.py", 1, "xAI", "format", ""), ("tests/test_client.py", 1, "Groq", "format", "test"),
                                      (".mcp.json", 2, "OpenAI", "format", "")]))
        summary = {"keys": 6, "files": 5, "other": 1, "scanned": saved["files_scanned"]}
        self.assertEqual(json.loads(self.read("manifest.json"))["secrets"], summary)
        self.assertEqual(self.result["secrets"], summary)

    def test_each_key_is_a_flag_with_its_severity_in_flags_json_and_the_bom(self):
        saved = json.loads(self.read("flags.json"))
        secret = sorted((f["severity"], f["subject"], f["file"], f["line"]) for f in saved["flags"] if f["category"] == "secret")
        self.assertEqual(secret, sorted([("high", "OpenAI", "src/client.py", 2), ("high", "Anthropic", ".env", 1), ("medium", "Mistral", ".env", 2), ("high", "Google", "config/app.yaml", 2),
                                         ("high", "xAI", "src/line.py", 1), ("low", "Groq", "tests/test_client.py", 1)]))
        # The key in .mcp.json is counted as a key but flagged once, by the MCP rule, which names the server (found in the M3 manual test).
        at = [(f["rule"], f["severity"]) for f in saved["flags"] if (f["file"], f["line"]) == (".mcp.json", 2)]
        self.assertEqual(at, [("mcp.plaintext-secret", "high")])
        bom = json.loads(self.read("aibom.cdx.json"))
        app = [json.loads(p["value"]) for p in bom["metadata"]["component"]["properties"] if p["name"] == F.PROPERTY]
        self.assertEqual(len([a for a in app if a["rule"] == "secret.api-key"]), 6)

    def test_the_report_lists_them_by_file_and_line_with_no_value(self):
        md = self.read("report.md")
        self.assertIn("secret.api-key" if False else "A OpenAI API key is written in this file.", md)
        block = md.split("## Flags")[1].split("\n## ")[0]
        for place in ("src/client.py:2", ".env:1", ".env:2", "config/app.yaml:2", "src/line.py:1", "tests/test_client.py:1"):
            self.assertIn(place, block)
        self.assertLess(block.index("HIGH"), block.index("LOW"))
        self.assertIn("id='flags'", self.read("report.html"))
        self.assertIn("Hardcoded API keys are found in the files on disk", self.read("report.md"))

    def test_a_key_on_the_same_line_as_a_model_name_is_masked_in_the_model_data(self):
        merged = self.read("merged.json") + self.read("findings.json")
        self.assertIn("gpt-4o-mini", merged)
        self.assertNotIn(KEYS["xai"][0], merged)

    def test_the_plain_terminal_summary_counts_the_keys(self):
        r = subprocess.run([sys.executable, "-m", "aibom_engine", "scan", self.repo.name, "--out", os.path.join(self.out.name, "again")], cwd=ROOT, capture_output=True, text=True,
                           env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
        self.assertEqual(r.returncode, 0, r.stderr)
        line = next(l for l in r.stdout.splitlines() if "hardcoded API keys" in l and "(values" in l)
        self.assertEqual(" ".join(line.split()), "6 hardcoded API keys in 5 files; 1 more in tests, examples or documentation (values are never stored; the report lists each file and line)")
        for secret in self.secret_values():
            self.assertNotIn(secret, r.stdout + r.stderr)

    def test_the_dashboard_row(self):
        from aibom_engine import screens, ui
        from test_ui import drawn, recorded
        result = {"app": "demo", "seconds": 1.0, "used": 0, "listed": 0, "left_out": 0, "rows": {"used": [], "listed": []}, "packages": {}, "warnings": [], "items": 0,
                  "secrets": {"keys": 3, "files": 2, "other": 1, "scanned": 9}}
        try:
            con = recorded()
            screens.dashboard(result, "runs/demo", [], mock.Mock(ok=False), "aibom", "", "9.9")
            self.assertIn("3 hardcoded API keys in 2 files; 1 more in tests, examples or documentation (values are never stored)", " ".join(drawn(con).split()))
            con = recorded()
            result["secrets"] = {"keys": 0, "files": 0, "other": 2, "scanned": 9}
            screens.dashboard(result, "runs/demo", [], mock.Mock(ok=False), "aibom", "", "9.9")
            self.assertIn("0 hardcoded API keys in 0 files; 2 more in tests, examples or documentation", " ".join(drawn(con).split()))   # samples are still shown
            con = recorded()
            result["secrets"] = {"keys": 0, "files": 0, "other": 0, "scanned": 9}
            screens.dashboard(result, "runs/demo", [], mock.Mock(ok=False), "aibom", "", "9.9")
            self.assertNotIn("hardcoded API keys", drawn(con))
        finally:
            ui.use_console(None)

    def test_rebuild_and_the_pdf_page_keep_the_flags(self):
        from aibom_engine.cli import make_pdf
        with mock.patch("aibom_engine.pdf.print_to_pdf", side_effect=lambda page, path: page):
            self.assertIn("tests/test_client.py:1", make_pdf(self.out.name))

    def test_the_run_is_the_same_every_time(self):
        with tempfile.TemporaryDirectory() as again:
            run(self.repo.name, again, app="demo")
            for name in ("credentials.json", "flags.json", "aibom.cdx.json"):
                with open(os.path.join(again, name), encoding="utf-8") as a, open(os.path.join(self.out.name, name), encoding="utf-8") as b:
                    self.assertEqual(a.read(), b.read(), name)

    def test_a_repository_without_keys_says_nothing(self):
        with make({"app.py": "from openai import OpenAI\n"}) as d, tempfile.TemporaryDirectory() as out:
            result = run(d, out, app="demo")
            self.assertEqual(result["secrets"]["keys"], 0)
            with open(os.path.join(out, "credentials.json"), encoding="utf-8") as fh:
                self.assertEqual(json.load(fh)["findings"], [])
            self.assertFalse([f for f in result["flags"] if f.category == "secret"])

    def test_a_failure_in_the_key_search_never_stops_the_scan(self):
        with make({"app.py": 'from openai import OpenAI\nOpenAI().chat.completions.create(model="gpt-4o-2024-08-06", messages=[])\n'}) as d, tempfile.TemporaryDirectory() as out:
            with mock.patch("aibom_engine.pipeline.credential_finder.find", side_effect=RuntimeError("boom")):
                result = run(d, out, app="demo")
            self.assertTrue(result["valid"])
            self.assertGreaterEqual(result["used"], 1)
            self.assertTrue(any("search for hardcoded API keys failed" in w for w in result["warnings"]))

    def test_a_search_cut_short_or_capped_is_a_warning(self):
        cut = {"findings": [], "files_scanned": 3, "problems": [{"file": "x.py", "error": "denied"}], "partial": True, "truncated": True}
        with make({"app.py": "from openai import OpenAI\n"}) as d, tempfile.TemporaryDirectory() as out:
            with mock.patch("aibom_engine.pipeline.credential_finder.find", return_value=cut):
                result = run(d, out, app="demo")
            text = " ".join(result["warnings"])
            for needle in ("time limit was reached while looking for hardcoded API keys", "More possible API keys were found than are listed", "Could not read x.py while looking for hardcoded API keys"):
                self.assertIn(needle, text)

    def test_the_key_search_runs_before_the_slow_steps(self):
        lines = []
        with make({"app.py": "from openai import OpenAI\n"}) as d, tempfile.TemporaryDirectory() as out:
            run(d, out, app="demo", log=lines.append)
        text = [l.strip() for l in lines]
        self.assertLess(text.index("Looking for hardcoded API keys ..."), text.index("Reading dependency files ..."))


if __name__ == "__main__":
    unittest.main()
