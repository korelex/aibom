import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from aibom_engine import verify  # noqa: E402
from aibom_engine.finders import shapes  # noqa: E402
from aibom_engine.finders.dictionary import load_names  # noqa: E402
from aibom_engine.triage import FileInfo  # noqa: E402

NAMES = load_names()
FAMS = shapes.families(NAMES)


def scan(rel, text):
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            f.write(text)
        return {f.name for f in shapes.run(d, [FileInfo(rel.replace(os.sep, "/"), "code" if not rel.endswith((".bicep", ".json", ".yaml")) else "config", len(text))], NAMES)}


class Constants(unittest.TestCase):
    def test_go_constants_that_spell_the_string(self):
        got = scan("c.go", 'const (\n\tGPT432K0314 = "gpt-4-32k-0314"\n\tGPT3Dot5TurboInstruct = "gpt-3.5-turbo-instruct"\n\tGPT3TextDavinci003 = "text-davinci-003"\n\tO1 = "o1"\n\tO120241217 = "o1-2024-12-17"\n)\n')
        self.assertEqual(got, {"gpt-4-32k-0314", "gpt-3.5-turbo-instruct", "text-davinci-003", "o1", "o1-2024-12-17"})

    def test_other_languages(self):
        self.assertIn("gpt-4o", scan("M.swift", 'static let gpt4_o = "gpt-4o"\n'))
        self.assertIn("claude-3-opus-20240229", scan("a.ts", "export const CLAUDE_3_OPUS_20240229 = 'claude-3-opus-20240229';\n"))
        self.assertIn("gpt-4o", scan("A.java", 'public static final String GPT_4_O = "gpt-4o";\n'))

    def test_constants_that_do_not_spell_a_model_are_ignored(self):
        self.assertEqual(scan("c.go", 'const MaxTokens4096 = "max-tokens-4096"\nconst Region1 = "eastus-1"\nconst Version2 = "v2-2024"\n'), set())

    def test_a_name_that_does_not_match_its_string_is_ignored(self):
        self.assertEqual(scan("c.go", 'const Default = "gpt-4o"\n'), set())


class Keys(unittest.TestCase):
    def test_learned_key_picks_up_the_other_values(self):
        got = scan("m.ts", 'const A = [\n { name: "gpt-4o", x: 1 },\n { name: "o1", x: 2 },\n { name: "claude-sonnet-4-0", x: 3 },\n { name: "Label only", x: 4 },\n]\n')
        self.assertTrue({"gpt-4o", "o1", "claude-sonnet-4-0"} <= got)
        self.assertNotIn("Label only", got)

    def test_type_words_are_never_learned_as_keys(self):
        text = "param a string = 'gpt-4o'\nparam b string = 'gpt-4o-mini'\nparam c string = 'gptkbindex'\nparam d string = 'embedding'\nparam e string = 'eastus2'\n"
        self.assertTrue({"gptkbindex", "embedding", "eastus2"}.isdisjoint(scan("m.bicep", text)))

    def test_key_must_mostly_hold_models(self):
        text = "\n".join([f'{{ title: "page {i}" }}' for i in range(10)] + ['{ title: "gpt-4o" }', '{ title: "gpt-4o-mini" }', '{ title: "gpt-5" }'])
        self.assertEqual(scan("a.ts", text), set())

    def test_bare_family_under_a_model_key(self):
        self.assertEqual(scan("e.ts", "const r = await chat({ model: 'llava', x: 1 })\nconst s = await chat({ model: 'default' })\n"), {"llava"})


class Shapes(unittest.TestCase):
    def test_glued_versions_and_bedrock_ids(self):
        got = scan("r.ts", "run('llama3.1:8b'); run('llama3.2-vision'); x = ['anthropic.claude-3-haiku-v1', 'us.anthropic.claude-sonnet-4-6-v1:0']\n")
        self.assertEqual(got, {"llama3.1:8b", "llama3.2-vision", "anthropic.claude-3-haiku-v1", "us.anthropic.claude-sonnet-4-6-v1:0"})

    def test_ordinary_strings_are_ignored(self):
        self.assertEqual(scan("r.ts", "a = 'python3.11'; b = 'utf-8'; c = 'user-1'; d = 'gptkbindex'; e = 'embedding'; f = 'app2'\n"), set())

    def test_family_prefix_needs_a_digit_next(self):
        self.assertEqual(shapes.family_of("gptkbindex", FAMS), "")
        self.assertEqual(shapes.family_of("gpt4", FAMS), "gpt")


class Bicep(unittest.TestCase):
    TEXT = ("@allowed([ 'canadaeast', 'eastus', 'eastus2' ])\nparam location string\n\n"
            "@description('Name of the chat model')\n@allowed([ 'gpt-35-turbo', 'gpt-4', 'gpt-4o', 'gpt-4-16k' ])\nparam chatModelName string = 'gpt-4o'\n\n"
            "@allowed([ '0613', '2024-07-18' ])\nparam chatModelVersion string = '2024-07-18'\n\nparam searchIndexName string = 'gptkbindex'\n")

    def test_allowed_values_of_a_model_parameter(self):
        got = scan("main.bicep", self.TEXT)
        self.assertTrue({"gpt-35-turbo", "gpt-4", "gpt-4o", "gpt-4-16k"} <= got)
        self.assertTrue({"eastus", "eastus2", "canadaeast", "0613", "2024-07-18", "gptkbindex"}.isdisjoint(got))


class SpecExamples(unittest.TestCase):
    YAML = ["paths:", "  /chat:", "    post:", "      requestBody:", "        content:", "          application/json:", "            example:", "              model: gpt-4o-mini",
            "            schema:", "              properties:", "                model:", "                  enum: [gpt-4o]"]

    def test_example_block_is_found_but_schema_is_not(self):
        self.assertTrue(verify.in_spec_example(self.YAML, 7))
        self.assertFalse(verify.in_spec_example(self.YAML, 11))

    def test_pretty_json_examples(self):
        j = ['{', '  "paths": {', '    "post": {', '      "examples": {', '        "a": {', '          "model": "gpt-4o"', '        }', '      }', '    }', '  }', '}']
        self.assertTrue(verify.in_spec_example(j, 5))

    def test_only_spec_files_are_treated_this_way(self):
        self.assertTrue(verify.SPEC_FILE.match("openapi.yaml"))
        self.assertTrue(verify.SPEC_FILE.match("swagger.json"))
        self.assertFalse(verify.SPEC_FILE.match("config.yaml"))


if __name__ == "__main__":
    unittest.main()
