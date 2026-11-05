import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from aibom_engine.finders import context, dictionary  # noqa: E402
from aibom_engine.triage import FileInfo  # noqa: E402


def run_on(finder, text, name="app.ts", category="code"):
    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, name), "w", encoding="utf-8") as fh:
            fh.write(text)
        return {(f.name) for f in finder.run(d, [FileInfo(name, category, len(text))])}


class ContextRules(unittest.TestCase):
    def test_model_named_key(self):
        self.assertIn("gpt-4-1106-preview", run_on(context, 'const r = await openai.chat.completions.create({\n  model: "gpt-4-1106-preview",\n})'))

    def test_provider_prefix(self):
        self.assertIn("claude-haiku-4-5-20251001", run_on(context, 'id="anthropic:claude-haiku-4-5-20251001",', "c.py"))

    def test_multiline_huggingface_call(self):
        got = run_on(context, 'const g = await pipeline(\n  "feature-extraction",\n  "Xenova/all-MiniLM-L6-v2"\n)')
        self.assertIn("Xenova/all-MiniLM-L6-v2", got)
        self.assertNotIn("feature-extraction", got)

    def test_import_path_is_not_a_model(self):
        self.assertEqual(run_on(context, 'import { X } from "openai/resources/chat/completions.mjs"'), set())

    def test_variable_name_is_not_a_model(self):
        self.assertEqual(run_on(context, "const m = selectedPreset.model\nfoo(chat.model)"), set())

    def test_env_default_js(self):
        self.assertIn("gpt-4o-mini", run_on(context, 'const m = process.env.OPENAI_MODEL || "gpt-4o-mini"'))

    def test_env_default(self):
        self.assertIn("mistral-small-latest", run_on(context, 'MODEL = os.getenv("CHAT_MODEL", "mistral-small-latest")', "x.py"))


class MergeAndTriage(unittest.TestCase):
    def test_provider_prefixed_forms_become_one_item(self):
        from aibom_engine.finding import Finding
        from aibom_engine.merge import merge
        items = merge([Finding("a", "model", "deepseek/deepseek-v3.2", "x.ts", 1), Finding("b", "model", "deepseek-v3.2", "x.ts", 1)])
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["name"], "deepseek-v3.2")
        self.assertIn("deepseek/deepseek-v3.2", items[0]["aliases"])

    def test_huggingface_owner_is_kept(self):
        from aibom_engine.finding import Finding
        from aibom_engine.merge import merge
        items = merge([Finding("a", "model", "sentence-transformers/all-MiniLM-L6-v2", "x.py", 1)])
        self.assertEqual(items[0]["name"], "sentence-transformers/all-MiniLM-L6-v2")

    def test_mock_files_are_tests(self):
        from aibom_engine.triage import classify
        self.assertEqual(classify("lib/ai/models.mock.ts"), "test")
        self.assertEqual(classify("lib/ai/models.ts"), "code")


class DictionaryScan(unittest.TestCase):
    def test_known_name_in_list(self):
        self.assertIn("gpt-4o", run_on(dictionary, 'export const list = ["gpt-4o", "other"]'))

    def test_provider_prefixed_name(self):
        self.assertIn("gpt-4o", run_on(dictionary, 'model="openai/gpt-4o"', "a.py"))

    def test_plain_word_is_ignored(self):
        self.assertEqual(run_on(dictionary, "the model is large and fast"), set())



class NewBehaviours(unittest.TestCase):
    """Fixes made after the first round of tests on unseen apps."""

    def test_java_call_style(self):
        self.assertIn("gpt-4o-mini", run_on(context, 'var m = OpenAiChatModel.builder().modelName("gpt-4o-mini").build();', "A.java"))

    def test_go_struct_field_and_csharp_call(self):
        self.assertIn("gpt-4-turbo", run_on(context, 'req := openai.ChatCompletionRequest{Model: "gpt-4-turbo"}', "a.go"))
        self.assertIn("gpt-4o", run_on(context, 'builder.WithModel("gpt-4o");', "a.cs"))

    def test_unquoted_yaml_and_properties(self):
        self.assertIn("gpt-4o-mini", run_on(context, "llm:\n  model: gpt-4o-mini  # fast\n", "c.yaml", "config"))
        self.assertIn("gpt-4o", run_on(context, "quarkus.langchain4j.openai.chat-model.model-name=gpt-4o\n", "application.properties", "config"))

    def test_config_key_must_end_in_model(self):
        self.assertEqual(run_on(context, "langchain4j.open-ai.chat-model.timeout=PT60S\n", "application.properties", "config"), set())

    def test_bicep_parameter(self):
        self.assertIn("gpt-5.4-mini", run_on(context, "param chatGptModelName string = 'gpt-5.4-mini'", "main.bicep", "config"))

    def test_labels_are_not_models(self):
        self.assertEqual(run_on(context, 'return myProvider.languageModel("title-model");', "p.ts"), set())

    def test_enum_constant_is_matched(self):
        self.assertIn("gpt-4o-mini", run_on(dictionary, "model(OpenAiChatModelName.GPT_4_O_MINI)", "A.java"))

    def test_fragment_of_a_longer_name_is_not_an_identifier(self):
        self.assertNotIn("llama3", run_on(dictionary, 'const id = "llama3-8b-8192"', "a.ts"))

    def test_folder_is_not_a_model(self):
        self.assertEqual(run_on(dictionary, 'out = "results/gpt-4o-mini"', "a.py"), set())


class VerifyStep(unittest.TestCase):
    def check(self, text, name, ext, category="code"):
        from aibom_engine.merge import merge
        from aibom_engine.verify import verify
        from aibom_engine.finding import Finding
        with tempfile.TemporaryDirectory() as d:
            path = "f" + ext
            with open(os.path.join(d, path), "w", encoding="utf-8") as fh:
                fh.write(text)
            fs = [Finding("t", "model", name, path, i + 1, "", category, l.strip()) for i, l in enumerate(text.split("\n")) if name in l]
            return verify(merge(fs), d)[0]

    def test_live_value_is_declared(self):
        self.assertEqual(self.check('model = "gpt-4o"  # the fast one', "gpt-4o", ".py")["tier"], "declared")

    def test_python_comment_is_rejected(self):
        it = self.check('# model = "gpt-4o"', "gpt-4o", ".py")
        self.assertEqual((it["tier"], it["reason"]), ("rejected", "comment"))

    def test_js_block_comment_is_rejected(self):
        self.assertEqual(self.check('/*\n model: "gpt-4o"\n*/', "gpt-4o", ".ts")["reason"], "comment")

    def test_yaml_comment_is_rejected_but_value_is_kept(self):
        self.assertEqual(self.check("# model: gpt-4o-mini\nmodel: gpt-4o-mini", "gpt-4o-mini", ".yaml")["tier"], "declared")
        self.assertEqual(self.check("# model: gpt-4o-mini", "gpt-4o-mini", ".yaml")["tier"], "rejected")

    def test_print_message_is_rejected(self):
        self.assertEqual(self.check('System.out.println("mistral-small says: hi");', "mistral-small", ".java")["reason"], "message")

    def test_docstring_is_rejected(self):
        self.assertEqual(self.check('def f():\n    """Uses gpt-4o internally."""\n    pass', "gpt-4o", ".py")["reason"], "text")

    def test_test_and_docs_only(self):
        self.assertEqual(self.check('x = "gpt-4o"', "gpt-4o", ".py", "test")["reason"], "test")
        self.assertEqual(self.check("Uses gpt-4o.", "gpt-4o", ".md", "docs")["reason"], "docs")

    def test_url_slashes_do_not_start_a_comment(self):
        self.assertEqual(self.check('const u = "http://x.com/gpt-4o"', "gpt-4o", ".ts")["tier"], "declared")


class TriageAndOutput(unittest.TestCase):
    def test_test_files_in_other_languages(self):
        from aibom_engine.triage import classify
        for p in ("chat_test.go", "pkg/user_test.py", "src/test/java/FooTest.java", "Shop.Tests/Cart.cs", "spec/model_spec.rb"):
            self.assertEqual(classify(p), "test", p)
        for p in ("src/main/java/FooTest.java", "src/Latest.java", "src/main.go", "pkg/contest.go", "src/Attestation.cs"):
            self.assertNotEqual(classify(p), "test", p)

    def test_bicep_is_config_and_results_are_data(self):
        from aibom_engine.triage import classify
        self.assertEqual(classify("infra/main.bicep"), "config")
        self.assertEqual(classify("evals/results/run1/params.json"), "data")

    def test_rejected_items_stay_out_of_the_aibom_and_output_is_repeatable(self):
        from aibom_engine.pipeline import run
        with tempfile.TemporaryDirectory() as d, tempfile.TemporaryDirectory() as o1, tempfile.TemporaryDirectory() as o2:
            with open(os.path.join(d, "a.py"), "w", encoding="utf-8") as fh:
                fh.write('m = "gpt-4o"\n# old = "gpt-3.5-turbo"\n')
            r1 = run(d, o1)
            run(d, o2)
            self.assertTrue(r1["valid"])
            with open(os.path.join(o1, "aibom.cdx.json"), encoding="utf-8") as fh:
                bom = fh.read()
            self.assertIn("gpt-4o", bom)
            self.assertNotIn("gpt-3.5-turbo", bom)
            with open(os.path.join(o2, "aibom.cdx.json"), encoding="utf-8") as fh:
                self.assertEqual(bom, fh.read())


if __name__ == "__main__":
    unittest.main()
