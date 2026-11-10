"""Evidence levels (M2.4): every component says declared, imported or called, plus reachability: not_verified. A model
is called only when live code passes its name into a call on an AI SDK; confidence (confirmed / worked out) is separate."""
import json
import os
import tempfile
import unittest

from aibom_engine.pipeline import run
from test_packages import Repo


class Scan(unittest.TestCase):
    files = {}

    @classmethod
    def setUpClass(cls):
        cls.repo = Repo(cls.files)
        cls.out = tempfile.TemporaryDirectory()
        run(cls.repo.tmp.name, cls.out.name)
        with open(os.path.join(cls.out.name, "merged.json"), encoding="utf-8") as fh:
            cls.items = {i["name"]: i for i in json.load(fh)}
        with open(os.path.join(cls.out.name, "aibom.cdx.json"), encoding="utf-8") as fh:
            cls.bom = json.load(fh)
        with open(os.path.join(cls.out.name, "packages.json"), encoding="utf-8") as fh:
            cls.packages = json.load(fh)

    @classmethod
    def tearDownClass(cls):
        cls.repo.close()
        cls.out.cleanup()

    def level(self, name):
        return self.items[name]["evidence_level"]

    def props(self, name):
        comp = next(c for c in self.bom["components"] if c["name"] == name)
        return {p["name"]: p["value"] for p in comp["properties"]}


class PythonModels(Scan):
    files = {
        "requirements.txt": "openai==1.30.0\nanthropic==0.30.0\ntransformers==4.40.0\n",
        "app/chat.py": """
            import os
            from openai import OpenAI
            import anthropic

            CLAUDE = "claude-sonnet-4-5-20250929"
            FALLBACK = "gpt-4o-mini-2024-07-18"
            client = OpenAI()
            claude = anthropic.Anthropic()
            env_model = os.getenv("MODEL", "o3-mini-2025-01-31")

            def ask(prompt):
                first = client.chat.completions.create(
                    model="gpt-4o-2024-08-06",
                    messages=[{"role": "user", "content": "Is gpt-4.1-2025-04-14 better? " + prompt}],
                )
                second = claude.messages.create(model=CLAUDE, max_tokens=100, messages=[])
                return first, second
            """,
        "app/local.py": """
            from transformers import AutoModelForCausalLM
            model = AutoModelForCausalLM.from_pretrained("meta-llama/Llama-3.1-8B-Instruct")
            """,
        "config/settings.yaml": "default_model: gemini-2.0-flash-001\n",
    }

    def test_a_name_passed_into_an_sdk_call_is_called(self):
        self.assertEqual(self.level("gpt-4o-2024-08-06"), "called")
        self.assertEqual(self.level("meta-llama/Llama-3.1-8B-Instruct"), "called")

    def test_a_constant_passed_into_an_sdk_call_is_called_at_the_constant(self):
        claude = self.items["claude-sonnet-4-5-20250929"]
        self.assertEqual(claude["evidence_level"], "called")
        self.assertEqual([e["line"] for e in claude["evidence"] if e.get("called")], [5])

    def test_names_not_proven_to_reach_an_ai_call_are_declared(self):
        self.assertEqual(self.level("gpt-4o-mini-2024-07-18"), "declared")  # a constant nobody passes on
        self.assertEqual(self.level("o3-mini-2025-01-31"), "declared")      # os.getenv is not an AI call
        self.assertEqual(self.level("gemini-2.0-flash-001"), "declared")    # a settings file

    def test_a_name_inside_a_prompt_is_not_called(self):
        # the prompt is passed into the call, but a string with spaces is prose, not a model setting
        self.assertEqual(self.level("gpt-4.1-2025-04-14"), "declared")

    def test_reachability_and_confidence_are_separate_fields(self):
        it = self.items["gpt-4o-2024-08-06"]
        self.assertEqual((it["reachability"], it["confidence"]), ("not_verified", "confirmed"))

    def test_the_ai_bom_carries_the_three_fields_and_no_tier(self):
        props = self.props("gpt-4o-2024-08-06")
        self.assertEqual(props["aibom-engine:evidence-level"], "called")
        self.assertEqual(props["aibom-engine:reachability"], "not_verified")
        self.assertEqual(props["aibom-engine:confidence"], "confirmed")
        self.assertNotIn("aibom-engine:tier", props)
        self.assertEqual(self.props("gemini-2.0-flash-001")["aibom-engine:evidence-level"], "declared")

    def test_every_package_says_reachability_not_verified(self):
        self.assertTrue(self.packages["packages"])
        for c in self.packages["packages"]:
            self.assertEqual(c["reachability"], "not_verified")
        self.assertNotIn("model_arguments", self.packages)  # working data for the model step, not an output


class JavaScriptModels(Scan):
    files = {
        "package.json": json.dumps({"dependencies": {"ai": "^4", "@ai-sdk/openai": "^1", "@anthropic-ai/sdk": "^0.30"}}),
        "src/route.ts": """
            import { generateText } from "ai";
            import { openai } from "@ai-sdk/openai";
            import Anthropic from "@anthropic-ai/sdk";

            const HAIKU = "claude-haiku-4-5-20251001";
            const UNUSED = "claude-3-opus-20240229";
            const client = new Anthropic();

            export async function POST(req: Request) {
              const { text } = await generateText({
                model: openai("gpt-4o-2024-11-20"),
                prompt: "hello",
              });
              const msg = await client.messages.create({ model: HAIKU, max_tokens: 10, messages: [] });
              return Response.json({ text, msg });
            }
            """,
    }

    def test_calls_and_constants(self):
        self.assertEqual(self.level("gpt-4o-2024-11-20"), "called")
        self.assertEqual(self.level("claude-haiku-4-5-20251001"), "called")
        self.assertEqual(self.level("claude-3-opus-20240229"), "declared")


class ComparisonsAndTokenizers(Scan):
    files = {
        "app.py": """
            import tiktoken
            from openai import OpenAI
            client = OpenAI()

            def ask(settings):
                enc = tiktoken.encoding_for_model("gpt-4-turbo-2024-04-09")
                return client.chat.completions.create(
                    model=settings.model,
                    max_tokens=4096 if settings.model == "gpt-4-vision-preview" else None,
                )
            """,
        "route.ts": """
            import OpenAI from "openai";
            const openai = new OpenAI();
            export const run = (s) => openai.chat.completions.create({
              model: s.model,
              max_tokens: s.model === "gpt-4-0125-preview" ? 4096 : null,
            });
            """,
    }

    def test_a_name_that_is_only_compared_is_not_called(self):
        self.assertEqual(self.level("gpt-4-vision-preview"), "declared")
        self.assertEqual(self.level("gpt-4-0125-preview"), "declared")

    def test_a_name_passed_to_a_tokenizer_is_not_called(self):
        self.assertEqual(self.level("gpt-4-turbo-2024-04-09"), "declared")


class NoAiImportNoCall(Scan):
    files = {
        "app.py": """
            import requests
            MODEL = "gpt-4o-2024-08-06"
            requests.post("https://api.example.com/v1/chat", json={"model": MODEL})
            """,
    }

    def test_a_call_that_is_not_on_an_ai_sdk_does_not_prove_use(self):
        # The model may well be used through plain HTTP; the scanner cannot prove it, so it says declared.
        self.assertEqual(self.level("gpt-4o-2024-08-06"), "declared")


if __name__ == "__main__":
    unittest.main()
