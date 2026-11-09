import unittest

from aibom_engine.db import load_db, resolve_model


# Each row: raw identifier -> expected first-party canonical ID.
CASES = [
    ("gpt-4o", "openai/gpt-4o"),
    ("openai/gpt-4o", "openai/gpt-4o"),
    ("gpt-4o-mini", "openai/gpt-4o-mini"),
    ("text-embedding-3-small", "openai/text-embedding-3-small"),
    ("openai/text-embedding-3-small", "openai/text-embedding-3-small"),
    # Vercel AI Gateway reseller prefix resolves to the first-party OpenAI model.
    ("vercel-ai-gateway/openai/text-embedding-3-small", "openai/text-embedding-3-small"),
    ("claude-sonnet-4-5", "anthropic/claude-sonnet-4-5"),
    ("anthropic/claude-sonnet-4-5", "anthropic/claude-sonnet-4-5"),
    ("claude-sonnet-4-5@20250929", "anthropic/claude-sonnet-4-5"),
    ("us.anthropic.claude-sonnet-4-5-20250929-v1:0", "anthropic/claude-sonnet-4-5"),
    ("claude-3-5-sonnet-20240620", "anthropic/claude-3-5-sonnet"),
    ("claude-3-opus-20240229", "anthropic/claude-3-opus"),
    ("gemma-2-9b-it", "google/gemma-2-9b-it"),
    ("google/gemma-2-9b-it", "google/gemma-2-9b-it"),
    ("meta-llama/Llama-3.1-8B-Instruct", "meta-llama/llama-3.1-8b-instruct"),
    ("deepseek-ai/DeepSeek-R1", "deepseek-ai/deepseek-r1"),
    ("black-forest-labs/FLUX.1-dev", "black-forest-labs/flux.1-dev"),
    ("mistralai/Mixtral-8x7B-Instruct-v0.1", "mistralai/mixtral-8x7b-instruct-v0.1"),
    ("stabilityai/stable-diffusion-xl-base-1.0", "stabilityai/stable-diffusion-xl-base-1.0"),
    # nscale reseller prefix (doubled) resolves to the Stability AI model.
    ("nscale/nscale/stabilityai/stable-diffusion-xl-base-1.0", "stabilityai/stable-diffusion-xl-base-1.0"),
    # aiand gateway prefix resolves to the DeepSeek / Moonshot models.
    ("aiand/aiand/deepseek-ai/deepseek-v4-flash", "deepseek-ai/deepseek-v4-flash"),
    ("aiand/aiand/moonshotai/kimi-k2.7-code", "moonshotai/kimi-k2.7-code"),
]


class CanonicalIds(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.db = load_db()

    def test_common_models_resolve_to_first_party_canonical_ids(self):
        failures = []
        for raw, expected in CASES:
            got = resolve_model(raw, db=self.db)["canonical_id"]
            if got != expected:
                failures.append(f"{raw!r} -> {got!r} (expected {expected!r})")
        self.assertFalse(failures, "wrong canonical IDs:\n  " + "\n  ".join(failures))

    def test_reseller_prefix_never_leaks_into_canonical_id(self):
        # A gateway/reseller segment must not survive as the maker of a canonical id.
        for raw, _ in CASES:
            got = resolve_model(raw, db=self.db)["canonical_id"]
            first = got.split("/")[0]
            self.assertNotIn(first, {"vercel-ai-gateway", "nscale", "aiand", "wandb", "unknown"}, f"{raw!r} -> {got!r}")


if __name__ == "__main__":
    unittest.main()
