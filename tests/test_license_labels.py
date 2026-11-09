"""License wording (PR #4 review): models sold under a provider's API terms are not "non-commercial"."""
import unittest

from aibom_engine.db import load_db, lookup_license, resolve_model
from aibom_engine.report import license_label


class CommercialUse(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.db = load_db()

    def test_provider_api_terms_are_not_a_non_commercial_license(self):
        self.assertEqual(lookup_license("proprietary", db=self.db)["commercial_use"], "provider-terms")
        for name in ("gpt-4o", "text-embedding-3-small", "claude-3-5-sonnet-20240620", "gemini-2.5-pro"):
            r = resolve_model(name, db=self.db)
            self.assertEqual(r["license_category"], "proprietary", name)
            self.assertNotEqual(r["license_commercial_use"], "no", name)
            self.assertNotIn("non-commercial", license_label(r).lower(), name)
            self.assertEqual(license_label(r), "Provider API terms", name)

    def test_real_non_commercial_licenses_are_still_flagged(self):
        for name in ("CohereForAI/c4ai-command-r-plus", "black-forest-labs/FLUX.1-dev", "mistralai/Mistral-Small-Instruct-2409"):
            r = resolve_model(name, db=self.db)
            self.assertEqual(r["license_commercial_use"], "no", name)
            self.assertTrue(r["license_restricted"], name)
            self.assertIn("(non-commercial)", license_label(r), name)

    def test_conditional_and_permissive_licenses(self):
        llama = resolve_model("meta-llama/Llama-2-7b-hf", db=self.db)
        self.assertEqual(llama["license_commercial_use"], "conditional")
        self.assertIn("(conditional)", license_label(llama))
        mistral = resolve_model("mistralai/Mistral-7B-Instruct-v0.3", db=self.db)
        self.assertEqual(mistral["license_commercial_use"], "yes")
        self.assertNotIn("(", license_label(mistral))

    def test_no_proprietary_model_anywhere_in_the_database_maps_to_no(self):
        # The mapping is per license category, so check the whole table rather than a few examples.
        for lic_id, lic in self.db["licenses"].items():
            info = lookup_license(lic_id, db=self.db)
            if lic.get("category") == "proprietary":
                self.assertEqual(info["commercial_use"], "provider-terms", lic_id)
            if lic.get("category") == "non-commercial":
                self.assertEqual(info["commercial_use"], "no", lic_id)

    def test_label_helper_cases(self):
        self.assertEqual(license_label({"license_name": "X License", "license_commercial_use": "yes"}), "X License")
        self.assertEqual(license_label({"license_name": "X License", "license_commercial_use": "no"}), "X License (non-commercial)")
        self.assertEqual(license_label({"license_name": "X License", "license_commercial_use": "conditional"}), "X License (conditional)")
        self.assertEqual(license_label({"license_name": "Commercial / Proprietary API Terms", "license_commercial_use": "provider-terms"}),
                         "Provider API terms")
        self.assertEqual(license_label({}), "unknown")


class CuratedLicensesMatchTheirRepos(unittest.TestCase):
    """Values checked against each Hugging Face repo and its license text on 2026-11-10
    (re-check any time with `python scripts/check_licenses.py`)."""

    @classmethod
    def setUpClass(cls):
        cls.db = load_db()

    def lic(self, name):
        r = resolve_model(name, db=self.db)
        return r["license"], r["license_commercial_use"]

    def test_corrected_entries(self):
        expected = {
            # was apache-2.0: the repo is under the Mistral AI Research License
            "mistralai/Mistral-Small-Instruct-2409": ("mistral-research", "no"),
            # was apache-2.0: the 72B model has its own Qwen License (over 100M monthly users needs a license)
            "Qwen/Qwen2.5-72B-Instruct": ("qwen", "conditional"),
            # was "research" (non-commercial): Qwen-72B is under the Tongyi Qianwen License Agreement
            "Qwen/Qwen-72B": ("tongyi-qianwen", "conditional"),
            # was non-commercial: the Stability AI Community License allows commercial use under US$1M revenue
            "stabilityai/stable-diffusion-3-medium": ("stabilityai-ai-community", "conditional"),
            "stabilityai/stable-diffusion-3.5-large": ("stabilityai-ai-community", "conditional"),
            # was mit: MIT covers the code; the weights are under the DeepSeek License
            "deepseek-ai/DeepSeek-V3": ("deepseek", "conditional"),
            "deepseek-ai/deepseek-llm-7b-chat": ("deepseek", "conditional"),
            "deepseek-ai/deepseek-coder-6.7b-instruct": ("deepseek", "conditional"),
            # was OpenRAIL-M: SDXL is under OpenRAIL++-M
            "stabilityai/stable-diffusion-xl-base-1.0": ("openrail++", "conditional"),
        }
        for name, want in expected.items():
            self.assertEqual(self.lic(name), want, name)

    def test_unchanged_entries_that_were_verified(self):
        for name, want in {"deepseek-ai/DeepSeek-R1": ("mit", "yes"), "Qwen/Qwen2.5-7B-Instruct": ("apache-2.0", "yes"),
                           "mistralai/Mistral-Large-Instruct-2407": ("mistral-research", "no"),
                           "sentence-transformers/all-MiniLM-L6-v2": ("apache-2.0", "yes")}.items():
            self.assertEqual(self.lic(name), want, name)

    def test_families_with_mixed_licenses_get_no_guess(self):
        # A name rule used to call every deepseek model MIT and every qwen2.5/qwen3, ministral and codestral model
        # Apache-2.0. Those families mix licenses, so an uncurated name now says "unknown" instead of guessing.
        for name in ("deepseek-v4-flash", "qwen3-coder-next", "codestral-2501", "ministral-8b-2512"):
            self.assertEqual(self.lic(name)[0], "unknown", name)

    def test_every_hugging_face_backed_entry_is_sourced_and_dated(self):
        import json
        import os
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "aibom_engine", "knowledge", "curated.json")
        with open(path, encoding="utf-8") as fh:
            models = json.load(fh)["curated_models"]
        for key, cm in models.items():
            if cm.get("hugging_face_id"):
                self.assertTrue(cm.get("license_source_url", "").startswith("https://huggingface.co/"), key)
                self.assertRegex(cm.get("license_checked", ""), r"^\d{4}-\d{2}-\d{2}$", key)


if __name__ == "__main__":
    unittest.main()
