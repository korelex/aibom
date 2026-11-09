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
        for name in ("CohereForAI/c4ai-command-r-plus", "black-forest-labs/FLUX.1-dev", "stabilityai/stable-diffusion-3-medium"):
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


if __name__ == "__main__":
    unittest.main()
