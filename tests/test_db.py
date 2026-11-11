import unittest

from aibom_engine.db import (
    extract_version_and_pinning,
    load_db,
    lookup_license,
    lookup_package,
    match_vulnerabilities,
    resolve_model,
)
from aibom_engine.finders.context import model_like, run as run_context
from aibom_engine.triage import FileInfo


class TestDatabasePhase1(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.db = load_db()

    def test_db_sections_and_counts(self):
        self.assertIn("meta", self.db)
        self.assertGreater(len(self.db["models"]), 2500)
        self.assertGreater(len(self.db["alias_index"]), 5000)
        self.assertGreaterEqual(len(self.db["packages"]), 120)
        self.assertGreater(len(self.db["vulnerabilities"]), 30)
        self.assertGreaterEqual(len(self.db["licenses"]), 20)

    def test_canonical_model_resolution_across_providers(self):
        variants = [
            "claude-sonnet-4-5",
            "claude-sonnet-4.5",
            "claude-sonnet-4-5-20250929",
            "anthropic.claude-sonnet-4-5-20250929-v1:0",
            "us.anthropic.claude-sonnet-4-5-20250929-v1:0",
            "claude-sonnet-4-5@20250929",
        ]
        for raw in variants:
            res = resolve_model(raw, db=self.db)
            self.assertEqual(res["canonical_id"], "anthropic/claude-sonnet-4-5", msg=f"Failed for {raw}")
            self.assertEqual(res["maker"], "Anthropic")

    def test_pinning_detection(self):
        # Floating / unpinned references
        for unpinned in ("gpt-4o", "claude-sonnet-4-5", "claude-3-5-sonnet-latest", "gemini-2.5-pro"):
            res = resolve_model(unpinned, db=self.db)
            self.assertFalse(res["pinned"], msg=f"Expected {unpinned} to be unpinned")

        # Pinned snapshots / dated versions / digests
        for pinned in (
            "gpt-4o-2024-08-06",
            "claude-sonnet-4-5-20250929",
            "anthropic.claude-sonnet-4-5-20250929-v1:0",
            "claude-sonnet-4-5@20250929",
            "llama3.1:8b",
            "gpt-3.5-turbo-0125",
        ):
            res = resolve_model(pinned, db=self.db)
            self.assertTrue(res["pinned"], msg=f"Expected {pinned} to be pinned")

    def test_bedrock_arn_and_vertex_path_resolution(self):
        arn = "arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-sonnet-4-5-20250929-v1:0"
        res_arn = resolve_model(arn, db=self.db)
        self.assertEqual(res_arn["canonical_id"], "anthropic/claude-sonnet-4-5")
        self.assertEqual(res_arn["provider"], "bedrock")
        self.assertEqual(res_arn["region"], "us-east-1")
        self.assertTrue(res_arn["pinned"])

        vtx = "projects/my-gcp-proj/locations/us-central1/publishers/google/models/gemini-1.5-pro-002"
        res_vtx = resolve_model(vtx, db=self.db)
        self.assertEqual(res_vtx["maker"], "Google")
        self.assertEqual(res_vtx["provider"], "vertex_ai")
        self.assertEqual(res_vtx["region"], "us-central1")
        self.assertTrue(res_vtx["pinned"])

    def test_deprecated_and_retired_models(self):
        # Values come from Anthropic's deprecations page (see tests/test_lifecycle.py for the full set).
        c2 = resolve_model("claude-2.1", db=self.db)
        self.assertEqual(c2["status"], "retired")
        self.assertEqual(c2["replacement"], "claude-opus-4-8")

    def test_license_classification(self):
        cmd_r = resolve_model("CohereForAI/c4ai-command-r-v01", db=self.db)
        self.assertEqual(cmd_r["license"], "cc-by-nc-4.0")
        self.assertTrue(cmd_r["license_restricted"])
        self.assertEqual(cmd_r["license_category"], "non-commercial")

        flux_dev = resolve_model("black-forest-labs/FLUX.1-dev", db=self.db)
        self.assertTrue(flux_dev["license_restricted"])

        flux_schnell = resolve_model("black-forest-labs/FLUX.1-schnell", db=self.db)
        self.assertEqual(flux_schnell["license"], "apache-2.0")
        self.assertFalse(flux_schnell["license_restricted"])

        llama = resolve_model("meta-llama/Llama-3.1-8B-Instruct", db=self.db)
        self.assertEqual(llama["license"], "llama3.1")
        self.assertTrue(llama["license_restricted"])
        self.assertEqual(llama["license_category"], "conditional-commercial")

        lic = lookup_license("CC-BY-NC-SA-4.0", db=self.db)
        self.assertTrue(lic["restricted"])

    def test_ai_package_lookup_and_osv_vulnerability_matching(self):
        pkg = lookup_package("PyPI", "langchain_community", db=self.db)
        self.assertIsNotNone(pkg)
        self.assertEqual(pkg["category"], "agent_framework")
        self.assertIn("langchain_community", pkg["import_names"])

        vdb = lookup_package("PyPI", "chromadb", db=self.db)
        self.assertIsNotNone(vdb)
        self.assertEqual(vdb["category"], "vector_db")

        # 0.2.1 is affected by GHSA-3hjh-jh2h-vrg6 (CVE-2024-2965, fixed in 0.2.5)
        vulns_021 = {v["id"]: v for v in match_vulnerabilities("PyPI", "langchain-community", "0.2.1", db=self.db)}
        self.assertIn("GHSA-3hjh-jh2h-vrg6", vulns_021)
        self.assertIn("CVE-2024-2965", vulns_021["GHSA-3hjh-jh2h-vrg6"]["aliases"])
        self.assertEqual(vulns_021["GHSA-3hjh-jh2h-vrg6"]["fixed_in"], "0.2.5")

        # A version past every advisory has none at all (no filter: an advisory with no fixed version must not match
        # every version)
        self.assertEqual(match_vulnerabilities("PyPI", "langchain-community", "99.0.0", db=self.db), [])

    def test_trailing_slash_false_positives_rejected(self):
        self.assertFalse(model_like("anthropic/"))
        self.assertFalse(model_like("browser-use/"))
        self.assertFalse(model_like("openai"))
        self.assertFalse(model_like("/models/gpt-4o"))
        self.assertTrue(model_like("gpt-4o"))
        self.assertTrue(model_like("claude-sonnet-4-5"))

    def test_end_to_end_pipeline_db_enrichment(self):
        import json
        import os
        import tempfile
        from aibom_engine.pipeline import run

        with tempfile.TemporaryDirectory() as src, tempfile.TemporaryDirectory() as out:
            code = "\n".join([
                'MODEL_A = "claude-sonnet-4-5"',
                'MODEL_B = "claude-3-sonnet-20240229"',
                'MODEL_C = "CohereForAI/c4ai-command-r-v01"',
                'ARN = "arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-sonnet-4-5-20250929-v1:0"',
                'PREFIX = "anthropic/" + MODEL_A',
            ])
            with open(os.path.join(src, "app.py"), "w", encoding="utf-8") as f:
                f.write(code)
            res = run(src, out, app="test-app")
            self.assertTrue(res["valid"])
            with open(os.path.join(out, "merged.json"), encoding="utf-8") as mf:
                merged = json.load(mf)
            by_name = {it["name"]: it for it in merged if it["tier"] != "rejected"}
            self.assertNotIn("anthropic/", by_name)
            self.assertIn("claude-sonnet-4-5", by_name)
            self.assertFalse(by_name["claude-sonnet-4-5"]["pinned"])
            self.assertEqual(by_name["claude-sonnet-4-5"]["canonical_id"], "anthropic/claude-sonnet-4-5")

            self.assertIn("claude-3-sonnet-20240229", by_name)
            self.assertTrue(by_name["claude-3-sonnet-20240229"]["pinned"])
            self.assertEqual(by_name["claude-3-sonnet-20240229"]["status"], "retired")
            self.assertEqual(by_name["claude-3-sonnet-20240229"]["replacement"], "claude-sonnet-5-5")

            self.assertIn("CohereForAI/c4ai-command-r-v01", by_name)
            self.assertTrue(by_name["CohereForAI/c4ai-command-r-v01"]["license_restricted"])
            self.assertEqual(by_name["CohereForAI/c4ai-command-r-v01"]["license"], "cc-by-nc-4.0")

            self.assertIn("anthropic.claude-sonnet-4-5-20250929-v1:0", by_name)
            self.assertTrue(by_name["anthropic.claude-sonnet-4-5-20250929-v1:0"]["pinned"])
            self.assertEqual(by_name["anthropic.claude-sonnet-4-5-20250929-v1:0"]["canonical_id"], "anthropic/claude-sonnet-4-5")


if __name__ == "__main__":
    unittest.main()
