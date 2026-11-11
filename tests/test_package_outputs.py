"""AI packages in the AI-BOM and the reports (M2.6): valid CycloneDX 1.6, packages as library / framework components with
a purl, vulnerabilities linked to them, provider services only where live code calls the provider's client."""
import csv
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest

from aibom_engine.pipeline import run
from test_packages import Repo

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")


class Scan(unittest.TestCase):
    files = {}

    @classmethod
    def setUpClass(cls):
        cls.repo = Repo(cls.files)
        cls.out = tempfile.TemporaryDirectory()
        cls.result = run(cls.repo.tmp.name, cls.out.name)
        cls.bom = cls.load("aibom.cdx.json")
        cls.manifest = cls.load("manifest.json")

    @classmethod
    def load(cls, name):
        with open(os.path.join(cls.out.name, name), encoding="utf-8") as fh:
            return json.load(fh)

    @classmethod
    def read(cls, name):
        with open(os.path.join(cls.out.name, name), encoding="utf-8-sig") as fh:
            return fh.read()

    @classmethod
    def tearDownClass(cls):
        cls.repo.close()
        cls.out.cleanup()

    def component(self, name, version=None):
        hits = [c for c in self.bom["components"] if c["name"] == name and (version is None or c.get("version") == version)]
        self.assertEqual(len(hits), 1, f"{name} {version}: {[c['name'] for c in self.bom['components']]}")
        return hits[0]

    @staticmethod
    def props(component):
        return {p["name"].split(":", 1)[1]: p["value"] for p in component.get("properties", [])}


APP = {
    "requirements.txt": "langchain-community==0.0.20\nopenai==1.30.0\nlangchain-openai>=0.1\n",
    "src/agent.py": """
        from openai import OpenAI
        from langchain_community.vectorstores import Chroma
        import chromadb
        client = OpenAI()
        client.chat.completions.create(model="gpt-4o-2024-08-06", messages=[])
        store = Chroma()
        db = chromadb.Client()
        """,
    "tests/test_agent.py": "import anthropic\nc = anthropic.Anthropic()\n",
    "dev/requirements.txt": "mistralai==1.0.0\n",
}


class PackagesInTheAiBom(Scan):
    files = APP

    def test_the_ai_bom_is_valid_cyclonedx_1_6(self):
        self.assertEqual(self.bom["specVersion"], "1.6")
        self.assertTrue(self.manifest["cyclonedx_1_6_valid"], self.manifest["validation_error"])

    def test_packages_are_library_or_framework_components_with_a_purl(self):
        oa = self.component("openai", "1.30.0")
        self.assertEqual((oa["type"], oa["purl"]), ("library", "pkg:pypi/openai@1.30.0"))
        lc = self.component("langchain-community", "0.0.20")
        self.assertEqual(lc["type"], "framework")  # an agent framework
        self.assertEqual(lc["purl"], "pkg:pypi/langchain-community@0.0.20")

    def test_a_package_without_an_exact_version_has_none_and_says_not_checked(self):
        lo = self.component("langchain-openai")
        self.assertNotIn("version", lo)
        props = self.props(lo)
        self.assertEqual(props["vulnerability-check"], "not_checked")
        self.assertTrue(props["vulnerability-check-reason"])

    def test_the_proof_lines_and_the_level_are_kept(self):
        oa = self.component("openai", "1.30.0")
        self.assertEqual(self.props(oa)["evidence-level"], "called")
        self.assertEqual(self.props(oa)["reachability"], "not_verified")
        contexts = [(o["location"], o["line"], o["additionalContext"].split(":")[0]) for o in oa["evidence"]["occurrences"]]
        self.assertEqual(contexts[0], ("src/agent.py", 4, "called"))
        self.assertIn(("requirements.txt", 2, "declared"), contexts)

    def test_left_out_packages_are_not_in_the_bom(self):
        names = {c["name"] for c in self.bom["components"]}
        self.assertNotIn("anthropic", names)    # called only in tests/: left out
        self.assertIn("mistralai", names)       # dev/ is not a left-out folder: declared, so listed, but never imported
        self.assertEqual(self.props(self.component("mistralai"))["evidence-level"], "declared")

    def test_vulnerabilities_point_at_components_that_exist(self):
        refs = {c["bom-ref"] for c in self.bom["components"]} | {s["bom-ref"] for s in self.bom.get("services", [])}
        self.assertEqual(len(refs), len(self.bom["components"]) + len(self.bom.get("services", [])), "bom-refs are unique")
        vulns = self.bom["vulnerabilities"]
        self.assertTrue(vulns)
        for v in vulns:
            for affected in v["affects"]:
                self.assertIn(affected["ref"], refs)
        self.assertEqual(len(vulns), self.result["packages"]["advisories"])
        ids = {v["id"] for v in vulns}
        self.assertIn("GHSA-f2jm-rw3h-6phg", ids)
        v = next(v for v in vulns if v["id"] == "GHSA-f2jm-rw3h-6phg")
        self.assertEqual(v["recommendation"], "Upgrade to 0.2.4 or later.")
        self.assertEqual(v["ratings"][0]["severity"], "high")
        self.assertEqual(v["ratings"][0]["method"], "CVSSv31")
        self.assertIn("CVE-2024-5998", {r["id"] for r in v["references"]})

    def test_the_app_depends_on_its_direct_packages_and_no_edges_are_invented(self):
        deps = self.bom["dependencies"]
        self.assertEqual([d["ref"] for d in deps], ["app"])
        refs = set(deps[0]["dependsOn"])
        self.assertIn(self.component("openai", "1.30.0")["bom-ref"], refs)

    def test_provider_services_come_from_live_calls_of_the_providers_own_client(self):
        names = {s["name"] for s in self.bom.get("services", [])}
        self.assertIn("OpenAI API", names)           # openai.OpenAI() is called in src/
        self.assertNotIn("Anthropic API", names)     # anthropic is only called in a test
        self.assertNotIn("Mistral API", names)       # mistralai is declared but never imported

    def test_the_date_of_the_advisory_data_is_recorded(self):
        props = {p["name"]: p["value"] for p in self.bom["metadata"]["properties"]}
        self.assertEqual(props["aibom-engine:advisory-data-fetched"], self.result["packages"]["advisory_data"])


class TheRulesOfTheBom(Scan):
    files = {
        "package.json": json.dumps({"name": "web", "dependencies": {"openai": "^4.0.0"}, "devDependencies": {"ai": "^4.0.0"}}, indent=2),
        "package-lock.json": json.dumps({"lockfileVersion": 3, "packages": {
            "": {"name": "web", "dependencies": {"openai": "^4.0.0"}, "devDependencies": {"ai": "^4.0.0"}},
            "node_modules/openai": {"version": "4.104.0"}, "node_modules/ai": {"version": "4.3.1", "dev": True},
            "node_modules/@langchain/core": {"version": "0.3.0"}}}, indent=2),
        "src/chat.ts": 'import OpenAI from "openai";\nconst c = new OpenAI();\n',
        "src/many.ts": 'import OpenAI from "openai";\n' + "".join(f"const c{i} = new OpenAI();\n" for i in range(40)),
    }

    def test_scope_follows_the_dependency_section(self):
        self.assertEqual(self.component("ai", "4.3.1")["scope"], "excluded")      # a dev dependency
        self.assertEqual(self.component("openai", "4.104.0")["scope"], "required")

    def test_a_package_only_in_a_lockfile_is_listed_but_is_not_a_dependency_of_the_app(self):
        core = self.component("@langchain/core", "0.3.0")
        self.assertEqual(self.props(core)["direct"], "false")
        self.assertEqual(core["purl"], "pkg:npm/%40langchain/core@0.3.0")
        self.assertNotIn(core["bom-ref"], self.bom["dependencies"][0]["dependsOn"])

    def test_proof_lines_are_capped_and_the_cap_is_stated(self):
        oa = self.component("openai", "4.104.0")
        self.assertLessEqual(len(oa["evidence"]["occurrences"]), 25)
        self.assertRegex(self.props(oa)["proof-lines"], r"^25 of \d+ shown$")


class NoPackages(Scan):
    files = {"app.py": 'MODEL = "gpt-4o-2024-08-06"\nprint(MODEL)\n'}

    def test_a_scan_without_packages_adds_nothing_to_the_bom(self):
        self.assertTrue(self.manifest["cyclonedx_1_6_valid"])
        for key in ("vulnerabilities", "dependencies"):
            self.assertNotIn(key, self.bom)
        self.assertEqual({c["type"] for c in self.bom["components"]}, {"machine-learning-model"})
        self.assertNotIn("## AI packages", self.read("report.md"))
        self.assertNotIn("<h2>AI packages</h2>", self.read("report.html"))
        self.assertNotIn("<span>AI packages", self.read("report.html"))  # no card either


class PackagesInTheReports(Scan):
    files = APP

    def test_markdown_lists_the_packages_most_urgent_first_with_the_caveats(self):
        md = self.read("report.md")
        self.assertIn("## AI packages", md)
        table = md.split("## AI packages")[1].split("**")[0]
        rows = [r for r in table.split("\n") if r.startswith("| ") and not r.startswith("| Package") and "---" not in r]
        self.assertTrue(rows[0].startswith("| langchain-community"), rows[0])  # the package with the worst advisory comes first
        self.assertIn("6 known (1 critical, 3 high, 2 medium)", rows[0])
        self.assertIn("None known", next(r for r in rows if r.startswith("| openai")))
        self.assertIn("Not checked", next(r for r in rows if r.startswith("| langchain-openai")))
        self.assertIn("reachability is not verified", md)
        self.assertIn("[GHSA-f2jm-rw3h-6phg](https://osv.dev/vulnerability/GHSA-f2jm-rw3h-6phg)", md)

    def test_html_has_the_section_a_card_and_balanced_tags(self):
        page = self.read("report.html")
        self.assertIn("<h2>AI packages</h2>", page)
        self.assertIn("AI packages (1 with known vulnerabilities)", page)
        self.assertIn("GHSA-f2jm-rw3h-6phg", page)
        self.assertEqual(page.count("<table"), page.count("</table>"))
        self.assertEqual(page.count("<details"), page.count("</details>"))

    def test_packages_csv(self):
        rows = list(csv.DictReader(io.StringIO(self.read("packages.csv"))))
        by = {r["package"]: r for r in rows}
        self.assertEqual(by["langchain-community"]["known_advisories"], "6")
        self.assertEqual(by["langchain-community"]["worst_severity"], "critical")
        self.assertEqual(by["openai"]["vulnerability_check"], "checked")
        self.assertEqual(by["langchain-openai"]["vulnerability_check"], "not_checked")
        self.assertTrue(all(r["reachability"] == "not_verified" for r in rows))
        self.assertEqual(by["openai"]["purl"], "pkg:pypi/openai@1.30.0")

    def test_rebuild_regenerates_the_package_reports_without_a_rescan(self):
        for name in ("report.md", "packages.csv"):
            os.remove(os.path.join(self.out.name, name))
        done = subprocess.run([sys.executable, "-m", "aibom_engine", "rebuild", self.out.name], cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn("## AI packages", self.read("report.md"))
        self.assertIn("langchain-community", self.read("packages.csv"))

    def test_rebuild_of_a_run_without_packages_json_still_works(self):
        with tempfile.TemporaryDirectory() as old:
            for name in ("merged.json", "manifest.json"):
                with open(os.path.join(old, name), "w", encoding="utf-8") as fh:
                    fh.write(self.read(name))
            done = subprocess.run([sys.executable, "-m", "aibom_engine", "rebuild", old], cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(done.returncode, 0, done.stderr)
            with open(os.path.join(old, "report.md"), encoding="utf-8") as fh:
                self.assertNotIn("## AI packages", fh.read())


if __name__ == "__main__":
    unittest.main()
