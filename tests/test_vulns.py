"""Vulnerability matching (M2.5): OSV's range rules, PEP 440 and SemVer ordering, and "not checked" for anything that
is not one exact installed version."""
import os
import sys
import unittest

from aibom_engine import vulns
from aibom_engine.db import load_db, vulnerability_check

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scripts"))
import osv_data  # noqa: E402


def adv(ranges=(), versions=(), id="GHSA-test", severity="high"):
    return {"id": id, "aliases": [], "severity": severity, "summary": "", "url": "", "versions": list(versions),
            "ranges": [{"type": "ECOSYSTEM", "events": list(r)} for r in ranges]}


class OsvRanges(unittest.TestCase):
    def hit(self, eco, version, advisory):
        return vulns.affected(eco, version, advisory)

    def test_introduced_and_fixed(self):
        a = adv([[{"introduced": "0"}, {"fixed": "1.2.0"}]])
        self.assertEqual(self.hit("pypi", "1.1.9", a), (True, "1.2.0"))
        self.assertEqual(self.hit("pypi", "1.2.0", a), (False, ""))

    def test_last_affected_includes_that_version(self):
        a = adv([[{"introduced": "0"}, {"last_affected": "0.0.26"}]])
        self.assertEqual(self.hit("pypi", "0.0.26", a), (True, ""))   # no fixed version is known
        self.assertEqual(self.hit("pypi", "0.0.27", a), (False, ""))

    def test_several_ranges_and_the_fix_for_each(self):
        a = adv([[{"introduced": "0"}, {"fixed": "3.0.28"}], [{"introduced": "4.0.0b10"}, {"fixed": "4.0.33"}]])
        self.assertEqual(self.hit("pypi", "3.5.0", a), (False, ""))   # between the ranges
        self.assertEqual(self.hit("pypi", "4.0.1", a), (True, "4.0.33"))
        self.assertEqual(self.hit("pypi", "2.0", a), (True, "3.0.28"))

    def test_events_out_of_order_and_reintroduced(self):
        a = adv([[{"fixed": "2.0"}, {"introduced": "0"}, {"introduced": "3.0"}, {"fixed": "3.1"}]])
        self.assertTrue(self.hit("pypi", "1.0", a)[0])
        self.assertFalse(self.hit("pypi", "2.5", a)[0])
        self.assertEqual(self.hit("pypi", "3.0.5", a), (True, "3.1"))

    def test_limit_stops_the_range(self):
        a = adv([[{"introduced": "1.0"}, {"limit": "2.0"}]])
        self.assertTrue(self.hit("pypi", "1.5", a)[0])
        self.assertFalse(self.hit("pypi", "2.5", a)[0])

    def test_explicit_versions_list(self):
        a = adv(versions=["0.4.1", "0.4.2"])
        self.assertTrue(self.hit("pypi", "0.4.2", a)[0])
        self.assertFalse(self.hit("pypi", "0.4.3", a)[0])

    def test_pep440_pre_and_post_releases(self):
        a = adv([[{"introduced": "0"}, {"fixed": "1.0.0"}]])
        self.assertTrue(self.hit("pypi", "1.0.0rc1", a)[0])    # a pre-release comes before the release
        self.assertFalse(self.hit("pypi", "1.0.0.post1", a)[0])
        self.assertTrue(self.hit("pypi", "1.0.0.dev3", a)[0])

    def test_semver_prerelease_order(self):
        a = adv([[{"introduced": "0"}, {"fixed": "2.0.0-beta.11"}]])
        self.assertTrue(self.hit("npm", "2.0.0-beta.2", a)[0])   # numeric identifiers compare as numbers: 2 < 11
        self.assertFalse(self.hit("npm", "2.0.0", a)[0])
        self.assertTrue(self.hit("npm", "2.0.0-alpha", a)[0])     # alpha < beta
        self.assertLess(vulns.SemVer("1.0.0-alpha"), vulns.SemVer("1.0.0-alpha.1"))
        self.assertLess(vulns.SemVer("1.0.0-rc.1"), vulns.SemVer("1.0.0"))
        self.assertEqual(vulns.SemVer("1.0.0+build.5"), vulns.SemVer("1.0.0"))

    def test_an_event_that_is_not_a_version_does_not_match(self):
        a = adv([[{"introduced": "0"}, {"fixed": "a1b2c3d"}]])
        self.assertFalse(self.hit("npm", "1.0.0", a)[0])


class NotChecked(unittest.TestCase):
    def test_a_range_or_no_version_is_not_checked(self):
        for version in ("^0.0.20", ">=1.0", "", "1.x", "latest"):
            r = vulns.check("pypi" if version != "1.x" else "npm", "x", version, [adv([[{"introduced": "0"}]])])
            self.assertEqual((r["status"], r["advisories"]), ("not_checked", []), version)
            self.assertTrue(r["reason"])

    def test_checked_with_none_known(self):
        r = vulns.check("pypi", "x", "1.0", [])
        self.assertEqual((r["status"], r["advisories"]), ("checked", []))


class BundledData(unittest.TestCase):
    """Against the advisories in ai_db.json; each id was checked on osv.dev."""

    @classmethod
    def setUpClass(cls):
        cls.db = load_db()

    def test_the_review_app_version_of_langchain_community(self):
        ids = {a["id"] for a in vulnerability_check("PyPI", "langchain-community", "0.0.20", self.db)["advisories"]}
        self.assertEqual(ids, {"PYSEC-2024-278", "GHSA-f2jm-rw3h-6phg", "GHSA-h5gc-rm8j-5gpr", "GHSA-pc6w-59fv-rh23",
                               "GHSA-3hjh-jh2h-vrg6", "GHSA-q25c-c977-4cmh"})

    def test_last_affected_is_respected_in_real_data(self):
        # PYSEC-2024-278 (CVE-2024-2057) affects langchain-community up to 0.0.26 and not after
        ids = {a["id"] for a in vulnerability_check("PyPI", "langchain-community", "0.0.27", self.db)["advisories"]}
        self.assertNotIn("PYSEC-2024-278", ids)

    def test_no_package_is_cut_off(self):
        self.assertGreater(len(self.db["vulnerabilities"]["pypi:vllm"]), 35)

    def test_the_data_says_when_it_was_fetched(self):
        meta = self.db["meta"]["vulnerabilities"]
        self.assertTrue(meta["fetched"])
        self.assertEqual(set(meta["dumps"]), {"PyPI", "npm"})


class OnEveryPackage(unittest.TestCase):
    def test_the_review_app(self):
        from aibom_engine.packages import find
        from aibom_engine.triage import triage
        root = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "review-app")
        r = find(root, triage(root))
        by = {c["name"]: c["vulnerabilities"] for c in r["packages"]}
        self.assertEqual(by["langchain-community"]["status"], "checked")
        self.assertEqual(len(by["langchain-community"]["advisories"]), 6)
        self.assertEqual((by["openai"]["status"], by["openai"]["advisories"]), ("checked", []))
        self.assertEqual(by["anthropic"]["status"], "not_checked")  # not declared with a version: never "no vulnerabilities"
        s = r["summary"]
        self.assertEqual((s["vulnerable_packages"], s["not_checked"]), (2, 3))
        self.assertEqual(sum(s["advisories_by_severity"].values()), s["advisories"])
        self.assertTrue(s["advisory_data"])


class Severity(unittest.TestCase):
    def test_cvss31_base_scores(self):
        for vector, score in [("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8), ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
                              ("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", 9.9), ("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.6)]:
            self.assertEqual(osv_data.cvss3_base_score(vector), score, vector)
        self.assertIsNone(osv_data.cvss3_base_score("CVSS:4.0/AV:N/AC:L/AT:N"))

    def test_github_severity_first_then_cvss_then_unknown(self):
        self.assertEqual(osv_data._severity({"database_specific": {"severity": "MODERATE"}}), "medium")
        self.assertEqual(osv_data._severity({"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}), "critical")
        self.assertEqual(osv_data._severity({}), "unknown")  # never a guessed "medium"

    def test_mirrors_are_merged_preferring_github(self):
        merged = osv_data.merge_mirrors([
            {"id": "PYSEC-2024-1", "aliases": ["CVE-2024-9"], "severity": "unknown", "cvss": "v", "summary": "p", "ranges": [], "versions": []},
            {"id": "GHSA-aaaa", "aliases": ["CVE-2024-9"], "severity": "high", "cvss": "", "summary": "g", "ranges": [], "versions": []},
            {"id": "GHSA-bbbb", "aliases": [], "severity": "low", "cvss": "", "summary": "other", "ranges": [], "versions": []},
        ])
        self.assertEqual([m["id"] for m in merged], ["GHSA-aaaa", "GHSA-bbbb"])
        self.assertEqual(merged[0]["aliases"], ["CVE-2024-9", "PYSEC-2024-1"])
        self.assertEqual(merged[0]["cvss"], "v")

    def test_when_databases_disagree_any_record_that_says_affected_counts(self):
        # CVE-2024-28088 in langchain: GitHub says fixed in 0.0.339, PYSEC says fixed in 0.1.11 (OSV counts both)
        ghsa = {"id": "GHSA-h59x", "aliases": ["CVE-2024-28088"], "severity": "high", "cvss": "", "summary": "",
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "0.0.339"}]}], "versions": []}
        pysec = {"id": "PYSEC-2024-43", "aliases": ["CVE-2024-28088"], "severity": "unknown", "cvss": "", "summary": "",
                 "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "0.1.11"}]}],
                 "versions": ["0.0.100", "0.1.5", "0.2.0"]}
        merged = osv_data.merge_mirrors([pysec, ghsa])[0]
        self.assertEqual(merged["id"], "GHSA-h59x")
        self.assertEqual(vulns.affected("pypi", "0.1.0", merged), (True, "0.1.11"))
        self.assertEqual(vulns.affected("pypi", "0.0.200", merged)[1], "0.0.339")  # the nearest fix above the version
        self.assertEqual(merged["versions"], ["0.2.0"])  # listed versions the ranges already cover are not stored again


if __name__ == "__main__":
    unittest.main()
