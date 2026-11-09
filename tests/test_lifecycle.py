"""Lifecycle (deprecated / retired), floating-alias and Hugging Face behaviour.

Every expectation below was checked against the provider's own page, listed in the record's lifecycle_source_url.
"""
import json
import os
import re
import unittest
from unittest import mock

from aibom_engine.db import is_pinned_reference, lifecycle_status, load_db, resolve_model, today_iso
from aibom_engine.display import build_rows

CURATED = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "aibom_engine", "knowledge", "curated.json")
ISO = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def at(day):
    """Run a block as if today were `day` (the status is computed from dates, so the date matters)."""
    return mock.patch.dict(os.environ, {"AIBOM_TODAY": day})


class StatusFollowsTheCalendar(unittest.TestCase):
    RECORD = {"deprecation_date": "2025-08-13", "retirement_date": "2025-10-28", "replacement": "x",
              "source_url": "https://example.test/deprecations", "checked": "2026-11-09"}

    def test_status_is_worked_out_from_dates(self):
        cases = [("2025-08-13", "deprecated"),   # the day it was announced
                 ("2025-10-27", "deprecated"),   # the day before it stops working
                 ("2025-10-28", "retired"),      # the retirement day itself: calls fail
                 ("2026-11-09", "retired")]
        for today, expected in cases:
            self.assertEqual(lifecycle_status(dict(self.RECORD), today=today)["status"], expected, today)

    def test_announced_in_the_future_with_no_retirement_is_still_active(self):
        lc = {"deprecation_date": "2027-01-01", "source_url": "https://example.test", "checked": "2026-11-09"}
        self.assertEqual(lifecycle_status(lc, today="2026-11-09")["status"], "active")
        self.assertEqual(lifecycle_status(lc, today="2027-01-01")["status"], "deprecated")

    def test_no_source_means_unknown_never_active(self):
        for lc in (None, {}, {"deprecation_date": "2020-01-01", "retirement_date": "2020-02-01"}, {"status": "active"}):
            out = lifecycle_status(lc, today="2026-11-09")
            self.assertEqual(out["status"], "unknown")
            self.assertEqual(out["retirement_date"], "")

    def test_a_past_retirement_date_is_retired_not_deprecated(self):
        # The bug found in review: a model whose retirement date had passed still showed "deprecated".
        with at("2026-11-09"):
            r = resolve_model("claude-3-5-sonnet-20240620")
        self.assertEqual(r["status"], "retired")
        self.assertEqual(r["deprecation_date"], "2025-08-13")
        self.assertEqual(r["retirement_date"], "2025-10-28")
        self.assertEqual(r["replacement"], "claude-sonnet-5-5")
        self.assertIn("platform.claude.com", r["lifecycle_source_url"])
        self.assertTrue(ISO.match(r["lifecycle_checked"]))

    def test_the_same_record_gives_a_different_status_on_a_different_day(self):
        with at("2025-09-01"):
            self.assertEqual(resolve_model("claude-3-5-sonnet-20240620")["status"], "deprecated")
        with at("2026-11-09"):
            self.assertEqual(resolve_model("claude-3-5-sonnet-20240620")["status"], "retired")

    def test_claude_sonnet_4_5_is_deprecated_now_and_retires_on_the_published_date(self):
        # Anthropic: deprecated 2026-09-30, retires 2026-11-30, replacement claude-sonnet-5-5.
        with at("2026-11-09"):
            r = resolve_model("claude-sonnet-4-5-20250929")
        self.assertEqual((r["status"], r["retirement_date"], r["replacement"]), ("deprecated", "2026-11-30", "claude-sonnet-5-5"))
        with at("2026-12-01"):
            self.assertEqual(resolve_model("claude-sonnet-4-5")["status"], "retired")

    def test_instant_does_not_inherit_claude_2s_dates(self):
        # claude-instant-1.2 retired on 2024-11-06; claude-2.x retired on 2025-07-21. They are different models.
        with at("2026-11-09"):
            self.assertEqual(resolve_model("claude-instant-1.2")["retirement_date"], "2024-11-06")
            self.assertEqual(resolve_model("claude-2.1")["retirement_date"], "2025-07-21")

    def test_retired_claude_models_from_the_provider_page(self):
        expected = {"claude-3-haiku-20240307": "2026-04-20", "claude-3-opus-20240229": "2026-01-05",
                    "claude-3-7-sonnet-20250219": "2026-02-19", "claude-3-5-haiku-20241022": "2026-02-19"}
        with at("2026-11-09"):
            for name, retired in expected.items():
                r = resolve_model(name)
                self.assertEqual((r["status"], r["retirement_date"]), ("retired", retired), name)

    def test_lifecycle_dates_are_for_the_makers_api_not_other_platforms(self):
        with at("2026-11-09"):
            self.assertEqual(resolve_model("claude-3-5-sonnet-20240620")["lifecycle_scope"], "first_party")
            self.assertEqual(resolve_model("anthropic.claude-3-5-sonnet-20240620-v1:0")["lifecycle_scope"], "platform")
            self.assertEqual(resolve_model("bedrock/anthropic.claude-3-5-sonnet-20240620-v1:0")["lifecycle_scope"], "platform")

    def test_today_can_be_fixed_and_a_bad_value_is_refused(self):
        with at("2030-01-02"):
            self.assertEqual(today_iso(), "2030-01-02")
        with at("tomorrow"):
            with self.assertRaises(ValueError):
                today_iso()


class CuratedRecordsAreSourced(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(CURATED, encoding="utf-8") as fh:
            cls.curated = json.load(fh)["curated_models"]

    def test_every_lifecycle_claim_has_a_source_and_a_check_date(self):
        problems = []
        for key, cm in self.curated.items():
            claims = [k for k in ("deprecation_date", "retirement_date", "replacement") if cm.get(k)]
            if claims and not (cm.get("lifecycle_source_url", "").startswith("https://") and ISO.match(cm.get("lifecycle_checked", ""))):
                problems.append(f"{key}: {claims} without lifecycle_source_url + lifecycle_checked")
            if cm.get("status"):
                problems.append(f"{key}: a stored 'status' word goes stale; store dates and let the scanner work the status out")
            for k in ("deprecation_date", "retirement_date"):
                if cm.get(k) and not ISO.match(cm[k]):
                    problems.append(f"{key}: {k}={cm[k]!r} is not YYYY-MM-DD")
            if cm.get("deprecation_date") and cm.get("retirement_date") and cm["deprecation_date"] > cm["retirement_date"]:
                problems.append(f"{key}: announced after it retires")
        self.assertFalse(problems, "\n".join(problems))

    def test_every_recommended_replacement_is_an_active_model(self):
        # Sending people to a model that is itself being retired is worse than recommending nothing.
        db = load_db()
        problems = []
        with at("2026-11-09"):
            for key, cm in self.curated.items():
                repl = cm.get("replacement")
                if not repl:
                    continue
                r = resolve_model(repl, db=db)
                if r["status"] != "active":
                    problems.append(f"{key} -> {repl!r} resolves to status {r['status']!r}")
        self.assertFalse(problems, "\n".join(problems))


class FloatingAliasesAndHuggingFace(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.db = load_db()

    def r(self, name):
        return resolve_model(name, db=self.db)

    def test_floating_only_when_a_dated_snapshot_exists_to_pin(self):
        for name in ("gpt-4o", "gpt-4o-mini", "claude-sonnet-4-5", "claude-3-5-sonnet-latest", "gpt-4"):
            self.assertTrue(self.r(name)["floating"], name)
        # text-embedding-3-small has no dated snapshot, so there is nothing to pin to and nothing to warn about.
        self.assertFalse(self.r("text-embedding-3-small")["floating"])
        self.assertFalse(self.r("text-embedding-3-small")["snapshot_available"])

    def test_pinned_names_are_not_floating(self):
        for name in ("gpt-4o-2024-08-06", "claude-sonnet-4-5-20250929", "gpt-4-1106-preview", "mistral-large-2407",
                     "gemini-2.5-flash-preview-05-20"):
            r = self.r(name)
            self.assertTrue(r["pinned"], name)
            self.assertFalse(r["floating"], name)

    def test_snapshot_suffixes_that_the_old_pattern_missed(self):
        # Review finding: -MMDD-preview and -YYMM were not recognised as snapshots.
        for name in ("gpt-4-1106-preview", "gpt-4-0125-preview", "mistral-large-2407", "codestral-2501", "command-r-08-2024",
                     "gemini-2.5-flash-lite-preview-09-2025", "deepseek-v3-0324", "o1-2024-12-17", "claude-3-haiku-20240307"):
            self.assertTrue(is_pinned_reference(name), name)
        for name in ("gpt-4o", "gpt-4-turbo-preview", "gpt-4-32k", "text-embedding-3-small", "qwen2.5-72b", "llama-3-8b-instruct",
                     "claude-3-5-sonnet-latest", "gemma-2-9b-it", "mixtral-8x7b-instruct-v0.1"):
            self.assertFalse(is_pinned_reference(name), name)

    def test_hugging_face_repos_are_reported_separately_not_as_floating_aliases(self):
        for name in ("meta-llama/Llama-2-7b-hf", "stabilityai/stable-diffusion-xl-base-1.0", "deepseek-ai/DeepSeek-R1",
                     "black-forest-labs/FLUX.1-dev"):
            r = self.r(name)
            self.assertTrue(r["hf_repo"], name)
            self.assertFalse(r["floating"], name)

    def test_provider_prefixed_names_are_not_hugging_face_repos(self):
        for name in ("openai/gpt-4o", "anthropic/claude-sonnet-4-5", "azure/gpt-4o", "google/gemini-2.5-pro"):
            self.assertFalse(self.r(name)["hf_repo"], name)
        self.assertTrue(self.r("azure/gpt-4o")["floating"])

    def test_an_unknown_model_is_never_called_floating(self):
        r = self.r("totally-made-up-model")
        self.assertFalse(r["floating"])
        self.assertEqual(r["status"], "unknown")


class MergedRowsShowOneConsistentLifecycle(unittest.TestCase):
    def item(self, name, status, dep, ret, repl):
        return {"name": name, "tier": "declared", "kind": "model", "aliases": [], "evidence": [], "maker": "Anthropic", "mode": "chat",
                "status": status, "deprecation_date": dep, "retirement_date": ret, "replacement": repl, "pinned": True,
                "floating": False, "hf_repo": False, "lifecycle_scope": "first_party", "lifecycle_source_url": "https://x.test",
                "lifecycle_checked": "2026-11-09"}

    def test_dates_and_replacement_come_from_the_same_spelling_as_the_status(self):
        rows = build_rows([self.item("claude-x", "deprecated", "2026-01-01", "2027-01-01", "new-a"),
                           self.item("claude_x", "retired", "2025-01-01", "2025-06-01", "new-b")])
        row = (rows["used"] + rows["listed"])[0]
        self.assertEqual((row["status"], row["deprecation_date"], row["retirement_date"], row["replacement"]),
                         ("retired", "2025-01-01", "2025-06-01", "new-b"))


if __name__ == "__main__":
    unittest.main()
