"""The benchmark scorer: what counts as found, correct and unreviewed."""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "benchmark"))
import score as S  # noqa: E402

KEY = {
    "items": [
        {"kind": "model", "name": "gpt-4o", "aliases": ["openai/gpt-4o"]},
        {"kind": "model", "name": "claude-sonnet-5-5", "aliases": []},
        {"kind": "framework", "name": "langchain", "aliases": []},   # not a model: not counted
    ],
    "extra_real": [{"name": "o4-mini", "why": "real constant"}],
    "junk": ["mock-model"],
    "reference_ranges": [{"file": "limits.py", "from": 10, "to": 20, "why": "token-limit table"}],
}


def item(name, file="app.py", line=1, tier="declared", kind="model"):
    return {"kind": kind, "name": name, "tier": tier, "evidence": [{"file": file, "line": line, "use": "live"}]}


class Score(unittest.TestCase):
    def run_score(self, items):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "merged.json"), "w", encoding="utf-8") as fh:
                json.dump(items, fh)
            return S.score(S.load_run(d), KEY)

    def test_counts(self):
        r = self.run_score([
            item("openai/gpt-4o"),                       # key item, through an alias spelling
            item("o4-mini"),                             # labelled real afterwards
            item("text-embedding-3-small", "limits.py", 15),  # inside a labelled reference range
            item("mock-model"),                          # junk
            item("nobody-labelled-this"),                # unreviewed: counts as wrong
            item("claude-sonnet-5-5", tier="rejected"),  # rejected by Verify: not reported, not found
        ])
        self.assertEqual((r["key_models"], r["found"]), (2, 1))   # the framework item is not counted
        self.assertEqual(r["recall"], 0.5)
        self.assertEqual((r["reported"], r["correct"], r["junk"], r["unreviewed"]), (5, 3, 1, 1))
        self.assertEqual(r["precision"], 3 / 5)
        self.assertEqual(r["unreviewed_names"], ["nobody-labelled-this"])

    def test_two_spellings_of_one_name_are_reported_once(self):
        r = self.run_score([item("gpt-4o"), item("GPT-4o")])
        self.assertEqual(r["reported"], 1)

    def test_every_answer_key_loads_and_lists_models(self):
        labels = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "benchmark", "labels")
        with open(os.path.join(labels, "..", "repos.json"), encoding="utf-8") as fh:
            repos = [r["name"] for r in json.load(fh)["repos"]]
        for name in repos:
            key = S.load_key(name)
            self.assertIn("items", key, name)
            self.assertTrue(key.get("status"), name)


if __name__ == "__main__":
    unittest.main()
