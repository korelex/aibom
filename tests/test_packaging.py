import json
import os
import subprocess
import sys
import unittest

import aibom_engine
from aibom_engine import db
from aibom_engine.finders import dictionary

PACKAGE_DIR = os.path.dirname(os.path.abspath(aibom_engine.__file__))
KNOWLEDGE_DIR = os.path.join(PACKAGE_DIR, "knowledge")
ROOT = os.path.abspath(os.path.join(PACKAGE_DIR, ".."))


class BundledKnowledge(unittest.TestCase):
    def test_runtime_data_lives_inside_the_package(self):
        # Only files inside the package are installed by `pip install .`; a path that climbs out of it works from a
        # checkout and crashes for every real user.
        self.assertEqual(os.path.abspath(db.AI_DB_PATH), os.path.join(KNOWLEDGE_DIR, "ai_db.json"))
        self.assertEqual(os.path.abspath(dictionary.KNOWLEDGE), os.path.join(KNOWLEDGE_DIR, "model_names.json"))
        for name in ("ai_db.json", "model_names.json"):
            self.assertTrue(os.path.isfile(os.path.join(KNOWLEDGE_DIR, name)), name)

    def test_package_data_is_declared(self):
        with open(os.path.join(ROOT, "pyproject.toml"), encoding="utf-8") as fh:
            text = fh.read()
        self.assertIn("[tool.setuptools.package-data]", text)
        self.assertIn("knowledge/*.json", text)

    def test_missing_database_is_a_loud_error_not_an_empty_database(self):
        saved_cache, saved_path = db._DB_CACHE, db.AI_DB_PATH
        try:
            db._DB_CACHE = None
            db.AI_DB_PATH = os.path.join(KNOWLEDGE_DIR, "does-not-exist.json")
            with self.assertRaises(FileNotFoundError) as caught:
                db.load_db(db.AI_DB_PATH)
            self.assertIn("Reinstall", str(caught.exception))
        finally:
            db._DB_CACHE, db.AI_DB_PATH = saved_cache, saved_path

    def test_database_file_uses_the_reviewable_layout(self):
        # One table entry per line keeps data changes visible in pull requests. Rebuild with
        # `python scripts/build_db.py --reformat` if this fails.
        with open(db.AI_DB_PATH, encoding="utf-8") as fh:
            lines = fh.read().split("\n")
        self.assertGreater(len(lines), 1000, "ai_db.json is not in the one-entry-per-line layout")
        # A whole table on one line would be megabytes; one entry can be long on its own (an OSV advisory that lists
        # 1,400 affected versions is about 36,000 characters), so the limit is on layout, not on the size of one entry.
        self.assertLess(max(len(line) for line in lines), 50000)
        with open(db.AI_DB_PATH, encoding="utf-8") as fh:
            json.load(fh)  # still plain, valid JSON

    def test_reformat_is_idempotent(self):
        before = open(db.AI_DB_PATH, "rb").read()
        sys.path.insert(0, os.path.join(ROOT, "scripts"))
        try:
            import build_db
            import tempfile
            with tempfile.TemporaryDirectory() as tmp:
                path = os.path.join(tmp, "ai_db.json")
                with open(db.AI_DB_PATH, encoding="utf-8") as fh:
                    build_db.dump_db(path, json.load(fh))
                self.assertEqual(open(path, "rb").read(), before)
        finally:
            sys.path.remove(os.path.join(ROOT, "scripts"))


if __name__ == "__main__":
    unittest.main()
