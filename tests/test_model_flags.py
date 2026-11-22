"""Risk flags for model files and trust_remote_code (M3.4), and the whole scan with them."""
import gzip
import json
import os
import pickle
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

from aibom_engine import flags as F
from aibom_engine import modelfiles as MF
from aibom_engine import remote_code as RC
from aibom_engine.pipeline import run
from aibom_engine.triage import FileInfo, triage
from aibom_engine.writer import validate
from test_mcp import make
from test_modelfiles import LAMBDA_MODEL, evil_pickle, keras_zip, safetensors_bytes, torch_zip, torch_like_pickle

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
APP = os.path.join(ROOT, "tests", "fixtures", "review-app")


def record(file="models/m.pt", location="", **kw):
    rec = MF.new_record(file, 1000, location)
    rec.update({"serialization": "pickle", "format": "Python pickle", "pickle_based": True, "status": "scanned"})
    rec.update(kw)
    return rec


def danger(module, name, severity="high", why=None):
    return {"module": module, "name": name, "severity": severity, "why": why or "runs commands or code"}


def flags_for(**kw):
    return MF.model_file_flags([record(**kw)])


def rules(flags):
    return sorted(f.rule for f in flags)


class DangerousCalls(unittest.TestCase):
    def test_a_high_import_in_the_products_own_file(self):
        got = flags_for(dangerous=[danger("os", "system")])
        self.assertEqual(rules(got), ["model-file.dangerous-call"])
        f = got[0]
        self.assertEqual((f.severity, f.category, f.subject, f.file, f.line, f.ref), ("high", "model-file", "models/m.pt", "models/m.pt", 0, "modelfile:models-m.pt"))
        self.assertIn("os.system (runs commands or code)", f.detail)
        self.assertIn("only read, never loaded", f.detail)
        self.assertIn("Do not load it", f.fix)

    def test_one_step_lower_in_a_test_or_example_file_and_no_component_to_sit_on(self):
        got = flags_for(location="test", dangerous=[danger("os", "system")])
        self.assertEqual((got[0].severity, got[0].ref), ("medium", ""))
        self.assertIn("in a test file", got[0].detail)

    def test_only_helpers_that_attacks_chain_are_medium(self):
        self.assertEqual(flags_for(dangerous=[danger("builtins", "getattr", "medium")])[0].severity, "medium")
        self.assertEqual(flags_for(location="example", dangerous=[danger("builtins", "getattr", "medium")])[0].severity, "low")

    def test_the_worst_import_sets_the_severity_and_a_long_list_is_cut(self):
        many = [danger("builtins", "getattr", "medium")] + [danger("os", f"f{i}") for i in range(6)]
        f = flags_for(dangerous=many)[0]
        self.assertEqual(f.severity, "high")
        self.assertIn("and 3 more", f.detail)
        self.assertEqual(f.detail.count("("), 4)

    def test_an_import_that_could_not_be_identified(self):
        got = flags_for(unresolved=2)
        self.assertEqual(rules(got), ["model-file.pickle-format", "model-file.unresolved-import"][1:])
        self.assertEqual((got[0].severity, flags_for(unresolved=2, location="test")[0].severity), ("medium", "low"))
        self.assertIn("2 import(s)", got[0].detail)

    def test_a_dangerous_file_does_not_also_get_the_plain_pickle_flag(self):
        self.assertEqual(rules(flags_for(dangerous=[danger("os", "system")])), ["model-file.dangerous-call"])


class MislabelledAndFormat(unittest.TestCase):
    def test_a_name_that_says_numbers_only_on_something_else(self):
        got = flags_for(file="m.safetensors", mislabelled="named .safetensors but the content is a pickle")
        self.assertIn("model-file.mislabelled", rules(got))
        f = next(f for f in got if f.rule == "model-file.mislabelled")
        self.assertEqual(f.severity, "high")
        self.assertIn("named .safetensors but the content is a pickle", f.detail)
        self.assertEqual(next(f for f in flags_for(location="docs", mislabelled="x") if f.rule == "model-file.mislabelled").severity, "medium")

    def test_a_pickle_with_nothing_found_is_still_a_pickle(self):
        f = flags_for(format="PyTorch checkpoint (zip)")[0]
        self.assertEqual((f.rule, f.severity), ("model-file.pickle-format", "medium"))
        self.assertIn("PyTorch checkpoint (zip)", f.title)
        self.assertIn("does not make loading it safe", f.detail)
        self.assertIn("safetensors", f.fix)
        self.assertEqual(flags_for(location="test")[0].severity, "low")

    def test_a_pickle_that_could_not_be_fully_scanned_says_so(self):
        f = [f for f in flags_for(status="not-scanned", reason="it is larger than 1 GB, the most that is read") if f.rule == "model-file.pickle-format"][0]
        self.assertIn("could not be fully scanned", f.detail)
        self.assertNotIn("does not make loading it safe", f.detail)

    def test_formats_that_hold_only_numbers_get_no_flag(self):
        for serialization, fmt in (("safetensors", "safetensors"), ("gguf", "GGUF"), ("onnx", "ONNX")):
            self.assertEqual(flags_for(serialization=serialization, format=fmt, pickle_based=False, status="safe-format"), [])


class Lambda(unittest.TestCase):
    def test_a_keras_zip_and_an_older_hdf5(self):
        z = flags_for(serialization="keras-zip", format="Keras model (zip)", pickle_based=False, lambda_layer=True)[0]
        h = flags_for(serialization="hdf5", format="Keras model (HDF5)", pickle_based=False, lambda_layer=True)[0]
        self.assertEqual((z.rule, z.severity, h.rule, h.severity), ("model-file.keras-lambda", "medium", "model-file.keras-lambda", "medium"))
        self.assertIn("safe_mode", z.detail)
        self.assertNotIn("safe_mode", h.detail)          # the protection is documented for the .keras format only
        self.assertEqual(flags_for(serialization="keras-zip", pickle_based=False, lambda_layer=True, location="test")[0].severity, "low")

    def test_no_layer_no_flag(self):
        self.assertEqual(flags_for(serialization="keras-zip", format="Keras model (zip)", pickle_based=False, lambda_layer=False), [])


class NotScanned(unittest.TestCase):
    def one(self, **kw):
        return [f for f in flags_for(pickle_based=False, serialization="", **kw) if f.rule == "model-file.not-scanned"]

    def test_reasons_that_suggest_hiding_or_a_cut_short_scan_are_low_the_rest_info(self):
        for reason in ("an entry is encrypted, so it cannot be read", "it holds another archive (a.zip), which is not read", "an entry is compressed far more than data normally is, which can be a zip bomb",
                       "it inflates to more than the size limit, so only the start was read", "the time limit was reached", "the zip has more than 100000 entries", "only part of it was read (opcode limit)"):
            self.assertEqual(self.one(status="not-scanned", reason=reason)[0].severity, "low", reason)
        for reason in ("it is a Git LFS pointer: the real file is not in this checkout", "it is compressed with zstd, which is not read", "it is larger than 1 GB, the most that is read",
                       "the content is not a valid safetensors file"):
            self.assertEqual(self.one(status="not-scanned", reason=reason)[0].severity, "info", reason)

    def test_a_partly_scanned_file_is_always_low(self):
        self.assertEqual(self.one(status="partly-scanned", reason="something harmless")[0].severity, "low")

    def test_the_text_says_that_unscanned_is_not_safe(self):
        f = self.one(status="not-scanned", reason="it is a Git LFS pointer: the real file is not in this checkout")[0]
        self.assertTrue(f.detail.startswith("It is a Git LFS pointer"))
        self.assertIn("not a file that was found safe", f.detail)

    def test_only_the_products_own_files_and_never_for_a_file_already_called_mislabelled(self):
        self.assertEqual(self.one(status="not-scanned", reason="x y", location="test"), [])
        self.assertEqual(self.one(status="not-scanned", reason="x y", mislabelled="named .safetensors but the content is a pickle"), [])
        self.assertEqual(self.one(status="scanned", reason=""), [])
        self.assertEqual(self.one(status="not-scanned", reason=""), [])
        self.assertEqual(self.one(status="safe-format", reason=""), [])

    def test_flags_collect_and_sort_like_any_other(self):
        fl = F.collect(MF.model_file_flags([record(dangerous=[danger("os", "system")]), record(file="b.pt", location="test"), record(file="c.safetensors", serialization="safetensors",
                                                                                                                                      pickle_based=False, status="safe-format")]))
        self.assertEqual([(f.severity, f.rule, f.file) for f in fl], [("high", "model-file.dangerous-call", "models/m.pt"), ("low", "model-file.pickle-format", "b.pt")])


class TrustRemoteCode(unittest.TestCase):
    def hits(self, text, rel="app.py"):
        return RC.scan_text(text, rel)

    def test_python_arguments_and_assignments(self):
        self.assertEqual(self.hits("m = AutoModel.from_pretrained('x', trust_remote_code=True)"), [(1, "keyword")])
        self.assertEqual(self.hits("LLM(\n    model='x',\n    trust_remote_code=True,\n)"), [(3, "keyword")])
        self.assertEqual(self.hits("trust_remote_code = True"), [(1, "assignment")])
        self.assertEqual(self.hits("self.trust_remote_code = True"), [(1, "assignment")])
        self.assertEqual(self.hits("trust_remote_code: bool = True"), [(1, "assignment")])
        self.assertEqual(self.hits("a(b(c(trust_remote_code=True)))"), [(1, "keyword")])
        self.assertEqual(len(self.hits("f(trust_remote_code=True)\ng(trust_remote_code=True)")), 2)

    def test_python_dicts_of_arguments(self):
        # Found in the M3 manual test: the model_kwargs form was missed.
        self.assertEqual(self.hits('kw = {"trust_remote_code": True}'), [(1, "dict")])
        self.assertEqual(self.hits('pipeline("t", model="x", model_kwargs={"x": 1,\n    "trust_remote_code": True})'), [(2, "dict")])
        self.assertEqual(self.hits("f(**{'trust_remote_code': True})"), [(1, "dict")])
        self.assertEqual(self.hits('d = {**base, "trust_remote_code": True}'), [(1, "dict")])
        for text in ('kw = {"trust_remote_code": False}', 'kw = {"trust_remote_code": flag}', 'kw = {"trust_remote_codes": True}', 'kw = {"x": "trust_remote_code"}', 'kw = {**base}'):
            self.assertEqual(self.hits(text), [], text)
        flag = RC.remote_code_flags([{"file": "a.py", "line": 1, "how": "dict", "location": ""}])[0]
        self.assertIn("set in a dict of arguments", flag.detail)

    def test_python_that_is_not_turning_it_on(self):
        for text in ("m = AutoModel.from_pretrained('x', trust_remote_code=False)", "f(trust_remote_code=flag)", "f(trust_remote_code=None)", "f(trust_remote_code=1)",
                     "# f(trust_remote_code=True)", "'''f(trust_remote_code=True)'''", "x = 'trust_remote_code=True'", "def f(trust_remote_code=False): pass", "trust_remote_code = False",
                     "print('--trust-remote-code')", "f(trust_remote_codes=True)"):
            self.assertEqual(self.hits(text), [], text)

    def test_python_that_does_not_parse_falls_back_to_the_text_rules_but_skips_comments(self):
        self.assertEqual(self.hits("def broken(:\n    f(trust_remote_code=True)\n"), [(2, "setting")])
        self.assertEqual(self.hits("def broken(:\n    # f(trust_remote_code=True)\n"), [])

    def test_other_kinds_of_file(self):
        cases = [("trust_remote_code: true", "x.yaml", [(1, "setting")]), ('{"trust_remote_code": true}', "x.json", [(1, "setting")]), ("trust_remote_code = true", "x.toml", [(1, "setting")]),
                 ("TRUST_REMOTE_CODE=1", ".env", [(1, "setting")]), ("TRUST_REMOTE_CODE=true", ".env", [(1, "setting")]), ("export TRUST_REMOTE_CODE=yes", "run.sh", [(1, "setting")]),
                 ('trust_remote_code: "true"', "x.yml", [(1, "setting")]), ("vllm serve m --trust-remote-code", "run.sh", [(1, "flag")]), ("python x.py --trust_remote_code", "run.sh", [(1, "flag")]),
                 ("CMD [\"serve\", \"--trust-remote-code\"]", "Dockerfile", [(1, "flag")]), ("    command: --model m --trust-remote-code --port 8000", "compose.yml", [(1, "flag")]),
                 ("--trust-remote-code=true", "x.sh", [(1, "flag")]), ("--trust-remote-code True", "x.sh", [(1, "flag")]), ("a\nb\ntrust_remote_code: on\n", "x.yaml", [(3, "setting")])]
        for text, rel, want in cases:
            self.assertEqual(self.hits(text, rel), want, (text, rel))

    def test_text_that_is_not_turning_it_on(self):
        for text, rel in (("trust_remote_code: false", "x.yaml"), ("trust_remote_code = 0", "x.toml"), ("TRUST_REMOTE_CODE=no", ".env"), ("--trust-remote-code=false", "x.sh"), ("--trust-remote-code false", "x.sh"),
                          ("--no-trust-remote-code", "x.sh"), ("foo--trust-remote-code", "x.sh"), ("a-b--trust-remote-code", "x.sh"), ("# trust_remote_code: true", "x.yaml"), ("// trust_remote_code = true", "x.js"), ("; trust_remote_code=1", "x.ini"),
                          ("mytrust_remote_code_x: true", "x.yaml"), ("trust_remote_code_enabled: true", "x.yaml"), ("nothing here", "x.yaml"), ("trust_remote_code", "x.txt"), ("--trust-remote-code-x", "x.sh")):
            self.assertEqual(self.hits(text, rel), [], (text, rel))

    def test_a_notebook_is_read_as_text(self):
        nb = json.dumps({"cells": [{"cell_type": "code", "source": ["m = AutoModel.from_pretrained('x', trust_remote_code=True)"]}]}, indent=1)
        self.assertEqual([h[1] for h in self.hits(nb, "n.ipynb")], ["setting"])

    def test_the_flags(self):
        found = [{"file": "src/a.py", "line": 7, "how": "keyword", "location": ""}, {"file": "tests/t.py", "line": 2, "how": "flag", "location": "test"}]
        a, b = RC.remote_code_flags(found)
        self.assertEqual((a.rule, a.severity, a.category, a.file, a.line, a.subject), ("code.trust-remote-code", "medium", "code", "src/a.py", 7, "trust_remote_code"))
        self.assertIn("passed as an argument", a.detail)
        self.assertIn("revision", a.fix)
        self.assertEqual((b.severity, "in a test file" in b.detail, "command-line flag" in b.detail), ("low", True, True))
        self.assertEqual(RC.remote_code_flags([]), [])


class Sizes(unittest.TestCase):
    def test_human_sizes(self):
        from aibom_engine.report import human_size
        for n, want in ((0, "0 B"), (1000, "1000 B"), (1023, "1023 B"), (1024, "1.0 KB"), (1536, "1.5 KB"), (5 * 2 ** 20, "5.0 MB"), (3 * 2 ** 30, "3.0 GB"), (5000 * 2 ** 30, "5000.0 GB")):
            self.assertEqual(human_size(n), want, n)


class FindingRemoteCode(unittest.TestCase):
    def found(self, files, **kw):
        with make(files) as d:
            return RC.find(d, triage(d), **kw)

    def test_the_products_files_come_first_and_documentation_is_not_read(self):
        got = self.found({"src/a.py": "f(trust_remote_code=True)\n", "tests/test_a.py": "f(trust_remote_code=True)\n", "docs/guide.md": "Pass trust_remote_code=True to it.\n",
                          "README.md": "trust_remote_code=True\n", "run.sh": "serve --trust-remote-code\n", "package-lock.json": "trust_remote_code: true"})
        self.assertEqual([(f["file"], f["line"], f["how"], f["location"]) for f in got["findings"]],
                         [("run.sh", 1, "flag", ""), ("src/a.py", 1, "keyword", ""), ("tests/test_a.py", 1, "keyword", "test")])
        self.assertEqual((got["partial"], got["truncated"]), (False, False))

    def test_files_that_cannot_be_read_as_text_are_skipped(self):
        with make({"a.py": "x = 1\n"}) as d:
            with open(os.path.join(d, "bin.dat"), "wb") as fh:
                fh.write(b"\x00trust_remote_code=True")
            with open(os.path.join(d, "latin.py"), "wb") as fh:
                fh.write(b"# caf\xe9\nf(trust_remote_code=True)\n")
            got = RC.find(d, triage(d))
        self.assertEqual([(f["file"], f["line"]) for f in got["findings"]], [("latin.py", 2)])

    def test_the_limits(self):
        text = "\n".join("f(trust_remote_code=True)" for _ in range(60))
        self.assertEqual(len(self.found({"a.py": text})["findings"]), RC.MAX_PER_FILE)
        self.assertTrue(self.found({"a.py": text})["truncated"])
        self.assertTrue(self.found({"a.py": "f(trust_remote_code=True)"}, deadline=1)["partial"])
        with mock.patch.object(RC, "MAX_FINDINGS", 3):
            got = self.found({f"f{i}.py": text for i in range(5)})
        self.assertEqual((len(got["findings"]), got["truncated"]), (3, True))

    def test_a_link_is_not_followed(self):
        with make({"a.py": "f(trust_remote_code=True)\n"}) as d:
            files = triage(d)
            with mock.patch("aibom_engine.remote_code.os.path.islink", return_value=True):
                self.assertEqual(RC.find(d, files)["findings"], [])

    def test_deep_or_odd_python_does_not_crash_the_search(self):
        deep = "f(" * 3000 + "trust_remote_code=True" + ")" * 3000
        got = self.found({"deep.py": deep, "ok.py": "f(trust_remote_code=True)\n"})
        self.assertIn("ok.py", [f["file"] for f in got["findings"]])


class WholeScan(unittest.TestCase):
    FILES = {
        "models/classifier.pkl": evil_pickle(2),
        "models/torch_model.pt": torch_zip(torch_like_pickle()),
        "models/other.pkl": pickle.dumps({"a": 1}, protocol=4),
        "models/weights.safetensors": safetensors_bytes(),
        "models/fake.safetensors": evil_pickle(4),
        "models/lambda.keras": keras_zip(LAMBDA_MODEL),
        "tests/data/sample.pkl": evil_pickle(4),
        "src/load.py": b"from transformers import AutoModel\nm = AutoModel.from_pretrained('x', trust_remote_code=True)\n",
        "src/client.py": b"from openai import OpenAI\nOpenAI().chat.completions.create(model='gpt-4o-2024-08-06', messages=[])\n",
    }

    @classmethod
    def setUpClass(cls):
        cls.repo = make({})
        for rel, data in cls.FILES.items():
            path = os.path.join(cls.repo.name, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "wb") as fh:
                fh.write(data)
        cls.out = tempfile.TemporaryDirectory()
        cls.result = run(cls.repo.name, cls.out.name, app="demo")

    @classmethod
    def tearDownClass(cls):
        cls.repo.cleanup()
        cls.out.cleanup()

    def read(self, name):
        with open(os.path.join(self.out.name, name), encoding="utf-8-sig") as fh:
            return fh.read()

    def test_modelfiles_json_manifest_and_result_agree(self):
        saved = json.loads(self.read("modelfiles.json"))
        self.assertEqual([(r["file"], r["status"], r["location"]) for r in saved["files"]],
                         [("models/classifier.pkl", "scanned", ""), ("models/fake.safetensors", "scanned", ""), ("models/lambda.keras", "scanned", ""), ("models/other.pkl", "scanned", ""), ("models/torch_model.pt", "scanned", ""),
                          ("models/weights.safetensors", "safe-format", ""), ("tests/data/sample.pkl", "scanned", "test")])
        summary = {"files": 6, "pickle": 4, "dangerous": 3, "not_scanned": 0, "safe": 1, "other": 1}
        self.assertEqual(json.loads(self.read("manifest.json"))["model_files"], summary)
        self.assertEqual((self.result["model_files"], self.result["remote_code"]), (summary, 1))
        self.assertEqual(json.loads(self.read("manifest.json"))["remote_code"], 1)
        self.assertEqual([(f["file"], f["line"]) for f in saved["remote_code"]["findings"]], [("src/load.py", 2)])

    def test_the_flags(self):
        saved = json.loads(self.read("flags.json"))
        got = sorted((f["severity"], f["rule"], f["file"]) for f in saved["flags"] if f["category"] in ("model-file", "code"))
        self.assertEqual(got, sorted([("high", "model-file.dangerous-call", "models/classifier.pkl"), ("high", "model-file.dangerous-call", "models/fake.safetensors"),
                                      ("high", "model-file.mislabelled", "models/fake.safetensors"), ("medium", "model-file.pickle-format", "models/torch_model.pt"), ("medium", "model-file.pickle-format", "models/other.pkl"),
                                      ("medium", "model-file.keras-lambda", "models/lambda.keras"), ("medium", "model-file.dangerous-call", "tests/data/sample.pkl"),
                                      ("medium", "code.trust-remote-code", "src/load.py")]))

    def test_each_live_model_file_is_a_component_with_its_flags_and_nothing_else_is(self):
        bom = json.loads(self.read("aibom.cdx.json"))
        self.assertIsNone(validate(bom))
        files = {c["name"]: c for c in bom["components"] if any(p["name"] == "aibom-engine:kind" and p["value"] == "model-file" for p in c["properties"])}
        self.assertEqual(sorted(files), ["models/classifier.pkl", "models/fake.safetensors", "models/lambda.keras", "models/other.pkl", "models/torch_model.pt", "models/weights.safetensors"])
        c = files["models/classifier.pkl"]
        self.assertEqual((c["type"], c["bom-ref"]), ("machine-learning-model", "modelfile:models-classifier.pkl"))
        props = {(p["name"], p["value"]) for p in c["properties"]}
        for want in (("aibom-engine:format", "Python pickle"), ("aibom-engine:pickle-based", "true"), ("aibom-engine:scan-status", "scanned"), ("aibom-engine:dangerous-import", "__builtin__.eval")):
            self.assertIn(want, props)
        self.assertEqual(c["evidence"]["occurrences"][0]["location"], "models/classifier.pkl")
        on = {c["name"]: sorted(json.loads(p["value"])["rule"] for p in c["properties"] if p["name"] == F.PROPERTY) for c in files.values()}
        self.assertEqual(on["models/classifier.pkl"], ["model-file.dangerous-call"])
        self.assertEqual(on["models/fake.safetensors"], ["model-file.dangerous-call", "model-file.mislabelled"])
        self.assertEqual(on["models/weights.safetensors"], [])
        app = [json.loads(p["value"])["rule"] for p in bom["metadata"]["component"]["properties"] if p["name"] == F.PROPERTY]
        self.assertIn("model-file.dangerous-call", app)            # the test file has no component, so its flag sits on the application
        self.assertIn("code.trust-remote-code", app)
        self.assertNotIn("tests/data/sample.pkl", files)

    def test_the_report_shows_the_files_and_what_was_found_and_never_says_safe(self):
        md = self.read("report.md")
        self.assertIn("## Model files", md)
        block = md.split("## Model files")[1].split("\n## ")[0]
        for needle in ("models/classifier.pkl", "imports __builtin__.eval", "PyTorch checkpoint (zip)", "no dangerous import found; that does not make loading it safe",
                       "A format that holds only numbers", "a Lambda layer, which holds Python code", "named .safetensors but the content is a pickle",
                       "1 more in tests, examples or documentation, left out.", "trust_remote_code is turned on in 1 place: src/load.py:2."):
            self.assertIn(needle, block)
        self.assertNotIn("is safe.", block.replace("not the same as safe", ""))
        self.assertIn("Model files</h2>", self.read("report.html"))

    def test_the_terminal_summary_and_the_dashboard(self):
        r = subprocess.run([sys.executable, "-m", "aibom_engine", "scan", self.repo.name, "--out", os.path.join(self.out.name, "again")], cwd=ROOT, capture_output=True, text=True,
                           env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
        self.assertEqual(r.returncode, 0, r.stderr)
        lines = [" ".join(l.split()) for l in r.stdout.splitlines()]
        self.assertIn("6 model files (4 use pickle, 3 with a dangerous or hidden import, a Lambda layer or a misleading name); 1 more in tests, examples or documentation", lines)
        self.assertIn("1 place turns trust_remote_code on", lines)
        from aibom_engine import screens, ui
        from test_ui import drawn, recorded
        result = {"app": "demo", "seconds": 1.0, "used": 0, "listed": 0, "left_out": 0, "rows": {"used": [], "listed": []}, "packages": {}, "warnings": [], "items": 0,
                  "model_files": {"files": 6, "pickle": 4, "dangerous": 2}, "remote_code": 2}
        try:
            con = recorded()
            screens.dashboard(result, "runs/demo", [], mock.Mock(ok=False), "aibom", "", "9.9")
            text = " ".join(drawn(con).split())
            self.assertIn("model files (4 use pickle, 2 with a dangerous or hidden import, a Lambda layer or a misleading name)", text)
            self.assertIn("places turn trust_remote_code on", text)
            con = recorded()
            result["model_files"], result["remote_code"] = {"files": 0, "pickle": 0, "dangerous": 0, "other": 2}, 1
            result["secrets"] = {"keys": 0, "files": 0, "other": 1}
            screens.dashboard(result, "runs/demo", [], mock.Mock(ok=False), "aibom", "", "9.9")
            text = " ".join(drawn(con).split())
            self.assertIn("model files (0 use pickle, 0 with a dangerous or hidden import, a Lambda layer or a misleading name); 2 more in tests, examples or documentation".replace(" ", ""),
                          text.replace(" ", "").replace("\u2502", ""))            # the panel wraps this long row
            self.assertIn("1 place turns trust_remote_code on", text)
            self.assertIn("hardcoded API keys in 0 files; 1 more in tests, examples or documentation", text)
            con = recorded()
            result["model_files"], result["remote_code"] = {"files": 0, "pickle": 0, "dangerous": 0}, 0
            screens.dashboard(result, "runs/demo", [], mock.Mock(ok=False), "aibom", "", "9.9")
            self.assertNotIn("model files", drawn(con))
        finally:
            ui.use_console(None)

    def test_rebuild_and_the_pdf_page_keep_everything_and_an_old_folder_still_rebuilds(self):
        from aibom_engine.cli import make_pdf
        with mock.patch("aibom_engine.pdf.print_to_pdf", side_effect=lambda page, path: page):
            self.assertIn("Model files</h2>", make_pdf(self.out.name))
        with tempfile.TemporaryDirectory() as copy:
            import shutil
            shutil.copytree(self.out.name, os.path.join(copy, "run"))
            run_dir = os.path.join(copy, "run")
            os.remove(os.path.join(run_dir, "report.md"))
            r = subprocess.run([sys.executable, "-m", "aibom_engine", "rebuild", run_dir], cwd=ROOT, capture_output=True, text=True, env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
            self.assertEqual(r.returncode, 0, r.stderr)
            with open(os.path.join(run_dir, "report.md"), encoding="utf-8") as fh:
                self.assertIn("## Model files", fh.read())
            os.remove(os.path.join(run_dir, "modelfiles.json"))
            r = subprocess.run([sys.executable, "-m", "aibom_engine", "rebuild", run_dir], cwd=ROOT, capture_output=True, text=True, env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
            self.assertEqual(r.returncode, 0, r.stderr)

    def test_the_run_is_the_same_every_time(self):
        with tempfile.TemporaryDirectory() as again:
            run(self.repo.name, again, app="demo")
            for name in ("modelfiles.json", "flags.json", "aibom.cdx.json"):
                with open(os.path.join(again, name), encoding="utf-8") as a, open(os.path.join(self.out.name, name), encoding="utf-8") as b:
                    self.assertEqual(a.read(), b.read(), name)

    def test_nothing_in_the_repository_was_run_or_changed(self):
        marker = os.path.join(self.repo.name, "ran.txt")

        class Boom:
            def __reduce__(self):
                return (exec, (f"open({marker!r}, 'w').write('ran')",))
        with make({"models/x.pkl": ""}) as d, tempfile.TemporaryDirectory() as out:
            with open(os.path.join(d, "models", "x.pkl"), "wb") as fh:
                fh.write(pickle.dumps(Boom(), protocol=4))
            before = open(os.path.join(d, "models", "x.pkl"), "rb").read()
            run(d, out, app="demo")
            self.assertEqual(open(os.path.join(d, "models", "x.pkl"), "rb").read(), before)
        self.assertFalse(os.path.exists(marker))

    def test_a_repository_with_no_model_files_says_nothing(self):
        with make({"app.py": "from openai import OpenAI\n"}) as d, tempfile.TemporaryDirectory() as out:
            result = run(d, out, app="demo")
            self.assertEqual((result["model_files"]["files"], result["remote_code"]), (0, 0))
            with open(os.path.join(out, "report.md"), encoding="utf-8") as fh:
                self.assertNotIn("## Model files", fh.read())
            with open(os.path.join(out, "modelfiles.json"), encoding="utf-8") as fh:
                self.assertEqual(json.load(fh)["files"], [])

    def test_a_failure_in_the_search_never_stops_the_scan(self):
        with make({"app.py": 'from openai import OpenAI\nOpenAI().chat.completions.create(model="gpt-4o-2024-08-06", messages=[])\n'}) as d, tempfile.TemporaryDirectory() as out:
            with mock.patch("aibom_engine.pipeline.modelfile_finder.find", side_effect=RuntimeError("boom")), mock.patch("aibom_engine.pipeline.remote_code_finder.find", side_effect=RuntimeError("bang")):
                result = run(d, out, app="demo")
            self.assertTrue(result["valid"])
            self.assertGreaterEqual(result["used"], 1)
            text = " ".join(result["warnings"])
            self.assertIn("search for model files failed", text)
            self.assertIn("search for trust_remote_code failed", text)

    def test_a_search_cut_short_or_capped_is_a_warning(self):
        cut = {"files": [], "problems": [{"file": "x.pt", "error": "denied"}], "partial": True, "truncated": True}
        with make({"app.py": "from openai import OpenAI\n"}) as d, tempfile.TemporaryDirectory() as out:
            with mock.patch("aibom_engine.pipeline.modelfile_finder.find", return_value=cut):
                result = run(d, out, app="demo")
        text = " ".join(result["warnings"])
        for needle in ("time limit was reached while looking for model files", "model files were found; only the first", "Could not read the model file x.pt"):
            self.assertIn(needle, text)

    def test_the_model_file_search_runs_before_the_slow_steps(self):
        lines = []
        with make({"app.py": "from openai import OpenAI\n"}) as d, tempfile.TemporaryDirectory() as out:
            run(d, out, app="demo", log=lines.append)
        text = [l.strip() for l in lines]
        self.assertLess(text.index("Looking for model files ..."), text.index("Reading dependency files ..."))


class ReviewAppFixture(unittest.TestCase):
    """tests/fixtures/review-app has a stub models/clf.pkl and an HF call with trust_remote_code=True, written to be risky: what they raise is known."""

    def test_the_stub_pickle_and_the_remote_code_setting(self):
        files = triage(APP)
        found = MF.find(APP, files)
        got = sorted((f.rule, f.severity, f.file) for f in MF.model_file_flags(found["files"]))
        self.assertEqual(got, [("model-file.not-scanned", "info", "models/clf.pkl"), ("model-file.pickle-format", "medium", "models/clf.pkl")])
        rec = found["files"][0]
        self.assertEqual((rec["status"], rec["reason"]), ("not-scanned", "the pickle is damaged or cut short"))
        rc = RC.find(APP, files)["findings"]
        self.assertEqual([(f["file"], f["line"], f["how"]) for f in rc], [("src/hf.py", 5, "keyword")])


if __name__ == "__main__":
    unittest.main()
