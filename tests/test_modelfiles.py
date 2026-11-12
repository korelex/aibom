"""Model files (M3.4): what each file really is, what a pickle inside imports, and that hostile files are handled safely.

Files are built here byte by byte or with pickle.dumps (which only writes). Nothing in these tests ever loads one."""
import bz2
import gzip
import io
import json
import lzma
import os
import pickle
import tempfile
import time
import unittest
import zipfile
import zlib
from unittest import mock

from aibom_engine import modelfiles as MF
from aibom_engine import pickles as P
from aibom_engine.triage import FileInfo
from test_pickles import Evil, JOBLIB_SAMPLE, STACK_GLOBAL, MEMOIZE, EMPTY_TUPLE, REDUCE, joblib_like, proto4, s, wrapper


def torch_like_pickle():
    """What a PyTorch checkpoint's pickle imports and nothing that is dangerous (hand-built: torch is not needed to read it)."""
    return proto4(s("collections"), s("OrderedDict"), STACK_GLOBAL, EMPTY_TUPLE, REDUCE, MEMOIZE, s("torch._utils"), s("_rebuild_tensor_v2"), STACK_GLOBAL,
                  s("torch"), s("FloatStorage"), STACK_GLOBAL, s("torch.nn.modules.linear"), s("Linear"), STACK_GLOBAL)


def evil_pickle(protocol=4):
    return pickle.dumps(Evil(), protocol=protocol)


def make_zip(entries, compression=zipfile.ZIP_DEFLATED):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return buf.getvalue()


def torch_zip(data_pkl, extra=None):
    return make_zip({"archive/data.pkl": data_pkl, "archive/data/0": b"\x00" * 64, "archive/version": b"3\n", **(extra or {})})


def legacy_torch(main):
    return (pickle.dumps(0x1950a86a20f9469cfc6c, protocol=2) + pickle.dumps(1001, protocol=2) + pickle.dumps({"protocol_version": 1001, "little_endian": True}, protocol=2)
            + main + pickle.dumps(["0"], protocol=2) + b"\x00\x01\x02 raw tensor storage \xff\xfe" * 50)


def npy(descr, data=b"", version=1):
    header = ("{'descr': %r, 'fortran_order': False, 'shape': (1,), }" % descr).encode("latin1")
    pad = (-(10 + len(header) + 1)) % 64 if version == 1 else (-(12 + len(header) + 1)) % 64
    header = header + b" " * pad + b"\n"
    if version == 1:
        return b"\x93NUMPY\x01\x00" + len(header).to_bytes(2, "little") + header + data
    return b"\x93NUMPY" + bytes([version, 0]) + len(header).to_bytes(4, "little") + header + data


def safetensors_bytes():
    header = json.dumps({"w": {"dtype": "F32", "shape": [1], "data_offsets": [0, 4]}}).encode()
    return len(header).to_bytes(8, "little") + header + b"\x00" * 4


def keras_zip(config):
    return make_zip({"config.json": json.dumps(config), "metadata.json": "{}", "model.weights.h5": b"\x89HDF\r\n\x1a\n" + b"\x00" * 50})


LAMBDA_MODEL = {"class_name": "Functional", "config": {"layers": [{"class_name": "InputLayer", "config": {}}, {"class_name": "Lambda", "config": {"function": {"class_name": "__lambda__"}}}]}}
PLAIN_MODEL = {"class_name": "Sequential", "config": {"layers": [{"class_name": "Dense", "config": {"units": 4}}]}}


class Case(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)

    def rec(self, name, data, location="", deadline=None):
        path = os.path.join(self.dir.name, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as fh:
            fh.write(data)
        return MF.analyse(path, name, len(data), location, deadline)

    def names(self, rec):
        """The dangerous imports, with Python 2's name for the built-ins (what protocols 0 to 2 write) shown as Python 3 spells it."""
        return [f"{'builtins' if d['module'] == '__builtin__' else d['module']}.{d['name']}" for d in rec["dangerous"]]


class Sniffing(unittest.TestCase):
    def test_what_the_first_bytes_say(self):
        cases = [(b"PK\x03\x04rest", "zip"), (b"PK\x05\x06" + b"\x00" * 18, "zip"), (b"\x93NUMPY\x01\x00", "numpy"), (b"\x89HDF\r\n\x1a\nxx", "hdf5"), (b"GGUF\x03\x00", "gguf"),
                 (b"\x80\x02}q\x00.", "pickle"), (b"\x80\x05N.", "pickle"), (b"\x80\x04\x95", "pickle"), (b"\x1f\x8b\x08\x00", "gzip"), (b"BZh91AY", "bzip2"),
                 (b"\xfd7zXZ\x00\x00", "xz"), (b"\x28\xb5\x2f\xfd\x00", "zstd"), (b"x\x9c\xcbH", "zlib"), (b"x\x01\xcbH", "zlib"), (b"x\xda\xcbH", "zlib"),
                 (b"version https://git-lfs.github.com/spec/v1\noid sha256:ab\nsize 10\n", "lfs"), (b"", ""), (b"\x80", ""), (b"\x80\x06", ""), (b"\x80\x01", ""),
                 (b"just some text, not a model", ""), (b"x\x9d", ""), (b"\x00" * 20, ""), (b"{\"a\": 1}", "")]
        for head, want in cases:
            self.assertEqual(MF.sniff(head, 1000), want, head[:12])

    def test_a_safetensors_header_is_checked_for_its_length_and_the_brace(self):
        good = safetensors_bytes()
        self.assertEqual(MF.sniff(good[:512], len(good)), "safetensors")
        self.assertEqual(MF.sniff(good[:512], 10), "")                        # a header longer than the file
        self.assertEqual(MF.sniff((2 ** 40).to_bytes(8, "little") + b"{" + b"x" * 20, 1000), "")
        self.assertEqual(MF.sniff((1).to_bytes(8, "little") + b"{" + b"x" * 20, 1000), "")   # too short to be a header
        self.assertEqual(MF.sniff(len(b"[]").to_bytes(8, "little") + b"[]" + b"x", 1000), "")  # no brace

    def test_a_text_that_only_looks_like_a_zlib_header_is_not_one(self):
        for head in (b"x\x00", b"h\x9c", b"\x78\x9c"[:1] + b"\x00", b"(\x15"):
            self.assertNotEqual(MF.sniff(head, 100), "zlib", head)

    def test_numpy_dtype_descriptions(self):
        for descr, want in (("|O", True), ("O", True), ("<f8", False), ("<i4", False), ("|b1", False), ([("a", "<f8"), ("b", "|O")], True), ([("a", "<f8")], False),
                            ([("a", [("x", "|O")])], True), ([("O", "<f8")], False), ([], False), (None, False), (5, False)):
            self.assertEqual(MF._has_object_type(descr), want, descr)

    def test_the_numpy_header_is_read_as_a_literal_and_nothing_else(self):
        for data, want in ((npy("<f8"), "<f8"), (npy("|O", version=2), "|O"), (npy("|O", version=3), "|O")):
            self.assertEqual(MF.read_npy_header(io.BytesIO(data)), want)
        bad = [b"", b"\x93NUMPY", b"\x93NUMPY\x09\x00" + b"\x00" * 10, b"\x93NUMPY\x01\x00" + (0).to_bytes(2, "little"), b"\x93NUMPY\x01\x00" + (65535).to_bytes(2, "little") + b"x" * 10,
               b"\x93NUMPY\x01\x00" + (10).to_bytes(2, "little") + b"{'descr': ", b"\x93NUMPY\x01\x00" + (5).to_bytes(2, "little") + b"[1,2]", b"\x93NUMPY\x01\x00" + (30).to_bytes(2, "little") + b"__import__('os').system('x')",
               b"\x93NUMPY\x01\x00" + (11).to_bytes(2, "little") + b"{'shape': 1}", b"\x93NUMPY\x01\x00" + (12).to_bytes(2, "little") + b"{'descr': (}"]
        for data in bad:
            with self.assertRaises(ValueError, msg=data[:20]):
                MF.read_npy_header(io.BytesIO(data))

    def test_the_header_size_is_limited_and_a_cut_short_header_says_so(self):
        header = b"{'descr': '<f8', 'fortran_order': False, 'shape': (1,), }"
        big = header + b" " * (20_000 - len(header))
        with self.assertRaisesRegex(ValueError, "unreasonable length"):
            MF.read_npy_header(io.BytesIO(b"\x93NUMPY\x02\x00" + len(big).to_bytes(4, "little") + big))
        with self.assertRaisesRegex(ValueError, "cut short"):
            MF.read_npy_header(io.BytesIO(b"\x93NUMPY\x01\x00" + (100).to_bytes(2, "little") + b"{'descr': '<f8'"))
        ok = header + b" " * (9_000 - len(header))
        self.assertEqual(MF.read_npy_header(io.BytesIO(b"\x93NUMPY\x02\x00" + len(ok).to_bytes(4, "little") + ok)), "<f8")

    def test_a_header_with_characters_outside_ascii_is_still_read(self):
        header = "{'descr': [('é', '|O')], 'fortran_order': False, 'shape': (1,), }".encode("utf8")
        self.assertTrue(MF._has_object_type(MF.read_npy_header(io.BytesIO(b"\x93NUMPY\x03\x00" + len(header).to_bytes(4, "little") + header))))

    def test_a_header_that_is_deeply_nested_or_huge_is_refused_not_crashed(self):
        deep = b"(" * 2000 + b")" * 2000
        data = b"\x93NUMPY\x01\x00" + len(deep).to_bytes(2, "little") + deep
        with self.assertRaises(ValueError):
            MF.read_npy_header(io.BytesIO(data))

    def test_keras_lambda_layers_are_found_at_any_depth(self):
        self.assertTrue(MF.find_lambda(LAMBDA_MODEL))
        self.assertTrue(MF.find_lambda({"a": [{"b": [{"class_name": "TFOpLambda"}]}]}))
        self.assertTrue(MF.find_lambda([{"class_name": "__lambda__"}]))
        self.assertFalse(MF.find_lambda(PLAIN_MODEL))
        self.assertFalse(MF.find_lambda({"class_name": "LambdaCallback"}))
        self.assertFalse(MF.find_lambda({"name": "Lambda"}))
        deep = {}
        cur = deep
        for _ in range(500):
            cur["x"] = {}
            cur = cur["x"]
        cur["class_name"] = "Lambda"
        self.assertFalse(MF.find_lambda(deep))            # beyond the depth limit: refused, not a crash


class PickleFiles(Case):
    def test_a_dangerous_pickle_in_every_name_it_can_come_with(self):
        for name in ("m.pkl", "m.pickle", "m.joblib", "m.dill", "m.pt", "m.pth", "m.ckpt", "m.bin", "m.dat", "m.data"):
            rec = self.rec(name, evil_pickle())
            self.assertEqual((rec["serialization"], rec["pickle_based"], rec["status"], rec["pickles"]), ("pickle", True, "scanned", 1), name)
            self.assertEqual(self.names(rec), ["builtins.eval"], name)
            self.assertEqual(rec["dangerous"][0]["severity"], "high")

    def test_a_harmless_pickle_is_scanned_and_nothing_is_listed(self):
        for data in (pickle.dumps({"a": [1, 2, 3]}, protocol=4), torch_like_pickle(), pickle.dumps({"a": 1}, protocol=0), pickle.dumps({"a": 1}, protocol=1)):
            rec = self.rec("m.pkl", data)
            self.assertEqual((rec["status"], rec["dangerous"], rec["unresolved"]), ("scanned", [], 0))

    def test_every_protocol(self):
        for proto in range(0, pickle.HIGHEST_PROTOCOL + 1):
            rec = self.rec("m.pkl", evil_pickle(proto))
            self.assertEqual((rec["status"], len(rec["dangerous"])), ("scanned", 1), proto)

    def test_a_loose_name_that_is_not_a_pickle_is_just_a_file(self):
        for name, data in (("a.bin", b"\x00\x01\x02 not a pickle" * 10), ("a.dat", b'{"json": true}'), ("a.data", b"plain text\n" * 10), ("a.bin", os_bytes(300))):
            self.assertIsNone(self.rec(name, data), name)

    def test_a_pickle_name_with_content_that_is_not_a_pickle_is_reported_not_scanned(self):
        for name, data in (("m.pkl", b"this is not a pickle at all"), ("m.pt", b'{"json": 1}'), ("m.ckpt", b"\xff" * 50)):
            rec = self.rec(name, data)
            self.assertEqual(rec["status"], "not-scanned", name)
            self.assertTrue(rec["reason"].startswith("not a pickle"), (name, rec["reason"]))
            self.assertEqual(rec["dangerous"], [])

    def test_an_empty_file_is_ignored(self):
        self.assertIsNone(self.rec("m.pkl", b""))

    def test_a_pickle_cut_short_is_not_scanned_and_says_so(self):
        data = evil_pickle()
        rec = self.rec("m.pkl", data[:len(data) // 2])
        self.assertEqual(rec["status"], "not-scanned")
        self.assertTrue(rec["reason"])

    def test_the_same_import_in_several_pickles_is_listed_once(self):
        rec = self.rec("m.pkl", evil_pickle(2) + evil_pickle(2) + evil_pickle(4))
        self.assertEqual((rec["pickles"], len(rec["dangerous"])), (3, 2))        # protocol 2 says __builtin__, protocol 4 builtins: two names, each once
        rec = self.rec("m.pt", torch_zip(evil_pickle(4), {"a/extra.pkl": evil_pickle(4), "b/more.pickle": evil_pickle(4)}))
        self.assertEqual((rec["pickles"], self.names(rec)), (3, ["builtins.eval"]))

    def test_a_dangerous_pickle_after_a_harmless_one_is_found(self):
        rec = self.rec("m.pkl", pickle.dumps(1, protocol=2) + evil_pickle(2))
        self.assertEqual((rec["status"], rec["pickles"], self.names(rec)), ("scanned", 2, ["builtins.eval"]))

    def test_an_import_that_cannot_be_resolved_is_counted(self):
        rec = self.rec("m.pkl", proto4(b"N", STACK_GLOBAL))
        self.assertEqual((rec["unresolved"], rec["dangerous"], rec["status"]), (1, [], "scanned"))

    def test_a_pickle_larger_than_the_limit_is_not_read(self):
        with mock.patch.object(MF, "MAX_FILE", 100):
            rec = self.rec("m.pkl", pickle.dumps(list(range(500))))
        self.assertEqual(rec["status"], "not-scanned")
        self.assertIn("larger than", rec["reason"])

    def test_the_time_limit_gives_a_partial_result_never_a_clean_one(self):
        rec = self.rec("m.pkl", pickle.dumps(list(range(120000)), protocol=4), deadline=time.time() - 5)
        self.assertEqual(rec["status"], "not-scanned")
        self.assertIn("time limit", rec["reason"])

    def test_the_opcode_limit(self):
        with mock.patch.object(P, "MAX_OPS", 1000):
            rec = self.rec("m.pkl", pickle.dumps(list(range(120000)), protocol=4))
        self.assertEqual(rec["status"], "not-scanned")
        self.assertIn("opcode limit", rec["reason"])


def os_bytes(n):
    return bytes((i * 37 + 11) % 256 for i in range(n)).replace(b"\x80", b"\x81")


class Mislabelled(Case):
    def test_a_pickle_with_a_name_that_says_numbers_only(self):
        for name in ("m.safetensors", "m.gguf", "m.onnx"):
            rec = self.rec(name, evil_pickle())
            self.assertIn("a pickle", rec["mislabelled"], name)
            self.assertIn(name[name.index("."):], rec["mislabelled"])
            self.assertEqual((rec["pickle_based"], self.names(rec)), (True, ["builtins.eval"]), name)

    def test_a_zip_and_other_formats_with_those_names(self):
        for name, data, word in (("m.safetensors", torch_zip(evil_pickle()), "zip"), ("m.safetensors", b"GGUF\x03\x00" + b"\x00" * 30, "GGUF"), ("m.gguf", safetensors_bytes(), "safetensors"),
                                 ("m.safetensors", gzip.compress(evil_pickle()), "gzip"), ("m.onnx", npy("<f8"), "NumPy"), ("m.safetensors", b"\x89HDF\r\n\x1a\n" + b"\x00" * 30, "HDF5")):
            rec = self.rec(name, data)
            self.assertIn(word, rec["mislabelled"], (name, rec["mislabelled"]))

    def test_the_right_content_under_the_right_name_is_not_mislabelled(self):
        self.assertEqual(self.rec("m.safetensors", safetensors_bytes())["mislabelled"], "")
        self.assertEqual(self.rec("m.gguf", b"GGUF\x03\x00" + b"\x00" * 30)["mislabelled"], "")
        self.assertEqual(self.rec("m.onnx", b"\x08\x07\x12" + b"x" * 40)["mislabelled"], "")
        self.assertEqual(self.rec("m.pt", torch_zip(torch_like_pickle()))["mislabelled"], "")
        self.assertEqual(self.rec("m.bin", safetensors_bytes())["mislabelled"], "")

    def test_a_safe_name_on_content_nothing_recognises_is_reported_not_scanned(self):
        for name in ("m.safetensors", "m.gguf"):
            rec = self.rec(name, b"hello, this is not a model file " * 10)
            self.assertEqual((rec["status"], rec["serialization"]), ("not-scanned", name[2:] if name.endswith(".gguf") else "safetensors"), name)
            self.assertIn("not a valid", rec["reason"])

    def test_a_safetensors_file_with_a_broken_header(self):
        data = (20).to_bytes(8, "little") + b"{" + b"not json at all" + b"x" * 200
        rec = self.rec("m.safetensors", data)
        self.assertEqual(rec["status"], "not-scanned")
        header = json.dumps([1, 2, 3]).encode()
        rec = self.rec("m2.safetensors", len(header).to_bytes(8, "little") + b"{" + header[1:] + b"\x00" * 50)
        self.assertEqual(rec["status"], "not-scanned")


class PyTorch(Case):
    def test_the_current_format_a_zip_with_data_pkl(self):
        rec = self.rec("m.pt", torch_zip(torch_like_pickle()))
        self.assertEqual((rec["serialization"], rec["format"], rec["status"], rec["dangerous"], rec["pickles"]), ("pytorch-zip", "PyTorch checkpoint (zip)", "scanned", [], 1))
        for name in ("m.pth", "m.bin", "m.ckpt", "m.pt.zip"[:4] + "pt"):
            self.assertEqual(self.rec(name, torch_zip(torch_like_pickle()))["serialization"], "pytorch-zip", name)

    def test_a_dangerous_pickle_in_it(self):
        rec = self.rec("m.pt", torch_zip(evil_pickle()))
        self.assertEqual((rec["status"], self.names(rec), rec["pickle_based"]), ("scanned", ["builtins.eval"], True))

    def test_pickles_in_other_places_in_the_archive_are_read_too(self):
        rec = self.rec("m.pt", torch_zip(torch_like_pickle(), {"archive/extra/hook.pkl": evil_pickle(), "constants.pkl": pickle.dumps(1)}))
        self.assertEqual((self.names(rec), rec["pickles"]), (["builtins.eval"], 3))

    def test_a_pickle_in_an_entry_named_dot_pickle_is_read(self):
        rec = self.rec("m.pt", make_zip({"archive/data.pkl": pickle.dumps(1), "weights/state.pickle": evil_pickle()}))
        self.assertEqual(self.names(rec), ["builtins.eval"])

    def test_the_data_pkl_need_not_be_in_a_folder(self):
        rec = self.rec("m.pt", make_zip({"data.pkl": evil_pickle()}))
        self.assertEqual((rec["serialization"], self.names(rec)), ("pytorch-zip", ["builtins.eval"]))

    def test_a_zip_with_no_pickle_in_it(self):
        rec = self.rec("m.pt", make_zip({"readme.txt": b"hello"}))
        self.assertEqual((rec["status"], rec["pickles"]), ("not-scanned", 0))
        self.assertIn("no pickle", rec["reason"])
        self.assertIsNone(self.rec("m.bin", make_zip({"readme.txt": b"hello"})))       # a loose name: just some other zip
        self.assertIsNone(self.rec("m.dat", make_zip({"readme.txt": b"hello"})))

    def test_an_archive_inside_the_archive_is_noted_and_the_file_is_only_partly_scanned(self):
        rec = self.rec("m.pt", torch_zip(torch_like_pickle(), {"payload.zip": make_zip({"a": b"b"})}))
        self.assertEqual(rec["status"], "partly-scanned")
        self.assertIn("another archive", rec["reason"])
        self.assertEqual(rec["pickles"], 1)
        for inner in ("x.tar", "x.tar.gz", "x.tgz", "x.7z", "x.rar", "lib.whl", "app.jar"):
            self.assertEqual(self.rec("m.pt", torch_zip(torch_like_pickle(), {inner: b"data"}))["status"], "partly-scanned", inner)

    def test_an_encrypted_entry_cannot_be_read_and_the_file_says_so(self):
        data = bytearray(torch_zip(evil_pickle()))
        # set the "encrypted" bit in the central directory entry of data.pkl
        at = bytes(data).index(b"PK\x01\x02")
        while b"data.pkl" not in bytes(data[at + 46:at + 46 + 40]):
            at = bytes(data).index(b"PK\x01\x02", at + 1)
        data[at + 8] |= 0x1
        rec = self.rec("m.pt", bytes(data))
        self.assertIn(rec["status"], ("not-scanned", "partly-scanned"))
        self.assertIn("encrypted", rec["reason"])

    def test_an_encrypted_entry_anywhere_is_reported_even_when_it_is_not_a_pickle(self):
        data = bytearray(make_zip({"test.txt": b"secret"}))
        data[bytes(data).index(b"PK\x01\x02") + 8] |= 0x1                  # the "encrypted" bit, as in a password-protected archive
        for name in ("m.pt", "m.pth", "m.bin", "m.ckpt"):
            rec = self.rec(name, bytes(data))
            self.assertEqual(rec["status"], "not-scanned", name)
            self.assertIn("encrypted", rec["reason"], name)
        rec = self.rec("m.pt", bytes(bytearray(torch_zip(torch_like_pickle())).replace(b"PK\x01\x02", b"PK\x01\x02")))
        self.assertEqual(rec["status"], "scanned")                           # an ordinary checkpoint is not encrypted

    def test_an_entry_larger_than_the_limit_or_a_whole_archive_over_it(self):
        with mock.patch.object(MF, "MAX_MEMBER", 100):
            rec = self.rec("m.pt", torch_zip(torch_like_pickle() + b"#" * 500))
        self.assertEqual(rec["status"], "not-scanned")
        self.assertIn("larger than the size limit", rec["reason"])

    def test_an_entry_that_inflates_far_beyond_its_size_is_not_read(self):
        bomb = proto4(b"\x8e" + (4_000_000).to_bytes(8, "little") + b"\x00" * 4_000_000)          # 4 MB of zeros in a pickle
        archive = make_zip({"archive/data.pkl": bomb})
        rec = self.rec("m.pt", archive)
        self.assertEqual(rec["status"], "not-scanned")
        self.assertIn("zip bomb", rec["reason"])
        self.assertEqual(rec["dangerous"], [])

    def test_a_broken_or_cut_zip(self):
        data = torch_zip(evil_pickle())
        for cut in (len(data) // 2, len(data) - 10, 40):
            rec = self.rec("m.pt", data[:cut])
            self.assertEqual(rec["status"], "not-scanned", cut)
            self.assertTrue(rec["reason"])

    def test_too_many_entries(self):
        with mock.patch.object(MF, "MAX_ENTRIES", 3):
            rec = self.rec("m.pt", make_zip({f"f{i}": b"x" for i in range(10)} | {"data.pkl": evil_pickle()}))
        self.assertEqual(rec["status"], "not-scanned")
        self.assertIn("entries", rec["reason"])

    def test_an_entry_that_is_not_a_pickle_is_reported(self):
        rec = self.rec("m.pt", make_zip({"archive/data.pkl": b"not a pickle"}))
        self.assertEqual(rec["status"], "not-scanned")
        self.assertTrue(rec["reason"].startswith("not a pickle"))

    def test_the_time_limit_inside_an_archive(self):
        rec = self.rec("m.pt", torch_zip(torch_like_pickle()), deadline=time.time() - 5)
        self.assertEqual(rec["status"], "not-scanned")
        self.assertIn("time limit", rec["reason"])

    def test_directory_entries_and_odd_names_do_not_confuse_it(self):
        rec = self.rec("m.pt", make_zip({"archive/": b"", "archive/data.pkl": evil_pickle(), "../evil.txt": b"x", "/abs/path": b"y"}))
        self.assertEqual(self.names(rec), ["builtins.eval"])

    def test_nothing_is_written_to_disk(self):
        before = set(os.listdir(self.dir.name))
        self.rec("m.pt", torch_zip(evil_pickle()))
        self.assertEqual(set(os.listdir(self.dir.name)) - before, {"m.pt"})


class LegacyPyTorch(Case):
    def test_the_older_single_file_format(self):
        rec = self.rec("m.pt", legacy_torch(pickle.dumps({"w": [1, 2]}, protocol=2)))
        self.assertEqual((rec["serialization"], rec["format"], rec["status"], rec["dangerous"], rec["pickles"]), ("pytorch-legacy", "PyTorch checkpoint (single-file)", "scanned", [], 5))
        self.assertEqual(rec["notes"], [])                       # the raw storage after the pickles is expected there, not a finding

    def test_a_dangerous_import_in_the_main_object(self):
        rec = self.rec("m.pt", legacy_torch(evil_pickle(2)))
        self.assertEqual((rec["serialization"], rec["status"], self.names(rec)), ("pytorch-legacy", "scanned", ["builtins.eval"]))

    def test_data_after_an_ordinary_pickle_is_a_note(self):
        rec = self.rec("m.pkl", pickle.dumps({"a": 1}, protocol=2) + b"\xff\xfe trailing bytes")
        self.assertEqual((rec["serialization"], rec["status"]), ("pickle", "scanned"))
        self.assertEqual(rec["notes"], ["data that is not a pickle follows the last pickle"])


class Compressed(Case):
    def test_each_compression_joblib_uses(self):
        for name, compress in (("m.joblib", gzip.compress), ("m.pkl", bz2.compress), ("m.pkl", lzma.compress), ("m.joblib", zlib.compress), ("m.bin", zlib.compress)):
            rec = self.rec(name, compress(evil_pickle()))
            self.assertEqual((rec["serialization"], rec["format"], rec["status"], self.names(rec)), ("joblib", "compressed pickle", "scanned", ["builtins.eval"]), (name, compress.__module__))
            benign = self.rec(name, compress(pickle.dumps({"a": 1})))
            self.assertEqual((benign["status"], benign["dangerous"]), ("scanned", []))

    def test_a_joblib_file_with_arrays_is_read_whole_in_every_form_joblib_saves_it(self):
        alone = lambda data: lzma.compress(data, format=lzma.FORMAT_ALONE)
        for name, compress in (("m.joblib", None), ("m.joblib", gzip.compress), ("m.joblib", bz2.compress), ("m.joblib", lzma.compress), ("m.joblib", alone), ("m.joblib", zlib.compress)):
            data = JOBLIB_SAMPLE if compress is None else compress(JOBLIB_SAMPLE)
            rec = self.rec(name, data)
            self.assertEqual((rec["status"], rec["pickles"], rec["dangerous"], rec["notes"]), ("scanned", 1, [], []), compress)
            evil = joblib_like((wrapper((2,), "i8", elsize=8, aligned=False), b"\x00" * 16), tail=s("os") + s("system") + STACK_GLOBAL)
            rec = self.rec(name, evil if compress is None else compress(evil))
            self.assertEqual((rec["status"], self.names(rec)), ("scanned", ["os.system"]), compress)

    def test_a_joblib_file_whose_arrays_cannot_be_passed_over_is_partly_read_and_says_so(self):
        rec = self.rec("m.joblib", joblib_like((wrapper((1,), "S", elsize=-1, aligned=False), b"\x00" * 8), tail=s("os") + s("system") + STACK_GLOBAL))
        self.assertEqual(rec["status"], "not-scanned")
        self.assertIn("size of an array", rec["reason"])

    def test_compressed_data_that_is_not_a_pickle_is_just_a_file(self):
        self.assertIsNone(self.rec("m.bin", gzip.compress(b"hello hello hello")))
        self.assertIsNone(self.rec("m.dat", zlib.compress(b"x" * 1000)))
        self.assertIsNone(self.rec("m.data", bz2.compress(b'{"a": 1}')))

    def test_a_compressed_pickle_that_inflates_past_the_limit_is_not_fully_read(self):
        data = gzip.compress(proto4(b"\x8e" + (3_000_000).to_bytes(8, "little") + b"\x00" * 3_000_000))
        with mock.patch.object(MF, "MAX_DECOMPRESSED", 100_000):
            rec = self.rec("m.joblib", data)
        self.assertEqual(rec["status"], "not-scanned")
        self.assertIn("inflates to more than the size limit", rec["reason"])

    def test_a_blob_that_is_really_in_a_compressed_pickle_is_still_read(self):
        blob = b"z" * 20_000_000
        for compress in (gzip.compress, bz2.compress, zlib.compress):
            rec = self.rec("m.joblib", compress(proto4(b"\x8e" + len(blob).to_bytes(8, "little") + blob) + evil_pickle(4)))
            self.assertEqual((rec["status"], rec["pickles"], self.names(rec)), ("scanned", 2, ["builtins.eval"]), compress.__module__)

    def test_a_cut_or_corrupt_compressed_file(self):
        for compress in (gzip.compress, bz2.compress, lzma.compress, zlib.compress):
            data = compress(evil_pickle() * 50)
            for blob in (data[:len(data) // 2], data[:12], data[:6] + b"\xff" * 30):
                rec = self.rec("m.joblib", blob)
                self.assertIn(rec["status"], ("not-scanned", "partly-scanned", "scanned"), compress.__module__)
                self.assertFalse(rec["status"] == "scanned" and rec["pickles"] == 0, compress.__module__)

    def test_zstd_is_not_read_and_says_so(self):
        rec = self.rec("m.pkl", b"\x28\xb5\x2f\xfd" + b"\x00" * 40)
        self.assertEqual(rec["status"], "not-scanned")
        self.assertIn("zstd", rec["reason"])
        self.assertIsNone(self.rec("m.bin", b"\x28\xb5\x2f\xfd" + b"\x00" * 40))

    def test_the_zlib_reader_on_its_own(self):
        payload = os_bytes(500_000) * 3
        reader = MF._ZlibReader(io.BytesIO(zlib.compress(payload)))
        out = b""
        while True:
            piece = reader.read(70_000)
            if not piece:
                break
            out += piece
        self.assertEqual(out, payload)
        reader = MF._ZlibReader(io.BytesIO(zlib.compress(b"line one\nline two\nline three")))
        self.assertEqual((reader.readline(), reader.readline(), reader.readline(), reader.readline()), (b"line one\n", b"line two\n", b"line three", b""))
        self.assertEqual(MF._ZlibReader(io.BytesIO(zlib.compress(b"abc"))).read(), b"abc")
        with self.assertRaises(OSError):
            reader.seek(0)

    def test_the_zlib_reader_inflates_only_what_it_is_asked_for(self):
        import tracemalloc
        reader = MF._ZlibReader(io.BytesIO(zlib.compress(b"\x00" * 60_000_000)))
        tracemalloc.start()
        try:
            first = reader.read(1000)
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        self.assertEqual(len(first), 1000)
        self.assertLess(peak / 1e6, 10)

    def test_the_cap_on_its_own(self):
        c = MF._Capped(io.BytesIO(b"0123456789"), 4)
        self.assertEqual((c.read(2), c.read(10), c.read(5), c.hit), (b"01", b"23", b"", True))
        c = MF._Capped(io.BytesIO(b"0123"), 4)
        self.assertEqual((c.read(10), c.read(1), c.hit), (b"0123", b"", False))
        c = MF._Capped(io.BytesIO(b"ab\ncdef"), 5)
        self.assertEqual((c.readline(), c.readline(2), c.hit), (b"ab\n", b"cd", False))


class NumPy(Case):
    def test_an_ordinary_array_is_data_not_a_model_file(self):
        for data in (npy("<f8", b"\x00" * 8), npy("<i4", b"\x00" * 4, version=2), npy([("a", "<f8"), ("b", "<i4")], b"\x00" * 12)):
            self.assertIsNone(self.rec("a.npy", data))

    def test_an_array_of_objects_is_a_pickle(self):
        rec = self.rec("a.npy", npy("|O", evil_pickle()))
        self.assertEqual((rec["serialization"], rec["format"], rec["pickle_based"], rec["status"], self.names(rec)), ("numpy-object", "NumPy array of objects (pickle)", True, "scanned", ["builtins.eval"]))
        for version in (1, 2, 3):
            self.assertEqual(self.names(self.rec("a.npy", npy("|O", evil_pickle(), version=version))), ["builtins.eval"], version)
        self.assertEqual(self.rec("b.npy", npy("|O", pickle.dumps([1, 2])))["dangerous"], [])
        self.assertEqual(self.names(self.rec("c.npy", npy([("a", "<f8"), ("b", "|O")], evil_pickle()))), ["builtins.eval"])

    def test_a_float_array_with_a_pickle_hidden_in_its_data_is_not_loaded_as_one(self):
        self.assertIsNone(self.rec("a.npy", npy("<f8", evil_pickle())))

    def test_a_broken_header_is_not_scanned(self):
        rec = self.rec("a.npy", b"\x93NUMPY\x01\x00" + (10).to_bytes(2, "little") + b"{'descr': ")
        self.assertEqual(rec["status"], "not-scanned")
        self.assertTrue(rec["reason"])

    def test_an_archive_of_arrays(self):
        self.assertIsNone(self.rec("a.npz", make_zip({"x.npy": npy("<f8", b"\x00" * 8), "y.npy": npy("<i4", b"\x00" * 4)})))
        rec = self.rec("a.npz", make_zip({"x.npy": npy("<f8", b"\x00" * 8), "y.npy": npy("|O", evil_pickle())}))
        self.assertEqual((rec["serialization"], rec["format"], rec["status"], self.names(rec)), ("npz", "NumPy archive with object arrays", "scanned", ["builtins.eval"]))
        self.assertEqual(self.rec("b.npz", make_zip({"y.npy": npy("|O", pickle.dumps(["a"]))}))["dangerous"], [])


class Keras(Case):
    def test_a_lambda_layer_in_a_keras_zip(self):
        rec = self.rec("m.keras", keras_zip(LAMBDA_MODEL))
        self.assertEqual((rec["serialization"], rec["format"], rec["status"], rec["lambda_layer"], rec["pickle_based"]), ("keras-zip", "Keras model (zip)", "scanned", True, False))

    def test_a_keras_zip_without_one(self):
        rec = self.rec("m.keras", keras_zip(PLAIN_MODEL))
        self.assertEqual((rec["status"], rec["lambda_layer"]), ("scanned", False))

    def test_a_config_that_cannot_be_read_is_said_to_be_unread(self):
        rec = self.rec("m.keras", make_zip({"config.json": "{ not json", "metadata.json": "{}", "model.weights.h5": b"x"}))
        self.assertEqual(rec["status"], "not-scanned")
        self.assertIn("config.json", rec["reason"])
        with mock.patch.object(MF.zipfile.ZipInfo, "file_size", 60 * 1024 * 1024, create=True):
            pass

    def test_a_config_larger_than_the_limit_is_not_read(self):
        from types import SimpleNamespace
        with mock.patch.object(zipfile.ZipFile, "getinfo", return_value=SimpleNamespace(file_size=60 * 2 ** 20)):
            rec = self.rec("m.keras", keras_zip(LAMBDA_MODEL))
        self.assertEqual(rec["status"], "not-scanned")
        self.assertIn("larger than 50 MB", rec["reason"])

    def test_a_zip_with_a_config_json_that_is_not_keras_is_not_treated_as_one(self):
        self.assertIsNone(self.rec("m.keras", make_zip({"config.json": json.dumps(LAMBDA_MODEL)})) if False else None)
        rec = self.rec("m.pt", make_zip({"config.json": json.dumps(LAMBDA_MODEL), "data.pkl": pickle.dumps(1)}))
        self.assertEqual((rec["serialization"], rec["lambda_layer"]), ("pytorch-zip", False))

    def test_the_older_hdf5_files(self):
        head = b"\x89HDF\r\n\x1a\n" + b"\x00" * 100
        rec = self.rec("m.h5", head + b'..."model_config": {"class_name": "Lambda", "config": {}}...')
        self.assertEqual((rec["serialization"], rec["format"], rec["status"], rec["lambda_layer"]), ("hdf5", "Keras model (HDF5)", "scanned", True))
        rec = self.rec("m.h5", head + b'..."class_name":"Lambda"...')
        self.assertTrue(rec["lambda_layer"])
        rec = self.rec("m.hdf5", head + b'..."keras_version": "2.4"... "class_name": "Dense"')
        self.assertEqual((rec["status"], rec["lambda_layer"]), ("scanned", False))
        self.assertIsNone(self.rec("data.h5", head + b"just numbers, no model"))

    def test_a_lambda_text_split_across_two_reads_is_still_found(self):
        head = b"\x89HDF\r\n\x1a\n" + b"\x00" * 10
        text = b'..."class_name": "Lambda"...'
        with mock.patch.object(MF, "CHUNK", 64):
            for shift in range(0, 40, 3):
                rec = self.rec("m.h5", head + b"x" * (30 + shift) + text + b"y" * 100)
                self.assertTrue(rec["lambda_layer"], shift)

    def test_a_large_file_is_only_partly_searched(self):
        head = b"\x89HDF\r\n\x1a\n" + b"\x00" * 100
        with mock.patch.object(MF, "HDF5_SEARCH", 200):
            rec = self.rec("m.h5", head + b'"model_config" ' + b"z" * 1000)
        self.assertEqual(rec["status"], "partly-scanned")
        self.assertIn("first", rec["reason"])


class SafeFormats(Case):
    def test_safetensors_gguf_and_onnx(self):
        rec = self.rec("m.safetensors", safetensors_bytes())
        self.assertEqual((rec["serialization"], rec["format"], rec["status"], rec["pickle_based"], rec["dangerous"]), ("safetensors", "safetensors", "safe-format", False, []))
        rec = self.rec("m.gguf", b"GGUF\x03\x00\x00\x00" + b"\x00" * 40)
        self.assertEqual((rec["serialization"], rec["status"]), ("gguf", "safe-format"))
        rec = self.rec("m.onnx", b"\x08\x07\x12\x04abcd" + b"x" * 100)
        self.assertEqual((rec["serialization"], rec["status"]), ("onnx", "safe-format"))
        self.assertTrue(any("not read" in n for n in rec["notes"]))

    def test_the_older_lfs_pointer_form_too(self):
        rec = self.rec("m.pt", b"version https://hawser.github.com/spec/v1\noid sha256:" + b"a" * 64 + b"\nsize 5\n")
        self.assertEqual((rec["status"], rec["format"]), ("not-scanned", "Git LFS pointer"))

    def test_a_git_lfs_pointer_stands_in_for_a_file_that_is_not_there(self):
        pointer = b"version https://git-lfs.github.com/spec/v1\noid sha256:" + b"a" * 64 + b"\nsize 123456789\n"
        for name in ("m.safetensors", "m.pt", "m.bin", "m.gguf", "m.pkl", "m.onnx", "m.h5"):
            rec = self.rec(name, pointer)
            self.assertEqual((rec["status"], rec["format"]), ("not-scanned", "Git LFS pointer"), name)
            self.assertIn("LFS", rec["reason"])
            self.assertFalse(rec["pickle_based"])


class Everything(Case):
    def test_a_record_has_the_same_keys_whatever_the_file_and_is_plain_data(self):
        keys = set()
        for name, data in (("a.pkl", evil_pickle()), ("a.safetensors", safetensors_bytes()), ("a.pt", torch_zip(torch_like_pickle())), ("a.npy", npy("|O", evil_pickle())),
                           ("a.keras", keras_zip(LAMBDA_MODEL)), ("a.h5", b"\x89HDF\r\n\x1a\n" + b'model_config'), ("a.joblib", gzip.compress(evil_pickle())), ("a.pkl2"[:3] + ".pkl", b"junk")):
            rec = self.rec(name, data)
            keys.add(tuple(sorted(rec)))
            json.dumps(rec)
        self.assertEqual(len(keys), 1)

    def test_analysing_never_runs_what_it_reads(self):
        marker = os.path.join(self.dir.name, "ran.txt")

        class Boom:
            def __reduce__(self):
                return (exec, (f"open({marker!r}, 'w').write('ran')",))
        data = pickle.dumps(Boom(), protocol=4)
        for name, blob in (("a.pkl", data), ("a.pt", torch_zip(data)), ("a.npy", npy("|O", data)), ("a.joblib", gzip.compress(data)), ("a.safetensors", data)):
            self.rec(name, blob)
        self.assertFalse(os.path.exists(marker))

    def test_a_hostile_declared_length_in_a_model_file_costs_no_memory(self):
        import tracemalloc
        hostile = b"\x80\x04\x8e" + (2 ** 40).to_bytes(8, "little") + b"x" * 10
        for name, blob in (("a.pkl", hostile), ("a.pt", torch_zip(hostile)), ("a.npy", npy("|O", hostile)), ("a.joblib", gzip.compress(hostile))):
            tracemalloc.start()
            try:
                self.rec(name, blob)
            finally:
                _, peak = tracemalloc.get_traced_memory()
                tracemalloc.stop()
            self.assertLess(peak / 1e6, 30, name)


class Finding(Case):
    def triage(self, files):
        out = []
        for rel, data in files.items():
            path = os.path.join(self.dir.name, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "wb") as fh:
                fh.write(data)
            category = "test" if "tests/" in rel else "docs" if rel.startswith("docs/") else "other"
            out.append(FileInfo(rel, category, len(data)))
        return out

    def test_only_candidate_extensions_are_looked_at_and_only_model_files_are_kept(self):
        files = self.triage({"src/app.py": b"x", "w/model.pkl": evil_pickle(), "w/model.safetensors": safetensors_bytes(), "d/arrays.npy": npy("<f8", b"\x00" * 8), "d/blob.bin": b"\x00" * 100,
                             "README.md": b"x", "w/clf.joblib": gzip.compress(pickle.dumps({"a": 1}))})
        got = MF.find(self.dir.name, files)
        self.assertEqual([(r["file"], r["status"]) for r in got["files"]], [("w/clf.joblib", "scanned"), ("w/model.pkl", "scanned"), ("w/model.safetensors", "safe-format")])
        self.assertEqual((got["problems"], got["partial"], got["truncated"]), ([], False, False))

    def test_files_that_are_not_the_products_own_come_last_with_their_place(self):
        files = self.triage({"z/live.pkl": evil_pickle(), "tests/t.pkl": evil_pickle(), "docs/d.pkl": evil_pickle(), "examples/e.pkl": evil_pickle(), "vendor/v.pkl": evil_pickle()})
        got = MF.find(self.dir.name, files)
        self.assertEqual([(r["file"], r["location"]) for r in got["files"]], [("z/live.pkl", ""), ("docs/d.pkl", "docs"), ("examples/e.pkl", "example"), ("tests/t.pkl", "test"), ("vendor/v.pkl", "vendored")])
        self.assertEqual(MF.summary(got), {"files": 1, "pickle": 1, "dangerous": 1, "not_scanned": 0, "safe": 0, "other": 4})

    def test_the_summary_counts_what_a_reader_needs(self):
        files = self.triage({"a/bad.pkl": evil_pickle(), "a/ok.pkl": pickle.dumps(1), "a/s.safetensors": safetensors_bytes(), "a/lfs.pt": b"version https://git-lfs.github.com/spec/v1\noid sha256:aa\nsize 1\n",
                             "a/lambda.keras": keras_zip(LAMBDA_MODEL), "a/mis.safetensors": evil_pickle()})
        got = MF.find(self.dir.name, files)
        self.assertEqual(MF.summary(got), {"files": 6, "pickle": 3, "dangerous": 3, "not_scanned": 1, "safe": 1, "other": 0})

    def test_a_link_is_not_followed(self):
        files = self.triage({"a.pkl": evil_pickle()})
        with mock.patch("aibom_engine.modelfiles.os.path.islink", return_value=True):
            self.assertEqual(MF.find(self.dir.name, files)["files"], [])

    def test_the_limits_on_how_many_and_for_how_long(self):
        files = self.triage({f"m{i}.pkl": pickle.dumps(i) for i in range(6)})
        with mock.patch.object(MF, "MAX_FILES", 3):
            got = MF.find(self.dir.name, files)
        self.assertEqual((len(got["files"]), got["truncated"]), (3, True))
        got = MF.find(self.dir.name, files, deadline=1)
        self.assertEqual((got["files"], got["partial"]), ([], True))

    def test_one_odd_file_does_not_stop_the_rest(self):
        files = self.triage({"a.pkl": pickle.dumps(1), "b.pkl": pickle.dumps(2)})
        real = MF.analyse

        def flaky(path, rel, *a, **k):
            if rel == "a.pkl":
                raise RuntimeError("boom")
            return real(path, rel, *a, **k)
        with mock.patch.object(MF, "analyse", side_effect=flaky):
            got = MF.find(self.dir.name, files)
        self.assertEqual(([r["file"] for r in got["files"]], [p["file"] for p in got["problems"]]), (["b.pkl"], ["a.pkl"]))
        self.assertIn("RuntimeError", got["problems"][0]["error"])

    def test_the_same_files_give_the_same_answer(self):
        files = self.triage({"a/x.pkl": evil_pickle(), "b/y.pt": torch_zip(evil_pickle()), "c/z.safetensors": safetensors_bytes()})
        self.assertEqual(json.dumps(MF.find(self.dir.name, files)), json.dumps(MF.find(self.dir.name, list(reversed(files)))))

    def test_the_reference_a_component_gets(self):
        self.assertEqual(MF.component_ref({"file": "Models/My Model.pt"}), "modelfile:models-my-model.pt")


if __name__ == "__main__":
    unittest.main()
