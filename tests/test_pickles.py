"""The pickle reader (M3.4): which imports a pickle holds, found without ever loading it, and which of them are dangerous.

Pickles here are made with pickle.dumps (which only writes) or put together byte by byte. Nothing in these tests ever loads one."""
import base64
import collections
import datetime
import decimal
import gzip
import io
import os
import pickle
import tempfile
import time
import unittest
from unittest import mock

from aibom_engine import pickles as P


def proto4(*parts):
    """A protocol-4 pickle from raw opcode pieces."""
    return b"\x80\x04" + b"".join(parts) + b"."


def s(text):                  # SHORT_BINUNICODE
    data = text.encode()
    return b"\x8c" + bytes([len(data)]) + data


MEMOIZE, STACK_GLOBAL, NONE, MARK, TUPLE, EMPTY_TUPLE, REDUCE = b"\x94", b"\x93", b"N", b"(", b"t", b")", b"R"


def get(i):
    return b"h" + bytes([i])


def put(i):
    return b"q" + bytes([i])


def read(data, **kw):
    return P.scan(io.BytesIO(data), **kw)


def names(result):
    return sorted(f"{m}.{n}" for m, n in result.globals)


class Evil:
    """Pickling this writes a call to builtins.eval; it is never unpickled."""
    def __reduce__(self):
        return (eval, ("1+1",))


class EveryProtocol(unittest.TestCase):
    def test_the_import_is_found_in_every_protocol(self):
        for proto in range(0, pickle.HIGHEST_PROTOCOL + 1):
            r = read(pickle.dumps(Evil(), protocol=proto))
            self.assertIn(names(r)[0].split(".")[-1], ("eval",), proto)
            self.assertEqual([d["severity"] for d in P.classify_all(r)], ["high"], proto)
            self.assertEqual((r.pickles, r.unresolved, r.trailing, r.stopped), (1, 0, "", ""), proto)

    def test_plain_python_data_has_no_imports_in_any_protocol(self):
        data = {"a": [1, 2.5, "x", None, True], "b": (1, 2), "c": {1, 2}, "d": b"bytes", "e": frozenset([1]), "f": 1 + 2j}
        for proto in range(0, pickle.HIGHEST_PROTOCOL + 1):
            r = read(pickle.dumps(data, protocol=proto))
            self.assertEqual(P.classify_all(r), [], proto)
            self.assertEqual((r.pickles, r.unresolved), (1, 0), proto)

    def test_ordinary_library_objects_are_found_but_not_dangerous(self):
        obj = [collections.OrderedDict(a=1), datetime.datetime(2020, 1, 2), decimal.Decimal("1.5"), collections.Counter("abc"), collections.deque([1])]
        for proto in (2, 4, 5):
            r = read(pickle.dumps(obj, protocol=proto))
            self.assertTrue({"collections.OrderedDict", "datetime.datetime", "decimal.Decimal"} <= set(names(r)), (proto, names(r)))
            self.assertEqual(P.classify_all(r), [], (proto, names(r)))

    def test_the_text_opcodes_of_the_old_protocols(self):
        r = read(b"cos\nsystem\n(S'echo hi'\ntR.")
        self.assertEqual(names(r), ["os.system"])
        r = read(b"(S'x'\ni__builtin__\neval\n.")                      # INST
        self.assertEqual(names(r), ["__builtin__.eval"])
        self.assertEqual(P.classify_all(r)[0]["severity"], "high")


class StackGlobal(unittest.TestCase):
    """Protocols 4 and 5 push two strings and run STACK_GLOBAL; they must be found exactly, and never guessed."""

    def test_two_strings_in_a_row(self):
        r = read(proto4(s("os"), MEMOIZE, s("system"), MEMOIZE, STACK_GLOBAL, MEMOIZE, EMPTY_TUPLE, REDUCE))
        self.assertEqual((names(r), r.unresolved), (["os.system"], 0))

    def test_strings_fetched_back_from_the_memo(self):
        r = read(proto4(s("os"), MEMOIZE, s("system"), MEMOIZE, NONE, get(0), get(1), STACK_GLOBAL))
        self.assertEqual((names(r), r.unresolved), (["os.system"], 0))
        r = read(proto4(s("os"), put(5), s("system"), put(9), NONE, get(5), get(9), STACK_GLOBAL))
        self.assertEqual((names(r), r.unresolved), (["os.system"], 0))

    def test_a_later_store_replaces_an_earlier_one(self):
        r = read(proto4(s("harmless"), put(1), s("os"), put(1), s("system"), put(2), get(1), get(2), STACK_GLOBAL))
        self.assertEqual(names(r), ["os.system"])
        r = read(proto4(s("os"), put(1), s("system"), put(2), s("harmless"), put(1), get(1), get(2), STACK_GLOBAL))
        self.assertEqual(names(r), ["harmless.system"])

    def test_the_same_string_used_twice(self):
        r = read(proto4(s("os"), MEMOIZE, s("system"), STACK_GLOBAL, get(0), s("popen"), STACK_GLOBAL))
        self.assertEqual((names(r), r.unresolved), (["os.popen", "os.system"], 0))

    def test_operands_that_are_not_two_strings_in_a_row_are_unresolved_not_guessed(self):
        for data in (proto4(s("os"), NONE, s("system"), STACK_GLOBAL),                  # something else between the two strings
                     proto4(s("os"), STACK_GLOBAL),                                       # only one string
                     proto4(STACK_GLOBAL),                                                # none
                     proto4(s("os"), MARK, s("system"), STACK_GLOBAL),                    # a MARK between
                     proto4(NONE, s("system"), STACK_GLOBAL),                             # the module is not a string
                     proto4(s("os"), get(77), STACK_GLOBAL),                              # a memo entry that was never stored
                     proto4(s("os"), MEMOIZE, NONE, MEMOIZE, get(1), get(0), STACK_GLOBAL)):   # a memo entry that holds None
            r = read(data)
            self.assertEqual(r.unresolved, 1, data)
            self.assertEqual(r.globals, {}, data)

    def test_an_unresolved_import_is_counted_per_occurrence(self):
        r = read(proto4(NONE, STACK_GLOBAL, NONE, STACK_GLOBAL, s("os"), s("system"), STACK_GLOBAL))
        self.assertEqual((r.unresolved, names(r)), (2, ["os.system"]))

    def test_the_global_it_pushes_is_not_a_string_for_the_next_one(self):
        r = read(proto4(s("os"), s("system"), STACK_GLOBAL, s("x"), STACK_GLOBAL))
        self.assertEqual((names(r), r.unresolved), (["os.system"], 1))

    def test_a_dangerous_import_dressed_in_other_opcodes_is_still_found(self):
        r = read(proto4(MARK, s("os"), MEMOIZE, s("system"), MEMOIZE, STACK_GLOBAL, MEMOIZE, MARK, s("echo"), TUPLE, REDUCE, MEMOIZE))
        self.assertEqual(names(r), ["os.system"])

    def test_a_module_name_with_a_dot_and_a_dotted_attribute(self):
        r = read(proto4(s("http.client"), s("HTTPSConnection"), STACK_GLOBAL))
        self.assertEqual((names(r), P.classify_all(r)[0]["why"]), (["http.client.HTTPSConnection"], P.NET))
        r = read(b"cmodule\nOuter.Inner\n.")
        self.assertEqual(names(r), ["module.Outer.Inner"])


class SeveralPicklesAndBadData(unittest.TestCase):
    def test_every_pickle_in_a_file_is_read_in_turn(self):
        good = pickle.dumps({"a": 1}, protocol=2)
        evil = pickle.dumps(Evil(), protocol=2)
        r = read(good + good + evil)
        self.assertEqual((r.pickles, [d["name"] for d in P.classify_all(r)]), (3, ["eval"]))

    def test_data_after_the_last_pickle_is_noted_not_a_crash(self):
        good = pickle.dumps({"a": 1}, protocol=2)
        r = read(good + b"\xff\xfe raw tensor bytes \x00\x01")
        self.assertEqual(r.pickles, 1)
        self.assertEqual(r.trailing, "data that is not a pickle follows the last pickle")
        self.assertEqual((read(good).trailing, read(good).stopped), ("", ""))

    def test_data_that_is_not_a_pickle_at_all(self):
        for data in (b"\xff\xff\xff", b"hello world, this is text", os.urandom(200) if False else bytes(range(200, 256)) * 3):
            r = read(data)
            self.assertEqual(r.pickles, 0, data[:10])
            self.assertTrue(r.trailing.startswith("not a pickle"), (data[:10], r.trailing))

    def test_a_pickle_cut_short(self):
        full = pickle.dumps(Evil(), protocol=4)
        for cut in (3, len(full) // 2, len(full) - 1):
            r = read(full[:cut])
            self.assertEqual(r.pickles, 0, cut)
            self.assertTrue(r.trailing, cut)

    def test_empty_input(self):
        r = read(b"")
        self.assertEqual((r.pickles, r.trailing, r.stopped, r.ops), (0, "", "", 0))

    def test_a_declared_length_far_beyond_the_data_is_refused_without_allocating_it(self):
        for data in (b"\x80\x04" + b"\x8d" + (2 ** 62).to_bytes(8, "little") + b"x" * 10,                 # BINUNICODE8
                     b"\x80\x04" + b"\x8e" + (2 ** 62).to_bytes(8, "little") + b"x" * 10,                 # BINBYTES8
                     b"\x80\x04" + b"\x8d" + (2 ** 64 - 1).to_bytes(8, "little") + b"x",
                     b"\x80\x03X" + (2 ** 31).to_bytes(4, "little") + b"abc",                              # BINUNICODE
                     b"\x80\x03B" + (2 ** 31).to_bytes(4, "little") + b"abc"):
            t = time.time()
            r = read(data)
            self.assertLess(time.time() - t, 3, data[:12])
            self.assertEqual(r.pickles, 0)
            self.assertTrue(r.trailing)

    def test_deeply_nested_and_very_wide_pickles(self):
        deep = b"\x80\x04" + b"]" * 1 + b"(" * 5000 + b"." if False else proto4(b"]" + (MARK + b"]") * 5000)
        read(deep)
        wide = pickle.dumps(list(range(100000)), protocol=4)
        r = read(wide)
        self.assertEqual((r.pickles, r.stopped), (1, ""))

    def test_scanning_a_file_object_and_a_stream_that_does_not_start_at_zero(self):
        data = b"PADDING" + pickle.dumps(Evil(), protocol=4)
        stream = io.BytesIO(data)
        stream.seek(7)
        self.assertEqual(len(P.classify_all(P.scan(stream))), 1)
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "x.pkl")
            with open(path, "wb") as fh:
                fh.write(pickle.dumps(Evil(), protocol=2))
            with open(path, "rb") as fh:
                self.assertEqual(len(P.classify_all(P.scan(fh))), 1)


class Limits(unittest.TestCase):
    big = pickle.dumps(list(range(120000)), protocol=4)

    def test_the_opcode_limit(self):
        r = read(self.big, max_ops=1000)
        self.assertEqual(r.stopped, "opcode limit")
        self.assertEqual(r.pickles, 0)
        self.assertEqual(read(self.big).stopped, "")

    def test_the_time_limit(self):
        r = read(self.big, deadline=time.time() - 1)
        self.assertEqual(r.stopped, "time limit")
        self.assertEqual(read(self.big, deadline=time.time() + 60).stopped, "")

    def test_the_pickle_count_limit(self):
        one = pickle.dumps(1, protocol=2)
        r = read(one * 200, max_pickles=10)
        self.assertEqual((r.pickles, r.stopped), (10, "pickle count limit"))
        self.assertEqual(read(one * 5, max_pickles=10).stopped, "")

    def test_a_stopped_scan_never_looks_like_a_clean_one(self):
        self.assertTrue(read(self.big, max_ops=10).to_dict()["stopped"])
        self.assertEqual(read(pickle.dumps(1)).to_dict()["stopped"], "")


class NeverRuns(unittest.TestCase):
    def test_scanning_a_pickle_that_would_write_a_file_does_not_write_it(self):
        with tempfile.TemporaryDirectory() as d:
            marker = os.path.join(d, "ran.txt")

            class Boom:
                def __reduce__(self):
                    return (exec, (f"open({marker!r}, 'w').write('ran')",))
            data = pickle.dumps(Boom(), protocol=4)           # only writes; nothing runs
            self.assertFalse(os.path.exists(marker))
            r = P.scan(io.BytesIO(data))
            self.assertEqual([x["name"] for x in P.classify_all(r)], ["exec"])
            self.assertFalse(os.path.exists(marker))

    def test_scanning_does_not_import_the_modules_a_pickle_names(self):
        import sys
        name = "aibom_never_imported_module_xyz"
        read(proto4(s(name), s("thing"), STACK_GLOBAL))
        read(f"c{name}\nthing\n.".encode())
        self.assertNotIn(name, sys.modules)


class Classification(unittest.TestCase):
    def sev(self, module, name):
        verdict = P.classify(module, name)
        return verdict[0] if verdict else None

    def test_everything_other_scanners_list_as_dangerous_is_dangerous_here_too(self):
        # the lists of other scanners were used to look for gaps; each entry must be caught
        for module, names_ in (("__builtin__", ("eval", "compile", "getattr", "apply", "exec", "open", "breakpoint", "__import__")),
                               ("builtins", ("eval", "compile", "getattr", "apply", "exec", "open", "breakpoint", "__import__")),
                               ("runpy", ("run_path", "_run_code")), ("os", ("system", "popen", "execv", "listdir")), ("nt", ("system",)), ("posix", ("system", "popen")),
                               ("socket", ("socket", "create_connection")), ("subprocess", ("Popen", "call", "run", "check_output")), ("sys", ("exit", "modules")),
                               ("operator", ("attrgetter",)), ("pty", ("spawn",)), ("pickle", ("loads", "load", "Unpickler")), ("_pickle", ("loads",)), ("bdb", ("Bdb",)),
                               ("pdb", ("run", "Pdb")), ("shutil", ("rmtree", "copyfile", "move")), ("asyncio", ("create_subprocess_shell", "run")),
                               ("webbrowser", ("open",)), ("httplib", ("HTTPSConnection",)), ("requests.api", ("get", "post")), ("aiohttp.client", ("ClientSession",))):
            for name in names_:
                self.assertIsNotNone(P.classify(module, name), f"{module}.{name}")

    def test_the_severity_and_the_reason(self):
        for module, name, severity, why in (("os", "system", "high", P.RUN), ("subprocess", "Popen", "high", P.RUN), ("builtins", "eval", "high", P.RUN), ("builtins", "open", "high", P.FILES),
                                            ("shutil", "rmtree", "high", P.FILES), ("socket", "socket", "high", P.NET), ("requests.api", "get", "high", P.NET),
                                            ("pickle", "loads", "high", P.UNPICKLE), ("torch", "load", "high", P.UNPICKLE), ("numpy", "load", "high", P.UNPICKLE),
                                            ("types", "FunctionType", "high", P.BUILD), ("marshal", "loads", "high", P.BUILD), ("builtins", "getattr", "medium", P.GADGET),
                                            ("operator", "attrgetter", "medium", P.GADGET), ("functools", "partial", "medium", P.GADGET), ("os.path", "join", "high", P.RUN),
                                            ("http.client", "HTTPSConnection", "high", P.NET), ("builtins", "__import__", "high", P.RUN)):
            self.assertEqual(P.classify(module, name), (severity, why), f"{module}.{name}")

    def test_what_machine_learning_files_ordinarily_import_is_not_flagged(self):
        for module, name in (("torch._utils", "_rebuild_tensor_v2"), ("torch", "FloatStorage"), ("torch", "LongStorage"), ("torch", "Size"), ("torch", "device"),
                             ("torch.nn.modules.linear", "Linear"), ("torch.nn.parameter", "Parameter"), ("torch._utils", "_rebuild_parameter"),
                             ("collections", "OrderedDict"), ("numpy.core.multiarray", "_reconstruct"), ("numpy", "dtype"), ("numpy", "ndarray"), ("numpy.core.multiarray", "scalar"),
                             ("sklearn.ensemble._forest", "RandomForestClassifier"), ("sklearn.tree._tree", "Tree"), ("copyreg", "_reconstructor"), ("builtins", "set"),
                             ("builtins", "slice"), ("builtins", "complex"), ("builtins", "frozenset"), ("builtins", "bytearray"), ("builtins", "object"), ("builtins", "range"),
                             ("datetime", "datetime"), ("_codecs", "encode"), ("functools", "wraps"), ("operator", "itemgetter"), ("types", "SimpleNamespace"),
                             ("transformers.models.bert.modeling_bert", "BertModel"), ("pandas.core.frame", "DataFrame"), ("scipy.sparse._csr", "csr_matrix"),
                             ("xgboost.sklearn", "XGBClassifier"), ("lightgbm.sklearn", "LGBMClassifier"), ("joblib.numpy_pickle", "NumpyArrayWrapper"), ("pathlib", "PosixPath")):
            self.assertIsNone(P.classify(module, name), f"{module}.{name}")

    def test_names_that_only_start_like_a_listed_module_are_not_confused_with_it(self):
        for module, name in (("osmium", "x"), ("os_helpers", "x"), ("subprocess_tools", "run"), ("sysconfig", "get_path"), ("coder", "x"), ("sockets", "x"), ("httpx_extras", "x"),
                             ("pickles", "x"), ("shutil2", "x"), ("requests_toolbelt", "x"), ("numpy_extras", "load"), ("torchvision", "load"), ("builtins_extra", "eval")):
            self.assertIsNone(P.classify(module, name), f"{module}.{name}")

    def test_a_whole_package_rule_reaches_submodules_but_a_name_rule_does_not(self):
        self.assertEqual(self.sev("urllib.request", "urlopen"), "high")
        self.assertEqual(self.sev("asyncio.subprocess", "create_subprocess_exec"), "high")
        self.assertEqual(self.sev("torch.hub", "anything"), "high")
        self.assertIsNone(self.sev("numpy.lib", "stride_tricks"))
        self.assertEqual(self.sev("numpy.lib.npyio", "load"), "high")
        self.assertIsNone(self.sev("numpy.lib.npyio", "NpzFile"))
        self.assertIsNone(self.sev("builtins.sub", "eval"))

    def test_the_worst_matching_rule_wins(self):
        self.assertEqual(P.classify("builtins", "open"), ("high", P.FILES))

    def test_classify_all_lists_the_worst_first_without_repeats(self):
        r = P.PickleResult()
        r.globals = {("operator", "attrgetter"): 1, ("os", "system"): 4, ("collections", "OrderedDict"): 9, ("builtins", "eval"): 1, ("functools", "partial"): 1}
        got = P.classify_all(r)
        self.assertEqual([(d["severity"], d["module"], d["name"]) for d in got],
                         [("high", "builtins", "eval"), ("high", "os", "system"), ("medium", "functools", "partial"), ("medium", "operator", "attrgetter")])
        self.assertEqual(set(got[0]), {"module", "name", "severity", "why"})

    def test_every_rule_row_is_well_formed(self):
        for module, names_, severity, why in P.RULES:
            self.assertIn(severity, ("high", "medium"))
            self.assertTrue(names_ == "*" or (isinstance(names_, tuple) and names_ and all(isinstance(n, str) and n for n in names_)), (module, names_))
            self.assertIn(why, (P.RUN, P.FILES, P.NET, P.UNPICKLE, P.BUILD, P.GADGET))
            self.assertTrue(module and module == module.strip() and not module.endswith("."), module)
        self.assertEqual(len({(m, n if n == "*" else tuple(n)) for m, n, _, _ in P.RULES}), len(P.RULES))

    def test_the_result_is_plain_data(self):
        import json
        r = read(pickle.dumps(Evil(), protocol=4))
        json.dumps(r.to_dict())
        self.assertEqual(sorted(r.to_dict()), ["globals", "ops", "pickles", "stopped", "trailing", "unresolved"])


class HostileLengths(unittest.TestCase):
    """A pickle declares how long each blob is. Read from a real file, an unguarded reader sets aside that much memory before it sees the file is short."""

    def peak_mb(self, path, **kw):
        import tracemalloc
        tracemalloc.start()
        try:
            with open(path, "rb") as fh:
                result = P.scan(fh, **kw)
        finally:
            _, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()
        return peak / 1e6, result

    def write(self, data):
        d = tempfile.mkdtemp()
        path = os.path.join(d, "hostile.pkl")
        with open(path, "wb") as fh:
            fh.write(data)
        self.addCleanup(lambda: (os.remove(path), os.rmdir(d)))
        return path

    def test_a_file_that_declares_hundreds_of_megabytes_but_holds_a_few_bytes_costs_no_memory(self):
        declared = 300 * 2 ** 20
        for opcode, width in ((b"\x8e", 8), (b"\x8d", 8), (b"X", 4), (b"B", 4), (b"\x8b", 4)):
            path = self.write(b"\x80\x04" + opcode + declared.to_bytes(width, "little") + b"x" * 10 + b".")
            peak, result = self.peak_mb(path)
            self.assertLess(peak, 20, (opcode, peak))
            self.assertEqual(result.pickles, 0)
            self.assertTrue(result.trailing, opcode)

    def test_declaring_more_than_could_ever_exist_is_refused_the_same_way(self):
        for declared in (2 ** 40, 2 ** 62, 2 ** 63 - 1, 2 ** 64 - 1):
            path = self.write(b"\x80\x04\x8e" + declared.to_bytes(8, "little") + b"x")
            peak, result = self.peak_mb(path)
            self.assertLess(peak, 20, declared)
            self.assertTrue(result.trailing)

    def test_a_blob_longer_than_the_read_limit_is_passed_over_and_what_follows_is_still_read(self):
        # Found in the M3 manual test: 300 MB of padding before os.system ended the reading as "damaged" and the import was missed.
        tail = s("os") + s("system") + STACK_GLOBAL
        for opcode, width in ((b"\x8e", 8), (b"B", 4), (b"\x8d", 8), (b"X", 4), (b"\x96", 8)):
            data = proto4(opcode + (5000).to_bytes(width, "little") + b"\x00" * 5000 + tail)
            with mock.patch.object(P, "MAX_READ", 1000):
                for stream in (io.BytesIO(data), gzip.GzipFile(fileobj=io.BytesIO(gzip.compress(data)))):
                    r = P.scan(stream)
                    self.assertEqual((names(r), r.stopped, r.trailing, r.pickles), (["os.system"], "", "", 1), (opcode, type(stream).__name__))

    def test_a_real_blob_past_the_read_limit_costs_no_memory_and_hides_nothing(self):
        n = P.MAX_READ + 2 ** 20
        d = tempfile.mkdtemp()
        path = os.path.join(d, "padded.pkl")
        with open(path, "wb") as fh:
            fh.write(b"\x80\x04\x8e" + n.to_bytes(8, "little"))
            fh.seek(n - 1, 1)
            fh.write(b"\x00" + s("os") + s("system") + STACK_GLOBAL + b".")
        self.addCleanup(lambda: (os.remove(path), os.rmdir(d)))
        peak, result = self.peak_mb(path)
        self.assertLess(peak, 20)
        self.assertEqual((names(result), result.trailing, result.pickles), (["os.system"], "", 1))

    def test_a_blob_declared_past_the_read_limit_but_not_there_is_cut_short(self):
        with mock.patch.object(P, "MAX_READ", 1000):
            for stream in (io.BytesIO(b"\x80\x04\x8e" + (5000).to_bytes(8, "little") + b"x" * 10),
                           gzip.GzipFile(fileobj=io.BytesIO(gzip.compress(b"\x80\x04\x8e" + (5000).to_bytes(8, "little") + b"x" * 10)))):
                r = P.scan(stream)
                self.assertEqual((r.pickles, r.stopped, r.trailing), (0, "", "the pickle is damaged or cut short"), type(stream).__name__)

    def test_time_running_out_while_passing_over_a_blob_is_the_time_limit_not_damage(self):
        data = gzip.compress(proto4(b"\x8e" + (5000).to_bytes(8, "little") + b"\x00" * 5000 + s("os") + s("system") + STACK_GLOBAL))
        with mock.patch.object(P, "MAX_READ", 1000):
            r = P.scan(gzip.GzipFile(fileobj=io.BytesIO(data)), deadline=time.time() - 1)
            self.assertEqual((r.stopped, r.trailing), ("time limit", ""))
            r = P.scan(io.BytesIO(gzip.decompress(data)[:3000]), deadline=time.time() - 1)    # a file of known length that is short is damaged
            self.assertEqual((r.stopped, r.trailing), ("", "the pickle is damaged or cut short"))

    def test_the_stand_in_for_a_passed_over_blob(self):
        p = P._Passed(10 ** 12)
        self.assertEqual((len(p), str(p, "utf-8", "surrogatepass"), p.decode("latin-1"), bytes(p), bytearray(p)), (10 ** 12, "", "", b"", bytearray()))

    def test_the_text_opcodes_cannot_force_a_huge_read_either(self):
        path = self.write(b"S'" + b"a" * 5_000_000)        # a string with no end: readline must not run on
        peak, result = self.peak_mb(path)
        self.assertLess(peak, 60)
        self.assertEqual(result.pickles, 0)

    def test_a_blob_that_is_really_there_is_still_read(self):
        blob = b"z" * 3_000_000
        data = proto4(b"\x8e" + len(blob).to_bytes(8, "little") + blob)
        path = self.write(data + data)
        _, result = self.peak_mb(path)
        self.assertEqual((result.pickles, result.trailing), (2, ""))

    def test_the_guard_on_its_own(self):
        g = P._Guard(io.BytesIO(b"0123456789"))
        self.assertEqual(g.read(4), b"0123")
        self.assertEqual(g.read(10 ** 12), b"456789")          # no more than what is left
        self.assertEqual(g.read(5), b"")
        self.assertEqual(g.tell(), 10)
        g.seek(2)
        self.assertEqual(g.read(-1), b"23456789")
        self.assertEqual(g.read(None), b"")
        g.seek(0)
        self.assertEqual(g.readline(), b"0123456789")
        self.assertEqual(P._Guard(io.BytesIO(b"abc\ndef")).readline(), b"abc\n")
        self.assertEqual(P._Guard(io.BytesIO(b"abcdef"), size=3).read(100), b"abc")  # a size the caller knows wins

    def test_a_stream_that_cannot_seek_is_still_clamped_to_the_read_limit(self):
        class Raw:
            def __init__(self):
                self.asked = []

            def read(self, n=-1):
                self.asked.append(n)
                return b""

            def tell(self):
                raise OSError("not seekable")
        raw = Raw()
        P._Guard(raw).read(10 ** 15)
        self.assertEqual(raw.asked, [P.PIECE])                # taken in pieces: nothing is set aside for what is not there
        self.assertEqual((P.MAX_READ, P.PIECE), (256 * 2 ** 20, 8 * 2 ** 20))

    def test_on_a_stream_of_unknown_length_data_is_taken_in_pieces_and_all_of_it_is_returned(self):
        class Slow:
            def __init__(self, total):
                self.left, self.asked = total, []

            def read(self, n=-1):
                self.asked.append(n)
                n = min(n, self.left)
                self.left -= n
                return b"x" * n

            def tell(self):
                raise OSError("not seekable")
        raw = Slow(20 * 2 ** 20)
        got = P._Guard(raw).read(100 * 2 ** 20)
        self.assertEqual(len(got), 20 * 2 ** 20)
        self.assertTrue(all(n <= P.PIECE for n in raw.asked))
        self.assertEqual(P._Guard(Slow(10)).read(5), b"xxxxx")

    def test_a_line_read_is_bounded_too(self):
        class Raw:
            def __init__(self):
                self.asked = []

            def readline(self, size=-1):
                self.asked.append(size)
                return b""

            def tell(self):
                raise OSError("not seekable")
        raw = Raw()
        P._Guard(raw).readline()
        P._Guard(raw).readline(10 ** 15)
        self.assertEqual(raw.asked, [P.MAX_READ, P.MAX_READ])

    def test_every_kind_of_failure_while_reading_is_reported_not_raised(self):
        for exc in (ValueError("x"), MemoryError(), OverflowError(), RecursionError(), EOFError(), KeyError("k"), IndexError("i")):
            with mock.patch("aibom_engine.pickles.pickletools.genops", side_effect=exc):
                r = read(b"\x80\x04N.")
            self.assertEqual(r.pickles, 0, repr(exc))
            self.assertTrue(r.trailing.startswith("not a pickle"), repr(exc))


class Pushback(unittest.TestCase):
    """A stream that cannot seek (a compressed one) cannot be rewound after looking at the next byte, so the guard holds that byte."""

    def test_peeking_does_not_lose_the_byte(self):
        g = P._Guard(io.BytesIO(b"abcdef"))
        self.assertEqual((g.peek(), g.peek(), g.tell()), (b"a", b"a", 0))
        self.assertEqual(g.read(3), b"abc")
        self.assertEqual((g.peek(), g.tell()), (b"d", 3))
        self.assertEqual(g.read(1), b"d")
        self.assertEqual(g.read(10), b"ef")
        self.assertEqual((g.peek(), g.read(1)), (b"", b""))

    def test_a_line_after_a_peek(self):
        g = P._Guard(io.BytesIO(b"first line\nsecond"))
        g.peek()
        self.assertEqual(g.readline(), b"first line\n")
        g = P._Guard(io.BytesIO(b"\nrest"))
        g.peek()
        self.assertEqual((g.readline(), g.readline()), (b"\n", b"rest"))
        g = P._Guard(io.BytesIO(b"abc\n"))
        g.peek()
        self.assertEqual((g.readline(1), g.readline()), (b"a", b"bc\n"))

    def test_the_room_left_counts_the_byte_held(self):
        g = P._Guard(io.BytesIO(b"0123456789"))
        g.peek()
        self.assertEqual(g.read(10 ** 9), b"0123456789")
        g = P._Guard(io.BytesIO(b"abc"), size=3)
        g.peek()
        self.assertEqual((g.read(2), g.read(10)), (b"ab", b"c"))

    def test_seeking_drops_the_held_byte(self):
        g = P._Guard(io.BytesIO(b"abcdef"))
        g.peek()
        g.seek(4)
        self.assertEqual(g.read(5), b"ef")

    def test_a_stream_that_cannot_seek_is_scanned_all_the_same(self):
        class OneWay:
            def __init__(self, data):
                self._b = io.BytesIO(data)

            def read(self, n=-1):
                return self._b.read(n)

            def readline(self, size=-1):
                return self._b.readline(size)

            def tell(self):
                return self._b.tell()

            def seek(self, *a):
                raise OSError("cannot seek")
        data = pickle.dumps({"a": 1}, protocol=2) + evil_for_pushback()
        r = P.scan(OneWay(data))
        self.assertEqual((r.pickles, [d["name"] for d in P.classify_all(r)]), (2, ["eval"]))

    def test_the_limits_are_read_when_called_not_when_defined(self):
        with mock.patch.object(P, "MAX_OPS", 1000):
            self.assertEqual(read(pickle.dumps(list(range(120000)), protocol=4)).stopped, "opcode limit")
        with mock.patch.object(P, "MAX_PICKLES", 3):
            self.assertEqual(read(pickle.dumps(1, protocol=2) * 50).stopped, "pickle count limit")


def evil_for_pushback():
    return pickle.dumps(Evil(), protocol=2)


class EveryWayToPushAString(unittest.TestCase):
    def pushes(self):
        def text(value, opcode, width):
            data = value.encode()
            return opcode + len(data).to_bytes(width, "little") + data
        return {"SHORT_BINUNICODE": lambda v: text(v, b"\x8c", 1), "BINUNICODE": lambda v: text(v, b"X", 4), "BINUNICODE8": lambda v: text(v, b"\x8d", 8),
                "UNICODE": lambda v: b"V" + v.encode() + b"\n", "STRING": lambda v: b"S'" + v.encode() + b"'\n", "BINSTRING": lambda v: text(v, b"T", 4),
                "SHORT_BINSTRING": lambda v: text(v, b"U", 1)}

    def test_each_way_gives_the_same_answer(self):
        for kind, push in self.pushes().items():
            r = read(b"\x80\x04" + push("os") + push("system") + STACK_GLOBAL + b".")
            self.assertEqual((names(r), r.unresolved), (["os.system"], 0), kind)

    def test_ways_can_be_mixed_and_memoized(self):
        pushes = self.pushes()
        r = read(b"\x80\x04" + pushes["BINUNICODE"]("subprocess") + MEMOIZE + pushes["SHORT_BINSTRING"]("Popen") + STACK_GLOBAL + b".")
        self.assertEqual(names(r), ["subprocess.Popen"])

    def test_bytes_are_not_names_so_they_are_unresolved(self):
        for blob in (b"C\x02os" + b"C\x06system", b"B\x02\x00\x00\x00osB\x06\x00\x00\x00system", b"\x8e\x02" + b"\x00" * 7 + b"os" + b"\x8e\x06" + b"\x00" * 7 + b"system"):
            r = read(b"\x80\x04" + blob + STACK_GLOBAL + b".")
            self.assertEqual((r.unresolved, r.globals), (1, {}), blob[:6])


class TableEdges(unittest.TestCase):
    def test_a_dotted_rule_does_not_match_a_longer_name_that_merely_starts_with_it(self):
        for module, name in (("numpy.testing_extra", "x"), ("torch.hubx", "x"), ("torch.utils.cpp_extension_extra", "x"), ("numpy.lib.npyio_extra", "load"), ("torch.serializationx", "load")):
            self.assertIsNone(P.classify(module, name), module)
        for module, name in (("numpy.testing._private.utils", "runstring"), ("numpy.testing", "assert_allclose"), ("torch.utils.cpp_extension", "load"), ("torch.hub", "load")):
            self.assertEqual(P.classify(module, name)[0], "high", module)

    def test_when_two_rules_match_the_worse_one_wins_whatever_the_order(self):
        for rows in ({"zz": [("zz", ("a",), "medium", P.GADGET), ("zz", ("a",), "high", P.RUN)]}, {"zz": [("zz", ("a",), "high", P.RUN), ("zz", ("a",), "medium", P.GADGET)]}):
            with mock.patch.dict(P.BY_TOP, rows):
                self.assertEqual(P.classify("zz", "a"), ("high", P.RUN))
        with mock.patch.dict(P.BY_TOP, {"zz": [("zz", ("a",), "medium", P.GADGET)]}):
            self.assertEqual(P.classify("zz", "a"), ("medium", P.GADGET))


# What joblib 1.6 writes for {"a": int64[3], "b": int64[5], "c": a structured array, "d": float32[1], "e": an object array}, uncompressed.
# It holds a NumpyArrayWrapper for each array, with the raw array bytes right after it, and a nested pickle for the object array.
JOBLIB_SAMPLE = base64.b64decode(
    "gAWV2AAAAAAAAAB9lCiMAWGUjBNqb2JsaWIubnVtcHlfcGlja2xllIwRTnVtcHlBcnJheVdyYXBwZXKUk5QpgZR9lCiMCHN1YmNsYXNzlIwFbnVtcHmUjAduZGFycmF5lJOUjAVz"
    "aGFwZZRLA4WUjAVvcmRlcpSMAUOUjAVkdHlwZZRoCIwFZHR5cGWUk5SMAmk4lImIh5RSlChLA4wBPJROTk5K/////0r/////SwB0lGKMCmFsbG93X21tYXCUiIwbbnVtcHlfYXJyYXlf"
    "YWxpZ25tZW50X2J5dGVzlEsQdWIM////////////////AAAAAAAAAAABAAAAAAAAAAIAAAAAAAAAlScAAAAAAAAAjAFilGgEKYGUfZQoaAdoCmgLSwWFlGgNaA5oD2gUaBeIaBhLEHVi"
    "B/////////8AAAAAAAAAAAEAAAAAAAAAAgAAAAAAAAADAAAAAAAAAAQAAAAAAAAAlaYAAAAAAAAAjAFjlGgEKYGUfZQoaAdoCmgLSwKFlGgNaA5oD2gRjANWMTKUiYiHlFKUKEsDjAF8"
    "lE6MAW6UjAF4lIaUfZQoaCVoEYwCaTSUiYiHlFKUKEsDaBVOTk5K/////0r/////SwB0lGJLAIaUaCZoEYwCZjiUiYiHlFKUKEsDaBVOTk5K/////0r/////SwB0lGJLBIaUdUsMSwFL"
    "EHSUYmgXiGgYSxB1Ygj//////////wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAJVJAAAAAAAAAIwBZJRoBCmBlH2UKGgHaApoC0sBhZRoDWgOaA9oEYwCZjSUiYiHlFKUKEsDaBVOTk5K"
    "/////0r/////SwB0lGJoF4hoGEsQdWIF//////8AAMA/lUkAAAAAAAAAjAFllGgEKYGUfZQoaAdoCmgLSwGFlGgNaA5oD2gRjAJPOJSJiIeUUpQoSwNoJE5OTkr/////Sv////9LP3SU"
    "YmgXiWgYSxB1YoAFlZIAAAAAAAAAjBZudW1weS5fY29yZS5tdWx0aWFycmF5lIwMX3JlY29uc3RydWN0lJOUjAVudW1weZSMB25kYXJyYXmUk5RLAIWUQwFilIeUUpQoSwFLAYWUaAOM"
    "BWR0eXBllJOUjAJPOJSJiIeUUpQoSwOMAXyUTk5OSv////9K/////0s/dJRiiV2UfZSMAWuUSwFzYXSUYi51Lg==")


def wrapper(shape, dtype="f8", elsize=-1, flags=0, aligned=True):
    """The pickled state of a joblib array wrapper, as joblib writes it (protocol 4), ending at its BUILD."""
    shape_ops = MARK + b"".join(b"K" + bytes([n]) for n in shape) + TUPLE
    state = (b"K\x03" + s("<") + b"NNN" + (b"J" + elsize.to_bytes(4, "little", signed=True)) * 2 + b"K" + bytes([flags]))
    dtype_ops = s("numpy") + s("dtype") + STACK_GLOBAL + s(dtype) + b"\x89\x88\x87" + REDUCE + MARK + state + TUPLE + b"b"
    body = (s("subclass") + s("numpy") + s("ndarray") + STACK_GLOBAL + s("shape") + shape_ops + s("order") + s("C") + s("dtype") + dtype_ops
            + s("allow_mmap") + b"\x88")
    if aligned:
        body += s("numpy_array_alignment_bytes") + b"K\x10"
    return s("joblib.numpy_pickle") + s("NumpyArrayWrapper") + STACK_GLOBAL + EMPTY_TUPLE + b"\x81" + b"}" + MARK + body + b"u" + b"b"


def joblib_like(*arrays, tail=b""):
    """A pickle holding wrapped arrays; each array is (wrapper bytes, the raw data that follows it)."""
    return proto4(MARK, *[w + raw for w, raw in arrays], TUPLE, tail)


# The same kind of file with a datetime array, whose dtype carries its unit as bytes (protocol 4) or as _codecs.encode text (protocol 2).
JOBLIB_DATETIME = {
    4: base64.b64decode(
    "gASV6QAAAAAAAAB9lCiMAXSUjBNqb2JsaWIubnVtcHlfcGlja2xllIwRTnVtcHlBcnJheVdyYXBwZXKUk5QpgZR9lCiMCHN1YmNsYXNzlIwFbnVtcHmUjAduZGFycmF5lJOUjAVzaGFw"
    "ZZRLAYWUjAVvcmRlcpSMAUOUjAVkdHlwZZRoCIwFZHR5cGWUk5SMAk04lImIh5RSlChLBIwBPJROTk5K/////0r/////SwBOKEMCbnOUSwFLAUsBdJSGlHSUYowKYWxsb3dfbW1hcJSI"
    "jBtudW1weV9hcnJheV9hbGlnbm1lbnRfYnl0ZXOUSxB1Ygv//////////////wAAirk1muUVlUsAAAAAAAAAjAF1lGgEKYGUfZQoaAdoCmgLSwGFlGgNaA5oD2gRjAJ1MZSJiIeUUpQo"
    "SwOMAXyUTk5OSv////9K/////0sAdJRiaBqIaBtLEHViA////wF1Lg=="),
    2: base64.b64decode(
    "gAJ9cQAoWAEAAAB0cQFjam9ibGliLm51bXB5X3BpY2tsZQpOdW1weUFycmF5V3JhcHBlcgpxAimBcQN9cQQoWAgAAABzdWJjbGFzc3EFY251bXB5Cm5kYXJyYXkKcQZYBQAAAHNoYXBl"
    "cQdLAYVxCFgFAAAAb3JkZXJxCVgBAAAAQ3EKWAUAAABkdHlwZXELY251bXB5CmR0eXBlCnEMWAIAAABNOHENiYiHcQ5ScQ8oSwRYAQAAADxxEE5OTkr/////Sv////9LAE4oY19jb2Rl"
    "Y3MKZW5jb2RlCnERWAIAAABuc3ESWAYAAABsYXRpbjFxE4ZxFFJxFUsBSwFLAXRxFoZxF3RxGGJYCgAAAGFsbG93X21tYXBxGYhYGwAAAG51bXB5X2FycmF5X2FsaWdubWVudF9ieXRl"
    "c3EaSxB1Yg3/////////////////AACKuTWa5RVYAQAAAHVxG2gCKYFxHH1xHShoBWgGaAdLAYVxHmgJaApoC2gMWAIAAAB1MXEfiYiHcSBScSEoSwNYAQAAAHxxIk5OTkr/////Sv//"
    "//9LAHRxI2JoGYhoGksQdWIK/////////////wF1Lg=="),
}


# A fitted scikit-learn scaler saved with joblib: its float64 dtype is built by a NumPy scalar, outside any array wrapper, and fetched by the arrays after it.
JOBLIB_SCALER = base64.b64decode(
    "gAWViwEAAAAAAACMG3NrbGVhcm4ucHJlcHJvY2Vzc2luZy5fZGF0YZSMDlN0YW5kYXJkU2NhbGVylJOUKYGUfZQojAl3aXRoX21lYW6UiIwId2l0aF9zdGSUiIwEY29weZSIjA5uX2Zl"
    "YXR1cmVzX2luX5RLAowPbl9zYW1wbGVzX3NlZW5flIwWbnVtcHkuX2NvcmUubXVsdGlhcnJheZSMBnNjYWxhcpSTlIwFbnVtcHmUjAVkdHlwZZSTlIwCZjiUiYiHlFKUKEsDjAE8lE5O"
    "Tkr/////Sv////9LAHSUYkMIAAAAAAAAGECUhpRSlIwFbWVhbl+UjBNqb2JsaWIubnVtcHlfcGlja2xllIwRTnVtcHlBcnJheVdyYXBwZXKUk5QpgZR9lCiMCHN1YmNsYXNzlGgNjAdu"
    "ZGFycmF5lJOUjAVzaGFwZZRLAoWUjAVvcmRlcpSMAUOUjAVkdHlwZZRoEowKYWxsb3dfbW1hcJSIjBtudW1weV9hcnJheV9hbGlnbm1lbnRfYnl0ZXOUSxB1Ygn////////////JnPiy"
    "2xjkP0dnD5Z9yeM/lSoAAAAAAAAAjAR2YXJflGgbKYGUfZQoaB5oIGghSwKFlGgjaCRoJWgSaCaIaCdLEHViDP///////////////70FzJMFJqM/+TsqQJExmj+VLAAAAAAAAACMBnNj"
    "YWxlX5RoGymBlH2UKGgeaCBoIUsChZRoI2gkaCVoEmgmiGgnSxB1Ygr/////////////5IkT1PvAyD/Bl+lFzXjEP5UeAAAAAAAAAIwQX3NrbGVhcm5fdmVyc2lvbpSMBTEuOS4xlHVi"
    "Lg==")


def imports(result):
    """The imports that are not just the array machinery itself."""
    return [n for n in names(result) if not n.startswith(("joblib.", "numpy."))]


class JoblibArrays(unittest.TestCase):
    """joblib puts each NumPy array's raw bytes inside the pickle. They are not opcodes, so they are passed over by the size the wrapper declares."""

    def test_a_real_joblib_file_is_read_to_its_end(self):
        r = read(JOBLIB_SAMPLE)
        self.assertEqual((r.pickles, r.stopped, r.trailing, r.unresolved), (1, "", "", 0))
        self.assertIn(("joblib.numpy_pickle", "NumpyArrayWrapper"), r.globals)
        self.assertIn(("numpy", "dtype"), r.globals)
        self.assertEqual(P.classify_all(r), [])

    def test_a_real_file_with_a_datetime_array_in_protocols_2_and_4(self):
        for proto, data in JOBLIB_DATETIME.items():
            r = read(data)
            self.assertEqual((r.pickles, r.stopped, r.trailing, P.classify_all(r)), (1, "", "", []), proto)

    def test_a_dangerous_import_in_the_nested_pickle_of_an_object_array_is_found(self):
        evil = pickle.dumps(Evil(), protocol=5)
        data = joblib_like((wrapper((1,), "O8", elsize=8, flags=1), evil))
        r = read(data)
        self.assertEqual(r.stopped, "")
        self.assertIn(("builtins", "eval"), r.globals)

    def test_bytes_inside_an_array_are_data_not_opcodes(self):
        decoy = b"cos\nsystem\n(S'echo hi'\ntR."          # looks like an attack, but is only numbers in an array
        decoy = decoy + b"\x00" * (-len(decoy) % 8)
        r = read(joblib_like((wrapper((len(decoy) // 8,), "i8", elsize=8, aligned=False), decoy)))
        self.assertEqual((r.pickles, r.stopped, r.trailing), (1, "", ""))
        self.assertNotIn(("os", "system"), r.globals)

    def test_an_import_after_the_arrays_is_still_found(self):
        data = joblib_like((wrapper((2,), "i8", elsize=8, aligned=False), b"\x00" * 16), tail=s("os") + s("system") + STACK_GLOBAL)
        self.assertEqual(imports(read(data)), ["os.system"])

    def test_padding_before_the_data_is_passed_over(self):
        r = read(joblib_like((wrapper((2,), "i8", elsize=8), bytes([5]) + b"\xff" * 5 + b"\x00" * 16), tail=s("os") + s("system") + STACK_GLOBAL))
        self.assertEqual((imports(r), r.stopped), (["os.system"], ""))

    def test_an_empty_array_and_a_zero_dimensional_one(self):
        for shape in ((0,), (), (3, 0)):
            r = read(joblib_like((wrapper(shape, "f8", elsize=-1, aligned=False), b"\x00" * (8 if shape == () else 0)), tail=s("os") + s("system") + STACK_GLOBAL))
            self.assertEqual((imports(r), r.stopped), (["os.system"], ""), shape)

    def test_data_that_ends_early_is_not_called_read(self):
        r = read(joblib_like((wrapper((100,), "i8", elsize=8, aligned=False), b"\x00" * 10)))
        self.assertEqual(r.pickles, 0)
        self.assertTrue(r.trailing or r.stopped)

    def test_a_declared_size_far_beyond_the_file_costs_nothing(self):
        for shape in ((255, 255, 255, 255, 255, 255, 255), (255,) * 12):
            started = time.time()
            r = read(joblib_like((wrapper(shape, "f8", elsize=-1, aligned=False), b"\x00" * 64)))
            self.assertLess(time.time() - started, 2)
            self.assertEqual(r.pickles, 0)

    def test_a_dtype_whose_size_is_unknown_stops_reading_and_says_so(self):
        r = read(joblib_like((wrapper((1,), "S", elsize=-1, aligned=False), b"\x00" * 8)))
        self.assertEqual(r.pickles, 0)
        self.assertIn("size of an array", r.stopped)

    def test_a_wrapper_that_is_not_in_the_form_joblib_writes_stops_reading_and_says_so(self):
        broken = s("joblib.numpy_pickle") + s("NumpyArrayWrapper") + STACK_GLOBAL + EMPTY_TUPLE + b"\x81" + b"]" + b"b"
        r = read(proto4(MARK, broken, b"\x00" * 8, s("os") + s("system") + STACK_GLOBAL, TUPLE))
        self.assertEqual(r.pickles, 0)
        self.assertIn("array description", r.stopped)

    def test_the_wrapper_class_without_a_wrapper_changes_nothing(self):
        r = read(proto4(s("joblib.numpy_pickle"), s("NumpyArrayWrapper"), STACK_GLOBAL, s("os"), s("system"), STACK_GLOBAL))
        self.assertEqual((names(r), r.stopped, r.pickles), (["joblib.numpy_pickle.NumpyArrayWrapper", "os.system"], "", 1))

    def test_a_pickle_cut_at_any_point_or_changed_at_any_byte_is_reported_not_crashed(self):
        for n in range(len(JOBLIB_SAMPLE)):
            r = read(JOBLIB_SAMPLE[:n])
            self.assertEqual(r.pickles, 0, n)
        for i in range(len(JOBLIB_SAMPLE)):
            for value in (0, 255):
                data = bytearray(JOBLIB_SAMPLE)
                data[i] = value
                read(bytes(data))                     # must come back with a result, whatever it says

    def test_a_real_file_whose_dtype_is_built_outside_any_array_wrapper(self):
        r = read(JOBLIB_SCALER)                 # a fitted scaler: a NumPy scalar builds the float64 dtype that its arrays then fetch from the memo
        self.assertEqual((r.pickles, r.stopped, r.trailing, r.unresolved, P.classify_all(r)), (1, "", "", 0, []))

    def test_an_array_with_an_object_field_is_followed_by_a_nested_pickle(self):
        evil = pickle.dumps(Evil(), protocol=5)
        r = read(joblib_like((wrapper((1,), "V16", elsize=16, flags=1), evil)))     # a structured dtype with an object field: flag bit 1 says so
        self.assertEqual((r.stopped, imports(r)), ("", ["builtins.eval"]))

    def test_a_fetched_global_is_not_taken_for_a_module_name(self):
        r = read(proto4(s("os"), s("system"), STACK_GLOBAL, MEMOIZE, get(0), s("x"), STACK_GLOBAL))
        self.assertEqual((names(r), r.unresolved), (["os.system"], 1))

    def test_a_dtype_class_used_in_some_other_way_does_not_stop_the_reading(self):
        r = read(proto4(s("numpy"), s("dtype"), STACK_GLOBAL, b"]", b"a", s("os"), s("system"), STACK_GLOBAL))
        self.assertEqual((names(r), r.stopped, r.pickles), (["numpy.dtype", "os.system"], "", 1))

    def test_skip_counts_what_was_really_there(self):
        g = P._Guard(io.BytesIO(b"abcdef"))
        self.assertEqual(g.skip(100), 6)
        g = P._Guard(io.BytesIO(b"abcdef"))
        g.peek()                                  # one byte is held back by peek and counts as passed over
        self.assertEqual((g.skip(3), g.read(1)), (3, b"d"))
        import gzip
        g = P._Guard(gzip.GzipFile(fileobj=io.BytesIO(gzip.compress(b"abcdef"))))
        g.peek()
        self.assertEqual((g.skip(100), g.read(1)), (6, b""))
        g = P._Guard(gzip.GzipFile(fileobj=io.BytesIO(gzip.compress(b"abcdef"))))
        self.assertEqual((g.skip(2), g.read(1)), (2, b"c"))

    def test_skip_stops_at_the_deadline_and_a_buffer_knows_its_length(self):
        import gzip
        g = P._Guard(gzip.GzipFile(fileobj=io.BytesIO(gzip.compress(b"a" * 1000))))
        self.assertEqual(g.skip(10 ** 9, deadline=time.time() - 1), 0)
        self.assertEqual(P._Guard(io.BytesIO(b"x" * 10))._room(100), 10)
        self.assertEqual(P._Guard(io.BytesIO(b"x" * 10)).read(100), b"x" * 10)

    def test_the_array_bytes_are_passed_over_in_a_compressed_stream(self):
        import gzip
        r = P.scan(gzip.GzipFile(fileobj=io.BytesIO(gzip.compress(JOBLIB_SAMPLE))))
        self.assertEqual((r.pickles, r.stopped, r.trailing), (1, "", ""))
        data = joblib_like((wrapper((2,), "i8", elsize=8, aligned=False), b"\x00" * 16), tail=s("os") + s("system") + STACK_GLOBAL)
        self.assertEqual(imports(P.scan(gzip.GzipFile(fileobj=io.BytesIO(gzip.compress(data))))), ["os.system"])


if __name__ == "__main__":
    unittest.main()
