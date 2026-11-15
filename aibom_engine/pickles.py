"""Read a pickle without running it, and say which Python callables it imports (M3.4).

A pickle is a small program for a stack machine. Loading one can call any function the file names, so a model saved with
pickle can run code on the machine that loads it. This module never loads anything. It walks the opcodes with Python's own
`pickletools.genops`, which only reads, and collects the `module.name` of every global the pickle imports. The caller then asks
`classify` whether a global is one that runs commands, reaches the network, builds code, or helps chain such calls.

How the module and name of a global are found:
- Protocols 0 to 3 write them as text in one opcode (GLOBAL, INST), read directly.
- Protocols 4 and 5 push two strings and then run STACK_GLOBAL. The strings are tracked, including ones fetched back from the
  pickle's memo (BINGET and friends), the way Python's own pickler writes them. If the two operands are not exactly two
  strings pushed one after the other, the global cannot be resolved and is counted as UNRESOLVED instead of being guessed at:
  a pickle built to hide what it imports is more suspicious than one that is not.

A file can hold several pickles one after another (older PyTorch files do). They are read in turn until the data stops being a
pickle. Everything is bounded: the number of opcodes, the bytes read and the time, and when a bound is hit the result says
so, because "stopped early" must never read as "nothing found".

The list of dangerous callables is written here from Python's own documentation of how pickle can be abused and from the
published lists of other scanners, which were used to look for gaps, not copied.
"""
import io
import pickletools
import time
from collections import namedtuple

UNRESOLVED = "<unresolved>"

# Opcodes that push a string, and the ones that store or fetch the memo, by name as pickletools reports them.
STRING_PUSH = {"SHORT_BINUNICODE", "BINUNICODE", "BINUNICODE8", "UNICODE", "STRING", "BINSTRING", "SHORT_BINSTRING"}
MEMO_GET = {"GET", "BINGET", "LONG_BINGET"}
MEMO_PUT = {"PUT", "BINPUT", "LONG_BINPUT"}
TEXT_GLOBAL = {"GLOBAL", "INST"}

Glob = namedtuple("Glob", "module name")   # a global the pickle has imported, kept in the memo so that a later fetch of it is recognised
WRAPPER = Glob("joblib.numpy_pickle", "NumpyArrayWrapper")
DTYPE = Glob("numpy", "dtype")
CODECS_ENCODE = Glob("_codecs", "encode")
BYTES_PUSH = {"SHORT_BINBYTES", "BINBYTES", "BINBYTES8", "BYTES"}
# While a joblib array wrapper is expected, only these opcodes may come between loading its class and building it.
WRAPPER_WAIT = {"EMPTY_TUPLE", "MEMOIZE", "BINPUT", "LONG_BINPUT", "PUT", "MARK", "TUPLE", "TUPLE1", "TUPLE2", "TUPLE3", "NEWOBJ", "NEWOBJ_EX", "REDUCE"}

MAX_READ = 256 * 1024 * 1024  # no single read returns more than this, whatever length a pickle declares
PIECE = 8 * 1024 * 1024       # on a stream of unknown length, data is taken in pieces of this size
MAX_OPS = 50_000_000
MAX_PICKLES = 64
CHECK_EVERY = 20_000  # how many opcodes between looks at the clock


class PickleResult:
    """What was found in one stream: the distinct imports, how many could not be resolved, and why reading stopped."""

    def __init__(self):
        self.globals = {}        # (module, name) -> how many times it is imported
        self.unresolved = 0
        self.pickles = 0         # how many complete pickles were read
        self.has_proto = False   # the first pickle began with a protocol marker, so it is a pickle that is damaged rather than something else
        self.ops = 0
        self.stopped = ""        # "" = read to the end; else why it stopped early ("opcode limit", "time limit", "byte limit")
        self.trailing = ""       # what followed the last pickle, when it was not another pickle ("" = nothing)

    def to_dict(self):
        return {"globals": sorted(f"{m}.{n}" for m, n in self.globals), "unresolved": self.unresolved, "pickles": self.pickles,
                "ops": self.ops, "stopped": self.stopped, "trailing": self.trailing}


class _Guard:
    """A read-only view of a stream that never hands back more than is left in it, nor more than MAX_READ at once.

    A pickle declares the length of each string or blob it holds, and a hostile one can declare gigabytes. Asked for that many bytes, Python may
    set aside the memory before it finds the file is short. With this view the answer is simply the few bytes that are really there, and the
    reader reports the pickle as cut short.

    A blob longer than MAX_READ that is really there is passed over instead of read (see `_pass_over`), so a pickle cannot hide an import
    behind a few hundred megabytes of padding."""

    def __init__(self, stream, size=None, deadline=None):
        self._s = stream
        self._end = size
        self._deadline = deadline
        self.timed_out = False   # passing over a long blob ran out of time
        self._pending = b""   # one byte read ahead by peek(), given back by the next read
        # The size is looked up by seeking to the end, which is free for a file or a buffer and, for a compressed stream, would mean inflating
        # all of it just to learn its length. So only those two are probed; any other stream is limited by MAX_READ alone.
        if size is None and isinstance(stream, (io.BufferedReader, io.FileIO, io.BytesIO)):
            try:
                here = stream.tell()
                self._end = stream.seek(0, 2)
                stream.seek(here)
            except (OSError, ValueError, AttributeError):
                self._end = None

    def _room(self, n):
        n = MAX_READ if n is None or n < 0 else min(n, MAX_READ)
        if self._end is not None:
            n = min(n, max(self._end - self.tell(), 0))
        return n

    def peek(self):
        """The next byte without taking it (b"" at the end). A stream that cannot seek, such as a compressed one, cannot be rewound, so this holds it."""
        if not self._pending:
            self._pending = self._s.read(1)
        return self._pending

    def _take(self, n):
        """Up to n bytes from the stream. When its length is not known (a compressed stream), they are taken in pieces, so that a pickle declaring
        a huge blob makes memory grow only with the data that is really there: a decompressor sets aside the whole amount it is asked for."""
        if self._end is not None or n <= PIECE:
            return self._s.read(n)
        parts, got = [], 0
        while got < n:
            piece = self._s.read(min(n - got, PIECE))
            if not piece:
                break
            parts.append(piece)
            got += len(piece)
        return b"".join(parts)

    def read(self, n=-1):
        if n is not None and n > MAX_READ and (self._end is None or self._end - self.tell() >= n):
            return self._pass_over(n)    # all of it is there (or, on a stream, may be): skip it; a short file is answered as before
        n = self._room(n)
        if n <= 0:
            return b""
        if self._pending:
            head, self._pending = self._pending, b""
            return head + self._take(n - 1) if n > 1 else head
        return self._take(n)

    def _pass_over(self, n):
        """A declared length beyond MAX_READ. A blob holds data, never an import, so when all n bytes are there they are skipped, not kept, and
        what follows is still read; the reader is given a stand-in of that length. When fewer are there, the answer is b"" and the pickle is cut short."""
        got = self.skip(n, self._deadline)
        if got == n:
            return _Passed(n)
        if self._deadline is not None and time.time() > self._deadline:
            self.timed_out = True    # only a stream gets here short: a file of known length is passed over only when all of it is there
        return b""

    def readline(self, size=-1):
        n = self._room(size)
        if n <= 0:
            return b""
        if self._pending:
            head, self._pending = self._pending, b""
            return head if head == b"\n" or n == 1 else head + self._s.readline(n - 1)
        return self._s.readline(n)

    def tell(self):
        return self._s.tell() - len(self._pending)

    def skip(self, n, deadline=None):
        """Pass over n bytes without keeping them. Returns how many were really there (fewer than n means the data ended or time ran out)."""
        got = 0
        if self._pending and n > 0:
            self._pending, got = b"", 1
        if self._end is not None:
            step = max(min(n - got, self._end - self._s.tell()), 0)
            self._s.seek(self._s.tell() + step)
            return got + step
        while got < n:
            if deadline is not None and time.time() > deadline:
                break
            piece = self._s.read(min(n - got, PIECE))
            if not piece:
                break
            got += len(piece)
        return got

    def seek(self, *args):
        self._pending = b""
        return self._s.seek(*args)


class _Passed(bytes):
    """Stands in for a blob that was passed over: as long as the blob, with nothing in it (it reads as "" or b"")."""

    def __new__(cls, n):
        obj = super().__new__(cls)
        obj._n = n
        return obj

    def __len__(self):
        return self._n


class _Unskippable(Exception):
    """The raw array data that joblib writes inside a pickle could not be passed over safely."""


class _Dtype:
    """A NumPy dtype as the pickle describes it. The pickle builds it in two steps (REDUCE, then BUILD), so it is filled in place."""

    def __init__(self, name):
        self.name, self.elsize, self.flags = name, None, 0

    def has_object(self):
        return self.name.lstrip("<>=|")[:1] == "O" or bool(self.flags & 1)

    def itemsize(self):
        if isinstance(self.elsize, int) and self.elsize > 0:
            return self.elsize
        name = self.name.lstrip("<>=|")
        digits = ""
        for ch in name[1:]:
            if not ch.isdigit():
                break
            digits += ch
        if name[:1] in "biufcmM" and digits:
            return int(digits)
        raise _Unskippable("the size of an array stored inside it is not known")


_MISSING = object()
DONE = object()


class _Eval:
    """Follows just enough of a pickle to read the state of a joblib array wrapper (shape, dtype, alignment): strings, numbers, tuples, dicts
    and NumPy dtypes. It computes nothing from the file but those values, and refuses (_Unskippable) at the first opcode it does not know."""

    def __init__(self, vals, stack=None, dtype_only=False):
        self.stack, self.marks, self.vals = stack or [], [], vals
        self.dtype_only = dtype_only    # following just one dtype (so a wrapper that fetches it later knows it), not a wrapper

    def feed(self, name, arg, memo):
        """Take one opcode. Returns the state when this opcode is the BUILD that completes the wrapper, else None."""
        st = self.stack
        try:
            if name in STRING_PUSH or name in BYTES_PUSH:
                st.append(arg)
            elif name in ("BININT", "BININT1", "BININT2", "LONG1", "LONG4", "INT"):
                st.append(int(arg))
            elif name == "NONE":
                st.append(None)
            elif name == "NEWTRUE":
                st.append(True)
            elif name == "NEWFALSE":
                st.append(False)
            elif name == "EMPTY_TUPLE":
                st.append(())
            elif name == "EMPTY_DICT":
                st.append({})
            elif name == "MARK":
                self.marks.append(len(st))
            elif name == "TUPLE":
                m = self.marks.pop()
                t = tuple(st[m:])
                del st[m:]
                st.append(t)
            elif name in ("TUPLE1", "TUPLE2", "TUPLE3"):
                n = int(name[-1])
                t = tuple(st[-n:])
                del st[-n:]
                st.append(t)
            elif name == "SETITEMS":
                m = self.marks.pop()
                items = st[m:]
                del st[m:]
                for i in range(0, len(items) - 1, 2):
                    st[-1][items[i]] = items[i + 1]
            elif name == "SETITEM":
                v, k = st.pop(), st.pop()
                st[-1][k] = v
            elif name == "STACK_GLOBAL":
                attr, mod = st.pop(), st.pop()
                if not (isinstance(mod, str) and isinstance(attr, str)):
                    raise _Unskippable("a global inside an array description is not two strings")
                st.append(Glob(mod, attr))
            elif name in TEXT_GLOBAL:
                module, _, attr = str(arg).partition(" ")
                st.append(Glob(module, attr))
            elif name in MEMO_GET:
                value = self.vals[arg] if arg in self.vals else memo.get(arg, _MISSING)
                if value is _MISSING or value == UNRESOLVED:
                    raise _Unskippable("an array description refers to a value that was not seen")
                st.append(value)
            elif name == "MEMOIZE":
                if st:
                    self.vals[len(memo)] = st[-1]
            elif name in MEMO_PUT:
                if st:
                    self.vals[arg] = st[-1]
            elif name == "REDUCE":
                args, func = st.pop(), st.pop()
                if func == CODECS_ENCODE and isinstance(args, tuple) and len(args) == 2 and isinstance(args[0], str) and args[1] == "latin1":
                    st.append(args[0].encode("latin1"))    # how protocols 0 to 2 write bytes (a datetime dtype carries its unit this way)
                    return None
                if func != DTYPE or not isinstance(args, tuple) or not args or not isinstance(args[0], str):
                    raise _Unskippable("an array description calls something other than a NumPy dtype")
                st.append(_Dtype(args[0]))
            elif name == "BUILD":
                state = st.pop()
                if not st:
                    return state                       # nothing below it: this is the wrapper's own state
                obj = st[-1]
                if not isinstance(obj, _Dtype) or not isinstance(state, tuple) or len(state) < 8:
                    raise _Unskippable("a dtype inside an array description has an unexpected form")
                obj.elsize, obj.flags = state[5], state[7]
                if self.dtype_only and len(st) == 1:
                    return DONE
            elif name == "POP":
                st.pop()
            elif name not in ("PROTO", "FRAME"):
                raise _Unskippable(f"an array description uses an opcode ({name}) that is not expected")
        except (IndexError, TypeError, ValueError, KeyError):
            raise _Unskippable("an array description is not in the form joblib writes")
        return None


def _skip_array(stream, state, result, deadline, max_ops):
    """The bytes joblib wrote right after an array wrapper: optional padding, then the raw data (or, for objects, a nested pickle). Returns True
    when they were passed over, False when the data ran out."""
    if not isinstance(state, dict) or not isinstance(state.get("shape"), tuple) or not isinstance(state.get("dtype"), _Dtype):
        raise _Unskippable("an array description has no usable shape and dtype")
    shape, dtype = state["shape"], state["dtype"]
    if not all(isinstance(x, int) and not isinstance(x, bool) and x >= 0 for x in shape):
        raise _Unskippable("an array has an invalid shape")
    if dtype.has_object():
        return _one_pickle(stream, result, {}, deadline, max_ops)
    count = 1
    for x in shape:
        count *= x
    if state.get("numpy_array_alignment_bytes") is not None:
        pad = stream.read(1)
        if not pad:
            return False
        if pad[0] and stream.skip(pad[0], deadline) < pad[0]:
            return False
    size = count * dtype.itemsize()
    if stream.skip(size, deadline) < size:
        if deadline is not None and time.time() > deadline:
            result.stopped = "time limit"
        return False
    return True


def _one_pickle(stream, result, memo, deadline, max_ops, vals=None):
    """Read one pickle from the stream (up to its STOP), adding what it imports to `result`. Returns True when it ended at a STOP.

    joblib stores each NumPy array's raw bytes inside the pickle, right after the opcode that builds its wrapper; those bytes are not opcodes, so
    they are passed over using the shape and dtype the wrapper declares."""
    items = []   # the strings pushed one after the other just now: what STACK_GLOBAL will use
    last = UNRESOLVED
    count = 0
    vals = {} if vals is None else vals    # values kept from the array descriptions, for the ones that are fetched again from the memo
    ev = None
    pending = False                        # the joblib wrapper class has just been loaded
    for opcode, arg, _pos in pickletools.genops(stream):
        name = opcode.name
        count += 1
        result.ops += 1
        if count == 1 and name == "PROTO" and result.pickles == 0:
            result.has_proto = True
        if pending and name not in WRAPPER_WAIT:
            pending = False
        if ev is not None:
            try:
                state = ev.feed(name, arg, memo)
                if state is DONE:
                    ev = None                          # the dtype it followed is complete and remembered
                elif state is not None:
                    ev = None
                    if not _skip_array(stream, state, result, deadline, max_ops):
                        return False
                    items, last = [], UNRESOLVED
                    continue
            except _Unskippable as e:
                if ev is not None and ev.dtype_only:
                    ev = None                          # it was only following a dtype that turned out to be something else
                else:
                    result.stopped = str(e)
                    return False
        if count % CHECK_EVERY == 0:
            if result.ops > max_ops:
                result.stopped = "opcode limit"
                return False
            if deadline is not None and time.time() > deadline:
                result.stopped = "time limit"
                return False
        if name in STRING_PUSH:
            last = arg   # these opcodes all yield text; the ones that yield bytes are not in STRING_PUSH, so a bytes operand stays unresolved
            items.append(last)
            continue
        if name in MEMO_GET:
            last = memo.get(arg, UNRESOLVED)
            items.append(last)
            pending = last == WRAPPER
            if last == DTYPE and ev is None:
                ev = _Eval(vals, [DTYPE], True)
            continue
        if name == "MEMOIZE":
            memo[len(memo)] = last
            continue
        if name in MEMO_PUT:
            memo[arg] = last
            continue
        if name == "STACK_GLOBAL":
            module, attr = (items[-2], items[-1]) if len(items) >= 2 else (UNRESOLVED, UNRESOLVED)
            if not isinstance(module, str) or not isinstance(attr, str) or module == UNRESOLVED or attr == UNRESOLVED:
                result.unresolved += 1
                last = UNRESOLVED
            else:
                result.globals[(module, attr)] = result.globals.get((module, attr), 0) + 1
                last = Glob(module, attr)  # the global it pushed is not a string, but is remembered as a global
            items = []
            pending = last == WRAPPER
            if last == DTYPE and ev is None:
                ev = _Eval(vals, [DTYPE], True)
            continue
        if name in TEXT_GLOBAL:
            module, _, attr = str(arg).partition(" ")
            if module and attr:
                result.globals[(module, attr)] = result.globals.get((module, attr), 0) + 1
                last = Glob(module, attr)
            else:
                result.unresolved += 1
                last = UNRESOLVED
            items = []
            pending = last == WRAPPER
            if last == DTYPE and ev is None:
                ev = _Eval(vals, [DTYPE], True)
            continue
        if name == "STOP":
            return True
        if pending and name in ("NEWOBJ", "NEWOBJ_EX", "REDUCE"):
            ev, pending = _Eval(vals), False   # the state that follows describes an array whose bytes come after it
        items, last = [], UNRESOLVED       # any other opcode breaks the "two strings in a row" the global needs
    return False


def scan(stream, deadline=None, max_ops=None, max_pickles=None, size=None):
    """Read every pickle in a binary stream, in turn, and return a PickleResult. Raises nothing for bad data: it is reported in the result.
    `size` is how long the stream is from its start when the caller knows it (a zip entry's size); otherwise it is found by seeking, for a file or a
    buffer, and left unknown for anything else."""
    max_ops = MAX_OPS if max_ops is None else max_ops
    max_pickles = MAX_PICKLES if max_pickles is None else max_pickles
    result = PickleResult()
    stream = _Guard(stream, size, deadline)
    while result.pickles < max_pickles:
        if not stream.peek():
            break
        memo = {}
        try:
            ended = _one_pickle(stream, result, memo, deadline, max_ops)
        except (ValueError, MemoryError, OverflowError, RecursionError, EOFError, KeyError, IndexError) as e:
            ended = False
            if stream.timed_out:
                result.stopped = result.stopped or "time limit"
            elif result.pickles == 0:
                result.trailing = "the pickle is damaged or cut short" if result.has_proto else f"not a pickle: {str(e)[:80]}"
            else:
                result.trailing = "data that is not a pickle follows the last pickle"
            break
        if not ended:
            if not result.stopped and not result.trailing:
                result.trailing = "the data ended before the pickle did" if result.pickles == 0 else "data that is not a pickle follows the last pickle"
            break
        result.pickles += 1
    else:
        result.stopped = result.stopped or "pickle count limit"
    return result


# ---- which imports are dangerous ----

RUN = "runs commands or code"
FILES = "reads or writes files"
NET = "reaches the network or opens a browser"
UNPICKLE = "loads another pickle or file that can run code"
BUILD = "builds code objects"
GADGET = "is a helper that attacks use to chain calls"
BUILTINS = ("builtins", "__builtin__", "__builtins__")

# One row per rule: (module, names, severity, why). names is "*" for everything in the module and its submodules, else the exact names. High runs
# commands or code, touches files or the network, or loads another pickle; medium is a helper that attacks chain calls with but that has ordinary
# uses too. Any row that is wrong is a bug in a security tool, so the whole list is tested name by name (tests/test_pickles.py).
RULES = (
    # commands, code and the interpreter
    ("os", "*", "high", RUN), ("posix", "*", "high", RUN), ("nt", "*", "high", RUN), ("subprocess", "*", "high", RUN), ("pty", "*", "high", RUN),
    ("popen2", "*", "high", RUN), ("commands", "*", "high", RUN), ("runpy", "*", "high", RUN), ("code", "*", "high", RUN), ("codeop", "*", "high", RUN),
    ("pdb", "*", "high", RUN), ("bdb", "*", "high", RUN), ("timeit", "*", "high", RUN), ("cProfile", "*", "high", RUN), ("profile", "*", "high", RUN),
    ("importlib", "*", "high", RUN), ("imp", "*", "high", RUN), ("zipimport", "*", "high", RUN), ("pkgutil", "*", "high", RUN), ("marshal", "*", "high", BUILD),
    ("ctypes", "*", "high", RUN), ("multiprocessing", "*", "high", RUN), ("asyncio", "*", "high", RUN), ("sys", "*", "high", RUN),
    ("platform", ("popen",), "high", RUN), ("types", ("FunctionType", "CodeType", "LambdaType", "MethodType", "ModuleType"), "high", BUILD),
    ("numpy.testing", "*", "high", RUN),
    # files
    ("shutil", "*", "high", FILES), ("tempfile", "*", "high", FILES), ("shelve", "*", "high", UNPICKLE),
    # the network and the browser
    ("socket", "*", "high", NET), ("ssl", "*", "high", NET), ("http", "*", "high", NET), ("httplib", "*", "high", NET), ("urllib", "*", "high", NET),
    ("urllib2", "*", "high", NET), ("urllib3", "*", "high", NET), ("requests", "*", "high", NET), ("aiohttp", "*", "high", NET), ("httpx", "*", "high", NET),
    ("ftplib", "*", "high", NET), ("smtplib", "*", "high", NET), ("telnetlib", "*", "high", NET), ("xmlrpc", "*", "high", NET), ("webbrowser", "*", "high", NET),
    ("paramiko", "*", "high", NET),
    # loading another pickle, or a file that is one
    ("pickle", "*", "high", UNPICKLE), ("_pickle", "*", "high", UNPICKLE), ("cPickle", "*", "high", UNPICKLE), ("dill", "*", "high", UNPICKLE),
    ("cloudpickle", "*", "high", UNPICKLE), ("joblib", ("load",), "high", UNPICKLE), ("numpy", ("load",), "high", UNPICKLE),
    ("numpy.lib.npyio", ("load",), "high", UNPICKLE), ("pandas", ("read_pickle",), "high", UNPICKLE), ("pandas.io.pickle", ("read_pickle",), "high", UNPICKLE),
    ("torch", ("load",), "high", UNPICKLE), ("torch.serialization", ("load",), "high", UNPICKLE), ("torch.jit", ("load",), "high", UNPICKLE),
    ("torch.hub", "*", "high", UNPICKLE), ("torch.utils.cpp_extension", "*", "high", RUN),
    # the built-in functions that run, open or build things
    *[(b, ("eval", "exec", "execfile", "compile", "__import__", "breakpoint", "apply", "reload"), "high", RUN) for b in BUILTINS],
    *[(b, ("open", "input"), "high", FILES) for b in BUILTINS],
    # helpers that are used to chain calls
    *[(b, ("getattr", "setattr", "delattr", "vars", "globals", "locals", "dir", "super", "type", "classmethod", "staticmethod", "property"), "medium", GADGET) for b in BUILTINS],
    ("operator", ("attrgetter", "methodcaller"), "medium", GADGET), ("functools", ("partial", "reduce", "partialmethod"), "medium", GADGET),
)
BY_TOP = {}
for _row in RULES:
    BY_TOP.setdefault(_row[0].split(".")[0], []).append(_row)


def classify(module, name):
    """(severity, why) when importing `module.name` is dangerous, else None. severity is "high" or "medium"; the worst matching rule wins."""
    best = None
    for rule_module, names, severity, why in BY_TOP.get(module.split(".")[0], ()):
        in_module = module == rule_module or (names == "*" and module.startswith(rule_module + "."))
        if in_module and (names == "*" or name in names) and (best is None or (severity == "high" and best[0] != "high")):
            best = (severity, why)
    return best


def classify_all(result):
    """The dangerous imports of a PickleResult, worst first: [{"module", "name", "severity", "why"}]. Unresolved imports are counted apart."""
    out = []
    for (module, name) in sorted(result.globals):
        verdict = classify(module, name)
        if verdict:
            out.append({"module": module, "name": name, "severity": verdict[0], "why": verdict[1]})
    out.sort(key=lambda d: (d["severity"] != "high", d["module"], d["name"]))
    return out
