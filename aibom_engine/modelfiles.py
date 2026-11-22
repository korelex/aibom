"""Model weight files in a project, and which of them can run code when they are loaded (M3.4).

Weights are saved in many formats. Some, such as safetensors and GGUF, hold only numbers. Others use Python's pickle, and a pickle can
call any function it names, so loading a model file from a source you do not trust can run that source's code. This finds the model
files in a project, works out from their CONTENT what each really is (an extension proves nothing: a pickle can be named model.safetensors),
reads the pickle ones with `aibom_engine.pickles` without ever loading them, and reports what each imports.

What is read:
  pickle files            .pkl .pickle .joblib .dill .ckpt .pt .pth, and .bin .dat .data when their content is a pickle or a zip
  PyTorch checkpoints     a zip with a data.pkl inside (the current format), and the older single-file one
  NumPy                   .npy and .npz, only when an array has the object type (that is a pickle inside)
  joblib                  pickles compressed with zlib, gzip, bzip2, xz or lzma; the raw NumPy arrays joblib stores inside a pickle are passed over by
                          the size their wrapper declares, so the opcodes after them are still read
  Keras                   .keras (zip) and .h5, for Lambda layers, which hold Python code
  safe formats            safetensors and GGUF (checked to be what they say), and ONNX (listed, not read)
Not read, and said so: TensorFlow SavedModel, TFLite, and files compressed in other ways.

Everything is bounded: file size, decompressed size, the number of zip entries, a compression ratio, and time. A file that could not be
read is reported as "not scanned" with the reason. Nothing here ever says a file is safe: "no dangerous import found" is not the same thing.
"""
import ast
import bz2
import gzip
import json
import lzma
import os
import re
import time
import zipfile
import zlib

from . import MAX_SECONDS
from . import pickles
from .credentials import location_of
from .flags import Flag
from .ids import slug

FIRM_PICKLE_EXT = {".pkl", ".pickle", ".joblib", ".dill", ".ckpt", ".pt", ".pth"}   # named like a pickle: unreadable content is reported
LOOSE_EXT = {".bin", ".dat", ".data"}                                              # named like anything: only content that is a pickle or a zip counts
SAFE_EXT = {".safetensors", ".gguf", ".onnx"}
OTHER_EXT = {".npy", ".npz", ".h5", ".hdf5", ".keras"}
EXTENSIONS = FIRM_PICKLE_EXT | LOOSE_EXT | SAFE_EXT | OTHER_EXT

MAX_FILE = 1_000_000_000          # a pickle file larger than this is not read
MAX_DECOMPRESSED = 512 * 1024 * 1024
MAX_ENTRIES = 100_000
MAX_MEMBER = 512 * 1024 * 1024
MAX_RATIO = 1000                  # a zip entry this many times larger than its compressed form is not read
MAX_HEADER = 100 * 1024 * 1024    # a safetensors header
MAX_FILES = 2000
PER_FILE_SECONDS = 60
HDF5_SEARCH = 256 * 1024 * 1024
CHUNK = 4 * 1024 * 1024

DESCRIBE = {"pickle": "a pickle", "zip": "a zip file", "numpy": "a NumPy file", "hdf5": "an HDF5 file", "gguf": "a GGUF file", "safetensors": "a safetensors file"}
# For a name that says "numbers only", the kinds of content that are something else.
_NOT_SAFETENSORS = {"zip", "pickle", "gzip", "bzip2", "xz", "lzma", "zlib", "zstd", "numpy", "hdf5", "gguf"}
MISLABELLED = {".safetensors": _NOT_SAFETENSORS, ".gguf": _NOT_SAFETENSORS - {"gguf"} | {"safetensors"},
               ".onnx": {"zip", "pickle", "gzip", "bzip2", "xz", "lzma", "zlib", "zstd", "numpy", "hdf5", "gguf", "safetensors"}}

ARCHIVE_NAMES = (".zip", ".tar", ".tgz", ".tar.gz", ".7z", ".rar", ".jar", ".whl")
FORMAT_NAME = {"pickle": "Python pickle", "pytorch-zip": "PyTorch checkpoint (zip)", "pytorch-legacy": "PyTorch checkpoint (single-file)", "joblib": "compressed pickle",
               "numpy-object": "NumPy array of objects (pickle)", "npz": "NumPy archive with object arrays", "keras-zip": "Keras model (zip)", "hdf5": "Keras model (HDF5)",
               "safetensors": "safetensors", "gguf": "GGUF", "onnx": "ONNX", "lfs": "Git LFS pointer", "": "unknown"}
PICKLE_BASED = {"pickle", "pytorch-zip", "pytorch-legacy", "joblib", "numpy-object", "npz"}
COMPRESSED = ("gzip", "bzip2", "xz", "lzma", "zlib")
LEGACY_TORCH_MAGIC = b"\x8a\x0a\x6c\xfc\x9c\x46\xf9\x20\x6a\xa8\x50\x19"   # the first pickle of an older PyTorch file: the number 0x1950a86a20f9469cfc6c


# ---- readers that keep a hostile file from using up memory or time ----

class _Capped:
    """A reader that stops at a total byte limit, so data that inflates enormously cannot fill the memory. `hit` says the limit cut something off."""

    def __init__(self, reader, limit):
        self._r = reader
        self._left = limit
        self.hit = False

    def read(self, n=-1):
        n = self._left if n is None or n < 0 else min(n, self._left)
        data = self._r.read(n)
        self._left -= len(data)
        if self._left <= 0 and not self.hit:
            self.hit = bool(self._r.read(1))
        return data

    def readline(self, size=-1):
        size = self._left if size is None or size < 0 else min(size, self._left)
        data = self._r.readline(size)
        self._left -= len(data)
        return data

    def tell(self):
        return 0

    def seek(self, *args):
        raise OSError("this reader cannot seek")


class _ZlibReader:
    """A reader over a zlib stream (the standard library has no file class for it). It inflates in pieces and never more than was asked for."""

    def __init__(self, fh):
        self._fh = fh
        self._d = zlib.decompressobj()
        self._buf = bytearray()
        self._eof = False

    def _fill(self, want):
        while not self._eof and len(self._buf) < want:
            chunk = self._d.unconsumed_tail or self._fh.read(1 << 20)
            if not chunk:
                self._eof = True
                break
            self._buf += self._d.decompress(chunk, max(want - len(self._buf), 1 << 16))
            if self._d.eof:
                self._eof = True

    def read(self, n=-1):
        self._fill((1 << 62) if n is None or n < 0 else n)
        n = len(self._buf) if n is None or n < 0 else n
        out = bytes(self._buf[:n])
        del self._buf[:n]
        return out

    def readline(self, size=-1):
        limit = (1 << 20) if size is None or size < 0 else size
        while b"\n" not in self._buf and len(self._buf) < limit and not self._eof:
            self._fill(len(self._buf) + (1 << 16))
        i = self._buf.find(b"\n")
        n = min(i + 1 if i >= 0 else len(self._buf), limit)
        out = bytes(self._buf[:n])
        del self._buf[:n]
        return out

    def tell(self):
        return 0

    def seek(self, *args):
        raise OSError("this reader cannot seek")


# ---- what a file is ----

def sniff(head, size):
    """What a file is, from its first bytes: zip, numpy, hdf5, gguf, pickle (protocol 2 and up), safetensors, lfs, a compressed stream, or "" when unknown."""
    if head.startswith((b"version https://git-lfs.github.com/spec", b"version https://hawser.github.com/spec")):
        return "lfs"
    if head[:4] in (b"PK\x03\x04", b"PK\x05\x06"):
        return "zip"
    if head[:6] == b"\x93NUMPY":
        return "numpy"
    if head[:8] == b"\x89HDF\r\n\x1a\n":
        return "hdf5"
    if head[:4] == b"GGUF":
        return "gguf"
    if len(head) >= 2 and head[0] == 0x80 and 2 <= head[1] <= 5:
        return "pickle"
    if head[:2] == b"\x1f\x8b":
        return "gzip"
    if head[:3] == b"BZh":
        return "bzip2"
    if head[:6] == b"\xfd7zXZ\x00":
        return "xz"
    if head[:4] == b"\x28\xb5\x2f\xfd":
        return "zstd"
    if len(head) >= 13 and head[0] == 0x5d and head[5:13] == b"\xff" * 8:   # the older ".lzma" header, with the length left unknown (what joblib writes)
        return "lzma"
    if head[:2] in (b"\x78\x01", b"\x78\x5e", b"\x78\x9c", b"\x78\xda"):     # the four headers zlib writes with its usual window size
        return "zlib"
    if len(head) >= 9 and size >= 10 and head[8:9] == b"{":
        n = int.from_bytes(head[:8], "little")
        if 2 <= n <= MAX_HEADER and n + 8 <= size:
            return "safetensors"
    return ""


def _has_object_type(descr):
    """True when a NumPy dtype description (a string, or a list of fields that may nest) has the object type."""
    if isinstance(descr, str):
        return descr.lstrip("|<>=") == "O"
    if isinstance(descr, (list, tuple)):
        return any(_has_object_type(item[1] if isinstance(item, (list, tuple)) and len(item) >= 2 else item) for item in descr)
    return False


def read_npy_header(fh):
    """The dtype description from a .npy file's header, leaving the file just after the header. Raises ValueError. The header is a Python dict
    literal and is read with literal_eval only."""
    magic = fh.read(8)
    if len(magic) < 8 or magic[:6] != b"\x93NUMPY":
        raise ValueError("not a NumPy file")
    major = magic[6]
    if major == 1:
        length = int.from_bytes(fh.read(2), "little")
    elif major in (2, 3):
        length = int.from_bytes(fh.read(4), "little")
    else:
        raise ValueError(f"NumPy format version {major} is not known")
    if not 0 < length <= 10_000:
        raise ValueError("the NumPy header has an unreasonable length")
    raw = fh.read(length)
    if len(raw) != length:
        raise ValueError("the NumPy header is cut short")
    try:
        header = ast.literal_eval(raw.decode("latin1").strip())      # only the dtype is used, and latin-1 never fails to decode
    except (ValueError, SyntaxError, MemoryError, RecursionError, UnicodeDecodeError) as e:
        raise ValueError(f"the NumPy header cannot be read ({type(e).__name__})")
    if not isinstance(header, dict) or "descr" not in header:
        raise ValueError("the NumPy header has no dtype")
    return header["descr"]


def find_lambda(obj, depth=0):
    """True when a Keras config (parsed JSON) holds a Lambda layer, which stores Python code."""
    if depth > 200:
        return False
    if isinstance(obj, dict):
        if obj.get("class_name") in ("Lambda", "TFOpLambda", "__lambda__"):
            return True
        return any(find_lambda(v, depth + 1) for v in obj.values())
    if isinstance(obj, list):
        return any(find_lambda(v, depth + 1) for v in obj)
    return False


LAMBDA_IN_BYTES = re.compile(rb'"class_name"\s*:\s*"(?:Lambda|TFOpLambda)"')


# ---- one file ----

def new_record(rel, size, location):
    return {"file": rel, "size": size, "extension": os.path.splitext(rel.lower())[1], "serialization": "", "format": "", "pickle_based": False, "status": "",
            "reason": "", "dangerous": [], "unresolved": 0, "pickles": 0, "notes": [], "mislabelled": "", "lambda_layer": False, "location": location}


def _is(rec, serialization):
    rec["serialization"] = serialization
    rec["format"] = FORMAT_NAME[serialization]
    rec["pickle_based"] = serialization in PICKLE_BASED
    return rec


def _add_result(rec, result, blocked):
    """Fold one pickle scan into a record: the dangerous imports (no repeats), the counts, and why reading was cut short if it was."""
    seen = {(d["module"], d["name"]) for d in rec["dangerous"]}
    rec["dangerous"] += [d for d in pickles.classify_all(result) if (d["module"], d["name"]) not in seen]
    rec["dangerous"].sort(key=lambda d: (d["severity"] != "high", d["module"], d["name"]))
    rec["unresolved"] += result.unresolved
    rec["pickles"] += result.pickles
    if result.stopped:
        blocked.append(f"only part of it was read ({result.stopped})")
    elif result.pickles == 0:
        blocked.append(result.trailing or "no pickle could be read")
    elif result.trailing and rec["serialization"] != "pytorch-legacy":
        if result.trailing not in rec["notes"]:
            rec["notes"].append(result.trailing)


def _conclude(rec, blocked):
    """The status of a pickle-based record: scanned, partly scanned (something was read and something was not), or not scanned."""
    if blocked and rec["pickles"] == 0:
        rec["status"], rec["reason"] = "not-scanned", blocked[0]
    elif blocked:
        rec["status"], rec["reason"] = "partly-scanned", blocked[0]
    else:
        rec["status"] = "scanned"
    return rec


def _scan_zip(rec, path, ext, deadline):
    """A zip: PyTorch's current format keeps its pickle in data.pkl; a .npz holds .npy arrays; a .keras file holds config.json. Entries are read
    one at a time from the archive and nothing is extracted to disk."""
    try:
        zf = zipfile.ZipFile(path)
    except (zipfile.BadZipFile, OSError, NotImplementedError, ValueError) as e:
        _is(rec, "pytorch-zip" if ext in (".pt", ".pth", ".bin", ".ckpt") else "pickle")
        rec["status"], rec["reason"] = "not-scanned", f"the zip could not be opened ({str(e)[:60]})"
        return rec
    blocked = []
    with zf:
        infos = zf.infolist()
        if len(infos) > MAX_ENTRIES:
            _is(rec, "pickle")
            rec["status"], rec["reason"] = "not-scanned", f"the zip has more than {MAX_ENTRIES} entries"
            return rec
        names = [i.filename for i in infos]
        bases = {os.path.basename(n) for n in names}
        keras = "config.json" in names and bool(bases & {"metadata.json", "model.weights.h5"})
        pkl = [i for i in infos if not i.is_dir() and i.filename.lower().endswith((".pkl", ".pickle"))]
        npy = [i for i in infos if not i.is_dir() and i.filename.lower().endswith(".npy")]
        if keras:
            _is(rec, "keras-zip")
        elif ext == ".npz":
            _is(rec, "npz")
        else:
            _is(rec, "pytorch-zip" if "data.pkl" in bases else "pickle")
        if any(i.flag_bits & 0x1 for i in infos):          # an encrypted entry hides what it holds, and a real checkpoint is never encrypted
            blocked.append("an entry is encrypted, so it cannot be read")
        nested = [n for n in names if n.lower().endswith(ARCHIVE_NAMES)]
        if nested:
            blocked.append(f"it holds another archive ({nested[0]}), which is not read")
        total = 0
        for info in pkl + (npy if rec["serialization"] == "npz" else []):
            if time.time() > deadline:
                blocked.append("the time limit was reached")
                break
            if info.flag_bits & 0x1:
                continue                                       # already reported above
            if info.file_size > MAX_MEMBER or total + info.file_size > 2 * MAX_MEMBER:
                blocked.append("an entry is larger than the size limit")
                continue
            if info.file_size > 1_000_000 and info.compress_size and info.file_size / info.compress_size > MAX_RATIO:
                blocked.append("an entry is compressed far more than data normally is, which can be a zip bomb")
                continue
            total += info.file_size
            try:
                with zf.open(info) as member:
                    if info.filename.lower().endswith(".npy"):
                        if not _has_object_type(read_npy_header(member)):
                            continue
                    _add_result(rec, pickles.scan(member, deadline=deadline, size=info.file_size), blocked)
            except (zipfile.BadZipFile, OSError, ValueError, RuntimeError, EOFError, NotImplementedError) as e:
                blocked.append(f"an entry could not be read ({str(e)[:60]})")
        if keras:
            _keras_config(rec, zf, blocked)
        elif not pkl and not (rec["serialization"] == "npz" and npy):
            blocked.append("the zip has no pickle in it that could be read")
    if keras and not blocked:
        rec["status"] = "scanned"
        return rec
    if rec["serialization"] == "npz" and not rec["pickles"] and not rec["dangerous"] and not blocked:
        return None                                    # an archive of ordinary arrays is data, not a model file
    return _conclude(rec, blocked) if (rec["pickles"] or blocked or keras) else _conclude(rec, ["no pickle could be read"])


def _keras_config(rec, zf, blocked):
    try:
        info = zf.getinfo("config.json")
        if info.file_size > 50 * 1024 * 1024:
            blocked.append("config.json is larger than 50 MB and was not read for Lambda layers")
            return
        with zf.open(info) as fh:
            config = json.loads(fh.read(info.file_size + 1))
    except (OSError, ValueError, KeyError, RuntimeError):
        blocked.append("config.json could not be read for Lambda layers")
        return
    rec["lambda_layer"] = find_lambda(config)


def _scan_compressed(rec, path, kind, deadline):
    """A pickle compressed with zlib, gzip, bzip2 or xz (joblib does this). It is inflated in pieces, up to a size limit."""
    _is(rec, "joblib")
    blocked = []
    try:
        with open(path, "rb") as fh:
            reader = {"gzip": lambda: gzip.GzipFile(fileobj=fh), "bzip2": lambda: bz2.BZ2File(fh), "xz": lambda: lzma.LZMAFile(fh), "lzma": lambda: lzma.LZMAFile(fh, format=lzma.FORMAT_ALONE), "zlib": lambda: _ZlibReader(fh)}[kind]()
            capped = _Capped(reader, MAX_DECOMPRESSED)
            result = pickles.scan(capped, deadline=deadline)
    except (OSError, EOFError, zlib.error, lzma.LZMAError, ValueError) as e:
        rec["status"], rec["reason"] = "not-scanned", f"the {kind} data could not be read ({str(e)[:60]})"
        return rec
    if result.ops == 0 and not result.stopped:
        # Its very first byte is not a pickle opcode (no opcode at all was read), so loading it fails before anything can run: it is not called a pickle.
        rec["format"], rec["pickle_based"] = f"{kind} data that is not a pickle", False
        rec["status"], rec["reason"] = "not-scanned", "once decompressed it is not a pickle, so loading it fails before anything runs"
        return rec
    _add_result(rec, result, blocked)
    if capped.hit:
        blocked.insert(0, "it inflates to more than the size limit, so only the start was read")
    return _conclude(rec, blocked)


def _scan_hdf5(rec, path, deadline):
    """Keras's older HDF5 files keep the model description as plain JSON text, where a Lambda layer shows up. Returns True for a Keras file."""
    _is(rec, "hdf5")
    keras = False
    try:
        with open(path, "rb") as fh:
            tail, read = b"", 0
            while read < min(rec["size"], HDF5_SEARCH) and time.time() < deadline:
                chunk = fh.read(CHUNK)
                if not chunk:
                    break
                read += len(chunk)
                window = tail + chunk
                keras = keras or b"model_config" in window or b"keras_version" in window
                if LAMBDA_IN_BYTES.search(window):
                    rec["lambda_layer"] = True
                tail = window[-64:]
    except OSError as e:
        rec["status"], rec["reason"] = "not-scanned", f"the file could not be read ({str(e)[:60]})"
        return True
    if rec["size"] > HDF5_SEARCH:
        rec["status"], rec["reason"] = "partly-scanned", f"only the first {HDF5_SEARCH // 2 ** 20} MB was searched for Lambda layers"
    else:
        rec["status"] = "scanned"
    return keras or rec["lambda_layer"]


def _scan_numpy(rec, path, size, deadline):
    try:
        with open(path, "rb") as fh:
            if not _has_object_type(read_npy_header(fh)):
                return None                            # an ordinary array of numbers is data, not a model file
            _is(rec, "numpy-object")
            blocked = []
            _add_result(rec, pickles.scan(fh, deadline=deadline, size=size), blocked)
            return _conclude(rec, blocked)
    except (OSError, ValueError) as e:
        _is(rec, "numpy-object")
        rec["status"], rec["reason"] = "not-scanned", str(e)[:100]
        return rec


def _scan_pickle(rec, path, size, head, deadline):
    _is(rec, "pytorch-legacy" if head[:2] == b"\x80\x02" and LEGACY_TORCH_MAGIC in head[:40] else "pickle")
    if size > MAX_FILE:
        rec["status"], rec["reason"] = "not-scanned", f"it is larger than {MAX_FILE // 10 ** 9} GB, the most that is read"
        return rec
    blocked = []
    try:
        with open(path, "rb") as fh:
            _add_result(rec, pickles.scan(fh, deadline=deadline, size=size), blocked)
    except OSError as e:
        rec["status"], rec["reason"] = "not-scanned", f"the file could not be read ({str(e)[:60]})"
        return rec
    return _conclude(rec, blocked)


def _check_safetensors(rec, path):
    _is(rec, "safetensors")
    try:
        with open(path, "rb") as fh:
            n = int.from_bytes(fh.read(8), "little")
            header = json.loads(fh.read(n))
        if not isinstance(header, dict):
            raise ValueError("the header is not an object")
        rec["status"] = "safe-format"
    except (OSError, ValueError):
        rec["status"], rec["reason"] = "not-scanned", "the safetensors header could not be read"
    return rec


def analyse(path, rel, size, location="", deadline=None):
    """One candidate file: a record of what it is and what was found, or None when it is not a model file."""
    now = time.time()
    deadline = min(deadline or now + PER_FILE_SECONDS, now + PER_FILE_SECONDS)
    rec = new_record(rel, size, location)
    ext = rec["extension"]
    try:
        with open(path, "rb") as fh:
            head = fh.read(512)
    except OSError as e:
        _is(rec, "")
        rec["status"], rec["reason"] = "not-scanned", f"the file could not be read ({str(e)[:60]})"
        return rec
    if size == 0:
        return None
    kind = sniff(head, size)
    # what the name promises against what the content is: a name that says "numbers only" on something that is not
    if kind in MISLABELLED.get(ext, ()):
        rec["mislabelled"] = f"named {ext} but the content is {DESCRIBE.get(kind, kind + ' data')}"
    out = _read_as(rec, path, size, ext, head, kind, deadline)
    if out is None and rec["mislabelled"]:           # harmless content under a misleading name is still worth saying
        _is(rec, "")
        rec["status"], rec["reason"] = "not-scanned", rec["mislabelled"]
        return rec
    return out


def _read_as(rec, path, size, ext, head, kind, deadline):
    """Read a file according to what its content is. Returns the record, or None when it is not a model file."""
    if kind == "lfs":
        _is(rec, "lfs")
        rec["status"], rec["reason"] = "not-scanned", "it is a Git LFS pointer: the real file is not in this checkout"
        return rec
    if kind == "safetensors":
        return _check_safetensors(rec, path)
    if kind == "gguf":
        _is(rec, "gguf")
        rec["status"] = "safe-format"
        return rec
    if ext == ".onnx" and kind == "":
        _is(rec, "onnx")
        rec["status"] = "safe-format"
        rec["notes"].append("ONNX files are listed but not read: they can point at external data files and custom operators")
        return rec
    if kind == "numpy":
        return _scan_numpy(rec, path, size, deadline)
    if kind == "hdf5":
        return rec if _scan_hdf5(rec, path, deadline) else None
    if kind == "zip":
        out = _scan_zip(rec, path, ext, deadline)
        if out and ext in LOOSE_EXT and out["status"] == "not-scanned" and not out["pickles"] and out["reason"].startswith("the zip has no pickle"):
            return None                                # a .bin, .dat or .data that is some other zip: just a file
        return out
    if kind in COMPRESSED:
        if ext not in FIRM_PICKLE_EXT | LOOSE_EXT:
            return None
        out = _scan_compressed(rec, path, kind, deadline)
        if ext in LOOSE_EXT and out["status"] == "not-scanned" and not out["pickles"] and (not out["pickle_based"] or out["reason"].startswith("not a pickle")):
            return None                                # a .bin, .dat or .data holding some other compressed data: just a file
        return out
    if kind == "zstd":
        if ext in FIRM_PICKLE_EXT:
            _is(rec, "joblib")
            rec["status"], rec["reason"] = "not-scanned", "it is compressed with zstd, which is not read"
            return rec
        return None
    if kind == "pickle" and ext in FIRM_PICKLE_EXT | LOOSE_EXT | SAFE_EXT:
        return _scan_pickle(rec, path, size, head, deadline)
    if ext in FIRM_PICKLE_EXT:                         # named like a pickle with no protocol-2 marker: an old protocol, or not a pickle at all
        return _scan_pickle(rec, path, size, head, deadline)
    if ext in (".safetensors", ".gguf"):               # a safe name on content that is neither that nor anything else this knows
        _is(rec, ext[1:])
        rec["status"], rec["reason"] = "not-scanned", f"the content is not a valid {ext[1:]} file"
        return rec
    return None


def find(root, files, deadline=None):
    """Every model file under `root` (`files` is the triage list): {"files", "problems", "partial", "truncated"}."""
    deadline = deadline or (time.time() + MAX_SECONDS)
    out, problems, partial, truncated = [], [], False, False
    for fi in files:
        if os.path.splitext(fi.path.lower())[1] not in EXTENSIONS:
            continue
        if time.time() > deadline:
            partial = True
            break
        path = os.path.join(root, fi.path)
        if os.path.islink(path):
            continue
        try:
            rec = analyse(path, fi.path, fi.size, location_of(fi.path, fi.category), deadline)
        except Exception as e:  # one odd file must never stop the rest
            problems.append({"file": fi.path, "error": f"{type(e).__name__}: {str(e)[:120]}"})
            continue
        if rec is None:
            continue
        out.append(rec)
        if len(out) >= MAX_FILES:
            truncated = True
            break
    out.sort(key=lambda r: (bool(r["location"]), r["file"]))
    return {"files": out, "problems": problems, "partial": partial, "truncated": truncated}


def summary(found):
    live = [r for r in found["files"] if not r["location"]]
    return {"files": len(live), "pickle": sum(1 for r in live if r["pickle_based"]),
            "dangerous": sum(1 for r in live if r["dangerous"] or r["unresolved"] or r["mislabelled"] or r["lambda_layer"]),
            "not_scanned": sum(1 for r in live if r["status"] in ("not-scanned", "partly-scanned")), "safe": sum(1 for r in live if r["status"] == "safe-format"),
            "other": len(found["files"]) - len(live)}


def component_ref(rec):
    return "modelfile:" + slug(rec["file"])


# A reason that suggests the file may be hiding something, or that the scan was cut short, as against one that is only "nothing to read".
WORRYING = ("encrypted", "another archive", "zip bomb", "inflates", "size limit", "time limit", "limit)", "entries", "only part", "only the first")
CAN_RUN_CODE = "It uses pickle, which can run code when the file is loaded."


def _worst(rec):
    return "high" if any(d["severity"] == "high" for d in rec["dangerous"]) else "medium"


def model_file_flags(files):
    """The risk flags for the model files of a scan. A file in the product's own folders is flagged at full strength, a test or example at one step lower,
    and only the product's own files are flagged for what could not be scanned."""
    out = []
    for r in files:
        live = not r["location"]
        base = {"category": "model-file", "subject": r["file"], "file": r["file"], "line": 0, "ref": component_ref(r) if live else ""}
        step = (lambda severity: severity) if live else (lambda severity: {"high": "medium", "medium": "low", "low": "info", "info": "info"}[severity])
        place = "" if live else f" It is in a {r['location']} file."
        if r["dangerous"]:
            names = [f"{d['module']}.{d['name']} ({d['why']})" for d in r["dangerous"]]
            shown = "; ".join(names[:4]) + (f"; and {len(names) - 4} more" if len(names) > 4 else "")
            out.append(Flag("model-file.dangerous-call", step(_worst(r)), title="This model file imports code that can run commands, reach the network or chain attacks.",
                            fix="Do not load it. Get the model again from a source you trust, or convert it to safetensors.",
                            detail=f"It imports {shown}. The file was only read, never loaded.{place}", **base))
        if r["unresolved"]:
            out.append(Flag("model-file.unresolved-import", step("medium"), title="This model file imports code that could not be identified.",
                            fix="Do not load it unless you trust where it came from.",
                            detail=f"{r['unresolved']} import(s) could not be worked out, which is unusual: a file built to hide what it imports looks like this.{place}", **base))
        if r["mislabelled"]:
            out.append(Flag("model-file.mislabelled", step("high"), title="The name of this model file says it holds only numbers, but its content is something else.",
                            fix="Do not load it. Find out where it came from.", detail=f"It is {r['mislabelled']}.{place}", **base))
        if r["pickle_based"] and not r["dangerous"] and not r["unresolved"]:
            checked = "The scan found no dangerous import in it, which does not make loading it safe." if r["status"] == "scanned" else "It could not be fully scanned."
            out.append(Flag("model-file.pickle-format", step("medium"), title=f"This model file is a {r['format']}: loading it can run code.",
                            fix="Use safetensors, or load it only from a source you trust.", detail=f"{CAN_RUN_CODE} {checked}{place}", **base))
        if r["lambda_layer"]:
            safe = " Keras refuses to load it unless safe_mode is turned off." if r["serialization"] == "keras-zip" else ""
            out.append(Flag("model-file.keras-lambda", step("medium"), title="This Keras model has a Lambda layer, which holds Python code.",
                            fix="Rebuild the model without Lambda layers, or load it only from a source you trust.",
                            detail=f"A Lambda layer stores Python code that can run when the model is loaded.{safe}{place}", **base))
        if live and r["status"] in ("not-scanned", "partly-scanned") and r["reason"] and not r["mislabelled"]:
            worrying = r["status"] == "partly-scanned" or any(w in r["reason"] for w in WORRYING)
            out.append(Flag("model-file.not-scanned", "low" if worrying else "info", title="This model file could not be fully scanned.",
                            fix="Check it by other means before loading it." if worrying else "Nothing to do unless you load it from an untrusted source.",
                            detail=f"{r['reason'][:1].upper()}{r['reason'][1:]}. A file that was not scanned is not a file that was found safe.", **base))
    return out
