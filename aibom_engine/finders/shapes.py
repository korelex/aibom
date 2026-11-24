"""Finder C: model names that no dictionary lists, found by their shape.
Five rules, each general:
  1. A constant whose name spells the string it holds:  GPT432K0314 = "gpt-4-32k-0314",  static let gpt4_o = "gpt-4o"
  2. A key that already holds known models in this file: every other value under that key is a candidate too
     ({ name: "gpt-4o" }, { name: "o1" } ...)
  3. A bare family name under a key whose name contains 'model':  model: 'llava'
  4. A string shaped like a model of a known family:  'llama3.1:8b', 'qwen2.5-coder', or a Bedrock id 'anthropic.claude-3-haiku-v1'
  5. The values of a Bicep @allowed([...]) list that belongs to a model parameter."""
import re
import time
from collections import Counter

from ..finding import Finding
from ..redact import quoted_line
from ..triage import read_lines
from .dictionary import load_names

SCAN = {"code", "config", "manifest", "notebook"}
# Model families we trust as a signal. Curated, and each must also be well covered by the dictionary (see families()).
ALLOW = {"gpt", "chatgpt", "claude", "gemini", "gemma", "llama", "codellama", "mistral", "mixtral", "ministral", "pixtral", "codestral", "devstral", "magistral",
         "qwen", "qwq", "deepseek", "grok", "kimi", "glm", "minimax", "phi", "command", "nova", "sonar", "jamba", "ernie", "granite", "hermes", "nemotron",
         "voxtral", "whisper", "tts", "dall", "embed", "rerank", "llava", "starcoder", "bge", "nomic", "cogito", "olmo", "dolphin", "internvl", "imagen", "veo",
         "sora", "flux", "gigachat", "davinci", "babbage", "curie", "ada", "titan", "gpt-oss", "zai"}
FIXED = {"gpt", "chatgpt", "davinci", "babbage", "curie", "whisper", "dall", "tts", "titan", "ada"}
O_SERIES = re.compile(r"^o\d{1,2}(?:-(?:mini|pro|preview|high|low|deep-research)|-\d{4}-\d{2}-\d{2}|-[a-z0-9.]+)*$")
TEXT_OLD = re.compile(r"^(?:text|code)-(?:davinci|curie|babbage|ada|embedding|moderation|search|similarity)[a-z0-9.-]*$")
BEDROCK = re.compile(r"^(?:(?:us|eu|apac|global)\.)?(?:anthropic|amazon|meta|mistral|cohere|ai21|deepseek|openai|writer|qwen)\.[a-z0-9][a-z0-9._-]*(?:-v\d+(?::\d+)?)$")
NOT_KEYS = {"id", "key", "type", "value", "label", "description", "title", "text", "content", "role", "string", "str", "int", "bool", "boolean", "number", "float", "object", "array", "var", "let", "const", "param", "any", "name_"}
STOP = {"default", "latest", "none", "model", "models", "auto", "test", "true", "false", "null", "undefined", "string", "input", "output", "base", "custom"}
Q = r"""["'`]"""
CONST = re.compile(r"""\b([A-Za-z_][A-Za-z0-9_]*)\s*(?::\s*[\w<>\[\].?]+\s*)?:?=\s*(""" + Q + r""")([A-Za-z0-9][A-Za-z0-9._:/@+-]{1,90})\2""")
PAIR = re.compile(r"""["']?([A-Za-z_][A-Za-z0-9_]*)["']?\s*[:=]\s*(""" + Q + r""")([A-Za-z0-9][A-Za-z0-9._:/@+-]{1,90})\2""")
LITERAL = re.compile(r"""(""" + Q + r""")([A-Za-z0-9][A-Za-z0-9._:/@+-]{2,90})\1""")
MODEL_KEY = re.compile(r"""(?i)\b([A-Za-z_.]*model[A-Za-z_]*)["']?\s*[:=]\s*(""" + Q + r""")([a-z][a-z0-9]{3,24})\2""")
IMPORT = re.compile(r"""^\s*(import\b|from\s+\S+\s+import\b|export\b.*\bfrom\b)|\brequire\(""")
VERSION_SHAPE = re.compile(r"""^([a-z]+)[-_]?(\d+(?:[._]\d+)*)([a-z]{0,2})((?:[-:@./][a-z0-9.]+)*)$""")


def squash(s):
    return re.sub(r"[^a-z0-9]", "", s.lower())


def families(names):
    c = Counter()
    for k in names:
        f = re.split(r"[-:./\d_]", k.split("/")[-1].lower())[0]
        if f:
            c[f] += 1
    return {f for f in ALLOW if c.get(f, 0) >= 3} | FIXED


def family_of(value, fams):
    """The family a string starts with, or '' when it does not look like a model name of a known family."""
    v = value.lower().split("/")[-1]
    v = re.sub(r"^(?:accounts/[a-z0-9_-]+/models/)", "", v)
    if O_SERIES.match(v) or v == "o1":
        return "o"
    if TEXT_OLD.match(v):
        return "text"
    m = re.match(r"^([a-z]+)", v)
    if not m:
        return ""
    w = m.group(1)
    if w in fams:
        return w
    # a leading word glued to a family (gpt4o, llama3): try the longest family prefix
    for f in sorted(fams, key=len, reverse=True):
        if v.startswith(f) and len(f) >= 3 and v[len(f):len(f) + 1].isdigit():
            return f
    return ""


def versioned(value, fams):
    """True for strings like 'llama3.1:8b', 'qwen2.5-coder', 'gemini-2.5-flash', 'claude-sonnet-4-0', 'o3-mini'."""
    v = value.lower().split("/")[-1]
    if O_SERIES.match(v) and re.search(r"\d", v):
        return True
    fam = family_of(v, fams)
    if not fam or fam == "text" and not TEXT_OLD.match(v):
        return False
    if fam in ("ada", "tts", "dall", "titan", "embed", "rerank", "flux", "veo", "sora", "olmo", "bge", "nomic") and not re.search(r"\d", v):
        return False
    return bool(re.search(r"\d", v)) and len(v) >= 4


def spells(identifier, value):
    """Does the constant's name spell the string?  GPT3Dot5TurboInstruct -> gpt-3.5-turbo-instruct, GPT3TextDavinci003 -> text-davinci-003."""
    a, b = squash(identifier), squash(value)
    if len(b) < 2:
        return False
    a2 = a.replace("dot", "").replace("point", "")
    return a == b or a2 == b or (len(b) >= 6 and (a.endswith(b) or a2.endswith(b)))


def run(root, files, names=None, deadline=None):
    names = names or load_names()
    fams = families(names)
    known = {k.lower() for k in names}
    found, seen = [], set()

    def add(name, fi, ln, line, col, note):
        key = (name.lower(), fi.path, ln)
        if key not in seen:
            seen.add(key)
            found.append(Finding("shapes", "model", name, fi.path, ln, note, fi.category, quoted_line(line, 200), col))

    for fi in files:
        if fi.category not in SCAN:
            continue
        if deadline and time.time() > deadline:
            break
        lines = read_lines(root, fi)
        low = fi.path.lower()
        # rule 2: learn which keys hold models in this file
        learned, total = Counter(), Counter()
        for line in lines:
            if len(line) > 400:
                continue
            for m in PAIR.finditer(line):
                v = m.group(3)
                total[m.group(1).lower()] += 1
                if v.lower() in known or versioned(v, fams):
                    learned[m.group(1).lower()] += 1
        keys = {k for k, c in learned.items() if c >= 2 and c / total[k] >= 0.5 and k not in NOT_KEYS}
        for i, line in enumerate(lines):
            ln = i + 1
            if len(line) > 600 or IMPORT.search(line):
                continue
            for m in CONST.finditer(line):  # rule 1
                ident, val = m.group(1), m.group(3)
                if val.lower() in STOP:
                    continue
                if spells(ident, val) and (family_of(val, fams) or O_SERIES.match(val.lower())) and re.search(r"\d", val) and not re.search(r"[\s]", val):
                    add(val, fi, ln, line, m.start(3), f"constant {ident}")
            for m in PAIR.finditer(line):  # rule 2
                k, v = m.group(1).lower(), m.group(3)
                if k in keys and v.lower() not in STOP and (versioned(v, fams) or family_of(v, fams)) and len(v) >= 2:
                    add(v, fi, ln, line, m.start(3), f"learned key {k}")
            for m in MODEL_KEY.finditer(line):  # rule 3
                v = m.group(3)
                if v in fams and v not in STOP and v not in ("gpt", "text", "embed", "rerank", "ada", "titan"):
                    add(v, fi, ln, line, m.start(3), f"family name under {m.group(1)}")
            for m in LITERAL.finditer(line):  # rule 4
                v = m.group(2)
                vl = v.lower()
                if BEDROCK.match(vl) or (re.match(r"^[a-z]+\d", vl) and versioned(v, fams) and VERSION_SHAPE.match(vl.split("/")[-1])):
                    if vl not in STOP:
                        add(v, fi, ln, line, m.start(2), "model-shaped string")
        if low.endswith((".bicep", ".bicepparam")):  # rule 5
            text = "\n".join(lines)
            for m in re.finditer(r"@allowed\(\s*\[([^\]]*)\]\s*\)\s*(?:@[^\n]*\n\s*)*param\s+(\w+)", text):
                if re.search(r"(?i)model", m.group(2)):
                    base = text[:m.start(1)].count("\n")
                    for q in re.finditer(r"'([A-Za-z0-9][A-Za-z0-9._:/-]{1,60})'", m.group(1)):
                        v = q.group(1)
                        if v.lower() in known or versioned(v, fams):
                            ln = base + m.group(1)[:q.start()].count("\n") + 1
                            add(v, fi, ln, lines[ln - 1] if ln - 1 < len(lines) else "", -1, f"allowed values of {m.group(2)}")
    return found
