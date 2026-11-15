"""Hardcoded AI provider API keys in a project's files (M3.3).

A key written into code is a leak: it is in the repository, in every clone and, once committed, in the history. This finds
them, says which provider's key it is and where, and never keeps the key: a finding holds the provider, the rule, the file,
the line and the length, nothing from the value itself.

Two ways a key is recognised, both chosen to keep false alarms rare (a false "key found" costs trust):

1. By its format. The providers below issue keys with a distinctive shape (`sk-ant-api03-...`, `AIza...`, `hf_...`). The formats
   were checked against each provider's own documentation where it exists (OpenRouter, Replicate), and otherwise against
   gitleaks' published rules (OpenAI, Anthropic, Hugging Face, Google, Perplexity, AWS and Amazon Bedrock); Groq and xAI
   are known by their prefix, with a length that is deliberately loose because neither documents one. A match must also
   have enough randomness (a minimum entropy) and not look like an example (repeated or counting characters, words such as
   `example` or `your`, an ellipsis).
2. By the name it is given. Mistral, Cohere and Azure OpenAI keys have no distinctive format, so a literal value is reported
   only when it is assigned to a variable or setting whose name says whose key it is (`MISTRAL_API_KEY = "..."`), the value
   is long and random enough, and it is not a placeholder, a path, a URL or a lookup such as `${KEY}` or `os.getenv(...)`.

Not covered: keys in git history (only the files on disk are read), keys with no distinctive format that are not given a
provider-named name, and keys split across lines or built from pieces.
"""
import bisect
import math
import os
import re
import time

from .flags import Flag
from .packages.common import left_out_reason
from .triage import MAX_BYTES

# (rule id, provider, regex, minimum entropy in bits per character). The patterns are wrapped so a match is a whole token.
FORMATS = (
    ("anthropic-api-key", "Anthropic", r"sk-ant-(?:api03|admin01)-[A-Za-z0-9_-]{80,}", 3.0),
    ("openai-project-key", "OpenAI", r"sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{40,}", 3.0),
    ("openai-key", "OpenAI", r"sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}", 3.0),
    ("openrouter-key", "OpenRouter", r"sk-or-v1-[a-f0-9]{64}", 3.0),
    ("huggingface-token", "Hugging Face", r"hf_[A-Za-z]{34}", 2.5),
    ("huggingface-org-token", "Hugging Face", r"api_org_[A-Za-z]{34}", 2.5),
    ("google-api-key", "Google", r"AIza[0-9A-Za-z_-]{35}", 3.0),
    ("groq-key", "Groq", r"gsk_[A-Za-z0-9]{40,}", 3.5),
    ("xai-key", "xAI", r"xai-[A-Za-z0-9]{40,}", 3.5),
    ("perplexity-key", "Perplexity", r"pplx-[A-Za-z0-9]{48}", 3.5),
    ("replicate-token", "Replicate", r"r8_[A-Za-z0-9]{37}", 3.5),
    ("aws-access-key", "AWS", r"(?:AKIA|ASIA)[A-Z2-7]{16}", 3.0),
    ("bedrock-api-key", "Amazon Bedrock", r"ABSK[A-Za-z0-9+/]{109,269}={0,2}", 3.5),
)
# Every format starts with one of these, so a file that holds none of them cannot hold a key by format. Checking this first is about ten times faster
# than running the pattern over every file (a test keeps this list in step with FORMATS).
PREFIXES = ("sk-", "AIza", "hf_", "api_org_", "gsk_", "xai-", "pplx-", "r8_", "AKIA", "ASIA", "ABSK")
RULES = {rule: (provider, min_entropy) for rule, provider, _, min_entropy in FORMATS}
FORMAT_RE = re.compile("(?<![A-Za-z0-9_])(?:" + "|".join(f"(?P<r{i}>{pattern})" for i, (_, _, pattern, _) in enumerate(FORMATS)) + ")(?![A-Za-z0-9])")

# Variable or setting names that say whose key a value is: OPENAI_API_KEY, mistralApiKey, "cohere_token", azure.openai.key
PROVIDER_WORDS = (("openai", "OpenAI"), ("anthropic", "Anthropic"), ("mistral", "Mistral"), ("cohere", "Cohere"), ("groq", "Groq"), ("gemini", "Google"),
                  ("google", "Google"), ("together", "Together"), ("replicate", "Replicate"), ("hugging", "Hugging Face"), ("huggingface", "Hugging Face"),
                  ("deepseek", "DeepSeek"), ("openrouter", "OpenRouter"), ("fireworks", "Fireworks"), ("perplexity", "Perplexity"), ("pplx", "Perplexity"),
                  ("voyage", "Voyage"), ("elevenlabs", "ElevenLabs"), ("eleven_labs", "ElevenLabs"), ("langsmith", "LangSmith"), ("langchain", "LangSmith"),
                  ("tavily", "Tavily"), ("pinecone", "Pinecone"), ("xai", "xAI"), ("grok", "xAI"), ("cerebras", "Cerebras"), ("nvidia", "NVIDIA"),
                  ("jina", "Jina"), ("stability", "Stability AI"), ("assemblyai", "AssemblyAI"), ("deepgram", "Deepgram"), ("sambanova", "SambaNova"))
NAME_ASSIGNMENT = re.compile(
    r"""(?<![A-Za-z0-9_.-])(?P<name>[A-Za-z][A-Za-z0-9_.-]{0,60}?(?:api[_-]?key|access[_-]?token|auth[_-]?token|secret[_-]?key|apikey|_token|_key|Key|Token))["']?\]?[ \t]*[:=][ \t]*"""
    r"""(?:["'](?P<quoted>[^"'\s]{20,})["']|(?P<bare>[A-Za-z0-9_+/=-]{20,})(?=\s|$|[,;#)]))""", re.I)
NAME_HINT = re.compile(r"key|token|secret", re.I)

PLACEHOLDER_WORDS = re.compile(r"\$\{|\$[A-Za-z_]|%[A-Za-z_]+%|\{\{|<[^>]*>|your[-_]|xxx|\*{3,}|\.{3,}|…|changeme|example|placeholder|dummy|sample|fake|redacted|replace|insert|"
                               r"notreal|not-real|todo|test[-_]?key|my[-_]|abc123|123456|secret[-_]?here|key[-_]?here", re.I)
NOT_A_SECRET = re.compile(r"^(?:true|false|null|none|\d+|https?://\S*|[./~\\].*|[A-Za-z]:[\\/].*)$", re.I)
ENV_NAME = re.compile(r"^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$")
LOOKUP = re.compile(r"(?:getenv|environ|process\.env|env\(|secrets?\.|config\.|settings\.|vault|keyring)", re.I)

MAX_FINDINGS = 500
MAX_PER_FILE = 25
SKIP_CATEGORIES = {"lock", "minified", "translation"}
EXAMPLE_SUFFIXES = (".example", ".sample", ".template", ".tmpl", ".dist", ".defaults")


def entropy(text):
    """Shannon entropy of a string in bits per character (a random base62 key is near 5.9, English text near 4, "aaaa" is 0)."""
    if not text:
        return 0.0
    counts = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(text)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def looks_fake(value):
    """True for values that are examples, not keys: repeated or counting characters, few distinct characters, or placeholder words."""
    body = re.sub(r"^[A-Za-z]+[-_]", "", value)
    if PLACEHOLDER_WORDS.search(value):
        return True
    if len(set(body)) <= 8 or re.search(r"(.)\1{7,}", body):
        return True
    for run in (("abcdefghijklmnopqrstuvwxyz", 9), ("ABCDEFGHIJKLMNOPQRSTUVWXYZ", 9)):  # (a run of digits holds "123456", a placeholder word above)
        alphabet, length = run
        if any(alphabet[i:i + length] in body for i in range(len(alphabet) - length + 1)):
            return True
    return False


def _provider_of(name):
    low = re.sub(r"[^a-z0-9]", "", name.lower())
    for word, provider in PROVIDER_WORDS:
        if word.replace("_", "") in low:
            return provider
    return ""


def _literal_key(value):
    """True when a value assigned to a provider-named setting is plausibly a real key rather than an example or a lookup."""
    v = value.strip()
    if len(v) < 20 or PLACEHOLDER_WORDS.search(v) or LOOKUP.search(v) or NOT_A_SECRET.match(v) or ENV_NAME.match(v) or looks_fake(v):
        return False
    return entropy(v) >= 3.5 and bool(re.search(r"\d", v)) and bool(re.search(r"[A-Za-z]", v))


def location_of(rel, category):
    """Where a file sits: "" for the product's own code and settings, else why it is not (test, docs, example, vendored, data)."""
    base = os.path.basename(rel.lower())
    reason = left_out_reason(rel)
    if reason:
        return reason
    if base.endswith(EXAMPLE_SUFFIXES) or ".example." in base or ".sample." in base:
        return "example"
    return category if category in ("test", "docs", "data") else ""


def _scan_text(text, rel, location):
    """The findings in one file's text: [{provider, rule, how, file, line, length, location}]."""
    found, starts = [], None

    def line_of(pos):
        nonlocal starts
        if starts is None:
            starts = [0] + [m.end() for m in re.finditer("\n", text)]
        return bisect.bisect_right(starts, pos)

    for m in (FORMAT_RE.finditer(text) if any(prefix in text for prefix in PREFIXES) else ()):
        rule = FORMATS[int(m.lastgroup[1:])][0]
        value = m.group(0)
        provider, min_entropy = RULES[rule]
        if entropy(value) < min_entropy or looks_fake(value):
            continue
        found.append({"provider": provider, "rule": rule, "how": "format", "file": rel, "line": line_of(m.start()), "length": len(value), "location": location})
    if NAME_HINT.search(text):
        for m in NAME_ASSIGNMENT.finditer(text):
            value = m.group("quoted") or m.group("bare")
            provider = _provider_of(m.group("name"))
            if not provider or not _literal_key(value):
                continue
            line = line_of(m.start())
            if any(f["file"] == rel and f["line"] == line for f in found):
                continue  # the same value was already found by its format
            found.append({"provider": provider, "rule": "named-key", "how": "name", "file": rel, "line": line, "length": len(value), "location": location})
    return found


def find(root, files, deadline=None):
    """The hardcoded provider keys in the files of `root` (`files` is the triage list): {"findings", "files_scanned", "problems", "partial", "truncated"}."""
    deadline = deadline or (time.time() + 120)
    findings, problems, scanned, partial, truncated = [], [], 0, False, False
    for fi in files:
        if fi.category in SKIP_CATEGORIES or fi.size > MAX_BYTES or fi.size == 0:
            continue
        if time.time() > deadline:
            partial = True
            break
        path = os.path.join(root, fi.path)
        try:
            if os.path.islink(path):
                continue
            with open(path, "rb") as fh:
                raw = fh.read(MAX_BYTES + 1)
        except OSError as e:
            problems.append({"file": fi.path, "error": str(e)[:200]})
            continue
        if b"\x00" in raw[:4096]:
            continue
        scanned += 1
        got = _scan_text(raw.decode("utf-8", errors="replace"), fi.path, location_of(fi.path, fi.category))
        if len(got) > MAX_PER_FILE:
            got, truncated = got[:MAX_PER_FILE], True  # one file full of keys must not bury the others
        findings += got
        if len(findings) >= MAX_FINDINGS:
            truncated = True  # stopped at the cap: there may be more
            break
    findings.sort(key=lambda f: (bool(f["location"]), f["file"], f["line"], f["rule"]))
    return {"findings": findings[:MAX_FINDINGS], "files_scanned": scanned, "problems": problems, "partial": partial, "truncated": truncated}


def summary(found):
    live = [f for f in found["findings"] if not f["location"]]
    return {"keys": len(live), "files": len({f["file"] for f in live}), "other": len(found["findings"]) - len(live), "scanned": found["files_scanned"]}


def credential_flags(findings, covered=()):
    """The risk flags for found keys. A key in the product's own code or settings is high when it has a provider's format, medium when it was
    recognised only by its name; in a test, example or documentation file it is low (such keys are usually samples, but one that is real is
    still a leak). `covered` holds the (file, line) places another flag already reports as a written credential (an MCP config file's
    mcp.plaintext-secret), so one key is not flagged twice; it is still counted and listed as a key."""
    covered = set(covered)
    out = []
    for f in findings:
        if (f["file"], f["line"]) in covered:
            continue
        live = not f["location"]
        severity = ("high" if f["how"] == "format" else "medium") if live else "low"
        where = "" if live else f" It is in a {f['location']} file, so it may be a sample."
        how = "its format" if f["how"] == "format" else "the name it is given"
        out.append(Flag("secret.api-key", severity, category="secret", title=f"A {f['provider']} API key is written in this file.", subject=f["provider"],
                        fix="Remove it, load it from an environment variable or a secrets manager, and rotate it: it stays in the git history.",
                        file=f["file"], line=f["line"], detail=f"Recognised by {how}; {f['length']} characters; the value is not stored.{where}"))
    return out
