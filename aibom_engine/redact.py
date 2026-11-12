"""Keep secrets out of the AI-BOM.

Every finding keeps the line of code that proves it. A line that names a model can also hold a key
(`OpenAI(api_key="sk-...", ...)` next to `model="gpt-4o"`), and that key must never be copied into aibom.cdx.json, the
JSON files or the reports. Anything that looks like a credential is replaced by asterisks of the same length, so the
position of the model name in the line stays right.

The patterns are deliberately few and specific: well-known key formats, and a quoted value assigned to a name such as
api_key, secret, token or password. This is a safety net for lines that happen to be quoted, not a secret scanner: finding
hardcoded secrets is a separate, later feature.
"""
import re

# (pattern, group to mask: 0 = the whole match)
PATTERNS = [(re.compile(p), g) for p, g in (
    (r"sk-[A-Za-z0-9_\-]{16,}", 0),                       # OpenAI, Anthropic (sk-ant-...) and look-alikes
    (r"AKIA[0-9A-Z]{16}", 0),                             # AWS access key id
    (r"gh[pousr]_[A-Za-z0-9]{30,}", 0),                   # GitHub tokens
    (r"github_pat_[A-Za-z0-9_]{30,}", 0),
    (r"xox[baprs]-[A-Za-z0-9\-]{10,}", 0),                # Slack
    (r"AIza[0-9A-Za-z_\-]{35}", 0),                       # Google API key
    (r"hf_[A-Za-z0-9]{30,}", 0),                          # Hugging Face
    (r"api_org_[A-Za-z]{30,}", 0),                        # Hugging Face organisation token
    (r"gsk_[A-Za-z0-9]{20,}", 0),                         # Groq
    (r"xai-[A-Za-z0-9]{20,}", 0),                         # xAI
    (r"pplx-[A-Za-z0-9]{20,}", 0),                        # Perplexity
    (r"r8_[A-Za-z0-9]{20,}", 0),                          # Replicate
    (r"ABSK[A-Za-z0-9+/]{40,}={0,2}", 0),                 # Amazon Bedrock API key
    (r"ASIA[0-9A-Z]{16}", 0),                             # AWS temporary access key id
    (r"(?<![A-Za-z0-9])eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}", 0),  # a JSON web token
    (r"(?i)(bearer\s+)([A-Za-z0-9._~+/\-]{20,}=*)", 2),   # Authorization: Bearer <token>
    (r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)", 0),
    # a quoted value given to a name that says it is a secret: api_key="...", "token": "...", password = '...'
    (r"""(?i)((?:key|secret|token|password|passwd|pwd)["']?\s*[:=]\s*["'])([^"'\s]{8,})(["'])""", 2),
    (r"(?i)(://[^/\s:@]{1,64}:)([^/\s@]{3,})(@)", 2),     # https://user:password@host
)]

# a placeholder is not a secret even when it sits where one would go
PLACEHOLDER = re.compile(r"^(?:your[-_ ]|<|\$|\{|xxx|\*{4,}|changeme|example|placeholder|dummy|none$|null$|true$|false$|test$)", re.I)


def _mask(match, group):
    if group == 0:
        value = match.group(0)
        return "*" * len(value) if not PLACEHOLDER.match(value) else value
    value = match.group(group)
    if PLACEHOLDER.match(value):
        return match.group(0)
    start, end = match.span(group)
    base = match.start()
    whole = match.group(0)
    return whole[: start - base] + "*" * len(value) + whole[end - base:]


def redact(text):
    """The line with credentials replaced by asterisks (same length). Text without any is returned unchanged."""
    if not text or len(text) < 8:
        return text
    for pattern, group in PATTERNS:
        text = pattern.sub(lambda m, g=group: _mask(m, g), text)
    return text
