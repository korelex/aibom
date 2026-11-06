"""Finder B: find model names that no dictionary knows, by looking at where a string sits.
A string is a model name candidate when it is
  1. the value of a key, variable or parameter whose name contains 'model' (model: "x", MODEL_ID = "x", "model_name": "x"),
  2. the first argument of a function or method whose name contains 'model' (.modelName("x"), withModel("x"), setModel("x")),
  3. written as provider:model or provider/model (init_chat_model("anthropic:claude-..."), "openai/gpt-4"),
  4. the argument of a known model-loading call (from_pretrained("org/name"), SentenceTransformer("x"), pipeline("task", "org/name")),
  5. the default value of an environment variable whose name contains MODEL,
  6. an unquoted value in a config file whose key contains 'model' (model: gpt-4o, chat-model.model-name=gpt-4o),
  7. a Bicep parameter whose name contains 'model' (param chatModelName string = 'gpt-4o')."""
import re
import time

from ..finding import Finding
from ..triage import read_lines

SCAN = {"code", "config", "manifest", "notebook"}
PROVIDERS = r"openai|anthropic|google[_-]?genai|google|azure[_-]?openai|azure|bedrock|ollama|groq|mistral(?:ai)?|cohere|huggingface|hf|together(?:_ai)?|fireworks(?:_ai)?|vertex[_-]?ai|xai|deepseek|perplexity|openrouter|baseten"
Q = r"""[\\]?["']"""
VALUE = r"""([A-Za-z0-9][A-Za-z0-9._:/@+-]{2,90})"""
SINKS = r"from_pretrained|SentenceTransformer|CrossEncoder|snapshot_download|hf_hub_download|init_chat_model|init_embeddings|AutoTokenizer|AutoModel\w*"
R_KEY = re.compile(r"""(?i)\b([A-Za-z_.]*model[A-Za-z_]*)["']?\s*[:=]\s*""" + Q + VALUE + Q)
R_CALL = re.compile(r"""(?i)\b([A-Za-z_]*model[A-Za-z_]*)\s*\(\s*""" + Q + VALUE + Q)
R_PROVIDER = re.compile(r"""(?i)""" + Q + r"(" + PROVIDERS + r")[:/]" + VALUE + Q)
R_SINK = re.compile(r"\b(" + SINKS + r")\s*\(\s*(?:[\w]+\s*=\s*)?" + Q + VALUE + Q)
R_PIPE = re.compile(r"""\bpipeline\s*\(\s*""" + Q + r"""[A-Za-z0-9_-]+""" + Q + r"""\s*,\s*(?:model\s*=\s*)?""" + Q + VALUE + Q)
R_ENV = re.compile(r"""(?i)(?:getenv|environ\.get)\s*\(\s*["'][A-Za-z0-9_]*MODEL[A-Za-z0-9_]*["']\s*,\s*""" + Q + VALUE + Q + r"""|process\.env\.[A-Za-z0-9_]*MODEL[A-Za-z0-9_]*\s*(?:\|\||\?\?)\s*""" + Q + VALUE + Q)
R_ENVLINE = re.compile(r"""^\s*[A-Z0-9_]*MODEL[A-Z0-9_]*\s*=\s*["']?""" + VALUE + r"""["']?\s*$""")
R_CFG = re.compile(r"""(?i)^\s*(?:-\s*)?([\w.\-]*model[\w.\-]*)\s*[:=]\s*["']?""" + VALUE + r"""["']?\s*(?:#.*)?$""")
R_BICEP = re.compile(r"""(?i)\bparam\s+\w*model\w*\s+\w+\s*=\s*'""" + VALUE + "'")
R_BEDROCK_ARN = re.compile(r"""arn:aws[a-z-]*:bedrock:[a-z0-9-]*:\d*:(?:foundation-model|inference-profile)/([A-Za-z0-9._:-]+)""")
R_VERTEX_PATH = re.compile(r"""projects/[^/"'\s]+/locations/[^/"'\s]+/publishers/([A-Za-z0-9_-]+)/models/([A-Za-z0-9._@-]+)""")
IMPORT = re.compile(r"""^\s*(import\b|from\s+\S+\s+import\b|export\b.*\bfrom\b)|\brequire\(""")
CALL_OPEN = re.compile(r"\b(" + SINKS + r"|pipeline)\s*\(\s*$")
CFG_EXT = (".yaml", ".yml", ".toml", ".properties", ".ini", ".cfg", ".conf", ".env", ".example", ".tfvars", ".bicepparam")
KEY_END = re.compile(r"(?i)model(s)?([-_.]?(name|id))?$")   # the key must end like this, so chat-model.timeout is not a model
STOP = {"model", "models", "default", "string", "number", "boolean", "object", "array", "none", "null", "true", "false", "text", "image", "audio",
        "chat", "user", "system", "assistant", "tool", "function", "latest", "auto", "custom", "local", "base", "large", "small", "medium", "name", "type"}
FILE_END = (".mjs", ".cjs", ".jsx", ".json", ".py", ".ts", ".tsx", ".js", ".png", ".jpg", ".md", ".txt", ".yaml", ".yml", ".toml", ".csv", ".html", ".css", ".svg", ".pdf", ".onnx.json")


def model_like(v):
    if v.lower() in STOP or len(v) < 4:
        return False
    if v.lower().endswith(FILE_END) or "://" in v or v.startswith(("/", ".", "@/", ":", "-")) or v.endswith(("/", ":", "-", ".")):
        return False
    if re.fullmatch(r"(?i)(" + PROVIDERS + r")", v.strip()):
        return False
    if not any(c.isalpha() for c in v):
        return False
    if "model" in v.lower() and not any(c.isdigit() for c in v):
        return False  # labels such as title-model or mock-model, not real model names
    return any(c.isdigit() for c in v) or any(c in v for c in "-:/")


def split_provider(v):
    """'anthropic:claude-x' -> ('claude-x', 'anthropic')"""
    m = re.match(r"(?i)^(" + PROVIDERS + r")[:/](.+)$", v)
    return (m.group(2), m.group(1).lower()) if m else (v, "")


def run(root, files, names=None, deadline=None):
    found, seen = [], set()
    for fi in files:
        if fi.category not in SCAN:
            continue
        if deadline and time.time() > deadline:
            break
        low = fi.path.lower()
        base = low.split("/")[-1]
        env_file = base.startswith(".env") or low.endswith((".env", ".example"))
        cfg_file = low.endswith(CFG_EXT) or env_file
        lines = read_lines(root, fi)
        for i, line in enumerate(lines):
            ln = i + 1
            if len(line) > 600 or IMPORT.search(line):
                continue
            hits = []
            for rx, why in ((R_KEY, "model-named key"), (R_CALL, "model-named call"), (R_PROVIDER, "provider:model string"), (R_SINK, "model-loading call"),
                            (R_PIPE, "model-loading call"), (R_ENV, "env default"), (R_BICEP, "bicep parameter"), (R_BEDROCK_ARN, "bedrock arn")):
                for m in rx.finditer(line):
                    if rx in (R_KEY, R_CALL) and not KEY_END.search(m.group(1)):
                        continue
                    hits.append((m.group(m.lastindex), why, ln, m.start(m.lastindex)))
            for m in R_VERTEX_PATH.finditer(line):
                hits.append((m.group(2), f"{m.group(1).lower()} | vertex model path", ln, m.start(2)))
            if CALL_OPEN.search(line):  # a call formatted over several lines: read the next few lines as one
                window = " ".join(x.strip() for x in lines[i:i + 4])
                for rx in (R_SINK, R_PIPE):
                    for m in rx.finditer(window):
                        value = m.group(m.lastindex)
                        at = next((j for j in range(i, min(i + 4, len(lines))) if value in lines[j]), i)
                        hits.append((value, "model-loading call", at + 1, lines[at].find(value)))
            if cfg_file:
                m = R_ENVLINE.match(line)
                if m:
                    hits.append((m.group(1), "config value", ln, m.start(1)))
                else:
                    m = R_CFG.match(line)
                    if m and KEY_END.search(m.group(1)):
                        hits.append((m.group(2), "config value", ln, m.start(2)))
            for raw, why, hit_ln, col in hits:
                if not model_like(raw):
                    continue
                name, prov = split_provider(raw)
                if not model_like(name):
                    continue
                key = (name, fi.path, hit_ln)
                if key in seen:
                    continue
                seen.add(key)
                found.append(Finding("context", "model", name, fi.path, hit_ln, (prov + " | " if prov else "") + why, fi.category, lines[hit_ln - 1].strip()[:140], col))
    return found
