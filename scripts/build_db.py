"""Automated compiler for aibom_engine/knowledge/ai_db.json (and aibom_engine/knowledge/model_names.json).

Combines 4 live sources + our curated overlay:
  1. aibom_engine/knowledge/curated.json (licenses, AI package catalog, curated models & deprecations)
  2. LiteLLM model_prices_and_context_window.json (4,700+ models, deprecation_date, regions, limits, costs, capabilities)
  3. OpenRouter /api/v1/models (canonical_slug, hugging_face_id, modalities, cutoff/expiration dates)
  4. OSV.dev ecosystem dumps (every advisory for every AI package and family, with its affected ranges; scripts/osv_data.py)

Usage:
  python scripts/build_db.py              # full live build from all upstream sources
  python scripts/build_db.py --offline    # build from local aibom_engine/knowledge/model_names.json + curated.json only
  python scripts/build_db.py --reformat   # rewrite ai_db.json and curated.json in their one-entry-per-line layout (no network)
  python scripts/build_db.py --apply-curated  # re-apply curated.json on the existing ai_db.json (no network, minimal diff)
  python scripts/build_db.py --osv-only   # refresh only the advisories from OSV, keep everything else as it is
"""
from __future__ import annotations

import concurrent.futures
import hashlib
import json
import os
import re
import sys
import time
import urllib.request

import osv_data  # noqa: E402  (scripts/osv_data.py)

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from aibom_engine.vendors import maker_of, type_of  # noqa: E402

LITELLM_URL = "https://raw.githubusercontent.com/BerriAI/litellm/main/model_prices_and_context_window.json"
OPENROUTER_URL = "https://openrouter.ai/api/v1/models"
OSV_CACHE = os.path.join(ROOT, "build", "osv")  # the ecosystem dumps, reused for 20 hours (build/ is git-ignored)

KNOWLEDGE_DIR = os.path.join(ROOT, "aibom_engine", "knowledge")
CURATED_PATH = os.path.join(KNOWLEDGE_DIR, "curated.json")
MODEL_NAMES_PATH = os.path.join(KNOWLEDGE_DIR, "model_names.json")
AI_DB_PATH = os.path.join(KNOWLEDGE_DIR, "ai_db.json")

PINNED_RE = re.compile(
    r"(?:"
    r"-\d{4}-\d{2}-\d{2}"          # -2024-08-06
    r"|-(?:20\d{6})"               # -20250929
    r"|-(?:0\d{3}|1\d{3})"         # -0613, -0125, -1106
    r"|-(?:00\d)"                  # -001, -002 (Google revisions)
    r"|@\d{8}"                     # @20250929 (Vertex AI)
    r"|-v\d+:\d+"                  # -v1:0 (AWS Bedrock)
    r"|:[0-9a-f]{12,64}"           # digest
    r")$",
    re.IGNORECASE,
)
BEDROCK_PREFIX_RE = re.compile(
    r"^(?:(us|eu|apac|global)\.)?(anthropic|amazon|meta|mistral|cohere|ai21|deepseek|openai|writer|qwen)\.(.+)$",
    re.IGNORECASE,
)
DATE_TAIL_RE = re.compile(
    r"^(.*?)(?:-(20\d{2}-\d{2}-\d{2}|20\d{6}|0\d{3}|1\d{3})|@(20\d{6})|-v\d+:\d+|-latest)$",
    re.IGNORECASE,
)
BACKTICK_SYM_RE = re.compile(r"`([A-Za-z_][A-Za-z0-9_.]{2,60})`")
STOP_SYMBOLS = {
    "true", "false", "none", "null", "self", "cls", "str", "int", "float", "dict", "list",
    "python", "javascript", "typescript", "json", "yaml", "http", "https", "bash", "pip", "npm",
}


def usable(n: str) -> bool:
    """Drop very generic words: need 5+ characters and a digit or a hyphen."""
    return len(n) >= 5 and (any(c.isdigit() for c in n) or "-" in n)


def is_pinned_reference(raw_name: str) -> bool:
    """Return True when raw_name pins a specific snapshot/date/revision rather than a floating alias."""
    low = raw_name.strip().lower()
    if low.endswith("-latest") or low.endswith(":latest"):
        return False
    return bool(PINNED_RE.search(low))


def normalize_family_slug(raw_name: str) -> tuple[str, str, str, str]:
    """Return (canonical_model_name, provider_route, region, snapshot_version) from a raw model string."""
    s = raw_name.strip()
    region = ""
    provider_route = ""
    # Strip size prefixes like 1024-x-1024/50-steps/bedrock/...
    if "/" in s and re.match(r"^\d+-x-\d+/", s):
        s = s.split("/")[-1]
    m_br = BEDROCK_PREFIX_RE.match(s)
    if m_br:
        region = (m_br.group(1) or "").lower()
        provider_route = "bedrock"
        s = m_br.group(3)
    elif "/" in s:
        head, tail = s.split("/", 1)
        if head.lower() in {
            "openai", "anthropic", "google", "vertex_ai", "vertex-ai", "azure", "bedrock",
            "groq", "mistral", "mistralai", "cohere", "xai", "deepseek", "ollama",
            "together", "together_ai", "fireworks", "fireworks_ai", "openrouter", "perplexity",
        }:
            provider_route = head.lower()
            s = tail

    # Normalize Bedrock version tails like claude-sonnet-4-5-20250929-v1:0 -> claude-sonnet-4-5
    base = re.sub(r"-v\d+(?::\d+)?$", "", s, flags=re.IGNORECASE)
    version = ""
    m_dt = DATE_TAIL_RE.match(base)
    if m_dt and len(m_dt.group(1)) >= 4:
        version = m_dt.group(2) or m_dt.group(3) or ""
        base = m_dt.group(1)
    # Normalize dotted vs hyphenated Claude/GPT minor versions (claude-3.5-sonnet -> claude-3-5-sonnet)
    if base.lower().startswith("claude-"):
        base = re.sub(r"(\d)\.(\d)", r"\1-\2", base.lower())
    return base.lower(), provider_route, region, version


def infer_license_for_maker(maker: str, name: str) -> str:
    low = name.lower()
    if "llama-3.3" in low or "llama3.3" in low:
        return "llama3.3"
    if "llama-3.2" in low or "llama3.2" in low:
        return "llama3.2"
    if "llama-3.1" in low or "llama3.1" in low:
        return "llama3.1"
    if "llama-3" in low or "llama3" in low:
        return "llama3"
    if "llama-2" in low or "llama2" in low or "codellama" in low:
        return "llama2"
    if "gemma" in low:
        return "gemma"
    if "flux.1-dev" in low or "flux-1-dev" in low:
        return "flux-1-dev-non-commercial"
    if "flux.1-schnell" in low or "flux-1-schnell" in low:
        return "apache-2.0"
    # Name-based guesses are kept only for families whose open releases share one license (checked against the
    # Hugging Face repos on 2026-11-10). Families that mix licenses get no guess: "unknown" is honest, a wrong
    # license is not. Removed for that reason: deepseek (MIT code, DeepSeek License weights), qwen2.5/qwen3 (the
    # 3B and 72B models use the Qwen License), ministral (research license) and codestral (non-production license).
    if "c4ai-command" in low:
        return "cc-by-nc-4.0"
    if "mistral-large-2407" in low:
        return "mistral-research"
    if "mixtral" in low or "mistral-7b" in low:
        return "apache-2.0"
    if "phi-3" in low or "phi-4" in low or "phi3" in low or "phi4" in low:
        return "mit"
    if re.search(r"bge-(small|base|large)-(en|zh)", low):
        return "mit"
    if "all-minilm" in low:
        return "apache-2.0"
    if maker in {"OpenAI", "Anthropic", "Google", "Cohere", "Amazon", "xAI", "AI21 Labs", "Perplexity", "Voyage AI"}:
        return "proprietary"
    return "unknown"


def dump_db(path: str, db: dict) -> None:
    """Write ai_db.json so that git diffs are reviewable: one table entry per line, keys sorted, no network needed.

    The file stays plain JSON; only the layout is chosen for humans. A changed model, alias or advisory shows up as
    a changed line instead of the whole file being one line.
    """
    def dumps(obj):
        return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

    parts = []
    for key in sorted(db):
        value = db[key]
        if key == "vulnerabilities" and isinstance(value, dict) and value:
            # one advisory per line: a package can have more than a hundred
            rows = [f"  {json.dumps(k, ensure_ascii=False)}:[\n" + ",\n".join(f"   {dumps(a)}" for a in v) + "\n  ]"
                    for k, v in sorted(value.items())]
            body = "{\n" + ",\n".join(rows) + "\n }"
        elif isinstance(value, dict) and key != "meta" and value:
            rows = [f"  {json.dumps(k, ensure_ascii=False)}:{dumps(v)}" for k, v in sorted(value.items())]
            body = "{\n" + ",\n".join(rows) + "\n }"
        else:
            body = dumps(value)
        parts.append(f" {json.dumps(key)}:{body}")
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write("{\n" + ",\n".join(parts) + "\n}\n")


def dump_curated(path: str, curated: dict) -> None:
    """Write curated.json in one stable layout: one license, package, model or record per line, sections in a fixed
    order. Hand edits stay easy, and every data change is a one-line diff."""
    def dumps(obj):
        return json.dumps(obj, ensure_ascii=False)

    parts = []
    for key, value in curated.items():  # keep the section order of the file
        if isinstance(value, dict) and value:
            rows = [f"    {dumps(k)}: {dumps(v)}" for k, v in value.items()]
            body = "{\n" + ",\n".join(rows) + "\n  }"
        elif isinstance(value, list) and value:
            rows = [f"    {dumps(v)}" for v in value]
            body = "[\n" + ",\n".join(rows) + "\n  ]"
        else:
            body = dumps(value)
        parts.append(f"  {dumps(key)}: {body}")
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write("{\n" + ",\n".join(parts) + "\n}\n")


def fetch_json(url: str, data: bytes | None = None, timeout: int = 30):
    headers = {"User-Agent": "korelex-aibom-db-builder/1.0"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


DOTTED_MAKER_RE = re.compile(
    r"^(?:(us|eu|apac|global|ca|sa|il|me|af|mx)\.)?"
    r"(anthropic|amazon|meta|mistral|cohere|ai21|deepseek|openai|writer|qwen|stability|nvidia|moonshotai|minimax|xai)\.(.+)$",
    re.IGNORECASE,
)


def maker_model_for(raw_name, maker_segments, gateway_prefixes, maker_of_fn, display_to_slug):
    segs = [s.replace("_", "-") for s in raw_name.strip().lower().split("/") if s]
    if not segs:
        return "", ""
    while len(segs) >= 2 and segs[0] in gateway_prefixes:
        segs.pop(0)

    def strip_version(name):
        base = re.sub(r"-v\d+(?::\d+)?$", "", name, flags=re.IGNORECASE)
        m = DATE_TAIL_RE.match(base)
        return m.group(1) if m and len(m.group(1)) >= 4 else base

    if len(segs) >= 2 and segs[0] in maker_segments:
        return maker_segments[segs[0]], strip_version("/".join(segs[1:]))
    for cut in range(1, len(segs)):
        tail_segs = segs[cut:]
        tail = "/".join(tail_segs)
        if len(tail_segs) == 1:
            dm = DOTTED_MAKER_RE.match(tail_segs[0])
            if dm:
                maker_seg = dm.group(2).lower()
                slug = maker_segments.get(maker_seg, maker_seg)
                return slug, strip_version(dm.group(3))
        if len(tail_segs) >= 2 and tail_segs[0] in maker_segments:
            return maker_segments[tail_segs[0]], strip_version("/".join(tail_segs[1:]))
        maker_disp = maker_of_fn(tail)
        if maker_disp:
            slug = display_to_slug.get(maker_disp.lower()) or re.sub(r"[^a-z0-9]+", "-", maker_disp.lower()).strip("-")
            if slug:
                return slug, strip_version(tail)
    return "", strip_version("/".join(segs))


def first_party_canonical(canonical_id, gateway_prefixes):
    seg = canonical_id.split("/")[0]
    return seg not in gateway_prefixes and seg not in ("unknown", "")


def build(offline: bool = False, from_existing: bool = False):
    """Compile ai_db.json. With from_existing=True nothing is fetched: the existing database is kept and only the
    curated overlay (curated.json) is re-applied on top of it. Use that for hand-curated changes, so the diff shows
    exactly those changes and not a day's worth of upstream catalogue drift."""
    with open(CURATED_PATH, encoding="utf-8") as f:
        curated = json.load(f)
    if from_existing:
        offline = True

    licenses_table = curated["licenses"]
    packages_list = curated["packages"]
    curated_models = curated["curated_models"]
    maker_segments = curated.get("maker_segments", {})
    gateway_prefixes = set(curated.get("gateway_prefixes", []))
    maker_display = curated.get("maker_display", {})
    display_to_slug = {v.lower(): k for k, v in maker_display.items()}

    litellm_data = {}
    openrouter_data = []

    if not offline:
        print("1. Fetching LiteLLM catalog...")
        try:
            litellm_data = fetch_json(LITELLM_URL, timeout=45)
            print(f"   Loaded {len(litellm_data):,} entries from LiteLLM.")
        except Exception as exc:
            print(f"   [warn] LiteLLM fetch failed ({exc}), falling back to local model_names.json")
        print("2. Fetching OpenRouter catalog...")
        try:
            openrouter_data = fetch_json(OPENROUTER_URL, timeout=45).get("data", [])
            print(f"   Loaded {len(openrouter_data):,} models from OpenRouter.")
        except Exception as exc:
            print(f"   [warn] OpenRouter fetch failed ({exc})")

    if not litellm_data and not from_existing and os.path.exists(MODEL_NAMES_PATH):
        with open(MODEL_NAMES_PATH, encoding="utf-8") as f:
            old = json.load(f).get("names", {})
        litellm_data = {k: {"litellm_provider": v.get("provider", ""), "mode": v.get("mode", "")} for k, v in old.items()}

    models: dict[str, dict] = {}
    alias_index: dict[str, dict] = {}
    legacy_names: dict[str, dict] = {}
    existing_vulns: dict[str, list] = {}
    existing_built = ""
    existing_osv_meta: dict = {}
    if from_existing:
        with open(AI_DB_PATH, encoding="utf-8") as fh:
            existing = json.load(fh)
        models.update(existing["models"])
        alias_index.update(existing["alias_index"])
        # Every model that is not in curated.json is reset: its license is re-derived from the name rules and it has
        # no lifecycle. A rule change, or an entry removed from curated.json, then takes effect without a network
        # rebuild, and nothing removed from curated.json lingers with a stale source.
        for key, m in models.items():
            if key not in curated_models:
                m["lifecycle"] = {}
                lic_id = infer_license_for_maker(m.get("maker") or "", m.get("name") or m.get("id", ""))
                meta = licenses_table.get(lic_id, {})
                m["license"] = {"id": lic_id, "category": meta.get("category", "unknown"),
                                "restricted": meta.get("restricted", False), "source_url": "", "checked": ""}
        existing_vulns = existing["vulnerabilities"]
        existing_built = existing.get("meta", {}).get("built", "")
        existing_osv_meta = existing.get("meta", {}).get("vulnerabilities", {})

    def register_model(canonical_id: str, name: str, maker: str, mode: str) -> dict:
        if canonical_id not in models:
            lic_id = infer_license_for_maker(maker, name)
            lic_meta = licenses_table.get(lic_id, {})
            models[canonical_id] = {
                "id": canonical_id,
                "name": name,
                "maker": maker,
                "mode": mode or "chat",
                "type_label": type_of(name, mode),
                "context_window": 0,
                "max_output_tokens": 0,
                "capabilities": [],
                "supported_regions": [],
                "pricing": {},
                "lifecycle": {},  # filled only from sourced curated records (see the curated overlay below)
                "license": {
                    "id": lic_id,
                    "category": lic_meta.get("category", "unknown"),
                    "restricted": lic_meta.get("restricted", False),
                    "source_url": "",
                    "checked": "",
                },
                "hugging_face_id": None,
                "snapshots": [],
                "floating_aliases": [],
            }
        return models[canonical_id]

    alias_priority: dict[str, int] = {}

    def register_alias(raw: str, canonical_id: str, provider: str = "", region: str = "", version: str = "", priority: int = 1):
        low = raw.strip().lower()
        if not low:
            return
        existing = alias_index.get(low)
        if existing and existing["canonical_id"] != canonical_id:
            if priority <= alias_priority.get(low, 0):
                return
        alias_priority[low] = priority
        pinned = is_pinned_reference(raw)
        previous = alias_index.get(low)
        if previous and previous["canonical_id"] != canonical_id and previous["canonical_id"] in models:
            # The alias moves to another model: forget it on the old one so no stale list remains.
            old = models[previous["canonical_id"]]
            for lst in (old["snapshots"], old["floating_aliases"]):
                if raw in lst:
                    lst.remove(raw)
        alias_index[low] = {
            "canonical_id": canonical_id,
            "provider": provider,
            "region": region,
            "version": version,
            "pinned": pinned,
        }
        m = models.get(canonical_id)
        if m:
            target_list = m["snapshots"] if pinned else m["floating_aliases"]
            if raw not in target_list and len(target_list) < 25:
                target_list.append(raw)

    # 1. Seed from LiteLLM
    today = time.strftime("%Y-%m-%d")
    for key, v in sorted(litellm_data.items()):
        if key == "sample_spec" or not isinstance(v, dict):
            continue
        provider = str(v.get("litellm_provider") or "")
        mode = str(v.get("mode") or "")
        for cand in {key, key.split("/")[-1]}:
            if usable(cand) and cand not in legacy_names:
                legacy_names[cand] = {"provider": provider, "mode": mode}

        if not usable(key) and not usable(key.split("/")[-1]):
            continue
        base_name, route, region, ver = normalize_family_slug(key)
        maker_slug, model_name = maker_model_for(key, maker_segments, gateway_prefixes, maker_of, display_to_slug)
        if maker_slug:
            maker_disp = maker_display.get(maker_slug, "") or maker_of(key) or maker_of(model_name)
        else:
            model_name = base_name if usable(base_name) else key.split("/")[-1].lower()
            maker_disp = maker_of(key) or maker_of(model_name)
            maker_slug = re.sub(r"[^a-z0-9]+", "-", (maker_disp or provider or "unknown").lower()).strip("-")
        canonical_id = f"{maker_slug}/{model_name}"
        priority = 2 if first_party_canonical(canonical_id, gateway_prefixes) else 1
        rec = register_model(canonical_id, model_name, maker_disp, mode)

        # Enrich fields from LiteLLM
        max_in = v.get("max_input_tokens") or v.get("max_tokens") or 0
        max_out = v.get("max_output_tokens") or 0
        if isinstance(max_in, int) and max_in > rec["context_window"]:
            rec["context_window"] = max_in
        if isinstance(max_out, int) and max_out > rec["max_output_tokens"]:
            rec["max_output_tokens"] = max_out

        for cap_flag, cap_name in (
            ("supports_function_calling", "function_calling"),
            ("supports_vision", "vision"),
            ("supports_reasoning", "reasoning"),
            ("supports_web_search", "web_search"),
            ("supports_audio_input", "audio_input"),
            ("supports_audio_output", "audio_output"),
            ("supports_response_schema", "structured_outputs"),
            ("supports_prompt_caching", "prompt_caching"),
        ):
            if v.get(cap_flag) and cap_name not in rec["capabilities"]:
                rec["capabilities"].append(cap_name)

        if v.get("supported_regions") and isinstance(v["supported_regions"], list):
            for r in v["supported_regions"]:
                if isinstance(r, str) and r not in rec["supported_regions"]:
                    rec["supported_regions"].append(r)

        in_cost = v.get("input_cost_per_token")
        out_cost = v.get("output_cost_per_token")
        if isinstance(in_cost, (int, float)) and in_cost > 0 and not rec["pricing"]:
            rec["pricing"] = {
                "input_per_1m": round(in_cost * 1_000_000, 4),
                "output_per_1m": round((out_cost or 0) * 1_000_000, 4),
            }

        register_alias(key, canonical_id, route or provider, region, ver, priority)
        tail = key.split("/")[-1]
        if usable(tail):
            register_alias(tail, canonical_id, route or provider, region, ver, priority)

    # 2. Enrich from OpenRouter
    for item in openrouter_data:
        or_id = item.get("id") or ""
        if not or_id:
            continue
        base_name, route, region, ver = normalize_family_slug(or_id)
        maker_slug, model_name = maker_model_for(or_id, maker_segments, gateway_prefixes, maker_of, display_to_slug)
        if maker_slug:
            maker_disp = maker_display.get(maker_slug, "") or maker_of(or_id) or maker_of(model_name) or or_id.split("/")[0]
        else:
            model_name = base_name if usable(base_name) else or_id.split("/")[-1].lower()
            maker_disp = maker_of(or_id) or maker_of(model_name) or or_id.split("/")[0]
            maker_slug = re.sub(r"[^a-z0-9]+", "-", maker_disp.lower()).strip("-") or "unknown"
        canonical_id = f"{maker_slug}/{model_name}"
        priority = 2 if first_party_canonical(canonical_id, gateway_prefixes) else 1
        rec = register_model(canonical_id, model_name, maker_disp, "chat")
        if item.get("hugging_face_id") and not rec["hugging_face_id"]:
            rec["hugging_face_id"] = item["hugging_face_id"]
            register_alias(item["hugging_face_id"], canonical_id, "huggingface", "", "", priority)
        ctx = item.get("context_length") or 0
        if isinstance(ctx, int) and ctx > rec["context_window"]:
            rec["context_window"] = ctx
        register_alias(or_id, canonical_id, "openrouter", region, ver, priority)
        if item.get("canonical_slug"):
            register_alias(item["canonical_slug"], canonical_id, "openrouter", region, ver, priority)

    # 3. Apply Curated Models (highest priority override)
    for canonical_id, cmod in curated_models.items():
        name = canonical_id.split("/")[-1]
        rec = register_model(canonical_id, name, cmod.get("maker", ""), cmod.get("mode", "chat"))
        lic_id = cmod.get("license", rec["license"]["id"])
        lic_meta = licenses_table.get(lic_id, {})
        rec["license"] = {
            "id": lic_id,
            "category": lic_meta.get("category", "unknown"),
            "restricted": lic_meta.get("restricted", False),
            "source_url": cmod.get("license_source_url", ""),
            "checked": cmod.get("license_checked", ""),
        }
        # Lifecycle comes only from curated, sourced records. Dates are stored; the status is worked out from them at
        # scan time (db.lifecycle_status), so a record never goes stale by itself.
        claims = {"deprecation_date": cmod.get("deprecation_date"), "retirement_date": cmod.get("retirement_date"),
                  "replacement": cmod.get("replacement"), "source_url": cmod.get("lifecycle_source_url"),
                  "checked": cmod.get("lifecycle_checked")}
        if claims["source_url"] and not claims["checked"]:
            raise SystemExit(f"{canonical_id}: lifecycle_source_url needs lifecycle_checked (the date it was checked)")
        if (claims["deprecation_date"] or claims["retirement_date"] or claims["replacement"]) and not claims["source_url"]:
            raise SystemExit(f"{canonical_id}: lifecycle dates need a lifecycle_source_url")
        rec["lifecycle"] = {k: v for k, v in claims.items() if v}
        if cmod.get("hugging_face_id"):
            rec["hugging_face_id"] = cmod["hugging_face_id"]
        for al in cmod.get("aliases", []):
            _, route, region, ver = normalize_family_slug(al)
            register_alias(al, canonical_id, route or cmod.get("maker", "").lower(), region, ver, 3)
            if usable(al) and al not in legacy_names:
                legacy_names[al] = {"provider": cmod.get("maker", "").lower(), "mode": cmod.get("mode", "chat")}

    # 3b. Per-snapshot lifecycle. Models are grouped into families for display, but a retirement belongs to a specific
    # snapshot: gpt-4-0314 was shut down on 2026-03-26 while gpt-4 (the family) is a different matter. Each record is
    # attached to the exact aliases it lists and wins over the family when that exact name is written in code.
    iso = re.compile(r"^\d{4}-\d{2}-\d{2}$")
    seen_names: set[str] = set()
    for rec in curated.get("lifecycle_records", []):
        where = ", ".join(rec.get("match", [])[:2])
        if not (rec.get("source_url", "").startswith("https://") and iso.match(rec.get("checked", ""))):
            raise SystemExit(f"lifecycle record [{where}]: needs source_url (https) and checked (YYYY-MM-DD)")
        if not iso.match(rec.get("retirement_date", "")) or (rec.get("deprecation_date") and not iso.match(rec["deprecation_date"])):
            raise SystemExit(f"lifecycle record [{where}]: dates must be YYYY-MM-DD")
        if rec.get("deprecation_date") and rec["deprecation_date"] > rec["retirement_date"]:
            raise SystemExit(f"lifecycle record [{where}]: announced after it retires")
        life = {k: rec[k] for k in ("deprecation_date", "retirement_date", "replacement", "note") if rec.get(k)}
        life.update({"source_url": rec["source_url"], "checked": rec["checked"]})
        for name in rec["match"]:
            low = name.strip().lower()
            if low in seen_names:
                raise SystemExit(f"lifecycle record: {name!r} appears in two records")
            seen_names.add(low)
            family = rec.get("family", "")
            current = alias_index.get(low)
            if current is None or (rec.get("move_to_family") and current["canonical_id"] != family):
                if not family:
                    raise SystemExit(f"lifecycle record: {name!r} is not a known alias, so the record needs a family")
                register_model(family, family.split("/")[-1], rec.get("maker", ""), "chat")
                _, route, region, ver = normalize_family_slug(name)
                register_alias(name, family, route or rec.get("maker", "").lower(), region, ver, 4)
            alias_index[low]["lifecycle"] = dict(life)

    # 3c. Dateless ids that the provider says are pinned snapshots (for example Claude 4.6 and later). Without this a
    # dateless name would always look like a floating alias.
    for rec in curated.get("pinned_names", []):
        if not (rec.get("source_url", "").startswith("https://") and re.match(r"^\d{4}-\d{2}-\d{2}$", rec.get("checked", ""))):
            raise SystemExit("pinned_names record needs source_url (https) and checked (YYYY-MM-DD)")
        pinned_names = set()
        for name in rec["match"]:
            low = name.strip().lower()
            if low not in alias_index:
                raise SystemExit(f"pinned_names: {name!r} is not a known alias; add it to curated_models first")
            alias_index[low]["pinned_override"] = True
            pinned_names.add(low)
        # The same model written the way a cloud platform spells it (anthropic.claude-opus-5-5, us.anthropic.claude-...-v1:0,
        # bedrock/anthropic....) is pinned too, as long as it is filed under the same model.
        spelling = re.compile(r"^(?:(?:us|eu|apac|global|ca|sa|il|me|af|mx)\.)?(?:anthropic\.)?(.+?)(?:-v\d+:\d+|@.*)?$")
        for alias, entry in alias_index.items():
            m = spelling.match(alias.split("/")[-1])
            base = m.group(1) if m else ""
            if base in pinned_names and alias != base and entry["canonical_id"] == alias_index[base]["canonical_id"]:
                entry["pinned_override"] = True

    # 4. Build Packages & OSV Vulnerabilities
    packages_table = {}
    for p in packages_list:
        pkey = f"{p['ecosystem'].lower()}:{p['name'].lower()}"
        packages_table[pkey] = p

    vulnerabilities_table = dict(existing_vulns)
    osv_meta = existing_osv_meta
    if not offline:
        print("3. Reading OSV advisories for AI packages...")
        vulnerabilities_table, osv_meta = osv_data.build(packages_list, curated.get("package_families", []), OSV_CACHE)
        total_vulns = sum(len(v) for v in vulnerabilities_table.values())
        print(f"   {total_vulns:,} advisories across {len(vulnerabilities_table)} AI packages.")

    db_body = {
        "models": dict(sorted(models.items())),
        "alias_index": dict(sorted(alias_index.items())),
        "packages": dict(sorted(packages_table.items())),
        "vulnerabilities": dict(sorted(vulnerabilities_table.items())),
        "licenses": dict(sorted(licenses_table.items())),
        "package_families": {f"{f['ecosystem'].lower()}:{f['prefix']}": f for f in curated.get("package_families", [])},
    }
    digest = hashlib.sha256(json.dumps(db_body, sort_keys=True).encode("utf-8")).hexdigest()
    full_db = {
        "meta": {
            "schema_version": "1.1.0",
            "built": existing_built or today,
            "vulnerabilities": osv_meta,
            "sha256": digest,
            "counts": {
                "canonical_models": len(models),
                "aliases": len(alias_index),
                "models_with_sourced_lifecycle": sum(1 for m in models.values() if m["lifecycle"].get("source_url")),
                "aliases_with_sourced_lifecycle": sum(1 for a in alias_index.values() if a.get("lifecycle", {}).get("source_url")),
                "models_with_scheduled_or_past_retirement": sum(
                    1 for m in models.values()
                    if m["lifecycle"].get("source_url") and (m["lifecycle"].get("deprecation_date") or m["lifecycle"].get("retirement_date"))
                ),
                "restricted_license_models": sum(1 for m in models.values() if m["license"]["restricted"]),
                "ai_packages": len(packages_table),
                "ai_vulnerable_packages": len(vulnerabilities_table),
                "ai_advisories": sum(len(v) for v in vulnerabilities_table.values()),
            },
        },
        **db_body,
    }

    dump_db(AI_DB_PATH, full_db)

    if from_existing:
        print("4. Wrote", AI_DB_PATH, "(curated overlay applied to the existing database; nothing fetched)")
        print("   Counts:", json.dumps(full_db["meta"]["counts"], indent=2))
        return

    # Also keep aibom_engine/knowledge/model_names.json in sync
    legacy_out = {
        "meta": {
            "source": LITELLM_URL,
            "license": "MIT, Copyright (c) 2023 Berri AI (LiteLLM)",
            "built": today,
            "entries_in_source": len(litellm_data),
            "names": len(legacy_names),
        },
        "names": dict(sorted(legacy_names.items())),
    }
    with open(MODEL_NAMES_PATH, "w", encoding="utf-8") as f:
        json.dump(legacy_out, f, indent=0, sort_keys=True)

    print("4. Wrote", AI_DB_PATH)
    print("   Counts:", json.dumps(full_db["meta"]["counts"], indent=2))


def refresh_osv():
    """Replace only the advisories (and their counts and source) in the existing ai_db.json."""
    with open(CURATED_PATH, encoding="utf-8") as f:
        curated = json.load(f)
    with open(AI_DB_PATH, encoding="utf-8") as fh:
        db = json.load(fh)
    print("Reading OSV advisories for AI packages...")
    table, meta = osv_data.build(curated["packages"], curated.get("package_families", []), OSV_CACHE)
    db["vulnerabilities"] = table
    db["meta"]["vulnerabilities"] = meta
    db["meta"]["schema_version"] = "1.1.0"
    db["meta"]["counts"]["ai_vulnerable_packages"] = len(table)
    db["meta"]["counts"]["ai_advisories"] = sum(len(v) for v in table.values())
    body = {k: v for k, v in db.items() if k != "meta"}
    db["meta"]["sha256"] = hashlib.sha256(json.dumps(body, sort_keys=True).encode("utf-8")).hexdigest()
    dump_db(AI_DB_PATH, db)
    print(f"   {db['meta']['counts']['ai_advisories']:,} advisories across {len(table)} AI packages. Wrote {AI_DB_PATH}")


if __name__ == "__main__":
    if "--reformat" in sys.argv:
        # Rewrite the existing database in the canonical layout without fetching anything.
        with open(AI_DB_PATH, encoding="utf-8") as fh:
            dump_db(AI_DB_PATH, json.load(fh))
        with open(CURATED_PATH, encoding="utf-8") as fh:
            dump_curated(CURATED_PATH, json.load(fh))
        print("Reformatted", AI_DB_PATH, "and", CURATED_PATH)
    elif "--apply-curated" in sys.argv:
        build(from_existing=True)
    elif "--osv-only" in sys.argv:
        refresh_osv()
    else:
        build(offline="--offline" in sys.argv)
