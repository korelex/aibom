"""Runtime AI Knowledge Base & Database Engine (offline-first, with opt-in --online SQLite cache).

Provides fast lookups over aibom_engine/knowledge/ai_db.json:
  - Model resolution (canonical ID, maker, provider, version, pinned status, deprecation, license)
  - AI package classification (llm_sdk, agent_framework, mcp, vector_db, model_runtime, dataset_loader, guardrail)
  - AI package vulnerability matching (OSV version-range comparator + affected symbols + fix version)
  - License risk classification (permissive, conditional-commercial, non-commercial, copyleft, proprietary)
  - Opt-in --online Hugging Face Hub lookup cached in ~/.cache/aibom/online_cache.sqlite (24h TTL)
"""
from __future__ import annotations

import datetime
import json
import os
import re
import sqlite3
import time
import urllib.request
from typing import Any

from .vendors import maker_of, type_of

AI_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "knowledge", "ai_db.json")
DEFAULT_CACHE_DIR = os.path.join(os.path.expanduser("~"), ".cache", "aibom")
ONLINE_CACHE_TTL = 24 * 3600

_DB_CACHE: dict[str, Any] | None = None
_PKG_NORM_INDEX: dict[str, str] | None = None

# A dated snapshot or revision in a model name. Providers spell the date many ways, so each spelling is listed.
PINNED_VERSION_RE = re.compile(
    r"(?:"
    r"(\d{4}-\d{2}-\d{2})"                                   # 2024-08-06
    r"|(20\d{6})"                                            # 20250929
    r"|-((?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01]))"          # -0613, -0125, -1106 (MMDD) ...
    r"(?:-(?:preview|vision-preview|instruct|chat))?$"       # ... also gpt-4-1106-preview
    r"|-(2[3-9](?:0[1-9]|1[0-2]))$"                          # -2407 (YYMM), e.g. mistral-large-2407
    r"|-((?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01]))$"        # -05-20 (Gemini previews)
    r"|-((?:0[1-9]|1[0-2])-20\d{2})$"                        # -09-2025
    r"|-(00\d)$"                                             # -001, -002 (Google Vertex revisions)
    r"|@(\d{8}|default)"                                     # @20250929 (Vertex)
    r"|(-v\d+:\d+)$"                                         # -v1:0 (Bedrock)
    r"|:([0-9a-f]{12,64})$"                                  # digest
    r"|:(?:\d+(?:\.\d+)?b[-a-z0-9._]*)$"                     # Ollama tag e.g. :8b-instruct-q4_0
    r")",
    re.IGNORECASE,
)
# Heads of "head/name" references that name an API provider rather than a Hugging Face account.
API_HEADS = {
    "openai", "anthropic", "google", "vertex_ai", "vertex-ai", "azure", "bedrock", "ollama", "groq", "gemini", "xai",
    "mistral", "cohere", "together", "together_ai", "fireworks_ai", "openrouter", "perplexity",
}
CLOUD_ROUTES = {"azure", "azure_ai", "bedrock", "vertex_ai", "vertex-ai"}
BEDROCK_ARN_RE = re.compile(
    r"^arn:aws[a-z-]*:bedrock:([a-z0-9-]*):\d*:(?:foundation-model|inference-profile)/(.+)$",
    re.IGNORECASE,
)
VERTEX_PATH_RE = re.compile(
    r"^projects/[^/]+/locations/([a-z0-9-]+)/publishers/([^/]+)/models/(.+)$",
    re.IGNORECASE,
)
BEDROCK_ID_RE = re.compile(
    r"^(?:(us|eu|apac|global)\.)?(anthropic|amazon|meta|mistral|cohere|ai21|deepseek|openai|writer|qwen)\.(.+)$",
    re.IGNORECASE,
)
DATE_STRIP_RE = re.compile(
    r"^(.*?)(?:-(20\d{2}-\d{2}-\d{2}|20\d{6}|0\d{3}|1\d{3})|@(20\d{6})|-v\d+(?::\d+)?|-latest)$",
    re.IGNORECASE,
)


def load_db(path: str = AI_DB_PATH) -> dict[str, Any]:
    """Load aibom_engine/knowledge/ai_db.json once and keep it in memory."""
    global _DB_CACHE, _PKG_NORM_INDEX
    if _DB_CACHE is not None and path == AI_DB_PATH:
        return _DB_CACHE
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    elif path == AI_DB_PATH:
        # The bundled database ships inside the package. If it is missing the install is broken, and scanning
        # without it would silently drop every lifecycle, license and pinning fact, so fail loudly instead.
        raise FileNotFoundError(
            f"The bundled AI database is missing: {path}. Reinstall aibom (pip install --force-reinstall aibom)."
        )
    else:
        data = {"meta": {}, "models": {}, "alias_index": {}, "packages": {}, "vulnerabilities": {}, "licenses": {}}
    if path == AI_DB_PATH:
        _DB_CACHE = data
        _PKG_NORM_INDEX = None
    return data


def _norm_pkg_name(ecosystem: str, name: str) -> str:
    eco = ecosystem.strip().lower()
    n = name.strip().lower()
    if eco == "pypi":
        n = re.sub(r"[-_.]+", "-", n)
    return f"{eco}:{n}"


def lookup_package(ecosystem: str, name: str, db: dict[str, Any] | None = None) -> dict[str, Any] | None:
    """Return the AI package entry for (ecosystem, name), or None if not an AI package."""
    global _PKG_NORM_INDEX
    db = db or load_db()
    pkgs = db.get("packages", {})
    direct = f"{ecosystem.strip().lower()}:{name.strip().lower()}"
    if direct in pkgs:
        return pkgs[direct]
    if _PKG_NORM_INDEX is None:
        _PKG_NORM_INDEX = {}
        for k, v in pkgs.items():
            eco, pkg_n = k.split(":", 1)
            _PKG_NORM_INDEX[_norm_pkg_name(eco, pkg_n)] = k
    mapped = _PKG_NORM_INDEX.get(_norm_pkg_name(ecosystem, name))
    return pkgs.get(mapped) if mapped else None


def _version_tuple(v: str) -> tuple:
    """Parse a version string into a comparable tuple for PEP 440 / SemVer ranges."""
    v = v.strip().lstrip("vV")
    if not v:
        return (0,)
    base = re.split(r"[-+]", v, maxsplit=1)[0]
    parts = []
    for seg in base.split("."):
        m = re.match(r"^(\d+)", seg)
        parts.append(int(m.group(1)) if m else 0)
    # Pre-release (rc, alpha, beta, dev, preview) sorts slightly before the release
    is_pre = bool(re.search(r"(?:a|alpha|b|beta|rc|dev|preview)", v, re.IGNORECASE))
    return tuple(parts) + ((0,) if is_pre else (1,))


def version_in_range(version: str, introduced: str, fixed: str) -> bool:
    """Return True when version is >= introduced and < fixed."""
    if not version or version in ("*", "latest", "unknown"):
        return False
    vt = _version_tuple(version)
    if introduced and introduced != "0":
        if vt < _version_tuple(introduced):
            return False
    if fixed:
        if vt >= _version_tuple(fixed):
            return False
    return True


def match_vulnerabilities(
    ecosystem: str,
    name: str,
    version: str,
    db: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Return all vulnerabilities in ai_db.json that affect (ecosystem, name, version)."""
    db = db or load_db()
    pkg = lookup_package(ecosystem, name, db=db)
    key = f"{pkg['ecosystem'].lower()}:{pkg['name'].lower()}" if pkg else f"{ecosystem.lower()}:{name.lower()}"
    advisories = db.get("vulnerabilities", {}).get(key, [])
    if not advisories or not version:
        return []
    clean_ver = re.sub(r"^[~^>=<]+", "", version.strip())
    if not clean_ver or not clean_ver[0].isdigit():
        return []
    matched = []
    for adv in advisories:
        if version_in_range(clean_ver, adv.get("introduced", "0"), adv.get("fixed", "")):
            matched.append(adv)
    return matched


def lookup_license(license_id: str | None, db: dict[str, Any] | None = None) -> dict[str, Any]:
    """Return license metadata {id, name, category, restricted, severity, reason}."""
    db = db or load_db()
    table = db.get("licenses", {})
    raw = (license_id or "").strip().lower()
    if not raw or raw == "unknown":
        return {
            "id": "unknown",
            "name": "Unknown License",
            "category": "unknown",
            "restricted": False,
            "severity": "low",
            "reason": "Model license is not declared in the knowledge base or local model card.",
        }
    if raw in table:
        entry = table[raw]
        return {"id": raw, **entry}
    # Normalize common SPDX / Hugging Face variations
    for prefix, mapped in (
        ("apache", "apache-2.0"),
        ("mit", "mit"),
        ("bsd-3", "bsd-3-clause"),
        ("bsd-2", "bsd-2-clause"),
        ("cc-by-nc-sa", "cc-by-nc-sa-4.0"),
        ("cc-by-nc-nd", "cc-by-nc-nd-4.0"),
        ("cc-by-nc", "cc-by-nc-4.0"),
        ("cc-by-4", "cc-by-4.0"),
        ("cc0", "cc0-1.0"),
        ("llama-3.3", "llama3.3"),
        ("llama-3.2", "llama3.2"),
        ("llama-3.1", "llama3.1"),
        ("llama-3", "llama3"),
        ("llama-2", "llama2"),
        ("gemma", "gemma"),
        ("agpl", "agpl-3.0"),
    ):
        if raw.startswith(prefix) and mapped in table:
            return {"id": mapped, **table[mapped]}
    if "non-commercial" in raw or "nc" in raw.split("-") or "research" in raw:
        return {
            "id": raw,
            "name": license_id or raw,
            "category": "non-commercial",
            "restricted": True,
            "severity": "high",
            "reason": f"License '{license_id}' restricts commercial use.",
        }
    return {
        "id": raw,
        "name": license_id or raw,
        "category": "custom",
        "restricted": False,
        "severity": "info",
        "reason": "Custom or unmapped license identifier.",
    }


def today_iso() -> str:
    """Today's date as YYYY-MM-DD. Set AIBOM_TODAY to fix the date, for example to reproduce a report exactly."""
    forced = os.environ.get("AIBOM_TODAY", "").strip()
    if forced:
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", forced):
            raise ValueError(f"AIBOM_TODAY must look like 2026-11-09, got {forced!r}")
        return forced
    return datetime.date.today().isoformat()


def lifecycle_status(lifecycle: dict[str, Any] | None, today: str | None = None) -> dict[str, Any]:
    """Work out where a model is in its life, from dates, as of today.

    Two different dates matter and they are kept apart:
      deprecation_date  the day the provider announced the model is going away (it still works)
      retirement_date   the day API calls start to fail

    The status follows from the dates, never from a stored word, so a record stays right as time passes:
      retired     retirement_date is today or in the past
      deprecated  announced (deprecation_date reached, or a retirement_date is scheduled) and still working
      active      a sourced record exists and nothing is scheduled
      unknown     nothing sourced is known about this model. Absence from the list is not evidence that it is fine.

    A record only counts when it carries a source_url; the unsourced upstream guesses that used to be copied into
    the database are ignored.
    """
    lc = lifecycle or {}
    out = {"status": "unknown", "deprecation_date": "", "retirement_date": "", "replacement": "",
           "lifecycle_source_url": "", "lifecycle_checked": ""}
    if not lc.get("source_url"):
        return out
    today = today or today_iso()
    dep = lc.get("deprecation_date") or ""
    ret = lc.get("retirement_date") or ""
    if ret and ret <= today:
        status = "retired"
    elif (dep and dep <= today) or ret:
        status = "deprecated"
    else:
        status = "active"
    out.update({"status": status, "deprecation_date": dep, "retirement_date": ret, "replacement": lc.get("replacement") or "",
                "lifecycle_source_url": lc["source_url"], "lifecycle_checked": lc.get("checked") or ""})
    return out


def is_pinned_reference(raw_name: str) -> bool:
    """True when the name pins a dated snapshot or revision rather than a floating alias."""
    return extract_version_and_pinning(raw_name)[1]


def extract_version_and_pinning(raw_name: str) -> tuple[str, bool]:
    """Return (extracted_version, is_pinned) for any raw model reference."""
    s = raw_name.strip()
    low = s.lower()
    if low.endswith("-latest") or low.endswith(":latest"):
        return "latest", False
    m = PINNED_VERSION_RE.search(s)
    if m:
        ver = next((g for g in m.groups() if g), m.group(0)).lstrip("-@:")
        return ver, True
    # Check Bedrock -v1:0 or -v2:0
    m_br = re.search(r"-(v\d+(?::\d+)?)$", low)
    if m_br:
        return m_br.group(1), True
    return "", False


def _unwrap_arn_or_path(raw_name: str) -> tuple[str, str, str]:
    """Unwrap AWS Bedrock ARN or Google Vertex AI model path into (model_id, provider, region)."""
    s = raw_name.strip()
    m_arn = BEDROCK_ARN_RE.match(s)
    if m_arn:
        return m_arn.group(2), "bedrock", m_arn.group(1).lower()
    m_vtx = VERTEX_PATH_RE.match(s)
    if m_vtx:
        return m_vtx.group(3), "vertex_ai", m_vtx.group(1).lower()
    m_br = BEDROCK_ID_RE.match(s)
    if m_br:
        return s, "bedrock", (m_br.group(1) or "").lower()
    return s, "", ""


def online_lookup_hf(repo_id: str, cache_dir: str = DEFAULT_CACHE_DIR) -> dict[str, Any] | None:
    """Opt-in (--online) lookup of a Hugging Face model's license and weight file safety, cached in SQLite."""
    if "/" not in repo_id or repo_id.count("/") != 1:
        return None
    os.makedirs(cache_dir, exist_ok=True)
    db_file = os.path.join(cache_dir, "online_cache.sqlite")
    now = int(time.time())
    try:
        conn = sqlite3.connect(db_file, timeout=5)
        conn.execute(
            "CREATE TABLE IF NOT EXISTS hf_cache (repo_id TEXT PRIMARY KEY, data TEXT, fetched_at INTEGER)"
        )
        row = conn.execute(
            "SELECT data, fetched_at FROM hf_cache WHERE repo_id = ?", (repo_id.lower(),)
        ).fetchone()
        if row and (now - row[1]) < ONLINE_CACHE_TTL:
            conn.close()
            return json.loads(row[0])
    except Exception:
        conn = None

    url = f"https://huggingface.co/api/models/{repo_id}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "korelex-aibom/1.0"})
        with urllib.request.urlopen(req, timeout=6) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
    except Exception:
        if conn:
            conn.close()
        return None

    card = payload.get("cardData") or {}
    lic = card.get("license")
    if isinstance(lic, list) and lic:
        lic = lic[0]
    siblings = [s.get("rfilename", "") for s in (payload.get("siblings") or []) if isinstance(s, dict)]
    has_safetensors = any(f.endswith(".safetensors") for f in siblings)
    has_pickle = any(f.endswith((".bin", ".pkl", ".pt", ".pth")) for f in siblings)
    result = {
        "repo_id": payload.get("id") or repo_id,
        "license": str(lic or "unknown"),
        "gated": bool(payload.get("gated")),
        "has_safetensors": has_safetensors,
        "has_pickle_weights": has_pickle and not has_safetensors,
        "base_model": card.get("base_model"),
    }
    if conn:
        try:
            conn.execute(
                "INSERT OR REPLACE INTO hf_cache (repo_id, data, fetched_at) VALUES (?, ?, ?)",
                (repo_id.lower(), json.dumps(result), now),
            )
            conn.commit()
            conn.close()
        except Exception:
            pass
    return result


def resolve_model(
    raw_name: str,
    db: dict[str, Any] | None = None,
    online: bool = False,
) -> dict[str, Any]:
    """Resolve any model identifier into full canonical metadata."""
    db = db or load_db()
    models_table = db.get("models", {})
    alias_index = db.get("alias_index", {})

    unwrapped, provider_hint, region_hint = _unwrap_arn_or_path(raw_name)
    low = unwrapped.strip().lower()
    ver_extracted, pinned_extracted = extract_version_and_pinning(unwrapped)

    # 1. Exact alias lookup. `exact` records whether the very name that was written is in the index; only then may a
    # per-snapshot lifecycle record apply (a name that merely resembles a known snapshot must not inherit its dates).
    alias_hit = alias_index.get(low)
    if not alias_hit and "/" in low:
        alias_hit = alias_index.get(low.split("/")[-1])
    exact = alias_hit is not None
    if not alias_hit:
        # Try stripping Bedrock regional prefix or dated suffix
        m_br = BEDROCK_ID_RE.match(low)
        inner = m_br.group(3) if m_br else low.split("/")[-1]
        inner_clean = re.sub(r"-v\d+(?::\d+)?$", "", inner)
        m_dt = DATE_STRIP_RE.match(inner_clean)
        base_candidate = m_dt.group(1) if m_dt else inner_clean
        if base_candidate.startswith("claude-"):
            base_candidate = re.sub(r"(\d)\.(\d)", r"\1-\2", base_candidate)
        alias_hit = alias_index.get(inner) or alias_index.get(inner_clean) or alias_index.get(base_candidate)
        exact = bool(alias_index.get(inner) or alias_index.get(inner_clean))

    canonical_rec = None
    if alias_hit:
        canonical_rec = models_table.get(alias_hit["canonical_id"])

    maker = (canonical_rec or {}).get("maker") or maker_of(unwrapped)
    mode_raw = (canonical_rec or {}).get("mode") or ""
    type_label = (canonical_rec or {}).get("type_label") or type_of(unwrapped, mode_raw)
    provider = provider_hint or (alias_hit or {}).get("provider") or (maker.lower() if maker else "")
    region = region_hint or (alias_hit or {}).get("region") or ""
    version = ver_extracted or (alias_hit or {}).get("version") or ""
    # Whether a reference is pinned is a fact about the name the code writes, so it is read from that name.
    pinned = pinned_extracted
    is_latest = low.endswith("-latest") or low.endswith(":latest")

    # A record for this exact snapshot wins; otherwise the family's record applies (only set when the whole family
    # shares one schedule); otherwise nothing is known.
    snapshot_lifecycle = (alias_hit or {}).get("lifecycle") if exact else None
    lifecycle = lifecycle_status(snapshot_lifecycle or (canonical_rec or {}).get("lifecycle"))
    first_segment = low.split("/")[0] if "/" in low else ""
    lifecycle["lifecycle_scope"] = "platform" if (provider_hint in CLOUD_ROUTES or first_segment in CLOUD_ROUTES) else "first_party"
    lic_id = ((canonical_rec or {}).get("license") or {}).get("id") or "unknown"
    if lic_id == "unknown" and maker in {
        "OpenAI", "Anthropic", "Google", "Cohere", "Amazon", "xAI", "AI21 Labs", "Perplexity", "Voyage AI",
    }:
        lic_id = "proprietary"

    hf_id = (canonical_rec or {}).get("hugging_face_id")
    if not hf_id and "/" in unwrapped and unwrapped.count("/") == 1:
        head = unwrapped.split("/")[0].lower()
        if head not in {"openai", "anthropic", "google", "vertex_ai", "azure", "bedrock", "ollama", "groq"}:
            hf_id = unwrapped
    # A Hugging Face repo id is pinned by a commit revision, not by a dated name, so it is reported on its own
    # instead of being called a "floating alias".
    if hf_id and hf_id.lower() == low:
        hf_repo = True
    else:
        hf_repo = low.count("/") == 1 and low.split("/")[0] not in API_HEADS
    # A name floats only when the provider offers a dated snapshot to switch to (or the name says "latest").
    snapshot_available = bool((canonical_rec or {}).get("snapshots"))
    floating = (not hf_repo) and (not pinned) and (is_latest or snapshot_available)

    has_unsafe_weights = False
    if online and hf_id:
        hf_live = online_lookup_hf(hf_id)
        if hf_live:
            if lic_id == "unknown" and hf_live.get("license") != "unknown":
                lic_id = hf_live["license"]
            has_unsafe_weights = bool(hf_live.get("has_pickle_weights"))

    lic_info = lookup_license(lic_id, db=db)
    canonical_id = (canonical_rec or {}).get("id") or (
        f"{re.sub(r'[^a-z0-9]+', '-', (maker or 'unknown').lower()).strip('-')}/{low.split('/')[-1]}"
    )

    return {
        "canonical_id": canonical_id,
        "maker": maker,
        "mode": type_label,
        "provider": provider,
        "region": region,
        "version": version,
        "pinned": pinned,
        "floating": floating,
        "snapshot_available": snapshot_available,
        "hf_repo": hf_repo,
        "status": lifecycle["status"],
        "deprecation_date": lifecycle["deprecation_date"],
        "retirement_date": lifecycle["retirement_date"],
        "replacement": lifecycle["replacement"],
        "lifecycle_source_url": lifecycle["lifecycle_source_url"],
        "lifecycle_checked": lifecycle["lifecycle_checked"],
        "lifecycle_scope": lifecycle["lifecycle_scope"],
        "license": lic_info["id"],
        "license_name": lic_info.get("name", lic_info["id"]),
        "license_category": lic_info.get("category", "unknown"),
        "license_restricted": bool(lic_info.get("restricted", False)),
        "license_reason": lic_info.get("reason", ""),
        "context_window": (canonical_rec or {}).get("context_window", 0),
        "capabilities": (canonical_rec or {}).get("capabilities", []),
        "hugging_face_id": hf_id,
        "has_unsafe_weights": has_unsafe_weights,
    }
