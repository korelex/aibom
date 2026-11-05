# AI BOM Engine — Product & Implementation Plan

> Status: proposal (v1). Audience: the team building the tool.
> This document defines **what** we are building (a client-facing AI BOM product for AI security
> pipelines), **why**, and **how** — architecture, data model, detection engines, policy, delta,
> storage, distribution, and a phased roadmap.
>
> It is grounded in two codebases we have analyzed deeply:
> - `aibom-engine` v0.5.0 (our Python engine, models-only, round-3 79% found / 99% correct), and
> - `safedep/vet` v2 (the supply-chain scanner whose architecture we are borrowing).

---

## 1. Executive summary

**Thesis.** Every company shipping or buying AI software now needs to answer one question and be
able to prove it: *"What AI models, providers, frameworks, agents, and data does this application
actually use, where do they come from, and does that comply with our policy?"* Today no tool answers
that question with evidence and a gate. SBOM tools inventory *libraries*; AI governance tools
inventory *policies*; our engine inventories *models*. The product is the intersection: an
evidence-backed, policy-gated **AI BOM** that lives in the CI/CD pipeline and the compliance
workflow.

**What we already have (moat).** `aibom-engine` does the hard, differentiating thing well:
discovering individual **model names** in code and config, and distinguishing *used* from *listed*
with per-evidence proof, at 79% recall / 99% precision in round 3. No free scanner and no SBOM tool
does this.

**What we lack (the product shell).** `safedep/vet` has everything else we need, as a pattern:
a staged engine, a versioned streaming report contract, a finding model with evidence + confidence +
change, delta/PR mode, a policy/gate with suppressions, state/cache with resume, and SARIF/PR
integrations. We borrow that architecture and re-point it at AI entities.

**North-star outcome.** A client runs one command in CI — or points us at a repo — and gets:
1. an accurate, evidence-backed inventory of AI **models + providers + libraries + agents + data**;
2. a *used vs listed* classification per model with proof;
3. a policy gate (approved/denied/deprecated/region/cost) with an exit code;
4. a diff of what the change added;
5. standards-aligned output (CycloneDX ML-BOM + SARIF + JSON) — **with no source code leaving the
   customer's environment.**

---

## 2. Market, problem, and pipeline position

### 2.1 Who buys this

| Persona | Job to be done | What they ask the tool |
|---|---|---|
| **AppSec / DevSecOps** | Gate AI risk in PRs | "Does this change add an unapproved model or provider? Block it." |
| **AI/ML platform engineer** | Know what models run where | "Which models are actually used vs listed in this repo?" |
| **Compliance / GRC** | Prove control under EU AI Act / NIST AI RMF | "Give me an inventory + risk register for the AI assets in this app." |
| **Security / incident response** | Find blast radius fast | "Which services use model X that just got recalled/breached?" |
| **Procurement / TPRM** | Assess third-party AI risk | "What models do our vendors' codebases reference?" |

### 2.2 The pain (why a dedicated AI BOM, not an SBOM)

1. **SBOMs inventory libraries, not models.** `package-lock.json` tells you `openai==1.x` is
   present; it never tells you the code calls `gpt-4o`, `claude-sonnet`, or a fine-tuned
   `meta-llama/...`. Models are data, not packages — they come from a config key, a string literal,
   an env var, an API call, or a prompt, not a registry entry.
2. **"Referenced" ≠ "used".** A repo full of model names in a README, a test mock, or a model-picker
   list produces a bloated, useless inventory. Clients need *used vs listed*, with proof.
3. **AI risk is a new failure class.** Unapproved provider, deprecated/withdrawn model, model that
   sends data to a disallowed region, unbounded-consumption endpoints, prompt-injection surfaces,
   unlicensed/training-data-unknown models. None of these are CVE-shaped.
4. **Governance needs a gate, not a report.** Compliance teams want a *policy* that fails the build,
   with suppressions and audit trail — exactly what SBOM tools don't provide.
5. **No code should leave the building.** AI code is sensitive. A client-facing tool must be
   local-first and prove it doesn't exfiltrate source.

### 2.3 Pipeline position

```
Developer ─▶ CI/CD ─────────────▶ Registry ─▶ Runtime
             │
             └─▶ AI BOM Engine ──▶ gate (pass/fail)
                   │                  │
                   ├─ aibom.cdx.json  ├─ SARIF (code scanning)
                   ├─ report.json     └─ PR comment / job summary
                   └─ report.md/html
```

Phase 1 target: **CI + local CLI** (repo scanning). Phase 2+: **runtime/endpoint inventory**
(what's actually deployed and configured).

### 2.4 Regulatory & standards context (verify versions before citing in docs)

- **OWASP CycloneDX ML-BOM**: CycloneDX 1.6 introduced the `machine-learning-model` component type
  and `cdx:mlbom` properties; 1.7 (2025) is the current spec and expands ML-BOM (model cards,
  dataset relationships). This is our primary output format.
- **OWASP Top 10s**: LLM Top 10 (2023, 2025 update), ML Top 10, GenAI Security, Agentic AI Security.
  These give us the *risk vocabulary* we map findings onto.
- **MITRE ATLAS**: adversarial ML threat framework — maps to our "attack" finding concept (borrowed
  from vet).
- **NIST AI RMF 1.0 + Generative AI Profile**: risk-management framing; our inventory feeds
  "Map/Measure/Manage".
- **EU AI Act** (phased 2025–2027): GPAI transparency and high-risk system risk/quality management;
  inventory + traceability is a prerequisite for both.
- **US EO 14110 / NIST**: AI governance and model-reporting pushes.

> Action: re-verify exact CycloneDX ML-BOM property names and spec version when we implement Layer
> output, against the published schema.

### 2.5 Positioning vs alternatives

| Category | Examples | What they do | What they miss |
|---|---|---|---|
| SBOM | cdxgen, Syft, Trivy | inventory *packages* | models, usage, AI policy |
| AI runtime security | Protect AI, HiddenLayer, Aim, Lasso, Lakera | scan *deployed* models/prompts | code-level model inventory + gate in CI |
| AI governance | Credo AI, RAI platforms | policy/risk register | evidence-backed *code* inventory, no code left behind |
| Supply-chain scanner | safedep/vet | packages + AI *capabilities* | individual model names/usage |

**Our wedge:** evidence-backed, policy-gated **model-level** inventory that runs in CI and emits
standards output. We are the "model layer" nobody else has, wrapped in the "product shell" vet
proved out.

---

## 3. Product definition

### 3.1 The AI BOM artifact — three layers, one document

```
┌────────────────────────────────────────────────────────────────────┐
│ AI BOM (CycloneDX ML-BOM + proprietary JSON + SARIF)               │
├────────────────────────────────────────────────────────────────────┤
│ Layer 1 — AI SOFTWARE  packages/SDKs/frameworks/MCP servers/       │
│                        agent configs/vector DBs (from manifests +  │
│                        code signatures)                            │
│ Layer 2 — AI MODELS    model IDs, providers, versions, aliases,    │
│                        usage sites, call forms (our engine)        │
│ Layer 3 — AI APP       agents, tools, prompts, guardrails, data    │
│                        flows (new)                                 │
├────────────────────────────────────────────────────────────────────┤
│ Cross-cutting: evidence, confidence, change, policy, gate,         │
│                diagnostics                                         │
└────────────────────────────────────────────────────────────────────┘
```

- **Layer 1** = `vet`'s `Capability` concept (library/SDK/agent-framework/MCP) — the *software* that
  gives the app AI ability.
- **Layer 2** = our moat — the *models* the app actually calls, with `used`/`listed`, provider,
  version, aliases, and every call site.
- **Layer 3** = the *application semantics* — agents, tools, prompt templates, vector stores,
  datasets, guardrails — the parts that make AI risk real (prompt injection, data exfil).

### 3.2 The questions the product answers (contract)

For every entity, the report must answer:

1. **What is it?** (canonical ID, name, kind, provider, version/alias set)
2. **Where is it?** (file, line, column, snippet — one evidence record per site)
3. **Is it really used?** (role: `used` | `listed`, tier: `declared` | `inferred`, per-site place:
   `live/comment/message/text/docs/test/data/output/example`)
4. **How sure are we?** (confidence, and *why*: finder, evidence count, ambiguity)
5. **What changed?** (added/modified/removed vs base ref)
6. **Does it comply?** (policy action, rule that fired, remediation, suppression)
7. **Where does it come from?** (provider registry, vendor, license, deprecation, region, cost band)

### 3.3 Example: what a client sees (PR gate)

```
$ aibom scan . --base-ref origin/main --policy .aibom/policy.yml --fail-on high
 Scanning 14,202 files (9,100 code, 3,100 config, 2,002 docs/test)
 Models found ..................... 37 (30 used, 7 listed)
 Libraries/capabilities .......... 11
 Agents/tools ..................... 3
 ── Gate ─────────────────────────────────────────────
 FAIL  policy rule no-unapproved-provider
   openai/gpt-4o  added in src/chat/client.py:42
     "client = OpenAI().chat.completions.create(model='gpt-4o')"
   → remediation: add 'openai' to .aibom/policy.yml approved_providers, or use azure-openai
 ── Summary ──────────────────────────────────────────
 12 findings · 3 block · 2 warn · 7 info
```
Exit code 1. SARIF uploaded to code scanning; PR comment explains the diff.

---

## 4. Architecture (borrowed from vet, re-pointed at AI)

### 4.1 Pipeline stages

```
source ─▶ triage ─▶ extract ─▶ find ─▶ merge ─▶ verify ─▶ enrich ─▶ evaluate ─▶ report
           files    manifests  models  canonicalize  evidence   metadata   policy+    sinks
                    + code units libs    + aliases    + role     + model    gate
                    (capabilities)        (dedupe)    + confidence  KB
```

Map to vet: `triage+extract ≈ extract`, `find+merge+verify ≈ enrich (local)`, `enrich ≈ enrich
(remote/metadata)`, `evaluate ≈ controls + finalize`, `report ≈ sinks`. We add a **find** stage vet
doesn't have (model discovery) and keep **verify** as our differentiation.

### 4.2 Plugin seams (interfaces, not implementations)

```
Source        → yields Artifact {root, kind, label, key, include, close}
Extractor     → Artifact → [Manifest | CodeUnit]   (lockfiles, pyproject, agent configs)
Finder        → (root, CodeUnits, KB) → [Finding]  (dictionary, context, shapes, callsites, ...)
Merger        → [Finding] → [Item]                 (canonicalize + alias + dedupe)
Verifier      → (Item, root) → Item + role + confidence
Enricher      → [Item] → metadata (provider/modality/version/license/region/deprecation)
Control       → (Item | App) → [Finding]           (policy-relevant findings)
Sink          → Report → bytes                      (json, cyclonedx, sarif, markdown, html, csv, pr-comment)
PolicySource  → [Rule | Suppression]
State         → scan store + cache + index          (sqlite)
```

Same optional-interface pattern as vet: a Finder may also implement `Diagnoser`; an Enricher may
implement `Preparer` (background index) or `CapabilityFinder` (Layer 1).

### 4.3 Report contract (versioned, streaming)

```jsonc
// report.json  (schema_version: "1.0.0", $schema published)
{
  "header": {
    "schema_version": "1.0.0",
    "tool": {"name": "aibom-engine", "version": "0.6.0"},
    "scan": {"id", "kind": "scan", "mode": "full|delta", "target", "target_key",
             "started_at", "base_ref", "continued"},
    "finders": ["dictionary","context","shapes","callsites"],
    "controls": [{"id","title"}]
  },
  "records": [
    {"kind":"manifest", "manifest": {...}},
    {"kind":"package",   "package": {...}},          // Layer 1
    {"kind":"capability","capability": {...}},       // Layer 1 (AI library/SDK)
    {"kind":"model",     "model": {...}},            // Layer 2  ← our entity
    {"kind":"agent",     "agent": {...}},            // Layer 3
    {"kind":"finding",   "finding": {...}},
    {"kind":"diagnostic","diagnostic": {...}}
  ],
  "trailer": {
    "summary": {"models": 37, "used": 30, "listed": 7, "capabilities": 11, "agents": 3, "findings": 12},
    "gate": {"outcome": "pass|fail|none", "rules": [], "finding_ids": []},
    "record_count": 74,
    "finished_at": "..."
  }
}
```

The record kinds are the contract. A format is a projection of the stream.

### 4.4 Core data model

```python
# finding.py — one shape for every detector's raw output (unchanged, it's good)
@dataclass
class Finding:
    tool: str
    kind: str      # model | provider | framework | agent | mcp | tool | vector_db |
                   # dataset | guardrail | service | secret | other
    name: str
    file: str; line: int; col: int
    note: str; category: str; snippet: str

# model.py — Layer 2 entity (new; replaces ad-hoc dicts in merge.py)
@dataclass
class Model:
    id: str                 # "openai/gpt-4o"
    name: str               # "gpt-4o"
    provider: str           # "openai"
    kind: str               # "model"
    mode: str               # "chat|embedding|image|audio|code|rerank|..."
    version: str | None     # resolved model version/date when known
    aliases: list[str]      # "gpt-4-0613", "gpt4", "gpt-4-turbo"
    role: str               # "used" | "listed"
    tier: str               # "declared" | "inferred" | "rejected"
    confidence: str         # "high" | "medium" | "low"
    found_by: list[str]
    evidence: list[Evidence]
    places: {"live": int, "other": int}
    change: str             # added | modified | removed | unchanged (delta mode)

@dataclass
class Evidence:
    file: str; line: int; col: int
    use: str                # live | comment | message | text | docs | test | data | output | example
    snippet: str
    via: str                # e.g. "identifier:GPT_4_O_MINI", "callsite:client.chat.completions.create"
    category: str

# capability.py — Layer 1 entity (new; modeled on vet's report.Capability)
@dataclass
class Capability:
    id: str                 # "ai.openai.client", "mcp.sdk"
    description: str
    vendor: str; product: str; service: str
    tags: list[str]         # ai, llm, agent, mcp, vectordb, ml, tokenizer
    occurrences: list[Occurrence]
    change: str

# agent.py — Layer 3 entity (new)
@dataclass
class Agent:
    id: str                 # "agent.support-bot"
    name: str
    framework: str          # langchain | llamaindex | crewai | autogen | custom
    models: list[str]       # model ids it calls
    tools: list[str]        # MCP tools / functions
    vector_stores: list[str]
    prompt_files: list[str]
    guardrails: list[str]
    change: str

# finding result (vet-shaped, for policy/gate)
@dataclass
class PolicyFinding:
    id: str
    control_id: str         # e.g. "unapproved-provider", "deprecated-model", "no-ai-policy"
    family: str             # "model" | "capability" | "agent" | "workflow"
    severity: str           # critical | high | medium | low | info
    confidence: str
    subject: str            # model/capability/agent/file id
    locus: {"path","line","snippet"}
    change: str
    title: str; description: str
    evidence: list
    remediation: {"summary","command"}
    suppression: {"reason","expires","rule"} | None
    gate: {"action","rules","broken","fail_on"} | None
```

All enums are **closed sets** with runtime validation, exactly like vet — invalid values become a
diagnostic, not a crash.

### 4.5 Failure semantics (borrowed from vet, and a differentiator)

- **Fail-open** by default: an enrichment backend that doesn't answer → diagnostic + continue.
- **Fail-closed for policy**: a policy rule that can't evaluate fails the gate (never silently pass).
- **`--strict`** turns any diagnostic into exit 3.
- **Exit codes**: 0 pass/none · 1 gate fail · 2 usage · 3 runtime/strict · 130 signal(resumable).
- **Diagnostics** are first-class records with stable codes (`extract_failed`, `enrich_unavailable`,
  `control_failed`, `unknown_ecosystem`, `base_policy_invalid`, ...).

---

## 5. Detection engines (the moat — deepen here)

### 5.1 Model discovery — current state + upgrades

We have three finders. Here is exactly how each works today and how we harden them.

| Finder | Mechanism | Strengths | Known gaps → fix |
|---|---|---|---|
| `dictionary` | literal catalog of model names over code/config | exact, high precision | neighbor-rule recall; `id` key; provider-prefixed `Literal` catalogs |
| `context` | names appearing in "model settings" (keys like `model`, `model_name`, `model_id`) | catches arbitrary/custom model IDs | `anthropic/`, `browser-use/` false positives |
| `shapes` | names matching a model-name *shape* | finds unknown/novel models | needs tighter anchoring to reduce FP |

**Upgrades to reach round-4 targets (≥85% found / ≥99% correct):**

1. **Call-site finder (new, highest value).** Instead of only matching names, parse actual client
   calls and extract the `model=` argument / positional model string:
   - `OpenAI().chat.completions.create(model="gpt-4o", ...)`
   - `Anthropic().messages.create(model="claude-sonnet-4-5", ...)`
   - `genai.GenerativeModel("gemini-1.5-pro")`
   - `BedrockClient.invoke_model(modelId="...")`
   - `ollama.chat(model="llama3.2", ...)`
   - `requests.post(".../v1/chat/completions", json={"model": "..."})`
   - This gives us *used* evidence with a call-site, not just a name — the single biggest recall
     and precision lever. Build as a lightweight per-language extractor (AST for Python/JS first,
     regex + import/namespace resolution as fallback).
2. **Neighbor rule.** When a name appears next to a strong signal (`temperature=`, `max_tokens=`,
   `top_p=`, `stream=True`), treat it as a model even if it's not in the dictionary.
3. **`id` / catalog key handling.** Recognize `"id": "gpt-4o"` and provider-prefixed `Literal[...]`
   catalogs (Python `typing.Literal["openai/gpt-4o", ...]`) — these are the registry-style-repo
   recall gap.
4. **False-positive suppression.** Fix `anthropic/` (provider prefix mis-canonicalized as a model)
   and `browser-use/` (name-shape false positive) at the canonicalization + verify layers, and add
   them as regression cases in the benchmark corpus.

### 5.2 Verification — used vs listed (our differentiation, keep and extend)

Current `verify.py` pipeline (this is good, and we keep it):

```
lexical spans (comments/strings/triple-quotes/templates)  → classify each site
  live | comment | message | text | docs | test | data | output | example
→ item tier: declared (has bare live) | inferred (only via constant) | rejected (no live)
→ covered: inferred name already declared under a fuller name → reject
→ assign_roles: used vs listed via list/table clustering (LIST_WINDOW=60, LIST_MIN=8, FILE_LIST_MIN=20)
```

**Extensions:**
- Add a **confidence** field computed from: number of independent finders, evidence count, whether
  evidence includes a call-site (high) vs only a string (medium) vs only a constant (low).
- Add a **`listed_reason`** ("in model-picker table", "in token-limit table", "in catalog file") so
  `listed` is explainable, not just counted.
- Surface **`ambiguous`** (name matches multiple providers/versions) as a distinct state, so clients
  see what a human must confirm.

### 5.3 Layer 1 — AI software capabilities (new)

Port `vet`'s capability concept with a small, high-precision signature set:

```yaml
# knowledge/signatures/ai/openai.yaml  (subset of vet's model)
signatures:
  - id: ai.openai.client
    product: OpenAI
    service: LLM client
    tags: [ai, llm]
    conditions:
      python: ["openai.OpenAI(", "openai.AsyncOpenAI(", "from openai import"]
      javascript: ["new OpenAI(", "openai.chat.completions"]
      go: ["github.com/sashabaranov/go-openai", "github.com/openai/openai-go"]
  - id: agent.langchain
    tags: [ai, agent, framework]
    conditions: {python: ["from langchain", "import langchain_core"], javascript: ["@langchain/core"]}
  - id: mcp.sdk
    tags: [ai, mcp]
    conditions: {python: ["from mcp import", "fastmcp"], javascript: ["@modelcontextprotocol/sdk"]}
```

Start with ~40 signatures (major LLM SDKs, agent frameworks, MCP, vector DBs, model runtimes), grow
from benchmark failures. Source of truth is a YAML catalog, not hardcoded code (same discipline as
vet's `aiSDKs` + signature files).

### 5.4 Layer 3 — application semantics (new, later)

- **Agents**: detect framework instantiation (`langchain`, `llamaindex`, `crewai`, `autogen`,
  `smolagents`) and associate models/tools.
- **Tools/MCP**: parse `.mcp.json`, `mcp_servers` configs, `@tool` decorators, function-calling
  schema.
- **Prompts**: locate prompt templates (`.txt`, `.md`, `prompts/`, `PromptTemplate`, system
  prompts) and flag them for secret/PII/instruction-injection review.
- **Datasets/vector stores**: dataset references (Hugging Face `datasets.load_dataset`, `HF_DATASETS`),
  vector DB clients (Pinecone, Chroma, Weaviate, pgvector, Milvus).
- **Guardrails**: NeMo, Llama Guard, Guardrails AI — flag as a distinct asset class.

This layer turns us from "inventory" into "AI application security".

---

## 6. Knowledge base & enrichment

The KB is what makes a model ID *meaningful* (risk, not just a string). Schema:

```jsonc
// knowledge/models/{provider}/{model}.json  (+ a compiled single-file cache)
{
  "id": "openai/gpt-4o",
  "name": "gpt-4o",
  "provider": "openai",
  "aliases": ["gpt-4o-2024-08-06", "gpt-4o-2024-05-13"],
  "mode": "chat",
  "modality": ["text", "image"],
  "context_window": 128000,
  "knowledge_cutoff": "2023-10",
  "status": "active | deprecated | retired | limited",
  "retired_at": null,
  "cost": {"input_per_1m": 2.5, "output_per_1m": 10.0, "currency": "USD"},
  "license": "proprietary | open (name/url)",
  "weights_url": null,
  "training_data_unknown": true,
  "data_residency": ["global"],
  "self_hostable": false,
  "capabilities": ["function-calling", "json-mode", "vision"],
  "safety": {"system_card_url": "...", "risk_tier": "standard"},
  "fingerprints": {   // detection hints consumed by finders
    "literal": ["gpt-4o", "gpt-4-0613"],
    "shapes": ["gpt-4o*"],
    "prefix": "openai/"
  }
}
```

**Enrichment sources (local-first):**
- Bundled, versioned KB shipped with the tool (offline capability — key differentiator).
- Optional remote KB refresh (`aibom kb update`) for cost/deprecation freshness.
- Provider registry calls only when the client opts in; never required; never sends source code.

**Enrichment output** feeds controls: `deprecated-model`, `unapproved-provider`, `data-residency`,
`retired-model`, `training-data-unknown`, `unbounded-consumption`.

---

## 7. Policy & gate

### 7.1 DSL (start minimal, model-specific)

```yaml
# .aibom/policy.yml
version: 1

providers:
  approved: [openai, azure-openai, anthropic]
  denied: [unknown, shadow-provider]

models:
  denied: [ "openai/gpt-4-0125-preview" ]      # retired, exact or glob
  deprecated_treat_as: warn
  require_license: false                        # when true, unknown-license models block
  data_residency: [us, eu]                      # models outside → fail

rules:
  - id: no-unapproved-provider
    when: "model.provider not in approved_providers"
    action: fail
    severity: high
    remediation: "Add the provider to .aibom/policy.yml, or migrate off it."

  - id: no-deprecated-model
    when: "model.status == 'deprecated'"
    action: fail

  - id: no-unknown-training-data
    when: "model.training_data_unknown and model.role == 'used'"
    action: warn

  - id: no-unused-capability
    when: "capability.tags contains 'mcp' and capability.change == 'added'"
    action: warn

suppressions:
  - id: "model:openai/gpt-3.5-turbo"            # or purl-ish / glob
    reason: "Legacy chat feature, EOL next quarter"
    expires: "2026-03-01"
```

**Rules engine options (decide at build time):**
- (a) **CEL** via a Python CEL lib (vet's choice — full power, harder UX), or
- (b) a **typed YAML rule set** (fewer primitives, better UX, covers 90% of AI cases), or
- (c) both: typed rules compile to CEL later.

Recommendation: **ship (b) first** (typed rules for providers/models/capabilities), add CEL in a
later phase. Rationale: our clients need provider/model allowlists and deprecation/residency rules —
not arbitrary expression power — and typed rules validate at `aibom policy validate`.

### 7.2 Gate semantics (from vet)

- `--fail-on {critical|high|medium|low|none|attacks}` adds a severity threshold.
- `--policy FILE` loads rules + suppressions.
- Suppression requires a reason, can expire, and stays in the report.
- A fail rule that errors fails the gate.
- `aibom report show last --policy FILE` re-runs policy on a saved scan (cheap iteration).

---

## 8. Delta / PR mode

```bash
aibom scan . --base-ref origin/main
```

- Requires a git working tree (we currently have **no git history** — this is a prerequisite we
  must add; use `pygit2`/`dulwich` to avoid shelling out, or `git` subprocess as a stopgap).
- Extract base tree → run the *same* finders/verifiers → diff entities:
  - model added / removed / (provider|version) modified,
  - capability added / removed,
  - agent added / removed,
  - finding on introduced content only.
- CI reads policy from the **base commit** (a PR can't disable its own controls).
- Enables the killer client feature: **"this PR adds a new model/provider — block it."**

---

## 9. State & cache

Follow vet's shape, in SQLite (`sqlite3` stdlib, no new deps):

```
~/.aibom/
  index.db          # scan index: target_key, status, gate, counts, started_at, finished_at
  scans/<id>.db     # one scan: artifacts, files, findings, models, capabilities, agents,
                    # diagnostics, header, trailer  (resumable, per-unit done marks)
  cache.db          # KB + enrichment cache, TTL
  kb/               # bundled + refreshed model knowledge base (versioned)
```

Benefits for a *client* product:
- **resume** an interrupted scan,
- **`aibom report show last`** re-render without rescanning,
- **cache** unchanged files between CI runs (huge speedup for large repos),
- **retention** by count/age/size,
- deterministic scan ID for traceability.

---

## 10. Outputs & integrations

| Format | Use | Notes |
|---|---|---|
| `json` / `jsonl` | programs | versioned schema, streaming |
| `cyclonedx` | SBOM/ML-BOM | CycloneDX 1.7: `machine-learning-model` (Layer 2), `library` + `cryptographic-asset` (Layer 1), `application` (Layer 3) |
| `sarif` | GitHub code scanning | one rule per control; findings map to file/line |
| `markdown` | job summary / comment | grouped by cause |
| `pr-comment` | one self-updating PR comment | diff vs last run |
| `html` / `csv` | humans / Excel | our existing report.py |
| `gitlab` | GitLab dependency scanning | optional |
| `plain` / `table` | grep / terminal | terminal view on stderr |

**CLI tree (target):**

```
aibom scan <target> [--base-ref REF] [--policy FILE] [--fail-on SEV]
                    [--report FORMAT=PATH ...] [--packages declared|all] [--exclude GLOB]
                    [--max-seconds N] [--strict] [--no-cache] [--resume|--fresh]
aibom policy init | validate | list-controls
aibom report show <id|last> [--policy FILE] [--report FORMAT=PATH]
aibom report schema get
aibom kb show <model> | update | list
aibom doctor                  # state/config/env health
aibom version
```

**CI integrations:**
- GitHub Action (pinned, `--base-ref`, `--policy`, SARIF upload, PR comment, step summary,
  release/package cooldowns — mirror `vet`'s Action).
- `aibom ci init` scaffolding.
- GitLab CI + Bitbucket Pipelines examples.

---

## 11. Security & privacy (table stakes for AI code)

1. **Local-first.** No source code, file paths, or model strings leave the machine by default.
2. **Offline KB.** Detection + model metadata work with no network.
3. **Opt-in remote.** KB refresh and optional provider lookups are explicit, and only send *model
   identifiers*, never source.
4. **Redaction.** Reports redact secrets; snippets are truncated and normalized (borrow vet's
   `agentconfig/redact` discipline).
5. **Path privacy.** Relative paths; option to hash filenames in exported reports.
6. **Telemetry** opt-in, minimal, and documented.
7. **Supply chain of the tool itself:** pinned dependencies, reproducible builds, signed releases,
   and our own `aibom scan` on our repo (dogfooding).

---

## 12. Evaluation & benchmark strategy (our honesty moat)

The 79%/99% numbers are our credibility. Formalize them into a regression gate.

**Metric definitions:**
- **found** (recall): of the ground-truth models in a repo, how many we emit (used+listed).
- **correct** (precision): of emitted models, how many are true positives (no FP, right identity).
- Report **per class**: by finder, by repo type (app/library/registry/agentic), by language.
- Track **false-positive classes** (provider-prefix, name-shape, test-mock, doc-mention) as named
  buckets with a regression corpus entry each.

**Corpora (mirror vet's discipline):**
- `benchmark/repos/` — curated real repos with hand-verified ground-truth AI BOMs.
- `benchmark/false_positive_corpus/` — one file per known FP class.
- `benchmark/evasion_corpus/` — obfuscated model references (constants, env vars, concatenation,
  config indirection, dynamic model routing).
- `benchmark/golden/` — golden report outputs, diffed on every change.

**The gate:** `scripts/benchmark.py` must hold or improve recall/precision before merge; the
summary is machine-readable and versioned (fix the current stale-label inconsistency).

---

## 13. Phased roadmap

Each phase ships a usable increment. "Done" = deliverable + acceptance + honest benchmark.

### Phase 0 — Foundation & contract (weeks 1–3)
**Goal:** a product-shaped skeleton with a versioned contract; kill the top false positives.
- `git init` the repo (history is now a product requirement).
- Define `report` contract + JSON schema (Section 4.3) and generate it from the model.
- Refactor pipeline into staged engine + plugin seams (`Source/Extractor/Finder/Verifier/Sink`),
  preserving behavior.
- Wire `adapters.py` into the pipeline (not just benchmark scoring).
- Fix `anthropic/`, `browser-use/` FPs; add them to the FP corpus.
- Fix `run_all.py`/`fetch_repos.py` default-path inconsistency and `summary_all.py` labels.
- **Acceptance:** `aibom scan -o json` emits schema-valid report; 92+ tests green; round-4 benchmark
  ≥79% found / ≥99% correct with the two FPs fixed.

### Phase 1 — Model layer hardening + KB + ML-BOM output (weeks 4–7)
**Goal:** recall up, model metadata, standards output.
- Call-site finder (Python/JS first) — the big recall lever.
- Neighbor rule + `id`/`Literal` catalog handling.
- Model KB (schema §6) + `aibom kb` commands + offline enrichment.
- CycloneDX 1.7 ML-BOM output (machine-learning-model + properties).
- Confidence + `ambiguous` states.
- **Acceptance:** ≥85% found / ≥99% correct on round 4; ML-BOM validates against official schema;
  KB ships bundled and works offline.

### Phase 2 — Layer 1 capabilities + combined BOM (weeks 8–10)
**Goal:** AI *software* inventory alongside models.
- Capability signatures (40 to start) + manifest extractors (pyproject/package.json/go.mod +
  `.mcp.json`/agent configs).
- Combined CycloneDX: `library` (SDK/framework) + `machine-learning-model` + `cryptographic-asset`.
- **Acceptance:** client repo shows SDKs + models in one BOM; capability FP/recall benchmarked.

### Phase 3 — Governance: policy, delta, state, CI (weeks 11–14)
**Goal:** turn the report into a gate clients run in CI.
- Policy DSL + `policy init/validate/list-controls` + typed rules + suppressions.
- Delta/PR mode (`--base-ref`) + base-policy protection.
- State/cache (SQLite) + resume + `report show last`.
- SARIF, PR comment, GitHub Action, `ci init`.
- **Acceptance:** a demo PR adding an unapproved model fails with a SARIF finding + PR comment; exit
  codes correct; resume works; policy iterates offline on saved scans.

### Phase 4 — Layer 3 application semantics + runtime inventory (weeks 15–18)
**Goal:** agents, tools, prompts, datasets; deployed reality.
- Agent/tool/prompt/dataset/guardrail detection + graph linking models→agents→tools.
- Endpoint/runtime inventory (configs on a machine/deployment, like `vet endpoint audit`).
- **Acceptance:** an agentic repo yields a model→agent→tool graph; runtime inventory shows deployed
  models not in code.

### Phase 5 — Scale, compliance packs, enterprise (weeks 19+)
**Goal:** distribution and trust at client scale.
- Packaging (pip, Docker, GitHub Action, signed releases), performance (incremental cache), large
  monorepo support.
- Compliance packs: EU AI Act / NIST AI RMF export, risk-register CSV.
- Optional SaaS: tenant policy, org KB, RBAC, audit log (only where clients want it — local-first
  remains the default).
- **Acceptance:** 100k-file monorepo scans <5 min with warm cache; compliance export maps entities
  to control requirements.

---

## 14. Risks & open questions

1. **Model KB is a moving target.** Models ship/deprecate weekly; a bundled KB ages. Mitigation:
   versioned KB + `aibom kb update` + community contribution path. Risk: maintaining freshness.
2. **Call-site parsing accuracy across languages.** Mitigation: start Python/JS, AST-first,
   fallback regex, per-language confidence.
3. **FP/recall tension.** Clients hate noise as much as misses. Mitigation: `used`/`listed` +
   confidence + `ambiguous` + suppressions; benchmark gate.
4. **Standard churn (ML-BOM).** Mitigation: emit latest spec + stable proprietary JSON; version
   the schema; keep output code isolated.
5. **Scope creep into full AI security.** We are inventory + governance, not a runtime firewall.
   Stay in the lane; partner for runtime.
6. **Distribution vs SaaS tension.** Some clients demand zero-exfil local; others want a SaaS
   registry. Decide per phase; local-first is non-negotiable.

---

## 15. Decisions

> **Locked (2026-11-03):** Python · typed YAML rules · AppSec CI gate first · CycloneDX 1.7 ML-BOM.
> See `AI_BOM_IMPLEMENTATION_PLAN.md` for the file-level build plan that follows from these.

Remaining decisions before Phase 0 code:

1. **Language/runtime.** Stay Python (fast iteration, our engine is Python, team velocity), or
   adopt Go (vet fidelity, static binary, CGO call-graph)? — *I recommend Python; we already have
   the moat there, and clients run us in CI where Python is fine.*
2. **Rules engine v1.** Typed YAML rules (recommended) vs CEL now.
3. **Output spec target.** CycloneDX 1.7 ML-BOM as primary (recommended) vs 1.6 with custom props.
4. **Distribution target.** pip + Docker + GitHub Action first (recommended), defer SaaS.
5. **First client profile.** Which persona/repo type do we nail first — AppSec CI gate, or
   compliance inventory? (This shapes Phase 0–1 ordering.)
6. **KB maintenance ownership.** Bundled + opt-in refresh (recommended) vs live lookups.

---

*This document is the plan. Implementation starts only after the decisions above are confirmed.*
