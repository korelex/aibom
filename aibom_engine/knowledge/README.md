# Knowledge Base (`aibom_engine/knowledge/`)

- **`ai_db.json`**: Compiled multi-source AI knowledge base containing:
  - `models` (4,300+ canonical AI models with maker, modalities, context window, pricing, deprecation/retirement dates, replacement suggestions, and license classification)
  - `alias_index` (7,200+ model aliases, Bedrock IDs, Vertex AI paths, and dated snapshots with `pinned` detection)
  - `packages` (135+ AI SDKs, agent frameworks, MCP packages, vector DBs, model runtimes, dataset loaders, and guardrails mapped to their code `import_names`)
  - `vulnerabilities` (440+ OSV advisories for AI packages with CVE mappings, `[introduced, fixed)` ranges, fix URLs, and extracted `affected_symbols`)
  - `licenses` (SPDX and AI model license risk classifications)
- **`curated.json`**: Human-maintained rules for licenses, AI packages, and high-priority model lifecycle/license overrides.
- **`model_names.json`**: Flat dictionary auto-generated alongside `ai_db.json` for fast token matching.

Refresh anytime with:
```bash
python scripts/build_db.py
```

Keep `ai_db.json` in its one-entry-per-line layout so that data changes can be reviewed:
`python scripts/build_db.py --reformat` rewrites it without fetching anything.

## Data sources and their terms

`ai_db.json` and `model_names.json` are derived from third-party data. Their terms apply to the derived data.

| Source | Used for | Terms |
| --- | --- | --- |
| [LiteLLM](https://github.com/BerriAI/litellm) model catalogue | model names, aliases, context windows, prices | MIT License, Copyright (c) 2023 Berri AI (files outside its `enterprise/` directory) |
| [OpenRouter](https://openrouter.ai/api/v1/models) model list | extra model IDs and Hugging Face IDs | public API; see openrouter.ai/terms |
| [OSV.dev](https://osv.dev) advisories | vulnerabilities in AI packages | each advisory keeps the license of the database it comes from; see osv.dev/docs |
| Provider documentation | lifecycle and license entries in `curated.json` | facts only, each with its `source_url` and the date checked |
