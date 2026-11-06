# Knowledge Base (`knowledge/`)

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
