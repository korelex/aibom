# aibom — Task List & Progress

## Milestone 1 — Honest beta (due 13 Nov 2026)

Outcome: an "AI Model Inventory" beta that pilot users can try, where every claim is true and the risk data is visible.

- [x] **M1.1** Rewrite the README to match today's tool.
- [x] **M1.5** Fix the vulnerability count mismatch (`ai_advisories` vs `ai_vulnerable_packages`).
- [x] **M1.6** Make it installable (`pyproject.toml`, `aibom` console command, plain `pytest`).
- [x] **M1.2** Show lifecycle and license risk in every human output (Status, Pinned, Deprecation date, Replacement, License columns + Risks summary).
- [x] **M1.3** Fix canonical IDs coming from reseller prefixes (`vercel-ai-gateway/...`, `nscale/...`); prefer first-party provider entries; test 20 common models.
- [x] **M1.4** Fill license gaps for the 50 most-used open models in `curated.json`, with source URL and date checked.

## Milestone 2 — Packages, SDKs and vector databases (due 27 Nov 2026)

Outcome: the AI-BOM lists every AI SDK, agent framework and vector database with evidence levels, and the vulnerability data is used.

- [ ] **M2.1** Read manifests and lockfiles (Declared).
- [ ] **M2.2** Find imports in live code (Imported).
- [ ] **M2.3** Find calls and instantiations (Called), signatures in YAML rules.
- [ ] **M2.4** Switch to the spec's evidence levels + `reachability: not_verified`.
- [ ] **M2.5** Match AI-package vulnerabilities with advisory, severity, fixed version and evidence level.
- [ ] **M2.6** Add SDK/framework components to the CycloneDX output.
- [ ] **M2.7** Extend benchmark labels for packages; report package precision and recall separately.

## Milestone 3 — MCP, secrets, unsafe models and CI (due 4 Dec 2026)

- [ ] **M3.1** Parse MCP configs and MCP SDK usage.
- [ ] **M3.2** Flag risky MCP configs (shell/exec, broad paths, secrets, unpinned `npx`/`uvx`, plain HTTP).
- [ ] **M3.3** Detect hardcoded AI provider keys; mask values everywhere.
- [ ] **M3.4** Flag unsafe model loading (ModelScan if installed; pickle formats; `trust_remote_code=True`; `torch.load` without `weights_only=True`).
- [ ] **M3.5** Severity and one-line fix text on every flag; Risks summary in HTML.
- [ ] **M3.6** Exit codes and `--fail-on`.
- [ ] **M3.7** GitHub Action (`korelex/aibom-action`).
- [ ] **M3.8** Performance: 200k-line repo under 60 seconds; record the result.

## Milestone 4 — KorelexOne integration (due 18 Dec 2026)

- [ ] **M4.1** Privacy defaults: no full code lines in `aibom.cdx.json`; snippets only with `--include-snippets`; secrets never written.
- [ ] **M4.2** Move to the `korelex:` schema and add repo/branch/commit/release/CI metadata.
- [ ] **M4.3** Login and upload (`aibom login`, `aibom scan --upload`); handle 201/401/413/429; token as a secret, OIDC later.
- [ ] **M4.4** No network calls without a flag; prove with a socket-blocking test.
- [ ] **M4.5** CERT-In readiness score (needs the CERT-In field mapping table from product).
- [ ] **M4.6** "What aibom sends" page with an example upload payload.
- [ ] **M4.7** Pilot run: 5 repos end to end with no blocker bugs.

## Progress log

- **2026-11-09** - M1.1, M1.5, M1.6: the README describes only what ships, the database counts are labelled (`ai_advisories` vs `ai_vulnerable_packages`), and `aibom` installs as a console command. Review found that a normal `pip install .` crashed because the database was not packaged; it now lives inside the package and a wheel smoke test (`scripts/smoke_wheel.py`, run in CI) installs the built wheel in a clean virtualenv and scans with it.
- **2026-11-09** - M1.2: CSV, Markdown and HTML show status, pinned, floating alias, deprecation and retirement dates, replacement and license, with a Risks block at the top. After review: status is worked out from dates on the day of the scan (a past retirement date is `retired`), only records with a source URL count (everything else is `not tracked`), a name is a floating alias only when a dated snapshot exists to pin, and Hugging Face repo ids are reported separately. In the review app `claude-3-5-sonnet-20240620` is retired (2025-10-28) with replacement `claude-sonnet-5-5`, per Anthropic's deprecations page.
- **2026-11-09** - M1.3: reseller and gateway prefixes (`vercel-ai-gateway/...`, `nscale/...`) resolve to the maker's canonical id; first-party entries win alias collisions (curated > first-party > reseller). `tests/test_canonical_ids.py` covers 22 identifiers. Upstream catalogue lifecycle dates are no longer used: they mixed up deprecation with earliest-retirement dates (for example, an active model appeared as deprecated). Lifecycle is now stored per snapshot from provider pages (`lifecycle_records` in `curated.json`, 44 records covering 81 names), each with a source URL and the date it was checked, and a snapshot that no record lists stays `not tracked`.
- **2026-11-09** - M1.4: curated license records for the 50 most-used open models (Llama 2/3/3.1/3.2/3.3, Mistral, Mixtral, Gemma, Qwen 2.5, Stable Diffusion, Falcon, DeepSeek, Phi, sentence-transformers, BGE, Command R+), each with the license name, a commercial-use flag, a source URL and the date checked. `meta-llama/Llama-2-7b-hf` shows the Llama 2 Community License as conditional. After review, models sold under a provider's API terms are labelled "Provider API terms", never "non-commercial".
