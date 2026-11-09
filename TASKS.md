# aibom — Task List & Progress

## Milestone 1 — Honest beta (due 13 Nov 2026)

Outcome: an "AI Model Inventory" beta that pilot users can try, where every claim is true and the risk data is visible.

- [x] **M1.1** Rewrite the README to match today's tool.
- [x] **M1.5** Fix the vulnerability count mismatch (`ai_advisories` vs `ai_vulnerable_packages`).
- [x] **M1.6** Make it installable (`pyproject.toml`, `aibom` console command, plain `pytest`).
- [x] **M1.2** Show lifecycle and license risk in every human output (Status, Pinned, Deprecation date, Replacement, License columns + Risks summary).
- [x] **M1.3** Fix canonical IDs coming from reseller prefixes (`vercel-ai-gateway/...`, `nscale/...`); prefer first-party provider entries; test 20 common models.
- [ ] **M1.4** Fill license gaps for the 50 most-used open models in `curated.json`, with source URL and date checked.

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

- **2026-11-09** — M1.1, M1.5, M1.6 complete. PR [#1](https://github.com/korelex/aibom/pull/1) opened. `python -m pytest` → 102 passed. `pip install -e .` → `aibom` console command works. `aibom scan` on the test app → 5 models, exit 0, valid CycloneDX 1.6.
- **2026-11-09** — M1.2 complete. CSV/Markdown/HTML now show status, pinned, deprecation date, replacement and license; HTML and Markdown lead with a Risks block. Added `tests/fixtures/review-app/` and `tests/test_risk_report.py`. `python -m pytest` → 106 passed. Review app: Claude 3.5 Sonnet 20240620 is deprecated with replacement `claude-sonnet-4-5`; `gpt-4o` is flagged as floating.
- **2026-11-09** — M1.3 complete. `build_db.py` now unwraps gateway/reseller prefixes and infers the first-party maker from the model name, with a curated `maker_segments`/`gateway_prefixes` registry in `curated.json` and an alias-collision priority (curated > first-party > reseller). `vercel-ai-gateway/.../text-embedding-3-small` → `openai/text-embedding-3-small`; `nscale/nscale/stabilityai/...` → `stabilityai/...`. Canonical models consolidated 4,687 → 3,029. Added `tests/test_canonical_ids.py` (22 identifiers). `python -m pytest` → 108 passed.
