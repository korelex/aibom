# Complete project context: Korelex AI-BOM engine

This is the whole story in one place: who this is for, what was researched, how the decision was made, how the engine was designed and built, how it was tested honestly, and what state it is in today. Read this top to bottom and you have everything that was discussed, with nothing left out.

---

## 1. Who this is for, and the setup

- Bhushan Wayal, final-year IIIT Bhopal CSE, is an intern at Korelex.ai, an early-stage AI red-teaming and AI-BOM startup founded by Manish Goyal (Bengaluru). Korelex is not one of several developers' sole project; the long-term goal is a complete end-to-end AI red-teaming tool, built from small units combined later. Current scope is only SBOM and AI-BOM; other stages follow.
- Internship terms: about 15 hours a week, remote, 2 to 3 months, two weekly syncs, a task tracker, short progress updates sent as Gmail chat messages (not email, at Manish's request).
- Manish wants ONE finished prototype at a time, not a sprawl of ideas, and short honest updates rather than long reports.

---

## 2. Research phase (before any code was written)

### 2.1 Initial self-study and tool testing
About 7 hours of self-study plus a 2-page brief on SBOM and AI-BOM, aimed at answering: what are the top 5 priority SBOM problems security companies can solve.

The team tested four existing tools (Cisco's AI BOM tool, cdxgen, Trusera's `ai-bom`, aibom-scanner) against real repos, including `open-webui` and four smaller repos, and wrote up a v0.1 findings report (`SBOM_AIBOM_Initial_Findings_Report_v0.1.docx/.pdf`).

**Baseline result on open-webui (18 known model names in the repo):**
- Cisco (first pass, free mode): 5 found
- cdxgen: 2 found
- aibom-scanner: 1 found
- Trusera: 0 found
- All four tools combined: 8 of 18
- 10 of 18 found by none of them

cdxgen also listed 75 "models" on that repo, 73 of which were wrong (noise, not real model names). On the SBOM (package) side, cdxgen did not silently drop any of 1,262 npm packages, so its package-scanning is solid; its AI-BOM model detection is not.

### 2.2 Cost modeling for an LLM-assisted verification stage
Cisco's tool has an LLM-assisted stage for higher accuracy. Testing it hit practical walls: Groq's free tier allows about 8,000 tokens/minute against requests of roughly 25,000 tokens; Gemini's free tier allows 20 requests/day. Neither was usable for real testing, and a paid key was never obtained (budget was flagged as a pending need, about $50, several times through the project and still not resolved as of this writing).

Cost model built anyway, using fixed ~25,000 tokens/request as an estimate:
- A small repo (11 components): about $0.09 on GPT-6 Luna or Claude Haiku 5.5 (range $0.03 to $0.24 across cheap models), about $1.81 on Claude Sonnet 5.5.
- The whole validation program (~18M input tokens): about $2 on the cheapest models up to $39.92 on Sonnet 5.5.
- Prices used (October 2026 trade-tracker snapshot): GPT-6 Luna $0.10/$0.50 per 1M tokens, Claude Haiku 5.5 $0.10/$0.50, Gemini 3.1 Flash-Lite $0.25/$1.50, Gemini 3.8 Flash $0.75/$3.75 (noted to possibly double 1 Jan 2027), Grok 4.3 $1.25/$2.50, Claude Sonnet 5.5 $2/$10.
- Manish separately mentioned a $3,000 to $5,000 cloud budget for Gemini on GCP/AWS, for a larger production deployment, not this prototype.
- Rough effort estimate for a fuller build: about 10 person-weeks.

### 2.3 India market and regulatory research
Primary documents actually read (not just summarized secondhand):
- **CERT-In Technical Guidelines v2.0** (9 July 2025): defines SBOM as 21 fields, AI-BOM as 19 minimum elements, in CycloneDX or SPDX format. This is guidance, not binding law.
- **CERT-In guidelines for OEMs and technology providers** (10 June 2026, phrased as "advised/should", hosted copy found at Delhi IT department's site): companies should give BOMs (software, hardware, cryptographic, AI, quantum) to Indian customers and to CERT-In itself, plus a continuous security assessment report (VAPT, breach-and-attack simulation, an updated SBOM) and evidence of AI-assisted testing. Customers and CERT-In may verify. No enforcement date found.
- **NSE circular NSE/INVG/76131** (2 September 2026): vendors supplying CTCL, IBT, STWT, API or back-office software to NSE members need an STQC certificate (existing vendors by 28 February 2027, yearly re-certification from 31 March 2028 onward), must supply an SBOM at registration with specific fields (supplier, license, hash, "known unknowns", and an update requirement on every change), and must run VAPT after major releases. Correction made during the research: the 28 February 2027 date is for the STQC certificate, not for the SBOM requirement itself; an earlier draft of the India handout stated this too loosely and was caught and flagged for a fix.
- **SEBI CSCRF** (20 August 2024), cited by the NSE circular as the backing framework.
- RBI's FREE-AI report (13 August 2025) and a draft model-risk guidance (24 June 2026), plus some SEBI AI/ML references, came only from secondary sources and were never independently verified. Two secondary sources cited an RBI SBOM circular from November 2024; this was explicitly flagged as unverified and never confirmed.
- Competitors/adjacent players found in India: CyberNX NXRadar (June 2026), OpsMx, AccuKnox, Resecurity, KPMG India (on the SBOM side); Protectt.ai, Repello AI (on the AI-security side). No public AI-BOM benchmark of the kind this project built was found anywhere.
- The NSE vendor spreadsheet referenced in the circular could not be opened in the sandbox (blocked), so the actual number of affected vendors is unknown.

This research produced a 2-page discussion handout (`AIBOM_India_Discussion_Handout.docx/.pdf`) with four questions and an options table, which is what was actually sent to Manish. A longer 13-page founders' decision brief (`v0.2`) was superseded and never sent.

---

## 3. Choosing what to build: options A through D

Four options were laid out for Manish:
- **A: BOM Check, SBOM-first.** A tool focused on software bill of materials first.
- **B: CERT-In assurance pack.** A compliance/documentation product aimed at the CERT-In and NSE requirements above; essentially a sellable product wrapped around the regulations.
- **C: AI testing for banks' vendors.** Testing services aimed at the regulated-finance vendor ecosystem.
- **D: The engine only.** A standalone AI-BOM discovery and verification engine, meant as a module that plugs into Korelex's larger red-teaming tool later.

Manish's own naming differs: what he calls "A" (his label) is the AI testing module, which maps onto what the team internally called "D". This caused some naming confusion in messaging but not in the actual work.

**Decision:** proceed with option D only. Option B (the compliance pack) is parked for later, once the engine is proven; any document referencing B as current work was told to be corrected or removed. No customer interviews have been done for any option. No customer has confirmed demand for anything built so far.

Manish's instruction after this decision: build a first prototype, or at minimum a high-level design, before the next sync. Send short 1 to 2 line progress updates as Gmail chat messages, not email. Manish approved the resulting high-level design ("looks good") and the build began.

---

## 4. High-level design

The approved design (`AI_BOM_Engine_HLD.pdf` / `.png`), built as a pipeline:

```
Input (a repo)
  -> 1. Triage: sort every file into code, config, docs, test, manifest, notebook, etc.
  -> 2. Find candidates, four parallel approaches:
        A. Dictionary scan (known model names)
        B. Context rules (where a string sits: model: "x", .modelName("x"), env defaults, etc.)
        C. Manifests and config (not yet built at HLD time)
        D. Reuse of the existing four scanners as extra voters (not yet built at HLD time)
  -> 3. Merge: unify duplicate/aliased names into one item
  -> 4. Verify: decide what's really used vs. only mentioned (not yet built at HLD time)
  -> 5. AI-BOM writer: emit a standard CycloneDX file
Output: AI-BOM file(s)
(dotted line to the red-team tool, which consumes this later)
(a benchmark harness alongside, for scoring)
```

A separate, older design document (`AI_Testing_Module_Design_v0.1/v0.2`) still mentioned option B in places and was explicitly marked "do not send" once B was parked.

**Key research finding that shaped the whole approach:** scanners like Cisco's only look for AI-library calls that have a model name as a literal argument. But model names also sit in places like menu/picker lists, config defaults, and notebooks, which those tools miss. A plain dictionary of known model names, combined with rules that look at *where* a string sits (not just what function it's passed to), catches a lot more. This was validated early: on the big test repo, the best existing tool found 5 of 18 known models; the dictionary-plus-rules approach found 15 of 18, later built out fully.

The dictionary itself is built from LiteLLM's public model list (MIT license, Copyright 2023 Berri AI), which had 4,323 entries expanding to 5,969 names once provider-prefix variants are generated. This was chosen because no other usable, maintained, public list of this breadth was found. License terms were checked outside the `enterprise/` directory before use.

---

## 5. The build itself: structure and how it works today

Project root: `aibom-engine/`. Current version: **0.5.0**.

### 5.1 Code layout
- `aibom_engine/`
  - `triage.py`: sorts files into code / config / docs / test / manifest / notebook / other.
  - `finders/dictionary.py` (Finder A): scans for literal matches against the model-name dictionary.
  - `finders/context.py` (Finder B): regex-based rules for model-shaped values sitting in model-named keys, calls, env defaults, Bicep params, provider:model strings, known model-loading calls (`from_pretrained`, `SentenceTransformer`, `pipeline(task, model)`, etc.).
  - `finders/shapes.py` (Finder C, added in version 0.4.0): catches names no dictionary lists, by five general rules — (1) constants whose identifier spells the string they hold (`GPT432K0314 = "gpt-4-32k-0314"`), (2) keys learned from the file itself (if a key already holds 2+ known-looking model values in this file, treat its other values as candidates too, with a "must mostly hold models" guard), (3) bare family names under a model-named key (`model: 'llava'`), (4) version-shaped strings and Bedrock-style ids anywhere (`llama3.1:8b`, `anthropic.claude-3-haiku-v1`), (5) Bicep `@allowed([...])` lists belonging to a parameter whose name contains "model".
  - `merge.py`: unifies provider-prefixed duplicates (`openai:gpt-4o`, `gpt-4o` -> one item) via a `VENDORS` set; caps stored evidence per item at 2,000 places for names that appear thousands of times, keeping code/config evidence first.
  - `verify.py`: decides, per occurrence, whether it is "live" (real code/config), or one of: comment, message/print, docstring, test, documentation, notebook-saved-output, or (added later) inside an API-spec example block (`openapi.yaml`/`swagger.json`, detected by indentation under an `example:`/`examples:` key). Only names with at least one live occurrence are kept; everything else is marked "rejected" with a reason. Also assigns a role per item: `used` (a live place that is not inside a long table/list) vs. `listed` (every live place sits inside a long table or list of 8+ different models within 60 lines, or a file naming 20+ distinct models counts as a catalog file outright).
  - `writer.py`: emits CycloneDX 1.6, schema-validated via `cyclonedx-python-lib`, with a deterministic `uuid5` serial number and no timestamp, so output is byte-identical across runs of the same input.
  - `vendors.py`: maps a model name to its maker (OpenAI, Anthropic, Google, etc.) and its mode/type (chat, embedding, image, speech-to-text, etc.).
  - `display.py` (added in 0.5.0): the presentation layer. Merges different spellings of the same model (`gpt-4o`, `openai-gpt-4o`, `openai/gpt-4o`, `gpt-35-turbo`/`gpt-3.5-turbo`) into one display row via a `key_of()` normalizer, while the underlying AI-BOM file keeps every spelling as its own entry. This changes only what people see, never what the engine finds.
  - `report.py`: builds the readable HTML report, the markdown summary, and the CSV export, all from the same `display.py` rows.
  - `source.py`: turns a folder path, a GitHub/GitLab/Bitbucket link, `owner/repo` shorthand, or a link to one sub-folder/branch into something scannable; downloads via a shallow `git clone` with no password prompts; gives plain-English errors for bad links, private repos, no internet, no git, missing branch/folder; includes a `Linker` class that builds a link to the exact file and line on the hosting site for the commit that was actually scanned, and a `linker_for_git_folder()` helper that does the same for a local folder that is a clean git clone (no uncommitted changes).
  - `pipeline.py`: runs the whole sequence, with progress logging, a configurable time limit (default 120s) that reports itself if hit, and warnings surfaced into both the terminal and the report.
  - `cli.py`: the command-line interface (`scan`, `show`, `explain`, `report`, `rebuild`).
- `knowledge/model_names.json` + README: the dictionary.
- `benchmark/`: `repos.json` (every test repo with its pinned commit), `labels/*.json` (hand-written answer keys), `baseline/<repo>/` (raw output of the four existing scanners), `score.py` (the scorer), `summary_all.py` / `check_roles.py` (aggregate views), `RESULTS.md` (the full honest write-up, appended to at every round, never edited away), `stress_test.md`, `round3_frozen/` (fingerprints proving the round-3 keys were written and the engine frozen before it ever saw those repos).
- `scripts/`: `preflight.py` (10-minute pre-meeting check), `setup_check.py`, `fetch_repos.py` (clones every pinned test repo), `run_all.py`, `compare_runs.py` (diffs two snapshots of engine output to prove nothing regressed), `stress_test.py` (scans a list of real-world links to check for crashes/speed, not accuracy), `build_dictionary.py`.
- `tests/`: 92 automated tests (`python -m unittest discover -s tests`), covering finders, merge, verify, the CycloneDX writer, link building, the display layer, the HTML/CSV/markdown report, the CLI commands, edge cases (empty folders, binary files, odd filenames, zero time limit, a file instead of a folder, nonsense input), and a from-scratch git-repo download test.
- `runs/`: saved scan output for all 17 test repos, used as "plan B" demo material when there's no internet.
- `docs/`: the HLD PDF/PNG and three screenshots of the current report.
- `demo/`: everything needed to run or record a demo (see section 8).

### 5.2 What the engine actually does, end to end
1. Point it at a folder or a link: `python -m aibom_engine scan <source> --out <dir>`.
2. It downloads (if a link), sorts every file, runs the three finders, merges duplicate spellings, verifies each occurrence as live or not, assigns a role (used vs. listed), and writes out:
   - `aibom.cdx.json`: the standard, schema-validated AI-BOM.
   - `report.html`: a readable page — headline sentence, three big numbers (used / only listed / left out), models grouped by maker, a search box, a Confirmed/Worked-out confidence badge per model, a clickable file:line link per place (to the exact commit scanned, on GitHub/GitLab/Bitbucket), a "Left out, and why" section, and a "What this scan cannot see" limits box. Black and white, prints cleanly, works with no internet, fits a phone-width screen.
   - `report.md`: the same content in plain markdown, with a one-line pasteable summary at the top.
   - `models.csv`: a spreadsheet export (UTF-8 with BOM, so Excel reads it correctly).
   - `merged.json`, `manifest.json`, `findings.json`, `files.json`: the underlying data.
3. `show` prints a plain terminal list (most important first, with `--all`, `--left-out`, `--item NAME` variants); `explain RUN MODEL` answers "why is this model here, and how sure are we", listing every live place with its link; `rebuild` regenerates the readable outputs from saved data without re-scanning (useful after a display-layer change).

---

## 6. Benchmarking methodology (the discipline that keeps the numbers honest)

This is the part that matters most if anyone questions the results, so it is laid out in full.

### 6.1 The core rule
For every claim of "the engine finds X% of real models on repos it has never seen":
1. **Write the answer key first**, by reading the actual code, before running the engine on that repo.
2. **Re-check the key a second way**, using independently written search patterns, different from whatever the engine's rules do.
3. **Freeze the engine's code** (recorded as a source fingerprint, a SHA-256 hash of every detection-relevant file) before it is ever run on those repos.
4. **Run once.** Score against the key.
5. **Label anything the engine reports that the key didn't cover**, from the actual code lines, using the same standard for every tool (not just the engine).
6. **Once the engine is changed to fix something found in that round, those repos are no longer "unseen."** Any new claim needs a new set of repos with keys written first, again.

This cycle happened three times (see 6.3). Every round's results live permanently in `benchmark/RESULTS.md`, appended to, never overwritten, including the honest "why it falls short" sections.

### 6.2 Regression protection
Every time detection code changed, the full set of previously-tested repos was re-run and diffed against a saved snapshot (`scripts/compare_runs.py`) to prove nothing that used to be found stopped being found. When the presentation layer (0.5.0) was polished, a separate "detection fingerprint" (hash of only the finder/triage/merge/verify/vendor/dictionary files) was taken before and after, and shown to be byte-identical, proving the polish changed only what people see, never what the engine finds.

### 6.3 The three rounds

**Round 1 — three repos, used to build the first working engine (chat-langchain, chatbot-ui, ai-chatbot).**
- chat-langchain (the repo the rules were tuned on): engine found 3 of 3 models (100%, versus the four existing tools' 1 of 3 together).
- chatbot-ui (first "blind" repo, but rules were refined after seeing its results, so not clean): engine found 33 of 33 models (100% correct) versus the four tools' 33 of 33 but only 69% correct (lots of junk).
- ai-chatbot (a genuinely held-out check: models found before any rule change, then two general fixes applied afterward): engine found 5 of 5 (100%); all four existing tools combined found 0 of 5.

**Round 2 — four fresh repos, the first real "unseen" test (go-openai, azure-search-openai-demo-csharp, ollama-js, open-canvas), engine frozen as v0.2.0/v0.2.1.**
- Honest average: engine found about 72% of real models, about 98% of its reports were correct; best existing tool per repo found about 30%.
- Failures found and documented: Java method-call style (`.modelName("x")`) and enum constants (`GPT_4_O_MINI`) entirely missed; Azure Bicep infrastructure files not scanned at all; wrong reports came from commented-out code and stored evaluation-result files, because the Verify step didn't exist yet in its final form.
- A general fix for test-file recognition (`*_test.go`, `*Test.java`, etc.) was added afterward (v0.2.1); an early version of this rule wrongly treated Java example classes as tests and was caught by the regression check (langchain4j-examples recall dropped from 30/31 to 23/31), then fixed to use folder location instead of filename pattern for Java/Kotlin.

**Round 3 — five fresh repos in different languages (fragments/TypeScript, simonw/llm/Python, MacPaw/OpenAI/Swift, anthropic-quickstarts/Python+TypeScript, browser-use/Python), engine frozen as v0.4.0 after adding the shapes finder (built using only the round-1/round-2 repos) and the API-spec-example Verify rule.**
- Keys written first, fingerprinted, re-checked a second way; one wrong commit hash in a key was caught and corrected before scoring.
- Results: fragments 41/62 (66%), llm 41/47 (87%), OpenAI/Swift 127/132 (96%), anthropic-quickstarts 15/22 (68%), browser-use 234/312 (75%). **Average: 79% found, 99% of reports correct.** Best free scanner per repo averaged about 10% (ranging 2% to 23%).
- Of 38 names the engine reported beyond the keys: 32 were real (keys had missed them) and 6 were genuinely wrong (two aliases, a provider prefix fragment, a message string, two underscore fragments), all labeled honestly after the fact.
- Of 117 misses: 114 were never found at all, 3 were found but incorrectly rejected (2 as "comment", 1 as "test").
- Known remaining gap, explicitly documented, not yet fixed: unknown model ids sitting inside long lists, JSON catalogs, or used as dictionary keys (for example browser-use's 241-entry model gateway list, or Claude ids used as dict keys in anthropic-quickstarts); the learned-key rule deliberately excludes the key name `id`, which alone cost fragments 21 models. The planned fix is a "neighbor" rule (accept a model-shaped string sitting beside two or more already-known models) — not built, would need yet another fresh-repo round to test honestly.

### 6.4 What never changed across all this
Four free/open tools were used as the baseline throughout: Cisco's AI-BOM tool (first-pass/free mode only — its stronger mode needs a paid key that was never obtained), cdxgen, Trusera's `ai-bom`, and aibom-scanner. They consistently found far fewer real models and, except for cdxgen on some TypeScript-heavy repos, reported more junk.

---

## 7. The "polish" phase (most recent work)

Explicitly split into two concerns that were never allowed to blend:
- **Detection** (what the engine finds) — governed by the strict benchmarking discipline above.
- **Presentation** (what a person reads) — could be changed freely, verified only by re-running all 17 saved repos and confirming identical output.

### 7.1 Version 0.3.0 — ready for a live demo on any repo
- `scan` accepts a GitHub/GitLab/Bitbucket link (or `owner/repo`, or a link to one sub-folder/branch) as well as a local folder; downloads a shallow clone, scans, deletes the clone.
- Progress lines printed at every step; a configurable time limit that says plainly when it was hit; plain-English errors (no tracebacks) for a wrong/private link, missing git, no internet, a file given instead of a folder.
- The "used directly" vs. "only listed in tables" split was introduced here, fixing a real problem: open_deep_research's report used to say "42 models are used in the code" when only about 9 are genuinely used and the other 33 are entries in a token-limit lookup table.
- `scripts/preflight.py` added, for a ten-minute pre-meeting sanity check including whether GitHub is reachable.
- Verified via: 52 tests, an 11-case stress test (huge repos to deliberately broken links), six edge cases, and a spot-check of random results by reading the actual lines, which caught large data files in langchain being wrongly counted as "used" (fixed with the 20-models-per-file catalog rule).

### 7.2 Version 0.4.0 — finds more (the shapes finder, round 3 above)
Covered fully in section 6.3.

### 7.3 Version 0.5.0 — readable and useful, the most recent work
- The HTML report was rebuilt from scratch around the test "can someone who has never heard of an AI-BOM understand it in 30 seconds": headline sentence, three big numbers, models grouped by maker (biggest group first), a live-filtering search box, Confirmed/Worked-out confidence badges with tooltips explaining what each means, a clickable link on every file:line that opens that exact line on the code-hosting site for the exact commit scanned, a "Left out, and why" collapsible section, and a "What this scan cannot see" limits box that states plainly: it cannot see a model chosen at run time, it only covers one repository, it covers models only (not agents/tools/vector-databases/frameworks yet), and it restates the tested accuracy (79% found, 99% correct, free scanners about 10%).
- A markdown summary and a CSV export were added, built from the same underlying rows as the HTML, so all three outputs always agree.
- The terminal `show` command was rewritten to list the most important models first, with `--all`, `--left-out`, and `--item` views; a new `explain RUN MODEL` command answers "why is this here and how sure are we" with every live location and its link; `rebuild` regenerates the readable files from saved data without re-scanning.
- Different spellings of the same model (`gpt-4o`, `openai-gpt-4o`, `gpt-35-turbo`/`gpt-3.5-turbo`) are now shown as a single row with "also written as," purely in the display layer; the underlying `aibom.cdx.json` still records every spelling as its own entry.
- Links were also added for local folders, but only when the folder is a clean git clone with no uncommitted changes, specifically to avoid showing a link whose line numbers might not match what is actually on screen.
- A warning banner was added to both the HTML and markdown outputs for any scan that hit its time limit before finishing, so a demo never silently shows an incomplete result as if it were final.
- Verified via: a detection-fingerprint comparison (identical before and after, proving zero change to what is found), all 17 saved repos re-scanned and diffed as identical, 92 automated tests (now also confirmed passing on a real, freshly installed Python 3.9, not just the development environment), the report opened in an actual browser via Playwright to test the search box and a phone-width viewport, and HTML-escaping of names tested against a deliberately malicious model name containing a script tag.
- A real cost of this version, found and documented rather than hidden: the new shapes finder roughly doubles to triples scan time on very large or notebook-heavy repos (the `transformers` repo: about 32 seconds without it, 66 to 95 seconds with it, depending on machine load; `litellm`, a huge model catalog, takes about two minutes total). Most ordinary app repos still finish in 5 to 40 seconds. This tradeoff was accepted deliberately, per instruction, in favor of being understandable and useful over being fast.

---

## 8. What exists right now for demoing or handing off

- `demo/TUTORIAL.md`: the complete step-by-step guide — setup, every command with its real captured output, how to read every part of the report, a 6-minute running order for a meeting, a table of exactly what was polished and how it was checked, honest numbers and hard-question answers, and a troubleshooting table.
- `demo/LIVE_MEETING_GUIDE.md`: a one-page version to keep open during an actual meeting, including a "plan B" using the 17 saved repos if there's no internet.
- `demo/run_demo.sh` and `demo/run_demo.ps1`: guided scripts (Mac/Linux and Windows) that pause before each command so the person running it can talk first.
- `demo/RECORDING_GUIDE.md` and `demo/voiceover_script.md`: for recording a standalone demo video.
- `docs/images/`: three real screenshots of the current report (top/headline, search in action, left-out section and limits box).
- `AI_BOM_Engine_Demo.mp4` (in the outputs folder, not inside the zip): an older video made for version 0.1's command set; every document now explicitly warns not to use it for a live meeting because the commands have changed.
- The full project is packaged as `aibom-engine.zip`, tested by unzipping into an empty folder, building a brand-new Python 3.9 virtual environment from `requirements.txt` alone, and running the guided demo (including a live scan of a real GitHub link) end to end successfully.

---

## 9. Everything still open, stated plainly

- **Scope:** AI models only. Agents, tools, vector databases, AI frameworks are not covered (this was Finder C/D in the original HLD and is explicitly future work).
- **Accuracy ceiling:** 79% found on the last honest fresh-repo round, with a known, documented failure pattern (unknown ids inside long lists/catalogs/dictionary keys) and a known fix (the "neighbor" rule) that has not been built or tested.
- **Verification depth:** Verify currently distinguishes live code from comments/tests/docs/messages/spec-examples; it does not yet use any LLM-assisted check. The plan (from the very first cost-modeling work) was to use a cheap model only on genuinely unclear items; this still needs a paid key (~$50 ask, outstanding since the research phase).
- **Answer-key integrity:** every key across all three rounds was written by Claude from the code, re-checked a second way, but never reviewed by an independent human. This is stated in every results write-up and every demo guide, deliberately, so it's never implied as independently verified.
- **No customer validation:** no interviews, no confirmed buyer, for either option D (the engine) or the parked option B (the CERT-In compliance pack).
- **Unresolved asks to Manish, still outstanding as of this document:** whether a model that only appears as a selectable UI option/agent tool/AI framework should count as an AI-BOM item (engine currently assumes yes); whether he has his own AI app repo to use as a genuinely fresh test case; a second person to review the answer keys; the ~$50 paid-API budget; and priority direction after the current polish — Finder C/D (frameworks, agents, tools, vector databases, MCP) versus further accuracy rounds versus the parked compliance pack (option B).
- **Housekeeping carried over from the very first sessions and never actioned:** an exposed Groq API key from early testing was flagged for rotation and, as far as this record shows, never confirmed rotated; the exact NSE vendor count was never obtained because the sandbox could not open NSE's vendor spreadsheet; the secondary-source claim of an RBI SBOM circular from November 2024 was never independently verified.

---

## 10. One-paragraph version, if you only need to say one thing

Korelex needed to know which AI models an app actually uses before it can be red-teamed or documented for compliance, and the free tools available (Cisco, cdxgen, Trusera, aibom-scanner) catch only a fraction of them with a lot of noise. After researching the India regulatory landscape (CERT-In, NSE, SEBI, RBI) and comparing four possible products, Manish chose to build just the detection engine first (option D), with the compliance product (option B) parked for later. The engine was designed, built, and benchmarked honestly in three rounds against repos it had never seen, with answer keys always written before it was run and the engine always frozen before each test: it currently finds about 79% of real AI models in unfamiliar code, with about 99% of what it reports being correct, versus roughly 10% for the best free alternative. It was then polished into something presentable in both a terminal and a browser, with clickable proof for every result, without changing a single thing about what it actually detects, and packaged with a full tutorial so it can be demoed live on any repository someone names in a meeting. It covers AI models only; everything else (agents, tools, vector databases, frameworks, a compliance layer, LLM-assisted verification) is deliberately still ahead.
