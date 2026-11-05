# Results so far: model detection (steps 1 to 4)

Models only, because only the model finders exist so far (Finder A dictionary scan, Finder B context rules).
Cisco is its first pass only. Answer keys are drafts written by Claude from the code (ai-chatbot: models only). Run 28 Oct 2026.

## chat-langchain (tuning repo)

| Method | Real models found | Reported models | Correct |
|---|---|---|---|
| cisco | 1 of 3 | 1 | 1 (100%) |
| cdxgen | 1 of 3 | 3 | 1 (33%) |
| trusera | 0 of 3 | 1 | 1 (100%) |
| aibom-scanner | 0 of 3 | 0 | n/a |
| all four baseline tools | 1 of 3 | 4 | 2 (50%) |
| **engine: Finder A only** | **3 of 3** | 4 | 4 (100%) |
| **engine: Finder A + B** | **3 of 3** | 4 | 4 (100%) |

## chatbot-ui (first blind repo; finder rules were refined after seeing its results)

| Method | Real models found | Reported models | Correct |
|---|---|---|---|
| cisco | 3 of 33 | 6 | 5 (83%) |
| cdxgen | 33 of 33 | 73 | 48 (66%) |
| trusera | 0 of 33 | 8 | 7 (88%) |
| aibom-scanner | 2 of 33 | 2 | 2 (100%) |
| all four baseline tools | 33 of 33 | 83 | 57 (69%) |
| **engine: Finder A only** | **17 of 33** | 24 | 24 (100%) |
| **engine: Finder A + B** | **33 of 33** | 43 | 43 (100%) |

## ai-chatbot (held-out check; models found before any change, two general fixes made afterwards)

| Method | Real models found | Reported models | Correct |
|---|---|---|---|
| cisco | 0 of 5 | 2 | 0 (0%) |
| cdxgen | 0 of 5 | 6 | 0 (0%) |
| trusera | 0 of 5 | 0 | n/a |
| aibom-scanner | 0 of 5 | 0 | n/a |
| all four baseline tools | 0 of 5 | 7 | 0 (0%) |
| **engine: Finder A only** | **5 of 5** | 5 | 5 (100%) |
| **engine: Finder A + B** | **5 of 5** | 5 | 5 (100%) |

## What we learned
- A dictionary alone is fresh-list dependent: on the 2024 repo it missed 16 of 33 models because LiteLLM has dropped retired models (claude-2.1, gemini-pro, gpt-4-turbo-preview). Context rules (Finder B) recover them.
- The baseline tools find models only where they sit inside an SDK call they know. On ai-chatbot (Vercel AI SDK with gateway ids like openai/gpt-oss-120b) none of the four found any of the 5 models.
- Merging provider-prefixed names (deepseek/deepseek-v3.2 and deepseek-v3.2) and treating *.mock.* files as tests were needed and are general fixes.
- 13 automated tests protect the rules (python -m unittest discover -s tests).

## Caveats
- Models only. Providers, frameworks, agents, tools, MCP and vector databases are not found yet (Finders C and D).
- Answer keys are written by Claude and still need a human review. Keys can be incomplete (one real model was missing in the first draft).
- The rules were refined after seeing chatbot-ui and ai-chatbot, so those are no longer blind. A fourth, unseen repo is needed for the final claim.
- Three repos, all TypeScript or Python. Nothing is claimed for Java, Go or C#.

# Round 1 on UNSEEN repos (engine frozen; keys written from the code before the engine ran)

Models only. Engine = Finders A + B, files in code, config, manifest or notebook (tests and docs excluded). Run 29 Oct 2026.
Every key item was re-checked by a second pass (literal text found outside tests and docs). Names the tools reported that the key did not cover were labelled from the actual lines, the same way for every tool.

| Repo | Language | Key items | Engine found | Engine correct of reported | Best baseline tool found | Best baseline correct of reported |
|---|---|---|---|---|---|---|
| open_deep_research | Python | 4 | 4 (100%) | 42 of 43 (98%) | cdxgen: 1 (25%) | 1 of 7 |
| langchain4j-examples | Java | 31 | 11 (35%) | 23 of 25 (92%) | aibom-scanner: 1 (3%) | 1 of 1 |
| bedrock-claude-chat | TypeScript + Python | 70 | 68 (97%) | 73 of 73 (100%) | cdxgen: 58 (83%) | 35 of 43 |
| azure-search-openai-demo | Python + TypeScript + Bicep | 5 | 4 (80%) | 6 of 11 (55%) | cdxgen: 1 (20%) | 2 of 5 |

Average over the 4 repos: engine finds 78% of key items with 86% of its reports correct; the best single baseline tool per repo finds 33%.

## Why it falls short (failures of the frozen engine)
- Java: 7 of 18 string-named models missed. The rules look for `model: "x"` and `model = "x"`, not method-call style `.modelName("x")`. All 13 enum-named models (GPT_4_O_MINI) are missed: no string to find.
- Azure: models set in infra/main.bicep are missed (Bicep files are not scanned).
- Wrong reports, all on the not-yet-built Verify step: commented-out lines (3 repos), a println text, a folder name, and stored evaluation results (evals/results/*.json).
- The baseline tools do well only where their SDK knowledge fits: cdxgen on the TypeScript model lists in bedrock-claude-chat (83% found, 81% correct). On Java they find about nothing. Cisco had not finished on the two largest repos.

## Fix list (general, to be tested on a NEW set of unseen repos, not these)
1. Method-call style rule: `.modelName("x")`, `setModel("x")`, `withModelId("x")`.
2. Enum-constant match: squash GPT_4_O_MINI to gpt4omini and match squashed dictionary names.
3. Scan infrastructure files: .bicep, .bicepparam, .tfvars, Helm values.
4. Verify step: reject names that appear only in comments, print/echo/log strings, and paths.
5. Triage: label results/, output/, snapshots/ folders as stored data, not configuration.
6. Later stage: a plain-language readable report built from the AI-BOM (the CycloneDX file stays exactly as it is).

## Caveats
- Four repos; Java is the weak spot. Keys are written by Claude. Items outside the key were labelled after seeing them, by the same rule for every tool.
- After the fixes these four repos are no longer unseen. The next claim needs fresh repos.


# Version 0.2: Verify step, readable report, fixes, and round 2 on fresh apps

What changed in the engine (v0.2.0): file triage knows infrastructure files (Bicep, Terraform variables) and stored-results folders; Finder A matches models written as constants
(GPT_4_O_MINI) and no longer reads `results/gpt-4o` as a model; Finder B reads method-call style (`.modelName("x")`), unquoted config values and Bicep parameters, and only accepts
keys that end in model, model-name or model-id; a Verify step rejects names that appear only in comments, printed or error messages, docstrings, docs, tests or stored data;
the AI-BOM lists only verified models, each with its maker and type; a readable report (report.html and report.md) is written next to the AI-BOM. 32 automated tests.

Round 2 protocol: five apps the engine had never seen (Go library, C# app, TypeScript library, TypeScript app, Python app with no models in code). The answer keys were written from the code
before the engine ran, each key item was checked to exist in the repo, and the engine's source fingerprint was identical before and after the runs (nothing was tuned).
Names reported by a tool that were not in my key were labelled from the actual lines, the same way for every tool.

```
A. FRESH APPS: the engine was frozen when these were tested
app                                real models   engine finds  engine correct      best other tool finds
go-openai                                  131     103 ( 79%)            93%      aibom-scanner: 1 (1%)
azure-search-openai-demo-csharp              7       6 ( 86%)           100%             cisco: 2 (29%)
ollama-js                                   13       9 ( 69%)           100%            cisco: 10 (77%)
open-canvas                                 27      15 ( 56%)           100%             cisco: 4 (15%)
average                                                   72%             98%                        30%

B. APP WITH NO MODELS NAMED IN ITS CODE (private-gpt): 17 names looked like models; 16 correctly left out (docs, tests, docstrings); 1 false alarm(s)

C. APPS USED TO BUILD THE FIXES: results are no longer independent
app                                real models   engine finds  engine correct      best other tool finds
open_deep_research                           4       4 (100%)           100%            cdxgen: 1 (25%)
langchain4j-examples                        31      30 ( 97%)           100%      aibom-scanner: 1 (3%)
bedrock-claude-chat                         70      68 ( 97%)            99%           cdxgen: 58 (83%)
azure-search-openai-demo                     5       5 (100%)           100%            cdxgen: 1 (20%)
average                                                   98%            100%                        33%

average on fresh apps: engine finds 72% of the real models, 98% of what it reports is correct; best other tool finds 30%
```

## What the fresh-app results show
- Fresh apps: the engine finds 72% of the real models on average and 98% of what it reports is correct. The best other tool finds 30% (Cisco first pass included, which is the best of the four on two of the apps).
- Cisco's first pass is 100% correct on the Ollama TypeScript library and finds 10 of 13 where the engine finds 9. It is far behind on every other app. Adding Cisco's findings to ours (simulated) raises the average only from 72% to 74%.
- private-gpt names no model in its code (it discovers models at run time). 16 of 17 candidate names were correctly left out; one false alarm: `"model": "private-gpt"` in an OpenAPI example.
- The apps marked "used to build the fixes" show 97% to 100%, but they are the apps the fixes were made against, so they are not independent evidence.

## Why it misses things (all found on the fresh apps, not yet fixed)
1. Names LiteLLM has dropped (davinci, curie, text-moderation-*, gpt-4-32k-0314, gemini-1.5-flash, claude-3-haiku): the dictionary cannot know them.
2. Models listed under a plain `name:` key (open-canvas) or passed as a function argument (`run('mistral')`): Finder B only trusts keys that end in model.
3. Very short or single-word names (o1, o3, llava, mistral): ignored on purpose to avoid false alarms.
4. Go test files (`*_test.go`) are not recognised as tests, so model names inside them count as live (7 of the 8 wrong reports on go-openai).
5. Strings inside a Bicep `@allowed([...])` list (gpt-4-16k) are not read.
6. An OpenAPI example value looked like a model (`"model": "private-gpt"`).

## Fix list for round 3 (to be tested on a NEW set of fresh apps)
- Learn the model key from the file: if a file has `name: "gpt-4.1"` and `name: "claude-3-5-haiku"` style entries, treat every value under that key in the file as a model candidate when it has a model shape.
- Accept strings that start with a known model family and have a version shape (llama3.2-vision, llama3.1:8b), anywhere in code.
- Self-describing constants: `GPT432K0314 = "gpt-4-32k-0314"` where the identifier squashes to the string.
- Recognise `_test.go`, `*Test.java`, `*.Tests` projects and similar as tests.
- Read Bicep `@allowed` arrays; ignore example payloads in OpenAPI files.

## Caveats
- Models only. Answer keys are written by Claude, and my keys were incomplete in places (the engine found 9 real models I had missed on the fresh apps), so recall figures are against my keys.
- Five fresh apps, mostly well-known open source projects; nothing is claimed for private company code.


# Addendum: engine v0.2.1 (test files recognised)

After round 2 one more general fix was made: files named `*_test.go`, `*_test.py`, `*_spec.rb`, and folders ending `.Tests`, count as tests. The first version of this rule also treated Java
classes named `FooTest.java` as tests; the regression check caught it (langchain4j-examples fell from 30 of 31 to 23 of 31, because in that repo such classes live under `src/main` and are runnable examples).
Java and Kotlin now mark tests by folder only. Final state of every table, current engine, frozen round-2 numbers kept separately in benchmark/round2_frozen:

```
A. FRESH APPS, engine v0.2.0 frozen when these were tested (the honest numbers)
app                                real models   engine finds  engine correct      best other tool finds
go-openai                                  131     103 ( 79%)            93%      aibom-scanner: 1 (1%)
azure-search-openai-demo-csharp              7       6 ( 86%)           100%             cisco: 2 (29%)
ollama-js                                   13       9 ( 69%)           100%            cisco: 10 (77%)
open-canvas                                 27      15 ( 56%)           100%             cisco: 4 (15%)
average                                                   72%             98%                        30%

B. APP WITH NO MODELS NAMED IN ITS CODE (private-gpt), v0.2.0: 17 names looked like models; 16 correctly left out (docs, tests, docstrings); 1 false alarm(s)

C. APPS USED TO BUILD THE FIXES: results are no longer independent
app                                real models   engine finds  engine correct      best other tool finds
open_deep_research                           4       4 (100%)           100%            cdxgen: 1 (25%)
langchain4j-examples                        31      30 ( 97%)           100%      aibom-scanner: 1 (3%)
bedrock-claude-chat                         70      68 ( 97%)            99%           cdxgen: 58 (83%)
azure-search-openai-demo                     5       5 (100%)           100%            cdxgen: 1 (20%)
average                                                   98%            100%                        33%

D. SAME FRESH APPS AFTER ONE MORE FIX, engine v0.2.1 (test files in Go, Java, C#, Python): no longer independent
app                                real models   engine finds  engine correct      best other tool finds
go-openai                                  131     101 ( 77%)            98%      aibom-scanner: 1 (1%)
azure-search-openai-demo-csharp              7       6 ( 86%)           100%             cisco: 2 (29%)
ollama-js                                   13       9 ( 69%)           100%            cisco: 10 (77%)
open-canvas                                 27      15 ( 56%)           100%             cisco: 4 (15%)
average                                                   72%            100%                        30%

average on fresh apps (frozen v0.2.0): engine finds 72% of the real models, 98% of what it reports is correct; best other tool finds 30%
```

Effect on the fresh apps: go-openai's correct share rises from 93% to 98%, and the number of real models found moves from 103 to 101 (two names had only been "found" inside test files).
33 automated tests. These four fresh apps are no longer independent; the next claim needs round 3 on new apps.


# Version 0.3.0: ready for a live demo on any repo (no accuracy changes)

Goal: Manish may name any repository in a live meeting, so the engine must take a link, never crash, say clearly what it is doing, and not mislead when it finds little.
Detection was deliberately not changed. Proof: on all 12 test repos the names and verdicts are identical to version 0.2.1 (`scripts/compare_runs.py`), and every number in the tables above is unchanged (`benchmark/summary_all.py`).

What is new
- `scan` takes a GitHub link (also owner/repo, a link to one folder or branch) or a folder. It downloads a shallow copy, scans it, and deletes the copy. It never waits for a password.
- Progress lines for each step, a time limit (120 seconds, `--max-seconds`) that says so when it stops early, and a cap on how many places are stored per name.
- Plain error messages for: a wrong or private link, no internet, no git, a missing branch or folder, a file instead of a folder, missing Python packages. No tracebacks; details go to `error.txt`.
- When nothing is found the report says why (the app may choose its model at run time). When the time limit stops a scan early with nothing found, it says "this is not a final answer".
- Each model is now marked `used` (set or used directly in the code) or `listed` (only inside a long table or list, or in a file that names 20 or more models). The report and the AI-BOM file carry it. Example: open_deep_research used to say "42 models are used in the code"; it now says 9 are used directly and 33 are only listed in tables.
- `scripts/preflight.py` (ten-minute check), `scripts/stress_test.py`, `demo/LIVE_MEETING_GUIDE.md`, a "paste any link" step in both demo scripts.

Checks
- 52 automated tests pass, including real downloads from a local git repository and the command line (also run with unclosed-file warnings treated as errors).
- Used/listed check against the answer keys (`benchmark/check_roles.py`): of 54 models the keys call a default or a direct use, 54 are labelled used and none is wrongly labelled listed. The label is cautious: a short model picker (fewer than 8 models) still counts as used.
- Six edge cases: zero time limit, empty folder, folder name with spaces and non-English characters, random binary data in .py and .json files, a file instead of a folder, a folder that was never scanned. All gave a clear message or a correct result.
- Stress test from links (`benchmark/stress_test.md`; checks robustness and speed, NOT accuracy, because these repos have no answer keys):

| Link | Total seconds | Used directly | Only listed | Left out | Result |
|---|---|---|---|---|---|
| openai/openai-cookbook | 32 | 84 | 1 | 72 | ok |
| huggingface/transformers | 39 | 208 | 19 | 491 | ok |
| langchain-ai/langchain | 9 | 87 | 216 | 56 | ok |
| ollama/ollama | 7 | 24 | 21 | 37 | ok |
| microsoft/semantic-kernel | 13 | 109 | 20 | 31 | ok |
| BerriAI/litellm | 59 | 306 | 262 | 1360 | ok |
| pallets/flask | 2 | 0 | 0 | 0 | ok |
| octocat/Hello-World | 2 | 0 | 0 | 0 | ok |
| langchain-ai/open_deep_research/tree/main/src/legacy | 2 | 8 | 0 | 2 | ok |
| octocat/this-repo-does-not-exist-12345 | 1 | 0 | 0 | 0 | polite error |
| not a link | 1 | 0 | 0 | 0 | polite error |

- A spot check of random "used" rows in langchain and transformers (reading the lines) found two things. In langchain, big data files of model profiles were counted as used; the 20-models-per-file rule fixed that (303 used became 87 used and 216 listed). In transformers, which is a library about thousands of models, many rows are checkpoint names in docstrings and model-type keys such as `"deepseek_v3": ...`; they are real references but not models the library "uses", so expect long lists on repos like that. Accuracy on model libraries was not measured.

Caveats
- Speed and stability are measured; accuracy on arbitrary repos is not. The accuracy numbers remain the five fresh apps (72% found, 100% correct, no longer independent) and the earlier apps.
- The known misses from round 2 are still open (retired model names, plain `name:` keys, bare function arguments, short names, Bicep allowed-lists, one OpenAPI example). They are listed above under "Fix list for round 3" and need a new set of fresh apps to test honestly.


# Round 3: five new apps, engine frozen first (the honest numbers)

How it was run
- Five apps the engine had never been run on: fragments (TypeScript), simonw/llm (Python), MacPaw/OpenAI (Swift), anthropic-quickstarts (Python and TypeScript), browser-use (Python).
- The answer keys were written first, from the code, each re-checked by a second and different search. Fingerprints of the keys and of the engine at the moment it was frozen are in `benchmark/round3_frozen/`.
- The fixes (a third finder called `shapes`, and an API-spec example rule in Verify) were built using only the older apps. Then the engine was frozen at version 0.4.0 and run once on the five new apps.
- The four free scanners were run on the same apps independently of the engine.
- The names the engine reported that my keys did not cover (38) were labelled from the lines afterwards, by the same rule for every tool. The key files record that.

Results (models only; "correct" counts every reported name that is a real model reference)

| App | Language | Real models in key | Engine finds | Engine reports correct | Best free scanner finds |
|---|---|---|---|---|---|
| fragments | TypeScript | 62 | 41 (66%) | 100% | cisco: 2 (3%) |
| llm | Python | 47 | 41 (87%) | 95% | cdxgen: 2 (4%) |
| OpenAI (MacPaw) | Swift | 132 | 127 (96%) | 100% | cisco: 2 (2%) |
| anthropic-quickstarts | Python, TypeScript | 22 | 15 (68%) | 100% | cdxgen: 5 (23%) |
| browser-use | Python | 312 | 234 (75%) | 98% | cisco: 52 (17%) |
| average | | | 79% | 99% | 10% |

- browser-use split: 57 of 71 models outside its big gateway catalog (80%), 177 of 241 catalog entries (73%).
- Of the 38 extra names: 32 are real or acceptable (my keys missed them, partial family checks, shortcut attributes whose name spells a model, other spellings of a model already in the key) and 6 are wrong (two aliases in llm, a provider prefix, a message text and two underscore fragments in browser-use).
- Of 117 misses, 114 were never found and 3 were found but rejected (two as comments, one as a test).
- Used/listed check on all keys (`benchmark/check_roles.py`): 69 models the keys call a default or direct use, 69 labelled used, none wrongly labelled listed.

Why it misses (nothing was changed after the freeze)
- Unknown ids that sit in a list, a dictionary or a JSON catalog right beside known ones: browser-use's gateway list, Claude ids used as dictionary keys in anthropic-quickstarts.
- JSON catalogs whose key is `id`: the learned-key rule deliberately skips `id`, which cost fragments 21 models.
- Short names inside tuples (`o1`, `o3`), alias strings, and size variants such as `text-embedding-3-small-512`.
- Names without a digit in constants (`text-moderation-latest`): the constant rule asks for a digit.
- One engine bug: a notebook docstring was counted as a live place (the name was still real, because it also appears in code and settings).

What this means
- On new apps the engine improves from 72% (round 2, different apps) to 79%, not to the 96% it now scores on the older apps. The older apps were used to build the fixes, so those numbers prove little. The honest figure is 79%.
- The free scanners are close to useless on these apps (about 10%).
- The next fix, not done: a neighbor rule (accept a model-shaped string beside two or more known models), allow `id` as a learned key, and read dictionary keys. It needs a new set of fresh apps to test honestly.

# Version 0.5.0: readable and useful (no change to what is found)

What changed (presentation only): a rebuilt report (headline, three numbers, models grouped by maker, search, confidence badges, clickable links to the exact line, left-out reasons, a limits box); a terminal summary with a table; `explain`, `show --all`, `show --left-out`, `rebuild`; `models.csv`; spellings of one model shown as one row; links also for local git clones that have no uncommitted changes.

Checks
- Detection fingerprint (finders, triage, merge, verify, vendors, dictionary) is identical before and after: `6a71f63a4da422489508`.
- All 17 test repos re-scanned: names and verdicts identical to the snapshot taken before the polish (`scripts/compare_runs.py`), and every number above is unchanged.
- 92 automated tests pass, including on a real Python 3.9.
- The report was opened in a real browser: the search box was tested (130 rows, a filter, a nonsense search, clearing), and a phone-width window fits without sideways scrolling.
- Colours in the page are limited to black and white; the page needs no internet; names from a repository are escaped (a test uses a name containing a script tag).
- Stress test from links on an idle machine (stability and speed, not accuracy; these repos have no answer keys). The third finder made big and notebook-heavy repos two to three times slower than in version 0.3.0:

| Link | Total seconds | Scan seconds | Used directly | Only listed | Left out | Result | Note |
|---|---|---|---|---|---|---|---|
| openai/openai-cookbook | 83 | 19.5 | 80 | 1 | 73 | ok |  |
| huggingface/transformers | 106 | 95.46 | 373 | 31 | 464 | ok |  |
| langchain-ai/langchain | 21 | 15.94 | 88 | 216 | 53 | ok |  |
| ollama/ollama | 14 | 10.04 | 76 | 45 | 40 | ok |  |
| microsoft/semantic-kernel | 37 | 31.23 | 113 | 26 | 32 | ok |  |
| BerriAI/litellm | 146 | 125.63 | 284 | 239 | 856 | ok |  |
| pallets/flask | 3 | 0.61 | 0 | 0 | 0 | ok |  |
| octocat/Hello-World | 2 | 0.06 | 0 | 0 | 0 | ok |  |
| langchain-ai/open_deep_research/tree/main/src/legacy | 3 | 0.49 | 8 | 0 | 2 | ok |  |
| octocat/this-repo-does-not-exist-12345 | 2 | - | 0 | 0 | 0 | polite error | Problem: I could not open https://github.com/octocat/this-repo-does-not-exi |
| not a link | 2 | - | 0 | 0 | 0 | polite error | Problem: I could not find a folder or a git link called 'not a link'. Give  |

Caveats
- Models only. The answer keys were written by Claude and not reviewed by an independent person.
- Speed varies on the machine used; the largest repository took between 66 and 95 seconds to scan in different runs.
- Accuracy on any given repository can be lower than 79%. The report says what a scan cannot see.
