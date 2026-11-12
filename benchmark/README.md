# Benchmark: model detection

How well aibom finds the AI models named in real code, measured against hand-written answer keys.
Only **models** are scored: that is what this version detects. Some answer keys also list frameworks, providers or
tools for future work; those items are not counted.

## Reproduce it

```bash
python -m pip install -e ".[dev]"
python benchmark/run.py                # clone the 17 repos at their pinned commits, scan, score
python benchmark/run.py --score-only   # score existing scans in runs/benchmark/ again
python benchmark/run.py llm fragments  # only some repos
```

Clones go to `repos/` and scans to `runs/benchmark/` (both git-ignored). The first run needs git and internet and
takes several minutes, mostly cloning. Results are written to `runs/benchmark/results.json`.

## What is in this folder

| File | What it is |
| --- | --- |
| `repos.json` | The 17 repositories: URL, full commit id, licence, and whether the repository is independent |
| `labels/<repo>.json` | The answer key for each repository |
| `score.py` | Scores one scan against its answer key |
| `run.py` | Clones, scans and scores all repositories |

## The repositories

Each is pinned to a full commit id, so a run always scans the same code. The repositories are other people's projects
under their own licences. This folder stores only model names, file paths, line numbers and short notes about them, not their code.
If an upstream repository is deleted or its history rewritten, a pinned commit can stop being available; the answer
keys then no longer have code to be checked against.

"Independent" means the answer key was written before the scanner was first run on that repository, so its score is a
fair measure. "Development" means the repository was used while building the scanner; its score only shows that the
scanner still works there.

| Repository | Commit | Licence | Use |
| --- | --- | --- | --- |
| langchain-ai/chat-langchain | `b8acf5c320` | MIT | development |
| mckaywrigley/chatbot-ui | `81328b61d2` | MIT | development |
| vercel/ai-chatbot | `c2f8235e1f` | Apache-2.0 | development |
| langchain-ai/open_deep_research | `1b7d2e80db` | MIT | development |
| langchain4j/langchain4j-examples | `33545d12c0` | Apache-2.0 | development |
| aws-samples/bedrock-claude-chat | `14e17cc3bd` | MIT-0 | development |
| Azure-Samples/azure-search-openai-demo | `558ffd397e` | MIT | development |
| sashabaranov/go-openai | `dd54fd2968` | Apache-2.0 | development |
| Azure-Samples/azure-search-openai-demo-csharp | `3aaa94555e` | MIT | development |
| ollama/ollama-js | `c276d078ee` | MIT | development |
| langchain-ai/open-canvas | `0310cecd51` | MIT | development |
| zylon-ai/private-gpt | `42ce052278` | Apache-2.0 | development |
| e2b-dev/fragments | `3b11c7fcd4` | Apache-2.0 | independent |
| simonw/llm | `aebaca27f9` | Apache-2.0 | independent |
| MacPaw/OpenAI | `8baf4aaf00` | MIT | independent |
| anthropics/anthropic-quickstarts | `1a18c340ca` | MIT | independent |
| browser-use/browser-use | `b49a68e406` | MIT | independent |

## How the scores are counted

- **Found (recall):** answer-key models the scanner reported, divided by answer-key models.
- **Correct (precision):** reported names that are real model references, divided by reported names. A reported name
  that the key does not list counts as correct only if someone has labelled it real from the code line
  (`extra_real`, or a `reference_ranges` block such as a token-limit table). A name nobody has labelled counts as
  **wrong**, so precision can be understated but never inflated.

## Results

### Round 3: the blind test

Five repositories the scanner had never been run on. The answer keys were written from the code first, and each key
item was checked a second time with a different search. The engine was then frozen (version 0.4.0) and run once.
Reported names that the keys did not cover were labelled from the code lines afterwards, by the same rule for every
name; each key records this in `labelled_after_the_run`.

| Repository | Language | Models in key | Found | Reported | Correct |
| --- | --- | ---: | ---: | ---: | ---: |
| e2b-dev/fragments | TypeScript | 62 | 41 (66%) | 40 | 40 (100%) |
| simonw/llm | Python | 47 | 41 (87%) | 43 | 41 (95%) |
| MacPaw/OpenAI | Swift | 132 | 127 (96%) | 132 | 132 (100%) |
| anthropics/anthropic-quickstarts | Python, TypeScript | 22 | 15 (68%) | 16 | 16 (100%) |
| browser-use/browser-use | Python | 312 | 236 (76%) | 244 | 241 (99%) |
| **Average** | | | **79%** | | **99%** |

These are the numbers of the current version (`python benchmark/run.py`, 2026-11-10). The frozen 0.4.0 run gave the
same averages (browser-use found 234 then, 236 now). The model dictionary has been refreshed since the blind run, which
can move these numbers slightly; any change made after seeing these five repositories would make them no longer blind.

### All 17 repositories

The other twelve repositories were used while building the scanner, so their scores are **not independent**: rules
were improved after seeing results on them. They show that the scanner still works on them, not how it does on new code.

| Repository | Models in key | Found | Reported | Correct |
| --- | ---: | ---: | ---: | ---: |
| langchain-ai/chat-langchain | 3 | 3 (100%) | 4 | 4 (100%) |
| mckaywrigley/chatbot-ui | 33 | 33 (100%) | 45 | 45 (100%) |
| vercel/ai-chatbot | 5 | 5 (100%) | 5 | 5 (100%) |
| langchain-ai/open_deep_research | 4 | 4 (100%) | 42 | 42 (100%) |
| langchain4j/langchain4j-examples | 31 | 30 (97%) | 43 | 43 (100%) |
| aws-samples/bedrock-claude-chat | 70 | 70 (100%) | 75 | 75 (100%) |
| Azure-Samples/azure-search-openai-demo | 5 | 5 (100%) | 7 | 7 (100%) |
| sashabaranov/go-openai | 131 | 121 (92%) | 131 | 129 (98%) |
| Azure-Samples/azure-search-openai-demo-csharp | 7 | 7 (100%) | 8 | 8 (100%) |
| ollama/ollama-js | 13 | 12 (92%) | 12 | 12 (100%) |
| langchain-ai/open-canvas | 27 | 27 (100%) | 28 | 28 (100%) |
| zylon-ai/private-gpt | 0 | - | 1 | 0 (the app's own name in its API spec) |

On 2026-11-10 four reported names in chatbot-ui, bedrock-claude-chat and go-openai were labelled real from their code
lines after a run (each entry says so). None of them is in a round-3 repository.

## Known misses

From the round-3 analysis, still true:

- Unknown model ids inside long lists, dictionaries or JSON catalogs next to known ones (browser-use's gateway list,
  Claude ids used as dictionary keys in anthropic-quickstarts).
- JSON catalogs whose key is `id`: the rule that learns model keys from a file skips `id` on purpose. This costs
  fragments 21 models.
- Short names inside tuples (`o1`, `o3`), and names without a digit in constants (`text-moderation-latest`).

## Limits of this benchmark

- **The answer keys were drafted with an AI assistant from the code and checked a second time with a different
  search. No independent person has reviewed them yet.** A key can miss a model; the scanner found 32 real models
  the round-3 keys had missed. Recall is measured against the keys as written.
- Seventeen repositories, mostly Python and TypeScript; one each in Go, Java, C# and Swift.
- A model chosen at run time (an environment variable, a settings page, a database) is outside what any of these
  numbers measure.
