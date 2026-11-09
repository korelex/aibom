# aibom

**Find the AI models in a codebase, with proof.**

`aibom` scans a local folder or a Git repository and builds an AI model inventory:
which AI models the code names, where each one appears, and whether the code
actually uses it or only lists it in a table, test, comment or document.

Every model entry carries:

- the model name and the file and line where it appears
- **used** (set or called in live code) or **listed** (only in a long table or list)
- **Confirmed** (the name is written in the code) or **Worked out** (the code builds
  it through a constant such as `GPT_4O_MINI`)
- the evidence line behind the claim

## What it does today

- Reads Python, JavaScript/TypeScript, Java, Go, C#, Rust, PHP and Ruby source text.
- Finds model names written directly, as the value of a model setting, or as a
  model-shaped string such as `llama3.1:8b` or a Bedrock ID.
- Separates live code from comments, docstrings, messages, tests, docs, sample
  data and notebook outputs.
- Adds canonical ID, provider, pinning, sourced lifecycle status and license metadata to
  the CycloneDX output from the bundled database (`aibom_engine/knowledge/ai_db.json`).
- Writes a CycloneDX 1.6 AI-BOM (`aibom.cdx.json`) and three human reports:
  `report.html`, `report.md` and `models.csv`.

## What it does not do yet

- Detect AI SDKs or frameworks, MCP servers, vector databases or datasets.
- Detect hardcoded API keys or inspect model weight files.
- Emit SARIF, upload to KorelexOne, or run as a GitHub Action.
- Provide `pipx install` or a packaged single binary.
- Prove entry-point reachability. Every finding is code usage, not exploitability.

A model chosen at run time (environment variable, settings page, database or
remote setting) cannot be seen by a scan that reads code.

## Run it

```bash
python -m pip install .
aibom scan .
aibom show runs/<app> --all
aibom explain runs/<app> MODEL
```

`scan` accepts a folder or a Git link. Results go to `runs/<app>/` unless
`--out` is given. The command prints the models it found and the files it wrote.
`python -m aibom_engine scan .` does the same without installing the command.

For development, install in editable mode with the test tools:

```bash
python -m pip install -e ".[dev]"
```

## Output

| File | What it is |
| --- | --- |
| `aibom.cdx.json` | CycloneDX 1.6 AI-BOM, the machine-readable source of truth |
| `report.html` | Readable report with evidence and the "what this scan cannot see" section |
| `report.md` | The same summary for a PR, an audit or a chat |
| `models.csv` | The model list for a spreadsheet |

## Database

`aibom_engine/knowledge/ai_db.json` is compiled from `aibom_engine/knowledge/curated.json`, the LiteLLM
model catalogue, OpenRouter and OSV advisories for AI packages. Rebuild it with:

```bash
python scripts/build_db.py
```

To apply a hand edit to `curated.json` without fetching anything (so the change
shows up as a small, reviewable diff), run `python scripts/build_db.py --apply-curated`.

### Lifecycle status

A model's status comes only from curated records that carry a `lifecycle_source_url`
(the provider's own page) and the date it was checked. Two dates are kept apart:
`deprecation_date` (announced; the model still works) and `retirement_date` (API
calls fail). The status is worked out from those dates on the day of the scan:

| Status | Meaning |
| --- | --- |
| `retired` | the retirement date is today or in the past |
| `deprecated` | announced, retirement scheduled, still working |
| `active` | a sourced record exists and nothing is scheduled |
| `not tracked` | no sourced record. This is not a statement that the model is fine |

A retirement belongs to a specific snapshot, so records are stored per name
(`lifecycle_records` in `curated.json`): `gpt-4-0314` is retired while another
`gpt-4` snapshot is a different matter. Models are still grouped into one family for
display. A snapshot that no record lists stays `not tracked`; it never inherits a
neighbour's date. Dates are for the maker's own API. Amazon Bedrock, Azure and Google Vertex AI set
their own schedules, so those rows carry a `*`. Set `AIBOM_TODAY=YYYY-MM-DD` to
reproduce a report as of a given day. Lifecycle data from upstream catalogues is not
used: it was found to mix up deprecation with earliest-retirement dates.

### Licenses

Each model carries a license name and a *commercial use* value. The report flags
licenses for legal review; it does not decide whether you are in compliance.

| Commercial use | Shown as | Example |
| --- | --- | --- |
| `yes` | the license name | Apache-2.0, MIT |
| `conditional` | `(conditional)` | Llama 2 Community License (attribution, 700M-user limit, acceptable-use policy) |
| `no` | `(non-commercial)` | CC-BY-NC, research-only licenses |
| `provider-terms` | `Provider API terms` | GPT-4o and Claude: hosted models sold under the provider's API terms |
| `unknown` | the license name | not stated |

Curated open-model entries carry the source URL of the license and the date it was
checked; `python scripts/check_licenses.py` re-checks every one of them against the
license its Hugging Face repo declares. A model that is not curated gets a license only
when its family has one license for all its open releases (Llama, Gemma, Mixtral, Phi);
anything else is `unknown` rather than a guess.

### Floating aliases

A name is a *floating alias* only when the model catalogue lists a dated snapshot you
could pin (`gpt-4o` has `gpt-4o-2024-08-06`; `text-embedding-3-small` has none, so it
is not flagged). Some providers pin the dateless name itself: Anthropic states that
every Claude ID is a pinned snapshot, including the dateless IDs from the 4.6
generation on, so `claude-opus-5` is pinned while `claude-haiku-4-5` is an alias. Such
names are listed with their source under `pinned_names` in `curated.json`. Hugging Face
repo ids are reported on their own: they are pinned by a commit revision, which this
scan does not check.

## Tests

```bash
python -m pip install -e ".[dev]"
python -m pytest
python scripts/smoke_wheel.py   # builds the wheel, installs it in a clean virtualenv and scans with it
```

The benchmark corpus and hand-written answer keys are in `benchmark/`.

## Status

Alpha. The scanner currently covers model discovery only. SDKs, MCP, vector
stores, secrets, weight files, SARIF, CI and KorelexOne upload are on the
roadmap, not in this build.

## License

Apache License 2.0, see [LICENSE](LICENSE). The bundled model data is derived in part
from third-party sources; their notices are in [NOTICE](NOTICE).

Built and maintained by [Korelex](https://korelex.ai).
