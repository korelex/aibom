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
- Adds canonical ID, provider, pinning, lifecycle status and license metadata to
  the CycloneDX output from the bundled database (`knowledge/ai_db.json`).
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
python -m pip install -r requirements.txt
python -m aibom_engine scan .
python -m aibom_engine show runs/<app> --all
python -m aibom_engine explain runs/<app> MODEL
```

`scan` accepts a folder or a Git link. Results go to `runs/<app>/` unless
`--out` is given. The command prints the models it found and the files it wrote.

Install the `aibom` command from this checkout with:

```bash
python -m pip install -e .
aibom scan .
```

## Output

| File | What it is |
| --- | --- |
| `aibom.cdx.json` | CycloneDX 1.6 AI-BOM, the machine-readable source of truth |
| `report.html` | Readable report with evidence and the "what this scan cannot see" section |
| `report.md` | The same summary for a PR, an audit or a chat |
| `models.csv` | The model list for a spreadsheet |

## Database

`knowledge/ai_db.json` is compiled from `knowledge/curated.json`, the LiteLLM
model catalogue, OpenRouter and OSV advisories for AI packages. Rebuild it with:

```bash
python scripts/build_db.py
```

Lifecycle and license entries from `curated.json` are hand-checked. Entries that
come only from an upstream catalogue are not yet verified and must not be
presented as confirmed retirements.

## Tests

```bash
python -m pip install -r requirements-dev.txt
python -m pytest
```

The benchmark corpus and hand-written answer keys are in `benchmark/`.

## Status

Alpha. The scanner currently covers model discovery only. SDKs, MCP, vector
stores, secrets, weight files, SARIF, CI and KorelexOne upload are on the
roadmap, not in this build.

Built and maintained by [Korelex](https://korelex.ai).
