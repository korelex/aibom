# How aibom works

This page explains how a scan decides what to report, and where the model data comes from. For installation and
usage, see the [README](../README.md).

## The scan, step by step

1. **Sort the files.** Every file is sorted into code, settings, docs, tests, manifests, notebooks or other.
2. **Find candidate names**, with three finders:
   - *known model names*: a dictionary of model ids, built from public model catalogues;
   - *names in model settings*: values in places that hold a model, such as `model="..."`, `.modelName("...")`,
     environment defaults, Bicep parameters or `from_pretrained("...")`;
   - *names by their shape*: ids no dictionary lists yet, recognised by how they are written, such as
     `llama3.1:8b`, a Bedrock id, or a constant whose name spells its value (`GPT_4O_MINI = "gpt-4o-mini"`).
3. **Merge** different spellings of one model (`openai/gpt-4o`, `gpt-4o`) into one item.
4. **Verify** every place a name appears: live code, or only a comment, docstring, message, test, document, notebook
   output or API-spec example. Only names with at least one live place are kept. A name whose live places all sit in
   a long table or list of models is reported as *only listed*, apart from models the code uses directly.
5. **Look up** each model in the bundled database: maker, canonical id, pinning, lifecycle and license.
6. **Read the dependency files** (requirements, pyproject, Pipfile, poetry/uv/pnpm/yarn/npm lockfiles, package.json)
   and find the AI packages among them, then the imports and calls of those packages in live code. The call
   signatures are in [`aibom_engine/rules/calls.yaml`](../aibom_engine/rules/calls.yaml). Each package is then checked
   against the bundled vulnerability advisories (see below).
7. **Read the MCP config files** (`.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`, `.gemini/settings.json`,
   `.codex/config.toml`, `claude_desktop_config.json`, and other JSON files with `mcp` in the name that hold server
   entries) as text. Each server is recorded with how it runs (the program or package a launcher such as `npx`, `uvx`
   or `docker run` fetches, or its URL), the file and line, and the names of its environment variables and headers.
   Values are never read into the output: environment variables and headers are kept by name, a URL loses its user
   name, password and query string, and a value after a flag such as `--token` is masked. No server is started, so
   the tools a server offers are not listed. Servers in tests, examples, documentation or vendored folders are left out.
8. **Write** the CycloneDX AI-BOM and the reports. Packages are `library` or `framework` components with a purl and the
   lines that prove their use; known vulnerabilities go in the `vulnerabilities` section, linked to the components they
   affect; and the hosted API that a provider's own client library talks to (OpenAI, Anthropic, Pinecone, and so on) is a
   `service`, listed only when live code calls that client. `packages.json` keeps the full evidence, and the reports and
   `packages.csv` list the packages with their vulnerabilities, most severe first.

## Evidence levels

Every model and package says how strongly its use is proven:

| Level | A package | A model |
| --- | --- | --- |
| `declared` | is in a dependency file | is written in the code or settings |
| `imported` | is imported by live code | (a model name is never imported) |
| `called` | is called by live code: a client is created, an agent built, a model loaded (`OpenAI()`, `ChatAnthropic(...)`, `Chroma(...)`, `from_pretrained(...)`, a Bedrock client and its `invoke_model`) | is passed into a call on an AI SDK: `create(model="gpt-4o")`, `ChatOpenAI(model=MODEL)` where `MODEL = "gpt-4o"`, `from_pretrained("meta-llama/...")` |

Each component gets the strongest level that is proven. A call counts only when the name being called is bound by
an import of an AI package in the same file, so a project's own `Agent` or `OpenAI` class never counts, and code in
tests, documentation and examples never raises a level.

`declared` means *not proven*, not *not used*. A model name that reaches its API through a variable set elsewhere, a
lookup table, a wrapper function or plain HTTP stays `declared`, because the scanner cannot follow it there. A name
that is only compared (`if model == "gpt-4o"`), passed to a tokenizer, or written inside a prompt does not count as a
call.

None of the levels proves that a request from outside reaches the code: that needs a full call graph and data-flow
trace, which aibom does not do. Every component therefore also says `reachability: not_verified`.

How sure aibom is of a model's *name* is a separate question, written as `confidence`: `confirmed` when the name is
written out, `worked_out` when it comes from a constant such as `GPT_4O`. A worked-out name can be called, and a
confirmed one only declared.

In the AI-BOM these are the properties `aibom-engine:evidence-level`, `aibom-engine:reachability` and
`aibom-engine:confidence`; each proof line that passes the name into an AI call starts with `called:`.

## Known vulnerabilities

Every AI package with one exact installed version (from a lockfile, or an `==` pin) is checked against the OSV
advisories bundled in the database. A version is affected when OSV's own rules say so: the advisory lists the version,
or one of its ranges contains it (`introduced`, `fixed`, `last_affected`, `limit`). Versions are compared the way their
ecosystem does: PEP 440 for PyPI, Semantic Versioning for npm. Each advisory found gives its id, aliases (CVE),
severity, summary and the version that fixes it, when one is known.

- **Not checked** is said, never hidden. A range (`^1.2.0`, `>=0.1`) or a manifest without a lockfile does not say
  which version is installed, so the package is marked `not_checked` with the reason. That is not "no
  vulnerabilities".
- **Records of one issue are merged.** GitHub, PyPA and CVE often publish the same problem; the GitHub advisory names
  it and the others become aliases. When the databases disagree about which versions are affected, a version counts as
  affected if any of them says so, as OSV itself does.
- **Severity** is GitHub's rating, or else the rating of the CVSS 3.x base score, computed from the vector by the
  CVSS 3.1 formula. Without either it is `unknown`, never a guess.
- **Only AI packages** are checked, and only PyPI and npm. A web framework or a database client in the same project is
  outside what aibom reports.
- **Affected is not exploitable.** A match means "this version has a known vulnerability", not that the app reaches the
  vulnerable code. Every package says `reachability: not_verified`.
- The advisories are as fresh as the database: `packages.json` says when they were fetched
  (`summary.advisory_data`). `python scripts/build_db.py --osv-only` refreshes them.

## Lifecycle status

A model's status comes only from curated records that carry the provider's own page as `source_url` and the date it
was checked. Two dates are kept apart:

- `deprecation_date`: the provider announced the model is going away; it still works;
- `retirement_date`: API calls fail from this day.

The status is worked out from those dates on the day of the scan, so a record never goes stale by itself:

| Status | Meaning |
| --- | --- |
| `retired` | the retirement date is today or in the past |
| `deprecated` | announced, retirement scheduled, still working |
| `active` | a sourced record exists and nothing is scheduled |
| `not tracked` | no sourced record. This is not a statement that the model is fine |

A retirement belongs to a specific snapshot, so records are stored per name: `gpt-4-0314` is retired while another
`gpt-4` snapshot may not be. A snapshot that no record lists stays `not tracked`; it never inherits a neighbour's
dates. Models are still grouped into one family for display.

Dates are for the maker's own API. Amazon Bedrock, Azure and Google Vertex AI set their own schedules, so those rows
carry a `*`. When the newest record is more than 90 days old, the report warns that newer announcements are missing.
Set `AIBOM_TODAY=YYYY-MM-DD` to reproduce a report as of a given day.

Lifecycle dates from upstream model catalogues are not used: they were found to mix up deprecation with the earliest
possible retirement date.

## Floating aliases and pinning

A name is a **floating alias** only when the model catalogue lists a dated snapshot you could pin instead
(`gpt-4o` has `gpt-4o-2024-08-06`). `text-embedding-3-small` has no dated snapshot, so it is not flagged.

Some providers pin the dateless name itself. Anthropic states that every Claude model id is a pinned snapshot,
including the dateless ids from the 4.6 generation on, so `claude-opus-5` is pinned while `claude-haiku-4-5` is an
alias. Such names are listed with their source under `pinned_names` in `curated.json`.

Hugging Face repo ids are reported on their own: they are pinned by a commit revision, which this scan does not check.

## Licenses

Each model carries a license name and a *commercial use* value. Findings are flags for legal review, not a decision
about whether you comply.

| Commercial use | Shown as | Example |
| --- | --- | --- |
| `yes` | the license name | Apache-2.0, MIT |
| `conditional` | `(conditional)` | Llama 2 Community License (attribution, user limit, acceptable-use policy) |
| `no` | `(non-commercial)` | CC-BY-NC, research-only licenses |
| `provider-terms` | `Provider API terms` | GPT-4o and Claude: hosted models sold under the provider's terms |
| `unknown` | the license name | not stated |

Curated open-model entries carry the source URL of their license and the date it was checked, and
`scripts/check_licenses.py` re-checks them against the license each Hugging Face repo declares. A model that is not
curated gets a license only when its whole family uses one license (Llama, Gemma, Mixtral, Phi); anything else is
`unknown` rather than a guess.

## Where the data comes from

`aibom_engine/knowledge/ai_db.json` is compiled by `scripts/build_db.py` from:

| Source | Used for |
| --- | --- |
| `aibom_engine/knowledge/curated.json` | hand-checked lifecycle and license records, each with its source |
| [LiteLLM](https://github.com/BerriAI/litellm) model catalogue | model names, aliases and context windows |
| [OpenRouter](https://openrouter.ai) model list | more model ids and their Hugging Face ids |
| [OSV.dev](https://osv.dev) ecosystem dumps (PyPI, npm) | known vulnerabilities of AI packages, with their affected version ranges |

Third-party notices are in [NOTICE](../NOTICE). How to update the data is in [CONTRIBUTING.md](../CONTRIBUTING.md).
