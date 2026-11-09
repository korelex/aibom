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
6. **Write** the CycloneDX AI-BOM and the reports.

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
| [OSV.dev](https://osv.dev) | known vulnerabilities in AI packages (not reported yet; used by a future release) |

Third-party notices are in [NOTICE](../NOTICE). How to update the data is in [CONTRIBUTING.md](../CONTRIBUTING.md).
