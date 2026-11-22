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

## Risk flags

A flag says something found in the scan is risky, how risky, where, and what to do. Every flag has a rule id that never
changes, a severity, the file and line, and a one-line fix. They are saved in `flags.json` (worst first), attached to the
component they are about in `aibom.cdx.json` (an `aibom-engine:flag` property), and shown in the reports.

A severity says how much a reader should worry, not whether the app can be attacked: `high` is something that breaks or
exposes the app now, `medium` is act soon, `low` is good practice, `info` is worth knowing.

| Rule | Severity | What it means |
| --- | --- | --- |
| `model.retired` | high | The provider has retired the model; calls to it fail. |
| `model.deprecated` | medium | The model has a retirement date. |
| `model.floating-alias` | low | A name such as `gpt-4o` can change the model behind it; a dated snapshot exists to pin. |
| `model.unpinned-hf-repo` | info | A Hugging Face model; this scan does not check for a pinned revision. |
| `model.license-restricted` | medium | The licence limits commercial use or needs review. |
| `model.license-unknown` | info | aibom does not know the licence. |
| `secret.api-key` | high / medium / low | A hardcoded AI provider API key in a file (see below). High for a key recognised by its format in the product's own code or settings, medium when recognised only by the variable name it is given, low in a test, example or documentation file (usually a sample, but one that is real is still a leak). |
| `model-file.dangerous-call` | high / medium | A pickle-based model file imports code that runs commands or code, touches files or the network, or loads another pickle (high), or a helper that attacks chain calls with (medium). |
| `model-file.unresolved-import` | medium | The file imports something that could not be identified, which is unusual: a pickle built to hide what it imports looks like this. |
| `model-file.mislabelled` | high | The name says the file holds only numbers (`.safetensors`, `.gguf`, `.onnx`) but the content is something else, such as a pickle. |
| `model-file.pickle-format` | medium | The file uses pickle, so loading it can run code. Said even when no dangerous import was found, because that does not make loading it safe. |
| `model-file.keras-lambda` | medium | A Keras model has a Lambda layer, which holds Python code. |
| `model-file.not-scanned` | low / info | The file could not be fully scanned (low when the reason is worrying: encrypted, too large, cut short by a limit; info when there was nothing to read). |
| `code.trust-remote-code` | medium / low | `trust_remote_code` is switched on, so a model's own repository can supply code that runs on this machine. Low in a test or example. |
| `mcp.plaintext-secret` | high / medium | A credential is written in an MCP config file. High when the value has a well-known key format or a URL carries a password; medium for a plain value under a name such as `API_KEY` or `Authorization`. A placeholder such as `${TOKEN}` or `YOUR_KEY` is not a credential. A provider key found here is flagged by this rule only, not also as `secret.api-key`, though it is still counted as a hardcoded key. |
| `mcp.shell-command` | medium / high | The server is started through a shell string or inline code (`bash -c ...`, `python -c ...`, `node -e ...`, `julia -e ...`, and the same in Ruby, Perl, PHP, R, Lua, Groovy, Elixir, Raku, Clojure, Babashka and AppleScript). High when that text downloads and runs something. `cmd /c npx ...`, the way Windows runs `npx`, is not flagged. |
| `mcp.unpinned-package` | medium | An npm, PyPI or container package has no exact version, so a new release changes what runs. |
| `mcp.package-from-url` | medium | The server runs code fetched from a URL or git address. |
| `mcp.broad-filesystem-path` | high / medium | The server is given the root of a drive or a system folder (high) or a whole home folder (medium). |

A server that its config switches off is not started, so only its credentials are flagged. Servers in tests, examples,
documentation or vendored folders get no flags. The value of a credential is judged and then dropped: a flag names where
it is and what it is called, never what it is.

**What the MCP rules are based on.** They follow OWASP's published MCP guidance, quoted only for what it says: the
[OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/) (MCP01 secret exposure, MCP02 privilege scope creep,
MCP04 supply chain, MCP05 command execution) and its
[MCP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html) (section 3: restrict
file system access to the required directories; section 5: never pass raw shell commands; section 6: never store tokens in
plaintext in MCP config files). The cheat sheet does not give version-pinning advice, so the pinning rule cites MCP04 only.
The Cloud Security Alliance's "MCP Security Baseline" was listed as v0.1 and "coming soon", with no published text, when
this was checked on 2026-11-12, so nothing here claims to follow it.

## Hardcoded API keys

A key written into code is in the repository, in every clone and, once committed, in the history. aibom reads the text files
on disk (not the git history) and reports each provider key it finds with the provider, the file, the line and the
length, and **never keeps the key**: no output, including `credentials.json`, holds any part of the value.

A key is recognised in two ways, both chosen to keep false alarms rare:

1. **By its format**, for providers that issue a distinctive one: Anthropic (`sk-ant-api03-`, `sk-ant-admin01-`), OpenAI
   (`sk-proj-`, `sk-svcacct-`, `sk-admin-` and the older keys that contain `T3BlbkFJ`), OpenRouter (`sk-or-v1-` and 64
   hex characters), Hugging Face (`hf_` and 34 letters; `api_org_`), Google (`AIza` and 35 characters), Groq (`gsk_`), xAI
   (`xai-`), Perplexity (`pplx-` and 48 characters), Replicate (`r8_`, 40 characters in all), AWS access key ids and
   Amazon Bedrock API keys. The formats were checked against the providers' own documentation where it exists
   (OpenRouter, Replicate) and otherwise against the published rules of [gitleaks](https://github.com/gitleaks/gitleaks);
   Groq and xAI are known by their prefix, with a deliberately loose length because neither documents one. A match must
   also be random enough (a minimum entropy) and must not look like an example: repeated or counting characters, words
   such as `example` or `your`, an ellipsis.
2. **By the name it is given**, for keys with no distinctive format (Mistral, Cohere, Azure OpenAI and others): a literal
   value is reported only when it is assigned to a variable or setting whose name says whose key it is
   (`MISTRAL_API_KEY = "..."`), is long and random enough, and is not a placeholder, a path, a URL or a lookup such as
   `${KEY}` or `os.getenv(...)`.

Not found: keys in git history, keys that have no distinctive format and are not given a provider-named name, and keys built
from pieces. Lock files, minified files and translation files are not read. Pinecone keys are not matched by format because
the sources checked disagree about their prefix.

## Model files

Weights are saved in many formats. Some (safetensors, GGUF) hold only numbers. Others use Python's pickle, and a pickle can
name any function to call when it is loaded, so loading a model file from a source you do not trust can run that source's code.
aibom finds the model files in the project, works out what each one **really is from its content** (a pickle can be named
`model.safetensors`), and reads the pickle ones **without ever loading them**: it walks the opcodes with Python's own
`pickletools.genops`, which only reads, and collects the `module.name` of every global the pickle imports. Each is then looked
up in a table of imports that run commands, touch files or the network, build code, or help chain such calls. The table is
written from Python's documentation of how pickle is abused and from published scanner lists used to look for gaps, not
copied; the whole table is tested name by name.

What is read: pickles (`.pkl`, `.pickle`, `.joblib`, `.dill`, `.ckpt`, `.pt`, `.pth`, and `.bin`/`.dat`/`.data` when the
content is a pickle or a zip); PyTorch checkpoints, both the zip form (`data.pkl` inside) and the older single-file form;
joblib files, plain or compressed with zlib, gzip, bzip2, xz or lzma (the raw array bytes joblib writes inside the pickle are
passed over using the shape and dtype each array declares, so what follows them is still read); NumPy `.npy`/`.npz`, only
when an array has the object type, because that is a pickle inside; Keras `.keras` and `.h5`, for Lambda layers; and
safetensors, GGUF and ONNX, which are checked to be what they say.

Some choices that matter:

- **A pickle that cannot be understood is a finding, not a pass.** An import whose name cannot be worked out is counted as
  unresolved and flagged; a file that is damaged, encrypted, cut short by a limit, or nested in another archive is reported
  as *not scanned* or *partly scanned* with the reason. "Not scanned" is never "safe", and a scan that found no dangerous
  import never says the file is safe either.
- **Hostile files are bounded.** File size, decompressed size, zip entries, compression ratio, opcodes, the length a pickle
  declares for a blob, and time are all limited, so a file built to exhaust memory or time ends as *not scanned*. A blob
  longer than 256 MB that is really in the file is passed over without being kept, and what follows it is still read, so
  padding cannot hide an import.
- **Where the file is matters.** A file in a test, example, docs or vendored folder is flagged one step lower, and only the
  product's own files are flagged for what could not be scanned.

`trust_remote_code` is a separate risk: it lets a model's repository supply Python that runs on the machine. aibom finds it
where it is set in code (as an argument, in a dict of arguments such as `model_kwargs={"trust_remote_code": True}`, or in
an assignment), in settings files, and as a command-line flag.

## Where the data comes from

`aibom_engine/knowledge/ai_db.json` is compiled by `scripts/build_db.py` from:

| Source | Used for |
| --- | --- |
| `aibom_engine/knowledge/curated.json` | hand-checked lifecycle and license records, each with its source |
| [LiteLLM](https://github.com/BerriAI/litellm) model catalogue | model names, aliases and context windows |
| [OpenRouter](https://openrouter.ai) model list | more model ids and their Hugging Face ids |
| [OSV.dev](https://osv.dev) ecosystem dumps (PyPI, npm) | known vulnerabilities of AI packages, with their affected version ranges |

Third-party notices are in [NOTICE](../NOTICE). How to update the data is in [CONTRIBUTING.md](../CONTRIBUTING.md).
