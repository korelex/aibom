# aibom

**Find the AI models in a codebase, with proof.**

`aibom` scans a folder or a Git repository and lists every AI model the code names: `gpt-4o`,
`claude-sonnet-5-5`, `meta-llama/Llama-2-7b-hf`, the model inside a Bedrock ARN, and so on. Each one comes with the file and line
that proves it, whether that model has been retired or is about to be, and the license it is offered under. The
result is an **AI bill of materials (AI-BOM)** in the CycloneDX 1.6 standard, plus a report a person can read.

> **Status: alpha.** This version finds **models**, **AI packages** (SDKs, agent frameworks, vector databases) with their
> known vulnerabilities, and the **MCP servers** a project's config files declare. Secrets and model weight files are on
> the roadmap, not in this build. See [What it does not do yet](#what-it-does-not-do-yet).

## Why aibom

- **Every finding has proof.** Each model is tied to a file and line, with a link to that exact line on GitHub,
  GitLab or Bitbucket.
- **Used or only mentioned?** Names that appear only in comments, tests, docs or example data are left out, and the
  report says why. Names that only appear in big lookup tables are reported apart from models the code really uses.
- **Retired and deprecated models.** `claude-3-5-sonnet-20240620` stopped working on 2025-10-28; the report says so,
  names the replacement and links to the provider's announcement. Dates come only from the providers' own pages.
- **License flags.** Llama, Gemma, Qwen, Stable Diffusion and other open models are flagged when their license sets
  conditions (for example, a monthly-user limit) or forbids commercial use, for your legal team to review.
- **Standard output.** A schema-validated CycloneDX 1.6 file that other SBOM tools can read.
- **Runs locally.** A scan of a folder on your machine does not use the network, and aibom never uploads anything.
- **Measured accuracy.** On a blind test with five open-source apps it found 79% of the models named in their code,
  and 99% of what it reported was correct. [How this was measured](benchmark/README.md).

## Quick start

You need **Python 3.9 or newer** and **Git**.

```bash
git clone https://github.com/korelex/aibom.git
cd aibom
python -m venv .venv
source .venv/bin/activate          # Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install .
```

Scan the small demo app that ships with the repository:

```bash
aibom scan tests/fixtures/review-app
```

```text
Scan finished in 0.27s: review-app

  6    models used directly in the code
  2    names left out (only in comments, messages, tests or docs)

The main ones:
  MODEL                        MADE BY    TYPE        WHERE (file:line)
  claude-3-5-sonnet-20240620   Anthropic  chat        src/agent.py:24
  gpt-4o                       OpenAI     chat        src/agent.py:16
  gpt-4o-mini                  OpenAI     chat        src/agent.py:11
  meta-llama/Llama-2-7b-hf     Meta       chat        src/hf.py:4
  ...

Files in runs/review-app:
  report.html     the readable report: open it in a browser (aibom report runs/review-app)
  models.csv      the same list for a spreadsheet
  aibom.cdx.json  the standard AI-BOM file (valid CycloneDX 1.6)
```

Open the report, which starts with a summary of the risks it found:

```bash
aibom report runs/review-app
```

```text
Risks
- Retired (API calls fail): 1 (claude-3-5-sonnet-20240620)
- Deprecated (retirement scheduled, still works): 2 (gpt-4o, gpt-4o-mini)
- Floating aliases (a dated snapshot exists to pin): 2 (gpt-4o, gpt-4o-mini)
- Hugging Face models (pin a commit revision; this scan does not check for one): 2 (...)
- Restricted licenses (flag for legal review): 2 (meta-llama/Llama-2-7b-hf, stabilityai/stable-diffusion-xl-base-1.0)
- Unknown licenses: 0
```

Then scan your own code, or any public repository by its link:

```bash
aibom scan path/to/your/project
aibom scan https://github.com/simonw/llm
```

## Installation

aibom is not published on PyPI yet, so it is installed from this repository.

**macOS and Linux**

```bash
git clone https://github.com/korelex/aibom.git
cd aibom
python3 -m venv .venv
source .venv/bin/activate
python -m pip install .
aibom --help
```

**Windows (PowerShell)**

```powershell
git clone https://github.com/korelex/aibom.git
cd aibom
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install .
aibom --help
```

If PowerShell refuses to run `Activate.ps1` ("running scripts is disabled on this system"), you can skip activation
and run the command from the environment directly: `.venv\Scripts\aibom.exe scan .`

**Without a virtual environment**, `python -m pip install .` puts the `aibom` command in the scripts folder of the
Python you ran it with. If your shell then says `aibom` is not recognised, that folder is not on your `PATH`;
`python -m aibom_engine` works everywhere and takes the same arguments (`python -m aibom_engine scan .`).

On Debian and Ubuntu, if `python3 -m venv` fails, install the venv module first: `sudo apt install python3-venv`.

## Usage

| Command | What it does |
| --- | --- |
| `aibom` | In a terminal: open a guided menu (see below). Anywhere else, print the help |
| `aibom scan SOURCE` | Scan a folder, or a repository link, and write the results |
| `aibom report RUN` | Open the HTML report of a finished scan in your browser |
| `aibom report RUN --pdf` | Write the report as a PDF (`report.pdf` in the scan folder, or `--output FILE`). It uses Chrome, Edge or Chromium if one is installed; if not, open `report.html` and use Print, Save as PDF |
| `aibom show RUN` | Print the models of a finished scan (`--all` for every model, `--left-out` for names left out) |
| `aibom explain RUN MODEL` | Show why a model is in the result, every place it appears and how sure aibom is |
| `aibom packages RUN` | List the AI packages of a finished scan with their evidence level and known vulnerabilities (`--all` adds those only in a lockfile) |
| `aibom packages RUN PACKAGE` | Look closer at one package: where it is used, and each advisory with the version that fixes it |
| `aibom vulns RUN` | The known vulnerabilities of a finished scan, worst first, with a fix plan (`--severity high` for high and worse, `--called` for packages your code calls, `--all` adds those only in a lockfile) |
| `aibom rebuild RUN` | Re-create the reports of a finished scan without scanning again |
| `aibom --version` | The version, and the dates of the model data and the vulnerability data |

`SOURCE` can be:

- a folder: `aibom scan .`
- a repository link: `aibom scan https://github.com/owner/repo` (GitHub, GitLab and Bitbucket; shallow clone, no
  password prompts, the copy is deleted after the scan unless you pass `--keep`)
- a short GitHub name: `aibom scan owner/repo`
- one branch or folder of a repository: `aibom scan https://github.com/owner/repo/tree/main/some/folder`

`RUN` is the folder a scan wrote to. By default that is `runs/<name of the app>` in the current directory; choose
another with `--out`.

Useful options for `scan`:

| Option | Default | Meaning |
| --- | --- | --- |
| `--out DIR` | `runs/<app>` | where to write the results |
| `--open` | off | open the report in your browser when the scan is done |
| `--max-seconds N` | 120 | stop reading files after N seconds; a report that hit the limit says so at the top |
| `--keep` | off | keep the downloaded copy of a repository |
| `--quiet` | off | print only the summary, not the progress lines |

Run `aibom <command> --help` for every option.

To run aibom on your own servers, in CI, or without internet, see [Running aibom in your own infrastructure](docs/running-in-your-infra.md).

### The guided menu

Type `aibom` with nothing after it, in a terminal, and a menu opens:

```text
? What do you want to do?  (arrow keys to move, Enter to choose, Esc to go back)
 » Scan a folder or a GitHub link
   Look at a scan I already made (2 found)
   Quit
```

It asks what to scan (press Enter for the current folder), runs the scan, and then lets you open the report, list the
models and the AI packages, ask why a model is in the result, look closer at one package, and see the names that were
left out. Every step prints the command that does the same thing without the menu, so the menu is also a way to learn
the commands:

```text
  Same thing without the menu:  aibom packages runs/review-app langchain-community
```

Keys: arrows move, Enter chooses, **Esc goes back** one step (at the first menu it quits), and Ctrl-C stops. Ctrl-C
during a scan stops the scan and returns to the menu; at a question it ends aibom, with exit code `130` like the other
commands. In a long list, type to filter.

The menu opens only when both input and output are a terminal. In a script, a pipe or CI, `aibom` with no arguments
prints the help and exits with `0`, so nothing can wait for a key press. If the menu does not open in your shell and you
get the help instead, that shell is not presenting itself as a terminal; use PowerShell, Windows Terminal or cmd on
Windows, or run the commands directly.

### What you see in a terminal

In a terminal, a scan shows one line per stage as it finishes (with the time it took and what it found), then a summary:
the models, the AI packages and how many are called by your code, and the known vulnerabilities by severity (critical,
high, medium, low), worst first. `aibom vulns RUN` lists them all: each with its advisory (a link in terminals that
support links), the package and version, whether your code **calls** the package, **imports** it or only **declares** it,
and the version that fixes it. It ends with a **fix plan**: for each package the lowest version that its advisories say fixes
everything, checked again against the advisory data, with a warning when the upgrade is a major or `0.x` jump that could
break your code. A vulnerability here means this exact version is in an advisory; it does not mean your app is exploitable.

Colour and boxes are drawn only when the output is a terminal. In a pipe, in CI, with `--plain`, or with `NO_COLOR` set,
aibom prints the same plain text it always did, so scripts and saved logs never contain escape codes. The HTML and Markdown
reports use the same severity order and fix plan; the HTML report adds the severity colours (the word is always written too).

**Exit codes:** `0` the scan finished, `2` it could not run (for example a wrong path or link; the message says
why), `130` stopped with Ctrl-C.

## Output

Each scan writes these files to its `RUN` folder:

| File | What it is |
| --- | --- |
| `aibom.cdx.json` | The AI-BOM: CycloneDX 1.6, validated against the official schema. Each model is a `machine-learning-model` component with its evidence (file and line), its evidence level, confidence and reachability, and properties for lifecycle, pinning and license. Each AI package is a `library` (or `framework`) component with a purl, the lines that prove its use and its evidence level; known vulnerabilities are listed in `vulnerabilities` and linked to the components they affect; the hosted API a provider's own client talks to is a `service`. |
| `report.html` | The readable report: a risk summary, every model grouped by maker with links to its lines, the AI packages with their known vulnerabilities, the names that were left out and why, and what the scan cannot see. Works offline and prints cleanly. |
| `report.md` | The same report in Markdown, for a pull request, a ticket or a chat. |
| `models.csv` | One row per model, for a spreadsheet. |
| `packages.csv` | One row per AI package: version, evidence level, first proof line, and its known vulnerabilities, for a spreadsheet. |
| `packages.json` | The AI packages with all their evidence: the imports and calls that prove their use, an evidence level, and the known vulnerabilities of each exact version (OSV advisories, or `not_checked` with the reason). |
| `flags.json` | The risk flags of the scan, worst first: each has a rule id, a severity (`high`, `medium`, `low`, `info`), the place it was found and a one-line fix. Model risks (retired, deprecated, floating alias, licence) and MCP risks (a credential in a config file, a shell string, an unpinned package, a very broad file system path); the report shows the MCP ones in a Flags section. In `aibom.cdx.json` each flag is an `aibom-engine:flag` property on the component it is about. Every rule is listed in [docs/how-it-works.md](docs/how-it-works.md#risk-flags). |
| `mcp.json`, `mcp.csv` | The MCP servers the project's config files declare (`.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`, `.gemini/settings.json`, `.codex/config.toml`, `claude_desktop_config.json`): how each is run, the file and line, and the names of its environment variables and headers (never their values). In `aibom.cdx.json` a local server is an `application` component and a remote one a `service`. |
| `merged.json`, `findings.json`, `files.json`, `manifest.json` | Working data behind the reports; `aibom rebuild` uses them. |

For the same code, a scan on the same day writes the same `aibom.cdx.json`, `report.html`, `report.md` and
`models.csv`, byte for byte (`manifest.json` also records how long the scan took).

### What the columns mean

- **Status**: `retired` (calls fail), `deprecated` (retirement announced), `active`, or `not tracked`. Not tracked
  means aibom has no sourced record for that model; it is not a claim that the model is fine. Dates are for the
  maker's own API; a `*` marks code that uses Amazon Bedrock, Azure or Google Vertex AI, which set their own dates.
- **Pinned**: whether the name fixes one model version. `gpt-4o` is a *floating alias*: the provider can move it to
  a newer snapshot, and `gpt-4o-2024-08-06` would pin it.
- **License**: the license name, with `(conditional)` or `(non-commercial)` where that applies. Hosted models sold
  under a provider's terms (GPT, Claude, Gemini) show `Provider API terms`.
- **Evidence level** (in `models.csv` and the AI-BOM): `called` when live code passes the name into a call on an AI
  SDK, otherwise `declared`. `declared` means not proven, not unused. **Reachability** is always `not_verified`:
  aibom does not prove that a request from outside reaches the code.

How each of these is decided, and where the data comes from, is in [docs/how-it-works.md](docs/how-it-works.md).

## What it does not do yet

- Read Go, Java or C# dependencies, or draw which package needs which: the dependency files are read for what a
  project depends on, not for the edges between packages.
- Find datasets or hardcoded API keys.
- Start an MCP server or list its tools, or see one declared outside the repository (a developer's own settings).
- Inspect model weight files, or check Hugging Face revision pinning.
- Run as a GitHub Action, fail a build on a policy (`--fail-on`), or write SARIF.
- See a model chosen at run time, from an environment variable, a settings page or a database. aibom reads code; it
  does not run your app.
- Find every model: about 1 in 5 is missed on unfamiliar code, mostly ids inside long lists and JSON catalogs.
  [Known misses](benchmark/README.md#known-misses).
- Track the lifecycle of every model: sourced records cover OpenAI, Anthropic and Google models today.

## Contributing

Bug reports with a link to the code that was misread are the most useful contribution. To set up a development
environment, run the tests and the benchmark, or update the model data, see [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache License 2.0, see [LICENSE](LICENSE). The bundled model data is derived in part from third-party sources; their
notices are in [NOTICE](NOTICE).

Built and maintained by [Korelex](https://korelex.ai).
