# Running aibom in your own infrastructure

aibom reads a code folder and writes an AI-BOM and reports. It can run on a laptop, a build server or a locked-down
network. This page says what it needs, what it touches, and how to run it by hand and in CI. Every command here was run
before it was written down; what does not exist yet is listed at the end.

## What it does with your code

- **Reads** the files in the folder you point it at. It does not change them (a test hashed a project before and after a
  scan: no file changed).
- **Writes** only to the output folder you choose (`--out`, default `runs/<app name>` in the current folder): the AI-BOM,
  the reports and some working JSON files.
- **Makes no network calls** when you scan a local folder. A test ran a full scan, `aibom vulns` and `aibom report --pdf`
  with every network call refused, and nothing failed. The model data and the vulnerability data are inside the package.
- **Sends nothing anywhere**: there is no telemetry and no upload. The only network use is `git clone`, and only when you
  give a repository link instead of a folder.
- **Never runs your code and never installs your dependencies.** It reads dependency files as text.
- **Keeps secrets out of its output.** Each result keeps the line of code that proves it. A key written on that line
  (`api_key="sk-..."`, a bearer token, a password in a URL) is replaced by asterisks before it is stored. Treat the output
  folder like the source it came from anyway: it contains file paths and short lines of your code.

**Recommended setup:** scan a local checkout inside your own network. Then your code never leaves it. Scanning a repository
link makes the machine running aibom clone that code, which is fine for public code and usually not what you want for private code.

## What you need

| | |
| --- | --- |
| Python | 3.9 or newer |
| Git | only to scan a repository link |
| Chrome, Edge or Chromium | only for `aibom report --pdf` (without one, open `report.html` and use Print, Save as PDF) |
| Disk and time | the package and its dependencies are about 10 MB. A scan of a project with about 1,500 files typically takes under half a minute |
| Network | none for a scan of a local folder |

## Install

aibom is not on PyPI yet. Use the wheel file (`aibom-<version>-py3-none-any.whl`) that comes with this page, or a checkout of
the repository.

```bash
python -m venv .venv
source .venv/bin/activate          # Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install aibom-0.5.0-py3-none-any.whl
aibom --version
```

```text
aibom 0.5.0
  model data:          2026-11-09
  vulnerability data:  2026-11-11
```

The two dates are how fresh the bundled data is. Advisories found after that date are not in it.

### Without internet (air-gapped)

On a machine **with** internet and the same operating system and Python version as the target, collect the wheel and every
dependency:

```bash
python -m pip download -d wheelhouse aibom-0.5.0-py3-none-any.whl
```

That was 37 files, 9 MB. Copy the `wheelhouse` folder to the offline machine and install from it:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --no-index --find-links wheelhouse aibom
```

## Run it

```bash
aibom scan /path/to/checkout --out /path/to/results      # scan a local folder
aibom vulns /path/to/results                             # known vulnerabilities, worst first, with a fix plan
aibom vulns /path/to/results --severity high             # high and critical only
aibom report /path/to/results --pdf                      # report.pdf in the results folder
```

The results folder holds `aibom.cdx.json` (the AI-BOM, CycloneDX 1.6), `report.html`, `report.md`, `models.csv`,
`packages.csv` and the working JSON. [What each file is.](../README.md#output) With no terminal attached (a pipe, CI) aibom
prints plain text with no colour.

## In a build pipeline

### GitHub Actions

aibom is also a GitHub Action. Add `.github/workflows/aibom.yml`:

```yaml
name: aibom
on: [pull_request, push]
permissions:
  contents: read
  security-events: write     # to show the findings in code scanning
jobs:
  aibom:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: korelex/aibom@<commit-sha>   # pin a release commit; the Releases page lists them
        with:
          fail-on: high
```

On every pull request it scans the repository, and:

- fails the check when a risk flag at `fail-on` or worse is found (leave `fail-on` empty to never fail on flags);
- sends the flags to GitHub code scanning as SARIF, so each one shows on its line in the pull request and in the
  Security tab, with its fix;
- writes the report to the job summary, starting with the verdict (passed or failed, each blocking risk with its file, line
  and fix, and what was found that does not block, such as known vulnerabilities), and keeps the results (report, AI-BOM, flags, SARIF) as an artifact named `aibom`.

| Input | Default | Meaning |
| --- | --- | --- |
| `path` | `.` | the folder to scan, relative to the repository root |
| `fail-on` | `high` | fail on a flag at `info`, `low`, `medium` or `high` or worse; empty never fails on flags |
| `upload-sarif` | `true` | send the flags to code scanning (needs `security-events: write`) |
| `upload-artifact` | `true` | keep the results as an artifact |
| `artifact-name` | `aibom` | its name, unique within a run |
| `output` | `aibom-out` | where the results are written on the runner |
| `max-seconds` | `600` | stop reading files after this many seconds |
| `python-version` | `3.12` | the Python that runs aibom |

The outputs are `exit-code` (0 passed, 3 a flag at `fail-on` or worse, 4 the scan did not finish, 2 the scan could not run), `results` and `sarif`.
Everything runs on the runner: the code is read, never executed, and nothing leaves it except what GitHub's own steps
upload to your repository. Code scanning is not available on every repository (a private one without GitHub Advanced
Security, a pull request from a fork); there the upload is skipped with a warning and the rest still works. The action
pins its own third-party steps to commit ids.

To run aibom without the action (an air-gapped runner, a wheel kept in your own artifact store):

```yaml
      - run: python -m pip install ./tools/aibom-0.5.0-py3-none-any.whl
      - run: aibom scan . --out aibom-out --quiet --fail-on high
```

GitLab CI and Jenkins use the same commands: install the wheel, `aibom scan . --out aibom-out --quiet --fail-on high`,
keep `aibom-out` as the build artifact. Every scan also writes `aibom-out/aibom.sarif` for tools that read SARIF.

### A repository you do not trust

aibom treats what it scans as untrusted. It starts no program from that folder and runs none of the folder's git hooks,
filters or settings. It reads only real files inside the folder: links, junctions and paths that climb out (such as
`-r ../../file` in a requirements file) are not followed, and a note says how many links were skipped. It writes no
result through a link. Run it with the installed `aibom` command: `python -m` lets Python load a package from the current
folder before aibom's own code starts.

### Failing the build

`aibom scan . --fail-on high` exits with code `3` when the scan has a risk flag (a leaked key, an MCP server started
through a shell string, a model file that imports dangerous code and the others in the README) at that severity or worse.
The results are still written. When there is no such flag but the scan did not finish (the time limit, a check that
failed), it exits with `4`: an unfinished scan is never a pass. A scan that cannot run exits with `2`, so a script can
tell a failed gate from a broken scan. The gate looks at risk flags only, not at vulnerabilities. For those, this script, run after the scan, fails the
build on critical or high vulnerabilities in AI packages the project depends on directly:

```python
# aibom-gate.py: python aibom-gate.py aibom-out [critical,high]
import json, sys

run = sys.argv[1]
levels = set(sys.argv[2].split(",")) if len(sys.argv) > 2 else {"critical", "high"}
with open(run + "/packages.json", encoding="utf-8") as f:
    packages = json.load(f)["packages"]
bad = [(c["name"], c["version"], a["id"], a["severity"])
       for c in packages if not c.get("left_out") and c.get("direct") is not False
       for a in (c.get("vulnerabilities") or {}).get("advisories", []) if a["severity"] in levels]
for name, version, advisory, severity in bad:
    print("%-8s %s %s %s" % (severity, name, version, advisory))
print("%d blocking vulnerabilities" % len(bad))
sys.exit(1 if bad else 0)
```

It exits `1` when it finds any and `0` when it finds none. A vulnerability here means the exact version is named in an
advisory; it does not mean your app can be exploited. Decide whether to block on that for your own policy.

## Keeping the data fresh

The vulnerability data is a snapshot made when the package was built (`aibom --version` shows its date). To get newer data,
install a newer wheel. There is no automatic update yet.

## Not available yet

- A published Docker image, and a release on PyPI or Homebrew.
- A GitLab CI template (the commands above work in any pipeline).
- Dependency data without a lockfile: with only a `requirements.txt` or `package.json`, aibom sees the direct dependencies,
  and only exact pins can be checked for vulnerabilities. A lockfile gives the whole tree.
- Languages other than Python and JavaScript/TypeScript for packages.
