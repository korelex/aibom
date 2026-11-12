# Contributing to aibom

Thank you for helping. The most useful contribution is a bug report that links to code aibom misread: a model it
missed, a name it reported that is not a model, or a wrong status or license. Please include the repository, the
commit, the file and line, and the aibom output.

## Development setup

```bash
git clone https://github.com/korelex/aibom.git
cd aibom
python -m venv .venv
source .venv/bin/activate          # Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
```

## Before you open a pull request

```bash
python -m pytest                     # the test suite
python scripts/smoke_wheel.py        # builds the wheel, installs it in a clean virtualenv and scans with it
```

`scripts/smoke_wheel.py` needs the `build` package (`python -m pip install build`). It catches files missing from the
installed package, which the test suite cannot see.

If you change how models are found (anything in `aibom_engine/finders/`, `merge.py`, `verify.py` or the model
dictionary), also run the benchmark and include the before and after tables in the pull request:

```bash
python benchmark/run.py
```

Detection changes must not lower the round-3 results. See [benchmark/README.md](benchmark/README.md) for how the
benchmark works and why its answer keys must not be changed to fit a result.

Pull request guidelines:

- One change per pull request, with a test for each new detection or option.
- Fixes asked for in a review go into the same pull request.
- Update the README and `--help` when behaviour changes. The README describes only what works today.
- The CycloneDX output must still validate (the tests check it).

## Updating the model data

The data lives in `aibom_engine/knowledge/`. `curated.json` is edited by hand; `ai_db.json` and `model_names.json`
are generated from it and from public catalogues. Both JSON files are written one entry per line so that a data
change is a readable diff.

| Command | What it does | Network |
| --- | --- | --- |
| `python scripts/build_db.py --apply-curated` | Re-apply `curated.json` to the existing database | no |
| `python scripts/build_db.py --reformat` | Rewrite both files in their one-entry-per-line layout | no |
| `python scripts/build_db.py --osv-only` | Refresh only the vulnerability advisories from OSV's ecosystem dumps (about 260 MB, cached in `build/osv/` for 20 hours) | yes |
| `python scripts/build_db.py` | Rebuild everything from LiteLLM, OpenRouter, OSV and `curated.json` | yes |
| `python scripts/check_licenses.py` | Check every curated license against its Hugging Face repo | yes |

Use `--apply-curated` after a hand edit, so the pull request shows only your change and not a day of upstream drift.

Rules for curated records:

- Every lifecycle record needs `source_url` (the provider's own page) and `checked` (the date you read it). Store
  dates, never a status word: the status is worked out from the dates at scan time.
- A retirement belongs to a specific snapshot. Add the exact names the provider lists, not a whole family, unless the
  whole family shares one schedule.
- Every open-model license needs `license_source_url` and `license_checked`. Read the license itself; do not guess
  from the model's name.

The tests in `tests/test_lifecycle.py` and `tests/test_license_labels.py` enforce these rules.

## License

By contributing, you agree that your contributions are licensed under the [Apache License 2.0](LICENSE).
