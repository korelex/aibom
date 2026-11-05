# Live meeting guide: showing the AI models scanner on any repo

The full step-by-step is in `TUTORIAL.md`. This page is the short version to keep open during the meeting.

## Ten minutes before
1. Open a terminal inside the `aibom-engine` folder. Make the font big (18 to 22 pt).
2. Run `python scripts/preflight.py`. It says "Ready for the meeting." when the tools work and GitHub can be reached from this network.
3. If the internet looks shaky, use plan B (bottom of this page) from the start.
4. Open `runs/open_deep_research/report.html` once in the browser, so the first page load is not a surprise.

## Explain it in 30 seconds
"It reads every file in a repository and sorts it: real code, settings, tests, docs. It looks for AI model names in three ways: a dictionary of about 6,000 known names, rules that read where a string sits, and rules that spot names by their shape. Then it checks each name: is it written in live code, or only in a comment, a printed message, a test or a doc page? Live ones go into the AI-BOM with the file and line as proof, and a link to that line. The rest are listed as left out, with the reason."

## The demo
1. Run the guided script: `bash demo/run_demo.sh` (Mac and Linux) or `powershell -ExecutionPolicy Bypass -File demo\run_demo.ps1` (Windows). It pauses before each step.
2. Or, for any repo someone names:

       python -m aibom_engine scan https://github.com/OWNER/REPO --open

   It downloads the repo, prints progress, and opens the report. Most repos take 5 to 40 seconds.
3. In the report: read the headline, point at the three numbers, search for a model, click a file and line to open it on GitHub, open "Left out, and why", and point at the box "What this scan cannot see".
4. If asked "why is this model here?": `python -m aibom_engine explain runs/REPO MODEL`.
5. If asked about accuracy: `python benchmark/summary_all.py`.

## What to say about accuracy
- On five apps the scanner had never seen (answer keys written first), it found 66% to 96% of the real models, 79% on average, and about 99% of what it reported was correct. The best free scanners found about 10%.
- On a repo he picks it may miss some. Say which gap it is: names no dictionary lists inside long lists or JSON catalogs, or a model chosen when the app runs.
- It finds AI models only. Agents, tools, vector databases and frameworks come later.

## What it cannot do (say it before he asks)
- It cannot see a model chosen when the app runs (an environment variable, a settings page, a database).
- It does not run the app and only reads one repository.
- Private repositories must be downloaded first; give it the folder.
- The answer keys for the test apps were written by me, not an independent person.

## If something goes wrong
| What you see | What to do |
|---|---|
| "I could not reach the internet" | Switch to plan B below |
| "The link may be wrong, or the repository is private" | Check the spelling, or download the code and scan the folder |
| Zero models found | Say it: the app may choose its model at run time. The report explains this on screen |
| It runs long | It stops reading at 120 seconds and says so. Rerun with `--max-seconds 300` |
| A wrong name appears | Open its row, show the line, say which rule let it through. That is a normal bug report |
| The report has no links | The folder is not a clean git clone. Scan the GitHub link instead |

## Plan B (no internet, or a surprise)
Saved results for 17 apps are in `runs/`, each with its report and links:

    python -m aibom_engine show runs/open_deep_research
    python -m aibom_engine report runs/open_deep_research
    python -m aibom_engine explain runs/open_deep_research gpt-4.1-mini

To scan a folder already on disk: `python -m aibom_engine scan C:\path\to\folder --open`

## One honest sentence if he asks "is this meaningful?"
"It is the first step of an AI-BOM: knowing exactly which models an app uses, with proof you can click. The free tools miss most of them. It is models only so far, and the next step is to prove it on a real company app."
