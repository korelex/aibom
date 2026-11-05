# How to record the demo yourself (about 20 minutes, 10 of them setup)

The complete guide, with every command and what you will see, is `TUTORIAL.md`. This page covers only the recording.

1. Set up once: `python -m pip install -r requirements.txt` then `python scripts/preflight.py` (see TUTORIAL.md, Part 1).
2. Get the terminal ready: font 18 to 22 pt, window at least 110 columns wide, dark background with white text. Clear the screen. Close anything private.
3. Open `runs/open_deep_research/report.html` once in the browser, then close the tab. Make the browser window large.
4. Start your recorder: Windows `Win + G` (Game Bar) or OBS, Mac `Cmd + Shift + 5`, Linux OBS.
5. Run the guided demo and read `voiceover_script.md` in your own words:

       Windows PowerShell:  powershell -ExecutionPolicy Bypass -File demo\run_demo.ps1
       Mac or Linux:        bash demo/run_demo.sh

6. For the last step, paste a GitHub link, wait for the report, and click one file and line.
7. Optional, 10 seconds of credibility: `python -m unittest discover -s tests` (92 tests, ends with OK).

If something goes wrong see TUTORIAL.md, Part 8. Keep these honest points in mind while talking: it finds AI models only, the answer keys were written by me, and about 79% of real models were found on apps it had never seen.
