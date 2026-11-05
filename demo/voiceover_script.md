# What to say while running demo/run_demo.sh (about 5 minutes)

Plain words, first person. Change anything that does not sound like you. The script pauses before each command, so say the line first, then press Enter.

Start
"This is the AI models part of the AI-BOM tool. You give it an app's code, and it tells you which AI models the app uses, with the exact line of code as proof."

1. Scan
"I'm pointing it at open deep research, a real open source app. It sorts the files, looks for model names, and checks each one. That took about half a second. Nine models are used directly in the code. Thirty-three more only appear in long tables, so I separate them. Three names were left out because they only appear in comments or documentation."

2. The list
"Here is the list, most important first. Model, maker, type, and the file and line that proves it."

3. Explain
"If someone asks why a model is here, this answers it. Three real places in the code, each with a link to the exact line on GitHub."

4. The report
"For people who don't read code there is a web page. The headline says it in one sentence, then the numbers. Models are grouped by maker. I can search, and I can click a file and line to open that exact line on GitHub. This part lists the names that were left out and why. And this box says what a scan cannot see, so nobody is misled."

5. The standard file
"Behind the page is the standard AI-BOM file, checked against the official format, so other security tools can read it."

6. Compared with the free scanners
"I wrote down the correct answers by hand before running anything. On this app the best free scanner found one of the four models and reported six wrong names. This one found all four."

7. Apps it had never seen
"On five apps it had never seen, it found about 79 percent of the real models and about 99 percent of what it reported was correct. The best free scanners found about 10 percent. It is weaker on some apps, and I know the gaps."

8. Live on any repo
"Now give me any repository. I paste the link, it downloads it, scans it, and opens the report." Then click one file and line together on GitHub.

End
"It finds AI models only so far, and it cannot see a model that an app chooses when it runs. Next I'm fixing the known gaps, testing on new apps so the numbers stay honest, and then adding the other AI parts."
