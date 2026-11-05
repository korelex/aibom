#!/bin/bash
# Live demo, step by step. From the aibom-engine folder:   bash demo/run_demo.sh [app] [model]
# Default app: open_deep_research (small, fast, and a clear mix of models used directly and models only listed in tables).
# Other apps you can use: go-openai, ollama-js, open-canvas, ai-chatbot, azure-search-openai-demo-csharp
# It downloads the app at the exact version used in the tests, then pauses before each command so you can talk first.
# Press Enter to run each step. The last step lets you paste any GitHub link.
set -e
cd "$(dirname "$0")/.."
APP=${1:-open_deep_research}
PY=$(command -v python3 || command -v python)
$PY scripts/fetch_repos.py --dir demo/apps "$APP" > /dev/null
step() { echo; read -p ">>> $1   (press Enter to run)" _; echo "\$ $(eval echo "$2")"; eval "$2"; }
step "1. Scan the app" '$PY -m aibom_engine scan demo/apps/$APP --out runs/$APP'
MODEL=${2:-$($PY -c "import csv; r=list(csv.reader(open('runs/$APP/models.csv', encoding='utf-8-sig'))); print(r[1][0])")}
step "2. The list, most important first" '$PY -m aibom_engine show runs/$APP'
step "3. Why is this model here, and how sure are we?" '$PY -m aibom_engine explain runs/$APP $MODEL'
step "4. The readable report (opens in your browser)" '$PY -m aibom_engine report runs/$APP'
step "5. The same model as stored in the standard AI-BOM file" '$PY -m aibom_engine show runs/$APP --item $MODEL'
step "6. Compared with the four free scanners (answer key written by hand)" '$PY benchmark/score.py $APP runs/$APP --compact'
step "7. Results on apps the scanner had never seen" '$PY benchmark/summary_all.py'
read -p ">>> 8. Live: paste a GitHub link to scan, or press Enter to skip   " LINK
if [ -n "$LINK" ]; then echo "\$ $PY -m aibom_engine scan $LINK --open"; $PY -m aibom_engine scan "$LINK" --open; fi
