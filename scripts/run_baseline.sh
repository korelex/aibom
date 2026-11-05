#!/bin/bash
# Runs the four existing scanners on a repo and saves their raw output in benchmark/baseline/<repo>/
# Usage: scripts/run_baseline.sh <repo-folder> <repo-name>
# Needs: cdxgen, ai-bom (Trusera), aibom-scanner, and Cisco's cisco-aibom with its own python (see ../cisco_test)
set -e
R=$1; N=$2; B=benchmark/baseline/$N; mkdir -p $B
cdxgen -t aibom --no-banner --no-install-deps -o $B/cdxgen.json "$R" > $B/cdxgen.log 2>&1
ai-bom scan "$R" -f json -o $B/trusera.json > $B/trusera.log 2>&1
aibom-scanner scan --path "$R" -f json -o $B/aibom_scanner.json > $B/aibom_scanner.log 2>&1
python nollm_scan.py "$R" $B/cisco.json > $B/cisco.log 2>&1   # run with Cisco's own python, first pass only
echo "baseline saved in $B"
