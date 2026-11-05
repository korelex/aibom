# Live demo for Windows PowerShell, step by step.
# Run from anywhere:   powershell -ExecutionPolicy Bypass -File demo\run_demo.ps1 [-App open_deep_research] [-Model gpt-4.1-mini]
# It downloads the app at the exact version used in the tests, then pauses before each command so you can talk first.
# Press Enter to run each step. The last step lets you paste any GitHub link.
param([string]$App = "open_deep_research", [string]$Model = "")
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")
$py = if (Get-Command python -ErrorAction SilentlyContinue) { "python" } elseif (Get-Command py -ErrorAction SilentlyContinue) { "py" } else { throw "Python was not found. Install Python 3.9 or newer." }
& $py scripts/fetch_repos.py --dir demo/apps $App | Out-Null
function Step($title, $cmd) {
    Write-Host ""
    Read-Host ">>> $title (press Enter to run)" | Out-Null
    Write-Host "PS> $cmd"
    Invoke-Expression $cmd
}
Step "1. Scan the app" "$py -m aibom_engine scan demo/apps/$App --out runs/$App"
if (-not $Model) { $Model = (Import-Csv "runs/$App/models.csv" -Encoding UTF8)[0].model }
Step "2. The list, most important first" "$py -m aibom_engine show runs/$App"
Step "3. Why is this model here, and how sure are we?" "$py -m aibom_engine explain runs/$App $Model"
Step "4. The readable report (opens in your browser)" "$py -m aibom_engine report runs/$App"
Step "5. The same model as stored in the standard AI-BOM file" "$py -m aibom_engine show runs/$App --item $Model"
Step "6. Compared with the four free scanners (answer key written by hand)" "$py benchmark/score.py $App runs/$App --compact"
Step "7. Results on apps the scanner had never seen" "$py benchmark/summary_all.py"
$link = Read-Host ">>> 8. Live: paste a GitHub link to scan, or press Enter to skip"
if ($link) { Write-Host "PS> $py -m aibom_engine scan $link --open"; Invoke-Expression "$py -m aibom_engine scan $link --open" }
