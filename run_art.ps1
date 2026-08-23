# run_art.ps1 - ART framework launcher (AI Red Team & VAPT)
# Usage:
#   .\run_art.ps1                          # interactive shell
#   .\run_art.ps1 list                     # list modules
#   .\run_art.ps1 scope add 127.0.0.1 -w lab
#   .\run_art.ps1 pipeline -t 127.0.0.1:8006 -w lab
#   .\run_art.ps1 demo-target              # start local vulnerable demo app

$VenvPython = Join-Path $PSScriptRoot "garak-lab\.venv\Scripts\python.exe"

if (-not (Test-Path $VenvPython)) {
    Write-Error "Python venv not found at '$VenvPython'. Run garak-lab\setup.ps1 first."
    exit 1
}

$env:PYTHONUTF8 = "1"
& $VenvPython -m art.cli @args
