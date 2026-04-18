# run_garak.ps1 - Garak Vulnerability Scanner wrapper (v0.14+)
#
# Garak v0.14 removed the native Google generator. This script uses the
# OpenAI-compatible generator with Gemini's REST endpoint instead.
# Configuration lives in garak_gemini.yaml.

$VirtualEnvName = ".venv"

Write-Host "=========================================="
Write-Host " AI Red Team Lab - Garak Scanner (v0.14)"
Write-Host "=========================================="

# ── Check if GEMINI_API_KEY is set ──────────────────────────────────────────
if (-not $env:GEMINI_API_KEY) {
    Write-Warning "GEMINI_API_KEY environment variable is not set!"
    $env:GEMINI_API_KEY = Read-Host "Please enter your Gemini API Key"
    if (-not $env:GEMINI_API_KEY) {
        Write-Error "API Key is required to proceed. Exiting."
        exit 1
    }
}

# Garak's OpenAICompatible generator reads the key from this env var:
$env:OPENAICOMPATIBLE_API_KEY = $env:GEMINI_API_KEY

# ── Check for Virtual Environment ──────────────────────────────────────────
$GarakExe = ".\$VirtualEnvName\Scripts\garak.exe"
if (-not (Test-Path -Path $GarakExe)) {
    Write-Error "Garak executable not found at '$GarakExe'. Please run .\setup.ps1 first."
    exit 1
}

# ── Target info ────────────────────────────────────────────────────────────
Write-Host "`nTarget : Gemini 2.0 Flash (via OpenAI-compatible endpoint)"
Write-Host "Config : garak_gemini.yaml"

# ── Ask user what they want to test ────────────────────────────────────────
Write-Host "`nSelect a probe class to run:"
Write-Host "   1) promptinject  (Prompt Injection)"
Write-Host "   2) dan           (Do Anything Now exploits)"
Write-Host "   3) gcg           (Greedy Coordinate Gradient attacks)"
Write-Host "   4) glitch        (Token glitch exploits)"
Write-Host "   5) encoding      (Encoding-based evasion)"
Write-Host "   6) lmrc          (Language Model Risk Cards)"
Write-Host "   7) all           (Run ALL probes - WARNING: very slow)"
$Choice = Read-Host "Enter your choice (1-7)"

$ProbeOpt = ""
switch ($Choice) {
    "1" { $ProbeOpt = "promptinject" }
    "2" { $ProbeOpt = "dan" }
    "3" { $ProbeOpt = "gcg" }
    "4" { $ProbeOpt = "glitch" }
    "5" { $ProbeOpt = "encoding" }
    "6" { $ProbeOpt = "lmrc" }
    "7" { $ProbeOpt = "all" }
    default { 
        Write-Warning "Invalid choice. Defaulting to 'promptinject'."
        $ProbeOpt = "promptinject"
    }
}

Write-Host "`nStarting Garak scan with probe(s): $ProbeOpt ..."
Write-Host "Reports will be saved in the garak_runs/ directory.`n"

# ── Run Garak with the Gemini YAML config ──────────────────────────────────
& $GarakExe --config garak_gemini.yaml --probes $ProbeOpt

Write-Host "`nGarak scan complete."
