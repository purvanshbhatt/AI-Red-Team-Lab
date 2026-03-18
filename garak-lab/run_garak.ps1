# run_garak.ps1 - Garak Vulnerability Scanner wrapper

$VirtualEnvName = ".venv"

Write-Host "=========================================="
Write-Host " AI Red Team Lab - Garak Scanner"
Write-Host "=========================================="

# Check if GEMINI_API_KEY is set
if (-not $env:GEMINI_API_KEY) {
    Write-Warning "GEMINI_API_KEY environment variable is not set!"
    $env:GEMINI_API_KEY = Read-Host "Please enter your Gemini API Key"
    if (-not $env:GEMINI_API_KEY) {
        Write-Error "API Key is required to proceed. Exiting."
        exit 1
    }
}

# Check for Virtual Environment
if (-not (Test-Path -Path ".\$VirtualEnvName\Scripts\garak.exe")) {
    Write-Error "Garak executable not found. Please run .\setup.ps1 first."
    exit 1
}

$ModelName = "gemini-1.5-pro"
Write-Host "`nTarget Model: $ModelName"

# Ask user what they want to test
Write-Host "`nSelect a probe class to run against $ModelName :"
Write-Host "   1) promptinject (Prompt Injection)"
Write-Host "   2) jailbreak (Jailbreaks)"
Write-Host "   3) dan (Do Anything Now exploits)"
Write-Host "   4) knownbadsignatures (EICAR, etc)"
Write-Host "   5) all (Run all available probes - WARNING: Takes a long time)"
$Choice = Read-Host "Enter your choice (1-5)"

$ProbeOpt = ""
switch ($Choice) {
    "1" { $ProbeOpt = "promptinject" }
    "2" { $ProbeOpt = "jailbreak" }
    "3" { $ProbeOpt = "dan" }
    "4" { $ProbeOpt = "knownbadsignatures" }
    "5" { $ProbeOpt = "all" }
    default { 
        Write-Warning "Invalid choice. Defaulting to 'promptinject'."
        $ProbeOpt = "promptinject"
    }
}

Write-Host "`nStarting Garak scan with probe(s): $ProbeOpt ..."
Write-Host "Check the garak_runs directory for the detailed JSONL logs.`n"

# Run Garak
& ".\$VirtualEnvName\Scripts\garak.exe" --model_type google --model_name $ModelName --probes $ProbeOpt

Write-Host "`nGarak scan complete."
