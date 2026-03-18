# run_promptfoo.ps1 - Promptfoo Red Teaming Wrapper

$GlobalNodePackage = "promptfoo"

Write-Host "=========================================="
Write-Host " AI Red Team Lab - Promptfoo Evaluator"
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

# Check for Promptfoo
if (-not (Get-Command $GlobalNodePackage -ErrorAction SilentlyContinue)) {
    Write-Error "'$GlobalNodePackage' not found. Please ensure Node.js is installed and run .\setup.ps1 first."
    exit 1
}

Write-Host "`nRunning Promptfoo Matrix Evaluation (promptfoo.yaml)..."
Write-Host "Target: Google Gemini 1.5 Pro`n"

# Run Promptfoo Eval
& $GlobalNodePackage eval --config promptfoo.yaml

Write-Host "`nEvaluation complete! Starting web viewer to see results..."
Write-Host "Close the browser window and press Ctrl+C here when finished.`n"

# Start the web viewer
& $GlobalNodePackage view
