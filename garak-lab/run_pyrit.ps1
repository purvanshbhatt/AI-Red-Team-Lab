# run_pyrit.ps1 - PyRIT Vulnerability Scanner wrapper

$VirtualEnvName = ".venv"

Write-Host "=========================================="
Write-Host " AI Red Team Lab - PyRIT Runner"
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
if (-not (Test-Path -Path ".\$VirtualEnvName\Scripts\python.exe")) {
    Write-Error "Python virtual environment not found. Please run .\setup.ps1 first."
    exit 1
}

Write-Host "`nExecuting Microsoft PyRIT Demonstration (run_pyrit_demo.py)...`n"

# Run PyRIT Demo
& ".\$VirtualEnvName\Scripts\python.exe" "run_pyrit_demo.py"

Write-Host "`nPyRIT tests finished."
