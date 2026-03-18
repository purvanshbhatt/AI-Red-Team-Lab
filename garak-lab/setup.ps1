# setup.ps1 - Initialize AI Red Team Lab Tools

$VirtualEnvName = ".venv"
$GlobalNodePackage = "promptfoo"

Write-Host "=========================================="
Write-Host " AI Red Team Lab - Environment Setup"
Write-Host "=========================================="
Write-Host ""
Write-Host "This script will install:"
Write-Host "  1. Garak (LLM vulnerability scanner)"
Write-Host "  2. PyRIT (Microsoft Python Risk Identification Tool)"
Write-Host "  3. Promptfoo (LLM application testing framework)"
Write-Host ""

# Check for Python
if (-not (Get-Command py -ErrorAction SilentlyContinue)) {
    Write-Warning "Python launcher ('py') not found. Please ensure Python is installed and added to PATH."
    exit 1
}

# Create Virtual Environment if it doesn't exist
if (-not (Test-Path -Path $VirtualEnvName)) {
    Write-Host "Creating Python virtual environment in '.\$VirtualEnvName'..."
    py -m venv $VirtualEnvName
} else {
    Write-Host "Virtual environment '.\$VirtualEnvName' already exists. Skipping creation."
}

# Install Python packages
Write-Host "`nActivating virtual environment and installing Python tools (Garak, PyRIT)..."
& .\$VirtualEnvName\Scripts\python.exe -m pip install --upgrade pip
& .\$VirtualEnvName\Scripts\python.exe -m pip install garak pyrit

if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to install Python packages."
    exit 1
}

# Check for Node.js and npm
if (-not (Get-Command npm -ErrorAction SilentlyContinue)) {
    Write-Warning "`nNode.js/npm not found. 'promptfoo' installation will be skipped."
    Write-Warning "Please install Node.js (https://nodejs.org/) and run 'npm install -g promptfoo' manually."
} else {
    Write-Host "`nInstalling '$GlobalNodePackage' globally via npm..."
    npm install -g $GlobalNodePackage
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "Failed to install promptfoo. You may need to run this as Administrator."
    }
}

Write-Host "`n=========================================="
Write-Host " Setup complete!"
Write-Host "=========================================="
Write-Host "To activate the virtual environment manually, run:"
Write-Host "    .\$VirtualEnvName\Scripts\Activate.ps1"
Write-Host "`nMake sure your environment variables (like GEMINI_API_KEY) are set before running the lab scripts."
Write-Host "=========================================="
