# AI Red Team Lab

Welcome to the AI Red Teaming Lab! This environment is pre-configured to test Large Language Models (specifically Google's Gemini) against various adversarial attacks to evaluate their safety, alignment, and robustness.

## Features & Tools Included

This lab utilizes three complementary open-source frameworks:

1.  **[Garak](https://garak.ai/)**: The "Nmap for LLMs." A vulnerability scanner that probes for prompt injections, jailbreaks, data leakage, and more.
2.  **[Microsoft PyRIT](https://github.com/Azure/PyRIT)**: The Python Risk Identification Tool. A framework for orchestrated, programmatic red teaming of generative AI using multi-turn conversations and persistent memory.
3.  **[Promptfoo](https://promptfoo.dev/)**: An extensible framework for running rapid, matrix-based adversarial evaluations against LLM applications from a configuration file, featuring web-based reporting.

---

## Prerequisites

-   Operating System: Windows
-   **Python 3.10+** (Available via the `py` launcher)
-   **Node.js & npm** (Required for Promptfoo)
-   **A Gemini API Key** (Get one from [Google AI Studio](https://aistudio.google.com/app/apikey))

---

## Getting Started

### 1. Initialize the Environment
Open a PowerShell terminal in this directory and run the setup script. This will create a Python virtual environment and install all necessary dependencies:

```powershell
.\setup.ps1
```

*(Note: During the Promptfoo installation, you might see npm warnings. Ignore them unless the installation explicitly fails).*

### 2. Set Your API Key
Before running any tool, set the Gemini API key in your current session:

```powershell
$env:GEMINI_API_KEY = "your-api-key-here"
```

---

## Running the Red Team Tools

### 🛠️ Garak: Vulnerability Scanner

Garak scans for LLM vulnerabilities using automated probes. It connects to Gemini via the OpenAI-compatible REST API (configured in `garak_gemini.yaml`).

```powershell
.\run_garak.ps1
```

You will be prompted to choose a probe class (e.g., prompt injections, DAN exploits, encoding attacks). Reports are saved in the `garak_runs/` directory as JSONL.

**Available probes:** `promptinject`, `dan`, `gcg`, `glitch`, `encoding`, `lmrc`, or `all`.

### 🐍 PyRIT: Microsoft's Risk Identification Tool

PyRIT sends adversarial payloads to Gemini and records the full conversation in a local SQLite database for forensic analysis.

```powershell
.\run_pyrit.ps1
```

This runs five predefined adversarial payloads (system prompt extraction, jailbreak, harmful knowledge elicitation, credential exfiltration, encoding bypass). Results are stored in `pyrit_results.db`.

### ⚡ Promptfoo: Rapid Adversarial Matrix

Promptfoo runs deterministic safety assertions against the model from a YAML config and generates a web-based report.

```powershell
.\run_promptfoo.ps1
```

This will execute the evaluation matrix and open a local web viewer (typically at `http://localhost:15500`) showing the results. The config is in `promptfoo.yaml`.

---

## Customizing the Target Model

By default, all tools target **`gemini-2.0-flash`**.

-   **Garak**: Edit the `target_name` field in `garak_gemini.yaml`.
-   **PyRIT**: Edit the `MODEL_NAME` constant in `run_pyrit_demo.py`.
-   **Promptfoo**: Edit the `providers` section in `promptfoo.yaml`.

---

## Project Structure

```
garak-lab/
├── setup.ps1              # One-time environment setup
├── garak_gemini.yaml      # Garak generator config (Gemini → OpenAI-compatible)
├── run_garak.ps1          # Garak scanner launcher
├── run_pyrit.ps1          # PyRIT launcher
├── run_pyrit_demo.py      # PyRIT adversarial payload script
├── run_promptfoo.ps1      # Promptfoo launcher
├── promptfoo.yaml         # Promptfoo adversarial evaluation config
├── promptfoo_test.yaml    # Promptfoo mock test (no API key needed)
├── echo.py                # Mock echo provider for promptfoo testing
└── README.md              # This file
```

---

## Technical Notes

-   **Garak** uses the `openai.OpenAICompatible` generator to talk to Gemini's OpenAI-compatible endpoint at `https://generativelanguage.googleapis.com/v1beta/openai/`.
-   **PyRIT** uses `OpenAIChatTarget` (from PyRIT v0.11+) pointed at the same endpoint. Memory is stored in a local SQLite database via `CentralMemory`.
-   **Promptfoo** uses its built-in `google:` provider prefix which calls the Gemini API natively.
