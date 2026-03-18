# AI Red Team Lab

Welcome to the AI Red Teaming Lab! This environment is pre-configured to test Large Language Models (specifically Google's Gemini) against various adversarial attacks to evaluate their safety, alignment, and robustness.

## Features & Tools Included

This lab utilizes three complimentary open-source frameworks:

1.  **[Garak](https://garak.ai/)**: The "Nmap for LLMs." A vulnerability scanner that probes for prompt injections, jailbreaks, data leakage, and more.
2.  **[Microsoft PyRIT](https://github.com/Azure/PyRIT)**: The Python Risk Identification Tool. A framework for orchestrated, programmatic red teaming of generative AI using multi-turn conversations and memory.
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

---

## Running the Red Team Tools

Before running any scans, ensure you have your API key ready. The scripts will prompt you for it if it's not set as an environment variable (`$env:GEMINI_API_KEY = "your_key_here"`).

### 🛠️ Garak: Vulnerability Scanner

To run automated vulnerability probes against Gemini:

```powershell
.\run_garak.ps1
```
You will be prompted to choose which probe class to execute (e.g., prompt injections, jailbreaks, or all). Detailed JSONL reports are saved in the `garak_runs/` directory.

### 🐍 PyRIT: Microsoft's Risk Identification Tool

To run a demonstration of PyRIT's orchestrated attacks:

```powershell
.\run_pyrit.ps1
```
This runs a predefined set of adversarial payloads asynchronously. The conversational history and memory are stored locally in the `pyrit_results.db` database. You can customize the payloads by editing `run_pyrit_demo.py`.

### ⚡ Promptfoo: Rapid Adversarial Matrix

To run deterministic safety assertions based on the `promptfoo.yaml` configuration:

```powershell
.\run_promptfoo.ps1
```
This script will execute the tests and automatically open a local web server (typically at `http://localhost:15500`) to display a detailed matrix comparing the payloads against the model's responses and assertions.

---

## Customizing the Target Model

By default, the scripts target `gemini-1.5-pro`. 

-   **Garak**: Edit the `$ModelName` variable in `run_garak.ps1`.
-   **PyRIT**: Edit the `model_name` parameter in `run_pyrit_demo.py`.
-   **Promptfoo**: Edit the `providers` section in `promptfoo.yaml`.
