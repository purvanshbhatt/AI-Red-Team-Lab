# AI Red Team Lab

Two integrated toolkits for authorized offensive security testing:

1. **ART** (`art/`) — an end-to-end AI red team & VAPT framework covering recon,
   web/network/cloud vulnerability assessment, LLM/agent attacks, and consolidated reporting.
2. **garak-lab/** — standalone garak / PyRIT / Promptfoo pipelines for deep LLM scanning
   (see their sections below).

> **Authorization required.** Active modules refuse to run against any target that has not
> been explicitly added to the workspace scope. Only test systems you own or have written
> permission to assess.

---

## Quick start

```powershell
# one-time setup (creates .venv in garak-lab/, installs deps)
.\garak-lab\setup.ps1

# start the local vulnerable demo app (safe practice target)
.\run_art.ps1 demo-target --port 8006

# in another terminal: authorize it and run the full pipeline
.\run_art.ps1 scope add 127.0.0.1 -w lab
.\run_art.ps1 pipeline -t http://127.0.0.1:8006 -w lab
.\run_art.ps1 report --format html -w lab     # -> reports/lab/report.html
```

Or drive everything interactively:

```powershell
.\run_art.ps1 shell
art> use web/sqli_detect
art (web/sqli_detect)> set target http://127.0.0.1:8006
art (web/sqli_detect)> set path /item
art (web/sqli_detect)> run
```

## Module catalog

| Category | Modules |
|---|---|
| **recon** | `dns_enum`, `subdomain_osint` (crt.sh CT logs), `port_scan`, `banner_grab`, `tech_fingerprint` |
| **web** | `security_headers`, `cors_misconfig`, `tls_audit`, `dir_bruteforce`, `sqli_detect` (error/boolean/time-based), `xss_reflect`, `cmd_inject_probe`, `rate_limit_check`, `jwt_audit` (none-alg / weak HMAC secrets) |
| **network** | `host_discovery` (TCP-ping CIDR sweep) |
| **cloud** | `storage_misconfig` (S3 / Azure Blob / GCS anonymous access) |
| **ai** | `prompt_inject_matrix`, `sysprompt_extraction`, `agent_tool_abuse`, `mcp_server_audit`, plus wrappers around garak & PyRIT |
| **postexp** | `validate_findings` — safely replays prior HIGH findings to confirm remediation |

Passive modules are marked `(passive)` in `list`; everything else requires scope authorization.

## CLI reference

```
art list [category]                     # show modules
art info <module>                       # module details + options
art scope add|remove|list <target>      # manage authorized targets (-w workspace)
art run <module> -t TARGET [-w ws] [--set k=v ...]
art pipeline -t TARGET [-w ws] [--modules m1,m2,...]
art report [--format html|json|md] [-w ws]
art shell                               # interactive console
art demo-target [--port 8006]           # local vulnerable practice app
```

Workspaces live under `reports/<name>/` and contain `scope.json`, `findings.db`
and exported reports. Module options used in a run are remembered per-workspace so
`postexp/validate_findings` can replay them exactly.

## Safety posture

- Detection/validation only — benign markers (`id` output, HTML comments), boolean diffs,
  short sleeps; no destructive payloads, no DoS, no credential brute force.
- Every active module passes through an explicit authorization gate.
- The demo app binds localhost only.

## AI attack configuration

The AI modules talk to any OpenAI-compatible endpoint:

```powershell
$env:GEMINI_API_KEY = "your-key"        # default target: gemini-2.0-flash
$env:ART_LLM_MODEL = "gemini-2.0-flash" # optional override
$env:ART_LLM_ENDPOINT = "https://generativelanguage.googleapis.com/v1beta/openai/"
```

```powershell
.\run_art.ps1 run ai/prompt_inject_matrix -t gemini -w lab
.\run_art.ps1 run ai/sysprompt_extraction -t gemini -w lab
.\run_art.ps1 run ai/mcp_server_audit --set url=http://localhost:6277/mcp -w lab
```

---

## Legacy toolchains (garak-lab/)

### Garak — LLM vulnerability scanner

```powershell
cd garak-lab
$env:GEMINI_API_KEY = "your-key"
.\run_garak.ps1          # choose probe class; reports -> garak_runs/
```

### PyRIT — Microsoft Risk Identification Tool

```powershell
.\run_pyrit.ps1          # 5 adversarial payloads -> pyrit_results.db
```

### Promptfoo — adversarial evaluation matrix

```powershell
.\run_promptfoo.ps1      # runs promptfoo.yaml, opens web viewer
```

## Customizing the LLM target

- **ART**: `$env:ART_LLM_MODEL` / `$env:ART_LLM_ENDPOINT`
- **Garak**: edit `target_name` in `garak-lab/garak_gemini.yaml`
- **PyRIT**: edit `MODEL_NAME` in `garak-lab/run_pyrit_demo.py`
- **Promptfoo**: edit `providers` in `garak-lab/promptfoo.yaml`
