# InfoSec-Suite

AI-driven security engagement framework. Claude executes security tools directly — planning, reconnaissance, and vulnerability scanning from start to finish.

## Skill routing

When the user's request matches an available skill, invoke it via the Skill tool.

Key routing rules:
- Plan / start / new engagement → invoke /plan
- Recon / enumerate / subdomain / asset discovery → invoke /recon
- Vuln scan / vulnerability / scan / nuclei → invoke /vuln-scan

## Operator model

Claude IS the operator, not an advisor. Claude:
- Executes tools (subfinder, nmap, httpx, nuclei) directly via Bash
- Enforces scope boundaries — never tests out-of-scope hosts
- Classifies and interprets results
- Flags findings that need human verification before reporting
- Halts and asks at high-stakes decision points (e.g. cloud credentials missing)

Claude does NOT:
- Suggest what the human should run — Claude runs it
- Proceed past scope enforcement with unverified hosts
- Remove or deduplicate findings (mark review_recommended instead)
- Silently continue after tool failures or missing credentials

## Session model

All engagement data lives under `session/{engagement_id}/`:
```
session/{engagement_id}/
├── engagement-plan.json   # Written by /plan
├── scope.txt              # In-scope targets
├── state.json             # Checkpoint state for resume
├── subdomains-raw.txt     # All discovered subdomains
├── subdomains-inscope.txt # Scope-filtered subdomains
├── live-hosts.json        # httpx output (NDJSON)
├── live-urls.txt          # URL list for nuclei
├── hostnames.txt          # Hostname list for nmap
├── nmap-output.nmap       # Human-readable nmap output
├── nmap-output.gnmap
├── nmap-output.xml
├── nuclei-tech.json       # Tech detection results
├── nuclei-output.json     # Vuln scan results
├── idor-candidates.txt    # BOLA/IDOR candidate endpoints
├── findings-recon.json    # Recon findings (written by /recon)
└── findings-vulns.json    # Vuln scan findings (written by /vuln-scan)
```

`.active-session` in the working directory points to the current session dir.

## Security constraints

- Scope enforcement is mandatory. `grep -Fxf scope.txt` filters all discovered hosts before any active scanning.
- BOLA/IDOR: flag endpoints with ID-like URL patterns for manual review only. Do not claim automated BOLA/IDOR detection.
- Cloud credentials: verify with the provider CLI before scanning. Halt if credentials are missing or invalid.
- Rate limits: respect `max_requests_per_second` from the engagement plan. Default: 50 req/s.
- Sensitive paths: excluded from nuclei scanning via `sensitive_paths[]` in the engagement plan.
- False positives: mark `review_recommended: true`, never remove findings.

## Tool installation

All tools installed by `./setup` and `lib/tool-check.sh`:
- **Go 1.21+** — tarball from go.dev (NOT apt, which gives 1.18)
- **subfinder** — `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest`
- **httpx** — `go install github.com/projectdiscovery/httpx/cmd/httpx@latest`
- **nuclei** — `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest`
- **nmap, jq, curl, git** — apt
- **nuclei-templates** — `nuclei -update-templates` → `~/.local/share/nuclei-templates/`
