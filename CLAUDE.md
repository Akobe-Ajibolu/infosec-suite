# InfoSec-Suite

AI-driven security engagement framework. Claude executes security tools directly — planning, reconnaissance, and vulnerability scanning from start to finish.

## Skill routing

When the user's request matches an available skill, invoke it via the Skill tool.

Key routing rules:
- Plan / start / new engagement → invoke /plan
- Recon / enumerate / subdomain / asset discovery → invoke /recon
- Vuln scan / vulnerability / scan / nuclei → invoke /vuln-scan
- Exploit / test / validate / inject / bruteforce / crawl → invoke /exploit
- Report / generate report / write report → invoke /report

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
├── engagement-plan.json        # Written by /plan
├── scope.txt                   # In-scope targets
├── state.json                  # Checkpoint state for resume
├── subdomains-subfinder.txt    # subfinder raw results
├── subdomains-crtsh.txt        # crt.sh certificate transparency results
├── subdomains-hackertarget.txt # HackerTarget passive DNS results
├── subdomains-raw.txt          # Merged unique subdomains (all sources)
├── subdomains-inscope.txt      # Scope-filtered subdomains
├── github-recon/               # GitHub OSINT results
│   ├── *.json                  # Per-dork code search results
│   ├── org-repos.json          # Target org public repos
│   ├── trufflehog-secrets.json # Verified secrets (trufflehog)
│   └── summary.txt             # GitHub recon summary
├── phonebook-results.json      # phonebook.cz / IntelligenceX results
├── live-hosts.json             # httpx output (NDJSON)
├── live-urls.txt               # URL list for nuclei and wafw00f
├── waf-detection.json          # wafw00f WAF detection results
├── hostnames.txt               # Hostname list for nmap
├── nmap-output.nmap            # Human-readable nmap output
├── nmap-output.gnmap
├── nmap-output.xml
├── nuclei-tech.json            # Tech detection results
├── nuclei-output.json          # Vuln scan results
├── idor-candidates.txt         # BOLA/IDOR candidate endpoints
├── findings-recon.json         # Recon findings (written by /recon)
├── findings-vulns.json         # Vuln scan findings (written by /vuln-scan)
├── exploit-crawl-unauth.jsonl    # mitmproxy request capture (unauthenticated)
├── exploit-crawl-{role}.jsonl   # mitmproxy capture per authenticated role
├── exploit-injection-points.json # Parsed injection points by type
├── exploit-ffuf-dirs.json        # ffuf directory bruteforce results
├── exploit-ffuf/                 # Per-host ffuf output files
├── exploit-verify/               # Nuclei verify pass results
├── exploit-authz/                # Cross-role replay results
│   ├── roles.txt                 # Role list (name|user|pass|cookies)
│   └── results.json             # Authorization bypass + IDOR findings
├── exploit-results/              # PoC tool output (sqlmap, dalfox, etc.)
│   └── poc.log                   # Human-readable PoC log
├── findings-exploit.json         # All exploit findings merged (written by /exploit)
└── report-YYYYMMDD.md          # Engagement report (written by /report)
```

API keys and config live in `~/.infosec-suite/config` (never committed to git):
```
GITHUB_TOKEN=ghp_...
PHONEBOOK_API_KEY=...
HACKERTARGET_API_KEY=...
PREPARER_NAME=Your Full Name
PREPARER_EMAIL=you@example.com
EVIDENCE_MAX_CHARS=500
```

Client contact info is stored in `engagement-plan.json` under `client{}` (set during /report).

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
- **trufflehog** — `go install github.com/trufflesecurity/trufflehog/v3@latest`
- **nmap, jq, curl, git, python3, python3-pip, unzip** — apt
- **wafw00f** — `pip3 install wafw00f`
- **nuclei-templates** — `nuclei -update-templates` → `~/.local/share/nuclei-templates/`
- **AWS CLI** — official installer (curl from awscli.amazonaws.com)
- **gcloud** — apt (packages.cloud.google.com)
- **Azure CLI** — official installer (aka.ms/InstallAzureCLIDeb)
- **Pacu** — `pip3 install pacu` or git clone from RhinoSecurityLabs
- **ffuf** — `go install github.com/ffuf/ffuf/v2@latest`
- **katana** — `go install github.com/projectdiscovery/katana/cmd/katana@latest`
- **dalfox** — `go install github.com/hahwul/dalfox/v2@latest`
- **interactsh-client** — `go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest`
- **sqlmap** — apt
- **mitmproxy** — `pip3 install mitmproxy`
- **playwright** — `pip3 install playwright && playwright install chromium --with-deps`
- **SecLists** — apt (wordlists for ffuf and LFI fuzzing)
