# infosec-suite

AI-driven security engagement framework built on [Claude Code](https://claude.ai/code).

Claude IS the operator — not an advisor. It runs full security engagements end-to-end: planning → recon → vulnerability scanning, using real security tools, enforcing scope, and producing structured findings.

## Who is this for

- Solo bug bounty hunters
- In-house AppSec teams (1–2 person teams)

## What it covers (v1)

- Web application testing (OWASP WSTG methodology)
- API security testing (OWASP API Security Top 10)
- Cloud infrastructure testing (CISA cloud security framework)

## Skills

| Skill | What it does |
|-------|-------------|
| `/plan` | Interactive engagement planning — defines targets, scope, methodology, and rules of engagement |
| `/recon` | Reconnaissance — subdomain enum, port scanning, tech detection, asset classification |
| `/vuln-scan` | Vulnerability scanning — methodology-aware nuclei templates, severity classification, false-positive flagging |

## Requirements

- Debian-based Linux: **Kali Linux**, **ParrotOS**, **Ubuntu 22.04+**, or **Debian 12+**
- [Claude Code CLI](https://claude.ai/code)
- Internet access (for tool installation and external targets)

## Setup

```bash
git clone https://github.com/akobeajiboluemmanuel/infosec-suite
cd infosec-suite
./setup
```

Setup installs:
- Go 1.21+ (from go.dev tarball — not apt)
- subfinder, httpx, nuclei (via `go install`)
- nmap, jq (via apt)
- nuclei templates

> **Note:** Setup takes ~7–15 minutes on a fresh system (Go + ProjectDiscovery tools). On Kali/ParrotOS with tools pre-installed, it's under 5 minutes.

## Usage

```bash
# Start Claude Code in your engagement workspace
claude

# Step 1: Plan the engagement
/plan

# Step 2: Run reconnaissance
/recon

# Step 3: Scan for vulnerabilities
/vuln-scan
```

All engagement data is saved to `session/{engagement_id}/`:

```
session/{engagement_id}/
├── engagement-plan.json    # Engagement parameters
├── scope.txt               # In-scope targets
├── findings-recon.json     # Recon findings
├── findings-vulns.json     # Vulnerability findings
└── idor-candidates.txt     # BOLA/IDOR candidates for manual review
```

## Scope enforcement

Scope enforcement is mandatory and non-negotiable. All discovered subdomains are filtered against `scope.txt` before any active scanning. Out-of-scope hosts are never tested.

## Legal

This tool is for **authorized security testing only**. You are responsible for ensuring you have explicit permission to test any target. The authors accept no liability for unauthorized use.

## Roadmap

- v1: plan + recon + vuln-scan (this release)
- v2: `/exploit` — guided exploitation with proof-of-concept generation
- v2: `/report` — structured report generation from findings JSON
- v2: parallel engagements, multi-target support
