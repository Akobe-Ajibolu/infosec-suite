# infosec-suite

AI-driven security engagement framework built on [Claude Code](https://claude.ai/code).

Claude IS the operator — not an advisor. It runs full security engagements end-to-end: planning → recon → vulnerability scanning → professional report, using real security tools, enforcing scope, and producing structured findings.

## Who is this for

- Solo bug bounty hunters
- Independent pentest consultants (1-person shops)

## What it covers

- Web application testing (OWASP WSTG methodology)
- API security testing (OWASP API Security Top 10)
- Cloud infrastructure testing (CISA cloud security framework)

## Skills

| Skill | What it does |
|-------|-------------|
| `/plan` | Interactive engagement planning — defines targets, scope, methodology, and rules of engagement |
| `/recon` | Reconnaissance — subdomain enum (subfinder + crt.sh + HackerTarget), GitHub OSINT, WAF detection, port scanning, tech detection, asset classification |
| `/vuln-scan` | Vulnerability scanning — methodology-aware nuclei templates, severity classification, false-positive flagging |
| `/exploit` | Guided exploitation — browser crawl via mitmproxy + Playwright, injection point discovery, directory bruteforce (ffuf), PoC validation per vuln class |
| `/report` | Report generation — professional pentest report or HackerOne-ready bug bounty submission from findings JSON |

## Requirements

- Debian-based Linux: **Kali Linux**, **ParrotOS**, **Ubuntu 22.04+**, or **Debian 12+**
- [Claude Code CLI](https://claude.ai/code)
- Internet access (for tool installation and external targets)

## Setup

```bash
git clone https://github.com/akobeajiboluemmanuel/infosec-suite
cd infosec-suite
chmod +x setup
./setup
```

Setup installs all required tools automatically:

- Go 1.21+ (from go.dev tarball — not apt)
- subfinder, httpx, nuclei, trufflehog, katana, ffuf, dalfox, interactsh-client (via `go install`)
- nmap, curl, jq, python3, sqlmap, seclists (via apt)
- wafw00f, mitmproxy, playwright, weasyprint, Markdown (via pip3)
- playwright chromium browser binary (~130 MB)
- nuclei templates
- AWS CLI, Google Cloud SDK, Azure CLI (required for cloud engagements)
- Pacu — AWS exploitation framework

> **Note:** Setup takes ~10–20 minutes on a fresh system. On Kali/ParrotOS with tools pre-installed, it's under 5 minutes.

## API keys (optional, improve coverage)

Some recon sources require API keys for full access. Store them in `~/.infosec-suite/config`:

```bash
mkdir -p ~/.infosec-suite
cat > ~/.infosec-suite/config <<EOF
GITHUB_TOKEN=ghp_...
PHONEBOOK_API_KEY=...
HACKERTARGET_API_KEY=...
PREPARER_NAME=Your Full Name
EVIDENCE_MAX_CHARS=500
EOF
chmod 600 ~/.infosec-suite/config
```

| Key | Source | Used for |
|-----|--------|----------|
| `GITHUB_TOKEN` | github.com/settings/tokens | GitHub code search + trufflehog secret scanning |
| `PHONEBOOK_API_KEY` | intelx.io | phonebook.cz email & subdomain discovery |
| `HACKERTARGET_API_KEY` | hackertarget.com | Unlimited passive DNS queries |
| `PREPARER_NAME` | — | Your name on internal pentest reports |
| `EVIDENCE_MAX_CHARS` | — | Truncate evidence snippets (default: 500) |

All keys are optional. `/recon` and `/report` degrade gracefully when keys are absent.

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

# Step 4: Exploit and validate findings
/exploit

# Step 5: Generate the report
/report
```

All engagement data is saved to `session/{engagement_id}/`:

```
session/{engagement_id}/
├── engagement-plan.json        # Engagement parameters
├── scope.txt                   # In-scope targets
├── findings-recon.json             # Recon findings
├── findings-vulns.json             # Vulnerability findings
├── exploit-injection-points.json   # Injection points from browser crawl
├── exploit-ffuf-dirs.json          # Directory bruteforce results
├── findings-exploit.json           # Confirmed PoC evidence
├── idor-candidates.txt             # BOLA/IDOR candidates for manual review
├── report-YYYYMMDD.md              # Generated report (Markdown)
├── report-YYYYMMDD.pdf             # PDF export (requires weasyprint)
└── report-YYYYMMDD.html            # Intermediate HTML (PDF debug artifact)
```

## Report modes

`/report` auto-detects the engagement context from `engagement-plan.json`:

- **`bug_bounty`** — generates a HackerOne/Bugcrowd-formatted submission block for each critical/high finding, with steps to reproduce and impact statements
- **`internal`** — generates a full pentest report with a confidential cover page, executive summary, and findings sorted by severity

After writing the Markdown file, `/report` automatically generates a PDF if `weasyprint` is installed:

```bash
pip3 install weasyprint   # one-time setup (or run ./setup)
```

The PDF output includes professional styling: A4 layout, severity colour bands (Critical=red, High=orange, Medium=amber, Low=blue), cover page, CONFIDENTIAL footer, and page numbers. An intermediate `.html` file is also written for debugging.

## Testing with fixtures

Sample session data is included in `fixtures/` to test `/report` without running a full engagement:

```bash
# Bug bounty report
cp -r fixtures/bug_bounty session/a8098c1a-f86e-11da-bd1a-00112444be1e
echo "session/a8098c1a-f86e-11da-bd1a-00112444be1e" > .active-session
# then in claude: /report

# Internal pentest report
cp -r fixtures/internal session/c3d4e5f6-1234-5678-abcd-ef0123456789
echo "session/c3d4e5f6-1234-5678-abcd-ef0123456789" > .active-session
# then in claude: /report
```

## Scope enforcement

Scope enforcement is mandatory and non-negotiable. All discovered subdomains are filtered against `scope.txt` before any active scanning. Out-of-scope hosts are never tested.

## Legal

This tool is for **authorized security testing only**. You are responsible for ensuring you have explicit permission to test any target. The authors accept no liability for unauthorized use.

## Inspiration

InfoSec-Suite was inspired by [Garry Tan's gstack](https://github.com/garrytan/gstack) — the idea that Claude Code skills can encode full professional workflows, not just code snippets. gstack proved that an AI agent with the right skill files can operate as a first-class practitioner in a domain. InfoSec-Suite applies that pattern to security engagements.

## Roadmap

- v1.0.0: `/plan` + `/recon` + `/vuln-scan` ✅
- v1.0.1: `/exploit` + `/report` — browser crawl, PoC validation, multi-role auth testing, professional report generation, PDF output via weasyprint ✅
- v1.2.0: parallel engagements, multi-target support, auth-aware scanning
