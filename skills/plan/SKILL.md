---
name: plan
version: 0.1.0
description: |
  Interactive security engagement planner. Guides the operator through
  target definition, scope, methodology selection, and rules of engagement.
  Produces engagement-plan.json and creates the session directory.
  Must be run before /recon and /vuln-scan.
triggers:
  - plan engagement
  - start engagement
  - new engagement
  - plan pentest
  - plan security test
---

# /plan

Interactive engagement planner — sets up everything /recon and /vuln-scan need.

## What this skill does

1. Asks the operator for engagement details (target, scope, type, context)
2. Selects the appropriate methodology
3. Creates `session/{engagement_id}/` with `engagement-plan.json` and `scope.txt`
4. Writes `.active-session` pointer so /recon and /vuln-scan auto-locate the plan
5. Prints a summary and hands off to /recon

## Step 0: Tool check

Run tool-check.sh to verify required tools are installed:

```bash
SUITE_DIR=$(dirname "$(dirname "$(readlink -f "${BASH_SOURCE[0]:-$0}")")" 2>/dev/null || echo ".")
if [ -f "$SUITE_DIR/lib/tool-check.sh" ]; then
  bash "$SUITE_DIR/lib/tool-check.sh"
else
  # Fallback: check minimum tools manually
  for t in subfinder httpx nmap nuclei jq; do
    command -v "$t" &>/dev/null || echo "MISSING: $t — run setup first"
  done
fi
```

If any MISSING lines appear, tell the operator: "Run `./setup` to install missing tools, then restart /plan."
Do NOT proceed with missing required tools.

## Step 1: Gather engagement details

Ask the operator the following questions. Use AskUserQuestion for each one. Collect all answers before proceeding.

### Q1 — Engagement type

Ask: "What type of security engagement is this?"

Options:
- Web application (OWASP WSTG methodology)
- API (OWASP API Security Top 10 methodology)
- Cloud infrastructure (CISA cloud security framework)
- Combined (web + API, or web + cloud — specify in notes)

### Q2 — Context

Ask: "What is the engagement context?"

Options:
- Bug bounty (external program — e.g. HackerOne, Bugcrowd)
- Internal security assessment (you own or are authorized to test the target)

### Q3 — Primary target

Ask: "What is the primary target domain or IP?"

Free text input. Examples: `example.com`, `api.example.com`, `192.168.1.0/24`

### Q4 — Additional targets

Ask: "Any additional in-scope targets? (comma-separated, or press Enter to skip)"

Free text. Parse comma-separated values into a list. Empty = no additional targets.

### Q5 — Known technology

Ask: "Any known technology stack? (e.g. 'React frontend, Node.js API, AWS') — or press Enter to skip"

Free text. Used to prioritize nuclei templates.

### Q6 — Sensitive paths

Ask: "Any paths that must NOT be actively tested? (e.g. '/payment,/admin/delete') — or press Enter to skip"

Free text. Comma-separated. These will be added to nuclei's exclusion list.

### Q7 — Rate limiting

Ask: "What rate limit should we use for active scanning?"

Options:
- Standard (50 req/s) — default for most engagements
- Careful (10 req/s) — use for production systems or explicit program rules
- Aggressive (150 req/s) — only for isolated lab environments

### Q8 — Notes

Ask: "Any additional notes, constraints, or rules of engagement? (or press Enter to skip)"

Free text. Stored verbatim in the plan.

## Step 2: Select methodology

Based on Q1 (engagement type), set the methodology field:

| Type | Methodology |
|------|-------------|
| Web application | WSTG |
| API | OWASP_API_TOP10 |
| Cloud | cloud_cisa |
| Combined | custom |

For cloud or combined engagements, note in the plan summary which sub-methodologies apply.

## Step 3: Generate engagement ID and create session directory

```bash
# Generate UUID
ENGAGEMENT_ID=$(cat /proc/sys/kernel/random/uuid 2>/dev/null || uuidgen 2>/dev/null || python3 -c "import uuid; print(uuid.uuid4())")

SESSION_DIR="session/${ENGAGEMENT_ID}"
mkdir -p "$SESSION_DIR"

echo "Engagement ID: $ENGAGEMENT_ID"
echo "Session directory: $SESSION_DIR"
```

## Step 4: Build scope.txt

From Q3 (primary target) and Q4 (additional targets), create `session/{engagement_id}/scope.txt`.

One entry per line. For domain targets, include the apex domain and any explicitly named subdomains.

Example `scope.txt`:
```
example.com
api.example.com
staging.example.com
```

For IP ranges (CIDR notation), write the range as-is. The /recon skill handles IP vs domain targets.

Write using the Write tool:
```
session/{engagement_id}/scope.txt
```

## Step 5: Build engagement-plan.json

Map all Q1–Q8 answers to the schema below. Set rate_limit based on Q7:
- Standard → `"standard"` (max_requests_per_second: 50)
- Careful → `"careful"` (max_requests_per_second: 10)
- Aggressive → `"aggressive"` (max_requests_per_second: 150)

```json
{
  "engagement_id": "{ENGAGEMENT_ID}",
  "created": "{ISO8601 timestamp}",
  "type": "web_app | api | cloud | combined",
  "context": "bug_bounty | internal",
  "targets": ["{primary}", "{additional...}"],
  "scope_file": "session/{engagement_id}/scope.txt",
  "rate_limit": "standard | careful | aggressive",
  "methodology": "WSTG | OWASP_API_TOP10 | cloud_cisa | custom",
  "known_tech": ["{tech stack items}"],
  "sensitive_paths": ["{path1}", "{path2}"],
  "rules": {
    "time_window": null,
    "excluded_tools": [],
    "max_requests_per_second": 50
  },
  "phases": ["recon", "vuln-scan"],
  "notes": "{free text from Q8}"
}
```

Write this file using the Write tool to `session/{engagement_id}/engagement-plan.json`.

## Step 6: Write .active-session pointer

```bash
echo "session/{ENGAGEMENT_ID}" > .active-session
echo "Active session set: session/{ENGAGEMENT_ID}"
```

This file is read by /recon and /vuln-scan to auto-locate the current engagement.

## Step 7: Print engagement summary

Print a structured summary to the operator:

```
Engagement Plan — {ENGAGEMENT_ID}
=========================================
Type:         {type}
Context:      {context}
Targets:      {targets joined by ", "}
Methodology:  {methodology}
Rate limit:   {rate_limit} ({max_requests_per_second} req/s)
Session dir:  session/{ENGAGEMENT_ID}/

Files created:
  engagement-plan.json  — full plan
  scope.txt             — {N} in-scope entries

Known tech:       {known_tech or "none specified"}
Sensitive paths:  {sensitive_paths or "none"}
Notes:            {notes or "none"}

Next step: run /recon to begin reconnaissance.
```

## Step 8: Offer to start /recon immediately

Ask: "Ready to start reconnaissance now?"

Options:
- Yes, run /recon now
- No, I'll run /recon manually later

If yes: invoke the /recon skill.
If no: tell the operator "When ready, type /recon — the session is already configured."

## Error handling

**uuidgen not available**: Fall back to `python3 -c "import uuid; print(uuid.uuid4())"`. If Python3 is also unavailable, use `date +%s%N | sha256sum | head -c 32` as the engagement ID (not a UUID but unique enough).

**Write tool failure**: Report the exact error. Do not proceed — the plan file is the contract for all subsequent skills.

**Operator aborts mid-flow**: The session directory may be partially created. Inform the operator: "Partial session at session/{ENGAGEMENT_ID}/ — you can delete it and start over with /plan."
