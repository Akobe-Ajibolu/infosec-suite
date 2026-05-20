---
name: vuln-scan
version: 0.1.0
description: |
  Vulnerability scanning skill. Reads findings-recon.json from /recon,
  selects nuclei templates based on detected tech and engagement type,
  runs targeted vuln scanning, classifies findings by severity, and
  produces findings-vulns.json. Handles cloud credential verification
  for cloud engagements.
triggers:
  - run vuln scan
  - vulnerability scan
  - start scanning
  - find vulnerabilities
  - vuln-scan
---

# /vuln-scan

Vulnerability scanning phase — exploits the attack surface mapped by /recon.

## Phases

1. Load engagement plan + recon findings
2. Cloud credential check (cloud/combined engagements only)
3. Template selection based on tech stack + engagement type
4. Nuclei vulnerability scan
5. Severity classification and false-positive flagging
6. Write findings-vulns.json
7. Print scan summary

## Step 0: Load engagement plan and recon findings

```bash
if [ -f .active-session ]; then
  SESSION_DIR=$(cat .active-session | tr -d '[:space:]')
  PLAN_FILE="$SESSION_DIR/engagement-plan.json"
  RECON_FILE="$SESSION_DIR/findings-recon.json"
else
  echo "ERROR: No active session found. Run /plan first, or provide engagement_id= param."
  exit 1
fi

if [ ! -f "$PLAN_FILE" ]; then
  echo "ERROR: engagement-plan.json not found at $PLAN_FILE"
  echo "Run /plan to create an engagement plan."
  exit 1
fi

if [ ! -f "$RECON_FILE" ]; then
  echo "ERROR: findings-recon.json not found at $RECON_FILE"
  echo "Run /recon before /vuln-scan."
  exit 1
fi
```

Read both files using the Read tool. Extract:
- From plan: `engagement_id`, `type`, `methodology`, `known_tech[]`, `sensitive_paths[]`, `rate_limit`, `rules.max_requests_per_second`
- From recon: `assets[]` (classifications + tech), `findings[]` (existing findings), `summary.live_hosts`

## Step 1: Cloud credential check (cloud/combined only)

Skip this step if `type` is `web_app` or `api`.

For cloud and combined engagements, verify credentials before scanning. **Halt if any required provider credentials are missing or invalid — do not silently continue with empty results.**

### AWS

```bash
# Check credential sources
if [ -f "$HOME/.aws/credentials" ] || { [ -n "${AWS_ACCESS_KEY_ID:-}" ] && [ -n "${AWS_SECRET_ACCESS_KEY:-}" ]; }; then
  RESULT=$(aws sts get-caller-identity 2>&1)
  if echo "$RESULT" | jq -e '.Account' &>/dev/null; then
    ACCOUNT=$(echo "$RESULT" | jq -r '.Account')
    echo "AWS: authenticated as account $ACCOUNT"
  else
    echo "AWS_AUTH_FAILED: $RESULT"
  fi
else
  echo "AWS_NOT_CONFIGURED"
fi
```

If `AWS_AUTH_FAILED` or `AWS_NOT_CONFIGURED`: halt with:
"Cloud credentials not configured for AWS. Configure AWS credentials (aws configure or set AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY) and retry."

### GCP

```bash
if [ -n "${GOOGLE_APPLICATION_CREDENTIALS:-}" ] && [ -f "$GOOGLE_APPLICATION_CREDENTIALS" ]; then
  ACTIVE=$(gcloud auth list --filter=status:ACTIVE --format='value(account)' 2>/dev/null | head -1)
  [ -n "$ACTIVE" ] && echo "GCP: authenticated as $ACTIVE" || echo "GCP_AUTH_FAILED"
else
  ACTIVE=$(gcloud auth list --filter=status:ACTIVE --format='value(account)' 2>/dev/null | head -1)
  [ -n "$ACTIVE" ] && echo "GCP: authenticated as $ACTIVE" || echo "GCP_NOT_CONFIGURED"
fi
```

If `GCP_AUTH_FAILED` or `GCP_NOT_CONFIGURED`: halt with:
"Cloud credentials not configured for GCP. Run `gcloud auth application-default login` and retry."

### Azure

```bash
RESULT=$(az account show 2>&1)
if echo "$RESULT" | jq -e '.id' &>/dev/null; then
  SUB=$(echo "$RESULT" | jq -r '.name')
  echo "Azure: authenticated, subscription: $SUB"
else
  echo "AZURE_NOT_CONFIGURED: $RESULT"
fi
```

If `AZURE_NOT_CONFIGURED`: halt with:
"Cloud credentials not configured for Azure. Run `az login` and retry."

## Step 2: Template selection

Select nuclei template categories based on engagement type and detected tech. Use short category names — nuclei resolves them from `~/.local/share/nuclei-templates/`.

### Base templates (all engagement types)

```
-t exposures/
-t misconfiguration/
-t default-logins/
```

### Web application additions (WSTG methodology)

```
-t vulnerabilities/
-t cves/
-t takeovers/
-t fuzzing/lfi/
-t fuzzing/xss/
-t fuzzing/sqli/
```

### API additions (OWASP API Top 10 methodology)

```
-t vulnerabilities/
-t exposures/apis/
-t fuzzing/
-t cves/
```

### Cloud additions (CISA cloud framework)

```
-t cloud/
-t misconfiguration/aws/
-t misconfiguration/gcp/
-t misconfiguration/azure/
-t exposures/
```

### Tech-specific additions

For each item in `known_tech[]` and detected tech from recon assets:

| Tech | Additional templates |
|------|---------------------|
| WordPress | `-t cms/wordpress/` |
| Drupal | `-t cms/drupal/` |
| Joomla | `-t cms/joomla/` |
| Jenkins | `-t exposures/configs/jenkins/` |
| Apache | `-t vulnerabilities/apache/` |
| nginx | `-t misconfiguration/nginx/` |
| Spring Boot | `-t exposures/configs/springboot/` |
| Grafana | `-t vulnerabilities/other/grafana/` |
| GitLab | `-t vulnerabilities/other/gitlab/` |
| Kubernetes | `-t cloud/kubernetes/` |

Build the final `-t` flag list by combining base + type-specific + tech-specific without duplicates.

Tell the operator: "Selected {N} template categories for {methodology} scan. Tech-specific additions: {list}."

## Step 3: Nuclei vulnerability scan

### Pre-scan: verify templates exist

```bash
TEMPLATES_DIR="$HOME/.local/share/nuclei-templates"
if [ ! -d "$TEMPLATES_DIR" ]; then
  echo "TEMPLATES_MISSING — running nuclei -update-templates"
  nuclei -update-templates -silent 2>/dev/null || true
fi
if [ ! -d "$TEMPLATES_DIR" ]; then
  echo "ERROR: nuclei templates could not be downloaded"
  exit 1
fi
```

### Build exclusions

Combine `sensitive_paths[]` from the plan into a nuclei exclusion pattern:

```bash
SENSITIVE=$(jq -r '.sensitive_paths[]' "$PLAN_FILE" | paste -sd ',' -)
EXCLUDE_FLAG=""
[ -n "$SENSITIVE" ] && EXCLUDE_FLAG="-exclude-matchers path:$SENSITIVE"
```

### Run nuclei

```bash
MAX_RPS=$(jq -r '.rules.max_requests_per_second' "$PLAN_FILE")
LIVE_URLS="$SESSION_DIR/live-urls.txt"

nuclei \
  -l "$LIVE_URLS" \
  {TEMPLATE_FLAGS} \
  -rate-limit "$MAX_RPS" \
  -c 25 \
  $EXCLUDE_FLAG \
  -o "$SESSION_DIR/nuclei-output.json" \
  -json \
  -silent
```

Replace `{TEMPLATE_FLAGS}` with the `-t category/` flags built in Step 2.

If nuclei exits with error: capture stderr and report to operator. Do not silently swallow errors.

## Step 4: Severity classification and false-positive flagging

Read `$SESSION_DIR/nuclei-output.json` using the Read tool (NDJSON — one JSON per line).

For each nuclei finding:

1. Map nuclei severity to our schema:
   - `critical` → `critical`
   - `high` → `high`
   - `medium` → `medium`
   - `low` → `low`
   - `info` → `info`

2. Flag for review (`review_recommended: true`) when:
   - The template is version-based (checks for a version number rather than proof-of-concept execution)
   - The finding is `info` severity with no HTTP evidence
   - The matched host does not appear in `assets[]` from recon (possible scope drift)
   - The template name contains `detect` or `check` (heuristic — detection-only templates)

3. Never remove or deduplicate findings — add the review flag and explain in `review_reason`.

4. Cross-reference with recon findings — if /recon already flagged the same host:port issue, note it in `review_reason`.

## Step 5: Write findings-vulns.json

Use the Write tool to create `session/{engagement_id}/findings-vulns.json`:

```json
{
  "target": "{primary target}",
  "timestamp": "{ISO8601}",
  "phase": "vuln-scan",
  "session_id": "{engagement_id}",
  "methodology": "{WSTG | OWASP_API_TOP10 | cloud_cisa | custom}",
  "templates_used": ["{category1}", "{category2}"],
  "findings": [
    {
      "id": "{uuid}",
      "type": "vulnerability",
      "severity": "critical | high | medium | low | info",
      "host": "{hostname}",
      "port": 443,
      "title": "{nuclei template name}",
      "evidence": "{matched response snippet or nuclei matcher output}",
      "cve": "{CVE-YYYY-NNNN or null}",
      "template_id": "{nuclei template ID}",
      "recommendation": "{remediation guidance}",
      "review_recommended": false,
      "review_reason": null
    }
  ],
  "summary": {
    "total_findings": {N},
    "by_severity": {
      "critical": {N},
      "high": {N},
      "medium": {N},
      "low": {N},
      "info": {N}
    },
    "review_recommended_count": {N}
  }
}
```

Generate UUIDs for finding IDs:
```bash
python3 -c "import uuid; print(uuid.uuid4())"
```
Or use `/proc/sys/kernel/random/uuid` for each finding.

## Step 6: Print scan summary

```
Vuln Scan Complete — {engagement_id}
============================================
Target:      {primary target}
Methodology: {methodology}
Templates:   {N} categories

Findings by severity:
  CRITICAL  {N}
  HIGH      {N}
  MEDIUM    {N}
  LOW       {N}
  INFO      {N}
  ─────────────
  TOTAL     {N}

Review recommended: {N} findings (automated detection — verify before reporting)

Output: session/{engagement_id}/findings-vulns.json
```

If IDOR candidates exist (from recon), remind:
"Don't forget to manually review session/{id}/idor-candidates.txt for BOLA/IDOR — these require authenticated testing."

If critical or high findings exist, highlight the top 3:
```
Top findings:
  [CRITICAL] {title} — {host}
  [HIGH]     {title} — {host}
  ...
```

## Step 7: Next steps guidance

Tell the operator:

```
Engagement data is in session/{engagement_id}/
  findings-recon.json   — {N} recon findings
  findings-vulns.json   — {N} vulnerability findings

Suggested next steps:
1. Review findings-vulns.json — verify all review_recommended findings
2. Check idor-candidates.txt with an authenticated session
3. For confirmed criticals/highs: document proof-of-concept steps
4. Draft a report from the two findings files
```

## Error handling

**nuclei produces no output**: If `nuclei-output.json` is empty or missing after the scan:
- Check that `live-urls.txt` is non-empty
- Check that template categories exist under `~/.local/share/nuclei-templates/`
- Warn: "Nuclei produced no findings. This may indicate the target is well-hardened, or template categories are missing. Run `nuclei -update-templates` and retry."
- Still write `findings-vulns.json` with empty findings array — do not fail.

**Cloud credential failure**: Already handled in Step 1 (halt). Do not suppress credential errors.

**Rate limit exceeded signals**: If nuclei output suggests WAF blocking (many 429/503 responses), warn the operator and suggest switching to "careful" rate limit. Do not auto-retry.

**Scope drift**: If nuclei finds a URL not in `live-urls.txt`, flag the finding with `review_recommended: true` and `review_reason: "URL not in original recon scope — verify this host is in scope before reporting"`.
