---
name: recon
version: 0.1.0
description: |
  Reconnaissance skill. Runs subfinder → nmap → httpx → nuclei-tech →
  asset classification. Reads engagement-plan.json from the active session
  (written by /plan) or accepts explicit target= and scope= params.
  Produces findings-recon.json with classified assets.
triggers:
  - run recon
  - start recon
  - reconnaissance
  - enumerate targets
---

# /recon

Reconnaissance phase — maps the attack surface before vulnerability scanning.

## Phases

1. Load engagement plan (from `.active-session` or explicit params)
2. Subdomain enumeration (subfinder)
3. Scope filtering
4. Live host probing (httpx)
5. Port scanning (nmap)
6. Tech detection (nuclei -t technologies/)
7. IDOR/BOLA candidate flagging
8. Asset classification + findings-recon.json

## Step 0: Load engagement plan

### Path A — Active session (preferred)

```bash
if [ -f .active-session ]; then
  SESSION_DIR=$(cat .active-session | tr -d '[:space:]')
  PLAN_FILE="$SESSION_DIR/engagement-plan.json"
  if [ ! -f "$PLAN_FILE" ]; then
    echo "ERROR: .active-session points to $SESSION_DIR but engagement-plan.json not found"
    exit 1
  fi
  echo "LOADED_FROM=active-session"
  echo "SESSION_DIR=$SESSION_DIR"
  cat "$PLAN_FILE"
fi
```

Read `engagement-plan.json` using the Read tool. Extract:
- `engagement_id`
- `targets[]`
- `scope_file`
- `rate_limit` → `max_requests_per_second`
- `known_tech[]`
- `sensitive_paths[]`
- `type` (web_app, api, cloud, combined)

### Path B — Explicit params (standalone fallback)

If `.active-session` does not exist, the operator must provide:
- `target=<domain>` — primary target
- `scope=<path-to-scope-file>` — path to scope.txt

Generate a one-off engagement ID:
```bash
ENGAGEMENT_ID=$(cat /proc/sys/kernel/random/uuid 2>/dev/null || uuidgen 2>/dev/null || python3 -c "import uuid; print(uuid.uuid4())")
SESSION_DIR="session/${ENGAGEMENT_ID}"
mkdir -p "$SESSION_DIR"
cp "$SCOPE_PARAM" "$SESSION_DIR/scope.txt"
```

Tell the operator: "Running without an engagement plan. Results will be saved to session/{ENGAGEMENT_ID}/. For full engagement tracking, run /plan first."

### Session resume check

```bash
STATE_FILE="$SESSION_DIR/state.json"
if [ -f "$STATE_FILE" ]; then
  COMPLETED=$(jq -r '.completed_steps | length' "$STATE_FILE" 2>/dev/null || echo 0)
  LAST_STEP=$(jq -r '.completed_steps[-1]' "$STATE_FILE" 2>/dev/null || echo "none")
  echo "RESUMING: $COMPLETED/8 steps completed. Last completed: $LAST_STEP"
fi
```

If resuming, announce: "Resuming recon from step {N}/8 — skipping completed steps."
Skip steps that appear in `state.json`'s `completed_steps` array.

## Step 1: Subdomain enumeration

Skip if `type` is `cloud` (no subdomains to enumerate for cloud-only engagements).

```bash
TARGET=$(jq -r '.targets[0]' "$PLAN_FILE")
subfinder -d "$TARGET" -silent -timeout 30 -o "$SESSION_DIR/subdomains-raw.txt"
COUNT=$(wc -l < "$SESSION_DIR/subdomains-raw.txt" | tr -d ' ')
echo "SUBFINDER: $COUNT subdomains found"
```

If subfinder finds 0 results: warn "No subdomains found for $TARGET. The target may have no resolvable subdomains, or DNS is rate-limiting. Continuing with primary target only."
Write the primary target itself to `subdomains-raw.txt` so subsequent steps have at least one host.

Update state:
```bash
jq -n --arg step "subdomain_enum" --argjson ts "$(date +%s)" \
  '{completed_steps: [$step], timestamps: {($step): $ts}}' > "$STATE_FILE.tmp"
# Merge with existing state if present
if [ -f "$STATE_FILE" ]; then
  jq -s '.[0] * .[1] | .completed_steps = (.[0].completed_steps + .[1].completed_steps | unique)' \
    "$STATE_FILE" "$STATE_FILE.tmp" > "$STATE_FILE.new" && mv "$STATE_FILE.new" "$STATE_FILE"
  rm -f "$STATE_FILE.tmp"
else
  mv "$STATE_FILE.tmp" "$STATE_FILE"
fi
```

## Step 2: Scope filtering

**Critical — this is the legal scope enforcement boundary.**

```bash
SCOPE_FILE=$(jq -r '.scope_file' "$PLAN_FILE")
grep -Fxf "$SCOPE_FILE" "$SESSION_DIR/subdomains-raw.txt" > "$SESSION_DIR/subdomains-inscope.txt" 2>/dev/null || true
# Always include the primary target itself if not caught by grep
TARGET=$(jq -r '.targets[0]' "$PLAN_FILE")
grep -qFx "$TARGET" "$SESSION_DIR/subdomains-inscope.txt" 2>/dev/null || echo "$TARGET" >> "$SESSION_DIR/subdomains-inscope.txt"
INSCOPE=$(wc -l < "$SESSION_DIR/subdomains-inscope.txt" | tr -d ' ')
FILTERED=$((COUNT - INSCOPE))
echo "SCOPE: $INSCOPE in-scope, $FILTERED filtered out"
```

Tell the operator: "{INSCOPE} hosts in scope, {FILTERED} out-of-scope hosts filtered."

Do NOT proceed with out-of-scope hosts under any circumstances.

Update state: add `"scope_filter"` to completed_steps.

## Step 3: Live host probing

```bash
httpx -l "$SESSION_DIR/subdomains-inscope.txt" \
  -silent -status-code -title -tech-detect \
  -timeout 10 \
  -o "$SESSION_DIR/live-hosts.json" -json

LIVE=$(jq -s 'length' "$SESSION_DIR/live-hosts.json" 2>/dev/null || wc -l < "$SESSION_DIR/live-hosts.json" | tr -d ' ')
echo "HTTPX: $LIVE live hosts"
```

Note: httpx with `-json` writes one JSON object per line (NDJSON), not a JSON array. Use `jq -s` or `jq --slurp` when processing the whole file.

If 0 live hosts: warn "No live HTTP/HTTPS hosts found. Check if targets are reachable. Stopping recon — nothing to scan."
Do not proceed to port scanning with empty results.

Update state: add `"live_host_probe"` to completed_steps.

## Step 4: Port scanning

```bash
jq -r '.host' "$SESSION_DIR/live-hosts.json" | sort -u > "$SESSION_DIR/hostnames.txt"
nmap -sV --open -T4 --min-parallelism 10 \
  -iL "$SESSION_DIR/hostnames.txt" \
  -oA "$SESSION_DIR/nmap-output"
```

Read `$SESSION_DIR/nmap-output.nmap` using the Read tool (human-readable nmap output).

For each host found, note:
- Open ports and services
- Service versions (for CVE correlation in /vuln-scan)
- Any unexpected services (e.g. port 22 exposed on a web server)

Update state: add `"port_scan"` to completed_steps.

## Step 5: Tech detection

```bash
jq -r '.url' "$SESSION_DIR/live-hosts.json" > "$SESSION_DIR/live-urls.txt"
nuclei -l "$SESSION_DIR/live-urls.txt" \
  -t technologies/ \
  -o "$SESSION_DIR/nuclei-tech.json" -json -silent
```

Read `nuclei-tech.json` using the Read tool. Extract detected technologies.
Merge with `known_tech` from the engagement plan to build the full tech stack picture.

Update state: add `"tech_detection"` to completed_steps.

## Step 6: IDOR/BOLA candidate flagging

Flag endpoints with ID-like URL patterns for manual review. This is NOT a finding — it is a manual review list. BOLA/IDOR requires authentication context that automated tools cannot provide.

```bash
grep -E '(/[0-9]+(/|$)|/[0-9a-f-]{36}(/|$)|\?.*[Ii][Dd]=)' \
  "$SESSION_DIR/live-urls.txt" \
  > "$SESSION_DIR/idor-candidates.txt" 2>/dev/null || true

IDOR_COUNT=$(wc -l < "$SESSION_DIR/idor-candidates.txt" 2>/dev/null | tr -d ' ' || echo 0)
echo "IDOR CANDIDATES: $IDOR_COUNT endpoints flagged for manual review"
```

Update state: add `"idor_flag"` to completed_steps.

## Step 7: Asset classification

Read the nmap output and nuclei-tech output (already loaded above). For each live host, classify using this logic:

| Signals | Classification |
|---------|---------------|
| Title contains "admin", "dashboard", "panel", port 8080/8443 | `admin-panel` |
| `api` in hostname or `/api/`, `/v1/`, `/graphql` paths | `api-endpoint` |
| `/login`, `/auth`, `/oauth` paths | `auth-service` |
| WordPress, Drupal, Joomla detected | `cms` |
| S3, GCS, Azure Blob URLs found in responses | `cloud-storage` |
| Default nginx/Apache page, no title | `generic-web` |
| Anything not matched above | `unknown` |

## Step 8: Write findings-recon.json

Use the Write tool to create `session/{engagement_id}/findings-recon.json`:

```json
{
  "target": "{primary target}",
  "timestamp": "{ISO8601}",
  "phase": "recon",
  "session_id": "{engagement_id}",
  "assets": [
    {
      "host": "{hostname}",
      "ip": "{resolved IP or null}",
      "ports": [80, 443],
      "tech": ["{detected tech}"],
      "classification": "{admin-panel | api-endpoint | auth-service | cms | cloud-storage | generic-web | unknown}",
      "scope_verified": true
    }
  ],
  "findings": [
    {
      "id": "{uuid}",
      "type": "subdomain | service | info",
      "severity": "info | low | medium | high | critical",
      "host": "{hostname}",
      "port": 443,
      "title": "{finding title}",
      "evidence": "{what was observed}",
      "recommendation": "{what to do}",
      "review_recommended": false,
      "review_reason": null
    }
  ],
  "idor_candidates_file": "session/{engagement_id}/idor-candidates.txt",
  "idor_candidate_count": {N},
  "summary": {
    "total_subdomains": {N},
    "in_scope": {N},
    "live_hosts": {N},
    "classified_assets": {N}
  }
}
```

For notable recon findings, add entries to the `findings` array. Examples of noteworthy findings:
- Exposed admin panel (severity: high)
- Dev/staging environment accessible externally (severity: medium)
- Outdated server software version (severity: info, review_recommended: true)
- Unexpected open ports on internet-facing hosts (severity: medium)

Mark `review_recommended: true` on findings where automated detection may be imprecise (e.g. version-based CVE suggestions). Never remove findings — add the flag and explain in `review_reason`.

Update state: add `"findings_written"` to completed_steps.

## Step 9: Print recon summary

```
Recon Complete — {engagement_id}
============================================
Target:         {primary target}
Subdomains:     {total} found, {in_scope} in scope
Live hosts:     {live_hosts}
IDOR candidates: {N} endpoints → session/{id}/idor-candidates.txt

Assets classified:
  {count} admin-panel
  {count} api-endpoint
  {count} auth-service
  {count} cms
  {count} generic-web

Notable findings:
  {list top 3-5 findings with severity}

Output:  session/{engagement_id}/findings-recon.json

Next step: run /vuln-scan to begin vulnerability scanning.
```

If IDOR candidates > 0, add:
"Review session/{id}/idor-candidates.txt manually — these endpoints may be vulnerable to BOLA/IDOR but require authenticated testing."

## Error handling

**subfinder timeout**: If subfinder hangs past 60s, kill it and continue with the primary target only. Warn the operator.

**nmap no targets**: If `hostnames.txt` is empty (all hosts filtered or none live), skip port scanning and warn.

**nuclei templates missing**: Check `~/.local/share/nuclei-templates/` exists. If not, run `nuclei -update-templates -silent` before scanning. If that fails, skip tech detection and warn.

**Partial results**: Always write whatever data exists to `findings-recon.json` before failing. Partial data is better than no data.

**Permission denied on write**: Report exact error and session directory path. The operator may need to check permissions or disk space.
