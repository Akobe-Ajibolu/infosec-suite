---
name: recon
version: 1.0.1
description: |
  Reconnaissance skill. Multi-source passive subdomain enumeration (subfinder,
  crt.sh, HackerTarget/DNSDumpster), OSINT intelligence gathering (GitHub
  exposure, phonebook.cz email discovery), live host probing (httpx), WAF
  detection (wafw00f), port scanning (nmap), tech detection (nuclei), IDOR
  flagging, and asset classification. Produces findings-recon.json.
triggers:
  - run recon
  - start recon
  - reconnaissance
  - enumerate targets
---

# /recon

Reconnaissance phase — maps the full attack surface before vulnerability scanning.

## Phases

1. Load engagement plan
2. Passive subdomain enumeration (subfinder + crt.sh + HackerTarget)
3. Scope filtering
4. OSINT intelligence gathering (GitHub exposure + phonebook.cz)
5. Live host probing (httpx)
6. WAF detection (wafw00f)
7. Port scanning (nmap)
8. Tech detection (nuclei)
9. IDOR/BOLA candidate flagging
10. Asset classification + findings-recon.json
11. Print summary

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
  COMPLETED=$(python3 -c "import json; d=json.load(open('$STATE_FILE')); print(len(d.get('completed_steps', [])))" 2>/dev/null || echo 0)
  LAST_STEP=$(python3 -c "import json; d=json.load(open('$STATE_FILE')); steps=d.get('completed_steps',[]); print(steps[-1] if steps else 'none')" 2>/dev/null || echo "none")
  echo "RESUMING: $COMPLETED/10 steps completed. Last completed: $LAST_STEP"
fi
```

If resuming, announce: "Resuming recon from step {N}/10 — skipping completed steps."
Skip steps that appear in `state.json`'s `completed_steps` array.

State update helper — use this pattern after each step:

```bash
_update_state() {
  local step="$1"
  local ts
  ts=$(date +%s)
  if [ -f "$STATE_FILE" ]; then
    python3 - <<EOF
import json, sys
with open('$STATE_FILE') as f:
    d = json.load(f)
steps = d.get('completed_steps', [])
if '$step' not in steps:
    steps.append('$step')
d['completed_steps'] = steps
d.setdefault('timestamps', {})['$step'] = $ts
with open('$STATE_FILE', 'w') as f:
    json.dump(d, f, indent=2)
EOF
  else
    python3 -c "import json; json.dump({'completed_steps': ['$step'], 'timestamps': {'$step': $ts}}, open('$STATE_FILE', 'w'), indent=2)"
  fi
}
```

## Step 1: Passive subdomain enumeration

Skip if `type` is `cloud` (no subdomains for cloud-only engagements).

### Step 1a: subfinder

```bash
TARGET=$(python3 -c "import json; print(json.load(open('$PLAN_FILE'))['targets'][0])")

subfinder -d "$TARGET" -silent -timeout 30 -o "$SESSION_DIR/subdomains-subfinder.txt"
SUBFINDER_COUNT=$(wc -l < "$SESSION_DIR/subdomains-subfinder.txt" 2>/dev/null | tr -d ' ' || echo 0)
echo "SUBFINDER: $SUBFINDER_COUNT subdomains"
```

### Step 1b: crt.sh certificate transparency

Query certificate transparency logs for all certificates issued to the target domain. These reveal subdomains that may not appear in DNS enumeration.

```bash
echo "[crt.sh] Querying certificate transparency logs for ${TARGET}..."
curl -s --max-time 30 "https://crt.sh/?q=%25.${TARGET}&output=json" 2>/dev/null | \
  python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    names = set()
    for cert in data:
        for field in ['name_value', 'common_name']:
            for name in str(cert.get(field, '')).split('\n'):
                name = name.strip().lstrip('*.').lower()
                if name and '.' in name and not name.startswith('CN=') and '${TARGET}' in name:
                    names.add(name)
    print('\n'.join(sorted(names)))
except Exception as e:
    sys.stderr.write(f'crt.sh parse error: {e}\n')
" > "$SESSION_DIR/subdomains-crtsh.txt" 2>/dev/null || true

CRTSH_COUNT=$(wc -l < "$SESSION_DIR/subdomains-crtsh.txt" 2>/dev/null | tr -d ' ' || echo 0)
echo "CRT.SH: $CRTSH_COUNT subdomains from certificate records"
```

### Step 1c: HackerTarget (DNSDumpster-equivalent passive DNS)

HackerTarget aggregates passive DNS data similar to DNSDumpster. Free tier allows up to 100 requests/day without API key; set `HACKERTARGET_API_KEY` in `~/.infosec-suite/config` for unlimited.

```bash
echo "[HackerTarget] Querying passive DNS for ${TARGET}..."
HT_API_KEY=$(grep '^HACKERTARGET_API_KEY=' ~/.infosec-suite/config 2>/dev/null | cut -d= -f2 | tr -d ' ' || echo "")
HT_URL="https://api.hackertarget.com/hostsearch/?q=${TARGET}"
[ -n "$HT_API_KEY" ] && HT_URL="${HT_URL}&apikey=${HT_API_KEY}"

curl -s --max-time 30 "$HT_URL" 2>/dev/null | \
  grep -v "^#\|API count\|error\|<!DOCTYPE" | \
  cut -d',' -f1 | \
  grep -E "\.${TARGET//./\\.}$" \
  > "$SESSION_DIR/subdomains-hackertarget.txt" 2>/dev/null || true

HT_COUNT=$(wc -l < "$SESSION_DIR/subdomains-hackertarget.txt" 2>/dev/null | tr -d ' ' || echo 0)
echo "HACKERTARGET: $HT_COUNT subdomains from passive DNS"
```

### Merge all subdomain sources

```bash
cat \
  "$SESSION_DIR/subdomains-subfinder.txt" \
  "$SESSION_DIR/subdomains-crtsh.txt" \
  "$SESSION_DIR/subdomains-hackertarget.txt" \
  2>/dev/null | sort -u > "$SESSION_DIR/subdomains-raw.txt"

TOTAL=$(wc -l < "$SESSION_DIR/subdomains-raw.txt" | tr -d ' ')
echo "TOTAL (merged): $TOTAL unique subdomains across all sources"
```

If all sources find 0 results: warn and write the primary target itself to `subdomains-raw.txt` so subsequent steps have at least one host.

```bash
if [ "$TOTAL" -eq 0 ]; then
  echo "[WARN] No subdomains found for $TARGET. Continuing with primary target only."
  echo "$TARGET" > "$SESSION_DIR/subdomains-raw.txt"
fi
```

_update_state "subdomain_enum"

## Step 2: Scope filtering

**Critical — this is the legal scope enforcement boundary.**

```bash
SCOPE_FILE=$(python3 -c "import json; print(json.load(open('$PLAN_FILE'))['scope_file'])")
grep -Fxf "$SCOPE_FILE" "$SESSION_DIR/subdomains-raw.txt" > "$SESSION_DIR/subdomains-inscope.txt" 2>/dev/null || true

# Always include the primary target itself
grep -qFx "$TARGET" "$SESSION_DIR/subdomains-inscope.txt" 2>/dev/null || echo "$TARGET" >> "$SESSION_DIR/subdomains-inscope.txt"

INSCOPE=$(wc -l < "$SESSION_DIR/subdomains-inscope.txt" | tr -d ' ')
RAW=$(wc -l < "$SESSION_DIR/subdomains-raw.txt" | tr -d ' ')
FILTERED=$((RAW - INSCOPE))
echo "SCOPE: $INSCOPE in-scope, $FILTERED filtered out"
```

Tell the operator: "{INSCOPE} hosts in scope, {FILTERED} out-of-scope hosts filtered."

**Do NOT proceed with out-of-scope hosts under any circumstances.**

_update_state "scope_filter"

## Step 3: OSINT intelligence gathering

This phase runs passive intelligence gathering against the target. No active scanning of the target's infrastructure occurs here.

### Step 3a: GitHub exposure recon

Search public GitHub for exposed credentials, internal hostnames, API keys, and source code belonging to the target.

```bash
GITHUB_TOKEN=$(grep '^GITHUB_TOKEN=' ~/.infosec-suite/config 2>/dev/null | cut -d= -f2 | tr -d ' ' || echo "${GITHUB_TOKEN:-}")
mkdir -p "$SESSION_DIR/github-recon"

if [ -n "$GITHUB_TOKEN" ]; then
  echo "[GitHub] Authenticated search (token set)"
  GH_AUTH="-H \"Authorization: Bearer ${GITHUB_TOKEN}\""
else
  echo "[GitHub] Unauthenticated — rate limited to 10 req/min. Set GITHUB_TOKEN in ~/.infosec-suite/config for full results."
fi
```

Run the following GitHub code search dorks. For each query, extract repo URLs and file paths containing sensitive patterns referencing the target:

```bash
DORKS=(
  "${TARGET}+password"
  "${TARGET}+api_key"
  "${TARGET}+secret"
  "${TARGET}+internal"
  "${TARGET}+staging"
)

for dork in "${DORKS[@]}"; do
  slug=$(echo "$dork" | tr ' +' '__')
  curl -s --max-time 20 \
    "https://api.github.com/search/code?q=${dork}&per_page=10" \
    ${GITHUB_TOKEN:+-H "Authorization: Bearer ${GITHUB_TOKEN}"} \
    -H "Accept: application/vnd.github.v3+json" \
    -H "User-Agent: InfoSec-Suite-Recon" \
    -o "$SESSION_DIR/github-recon/${slug}.json" 2>/dev/null || true
  sleep 2  # Rate limit compliance
done
```

If `GITHUB_TOKEN` is set, also attempt organization discovery:

```bash
if [ -n "$GITHUB_TOKEN" ]; then
  # Guess org name from target domain (e.g., example.com → example)
  ORG_GUESS=$(echo "$TARGET" | sed 's/\..*//')
  curl -s --max-time 20 \
    "https://api.github.com/orgs/${ORG_GUESS}/repos?per_page=30&type=public" \
    -H "Authorization: Bearer ${GITHUB_TOKEN}" \
    -H "Accept: application/vnd.github.v3+json" \
    -o "$SESSION_DIR/github-recon/org-repos.json" 2>/dev/null || true

  # Scan the most recently active public repos for secrets using trufflehog
  if command -v trufflehog &>/dev/null; then
    echo "[trufflehog] Scanning GitHub org ${ORG_GUESS} for verified secrets…"
    trufflehog github \
      --org "$ORG_GUESS" \
      --only-verified \
      --json \
      --token "$GITHUB_TOKEN" \
      > "$SESSION_DIR/github-recon/trufflehog-secrets.json" 2>/dev/null || true
  fi
fi
```

Read the GitHub search result files. For each file with `total_count > 0`:
- Extract repo names, file paths, and code snippets
- Flag any result containing the target domain alongside credential keywords as a HIGH severity finding
- Flag any exposed internal hostnames or staging URLs as MEDIUM severity

Write a summary to `$SESSION_DIR/github-recon/summary.txt`.

_update_state "osint_github"

### Step 3b: phonebook.cz / IntelligenceX email and asset discovery

phonebook.cz (powered by IntelligenceX) discovers email addresses, subdomains, and URLs associated with the target domain. Requires API key — set `PHONEBOOK_API_KEY` in `~/.infosec-suite/config`.

```bash
PHONEBOOK_KEY=$(grep '^PHONEBOOK_API_KEY=' ~/.infosec-suite/config 2>/dev/null | cut -d= -f2 | tr -d ' ' || echo "${PHONEBOOK_API_KEY:-}")

if [ -z "$PHONEBOOK_KEY" ]; then
  echo "[phonebook.cz] No API key — skipping. Set PHONEBOOK_API_KEY in ~/.infosec-suite/config"
  echo "  Get your key at: https://intelx.io/account?tab=developer"
else
  echo "[phonebook.cz] Searching IntelligenceX for ${TARGET}…"

  # Step 1: Initiate search (returns a search ID)
  SEARCH_RESP=$(curl -s --max-time 20 -X POST "https://2.intelx.io/phonebook/search" \
    -H "x-key: ${PHONEBOOK_KEY}" \
    -H "Content-Type: application/json" \
    -d "{\"term\":\"${TARGET}\",\"maxresults\":200,\"media\":0,\"target\":0,\"terminate\":[]}" 2>/dev/null || echo "{}")

  SEARCH_ID=$(echo "$SEARCH_RESP" | python3 -c "import json,sys; print(json.load(sys.stdin).get('id',''))" 2>/dev/null || echo "")

  if [ -n "$SEARCH_ID" ] && [ "$SEARCH_ID" != "null" ]; then
    sleep 5  # Allow IntelligenceX to complete the search
    # Step 2: Retrieve results
    curl -s --max-time 30 \
      "https://2.intelx.io/phonebook/search/result?id=${SEARCH_ID}&limit=200&offset=0" \
      -H "x-key: ${PHONEBOOK_KEY}" \
      > "$SESSION_DIR/phonebook-results.json" 2>/dev/null || true

    # Extract emails from results
    python3 -c "
import json, sys
try:
    data = json.load(open('$SESSION_DIR/phonebook-results.json'))
    emails = set()
    domains = set()
    for sel in data.get('selectors', []):
        val = sel.get('selectorvalue', '')
        t = sel.get('selectortype', 0)
        if t == 1:  # email
            emails.add(val)
        elif t == 2:  # domain
            domains.add(val)
    print(f'Emails: {len(emails)}, Domains/Subdomains: {len(domains)}')
    if emails:
        print('Top emails:')
        for e in sorted(emails)[:10]:
            print(f'  {e}')
except Exception as e:
    print(f'Parse error: {e}')
" 2>/dev/null || true
  else
    echo "[phonebook.cz] Search initiation failed — check API key validity"
  fi
fi
```

Read `phonebook-results.json` using the Read tool. Extract:
- Email addresses → add as INFO findings with `review_recommended: true` (useful for phishing context, social engineering)
- Discovered subdomains → add to `subdomains-inscope.txt` IF they pass scope filtering
- Any credentials/leaked data → HIGH severity finding

_update_state "osint_phonebook"

## Step 4: Live host probing

```bash
httpx -l "$SESSION_DIR/subdomains-inscope.txt" \
  -silent -status-code -title -tech-detect \
  -timeout 10 \
  -o "$SESSION_DIR/live-hosts.json" -json

LIVE=$(python3 -c "
lines = open('$SESSION_DIR/live-hosts.json').read().strip().split('\n')
print(sum(1 for l in lines if l.strip()))
" 2>/dev/null || wc -l < "$SESSION_DIR/live-hosts.json" | tr -d ' ')
echo "HTTPX: $LIVE live hosts"
```

Note: httpx with `-json` writes NDJSON (one JSON object per line). Use `python3 -c "import json; data=[json.loads(l) for l in open(f) if l.strip()]"` when processing.

If 0 live hosts: warn "No live HTTP/HTTPS hosts found. Check if targets are reachable. Stopping recon — nothing to scan."
Do not proceed to WAF detection or port scanning with empty results.

_update_state "live_host_probe"

## Step 5: WAF detection

Identify Web Application Firewalls protecting each live host. WAF presence affects subsequent scanning strategy — rate limits, evasion, and template selection in /vuln-scan.

```bash
python3 -c "
import json
urls = []
for line in open('$SESSION_DIR/live-hosts.json'):
    line = line.strip()
    if line:
        try:
            urls.append(json.loads(line)['url'])
        except: pass
with open('$SESSION_DIR/live-urls.txt', 'w') as f:
    f.write('\n'.join(urls))
" 2>/dev/null || python3 -c "import json; [open('$SESSION_DIR/live-urls.txt','a').write(json.loads(l)['url']+'\n') for l in open('$SESSION_DIR/live-hosts.json') if l.strip()]"

if command -v wafw00f &>/dev/null; then
  echo "[wafw00f] Detecting WAFs on $(wc -l < "$SESSION_DIR/live-urls.txt") hosts…"
  wafw00f \
    -i "$SESSION_DIR/live-urls.txt" \
    -a \
    -f json \
    -o "$SESSION_DIR/waf-detection.json" \
    2>/dev/null || true

  # Print WAF summary
  python3 -c "
import json, sys
try:
    data = json.load(open('$SESSION_DIR/waf-detection.json'))
    wafs = [(e.get('url',''), e.get('detected',False), e.get('firewall','None'), e.get('manufacturer','')) for e in data]
    protected = [w for w in wafs if w[1]]
    print(f'WAF detected: {len(protected)}/{len(wafs)} hosts')
    for url, det, fw, mfr in protected:
        print(f'  {url} → {fw} ({mfr})')
    if not protected:
        print('  No WAF detected on any host')
except Exception as e:
    print(f'  wafw00f parse error: {e}')
" 2>/dev/null || true
else
  warn "wafw00f not installed — skipping WAF detection. Run: pip3 install wafw00f"
fi
```

Read `waf-detection.json`. For each protected host, add a recon finding:
- WAF detected → INFO severity, `review_recommended: true`, note WAF vendor + host
- This informs /vuln-scan: protected hosts may need rate limit reduction and evasion-aware templates

_update_state "waf_detection"

## Step 6: Port scanning

```bash
python3 -c "
import json
hosts = set()
for line in open('$SESSION_DIR/live-hosts.json'):
    line = line.strip()
    if line:
        try:
            hosts.add(json.loads(line)['host'])
        except: pass
with open('$SESSION_DIR/hostnames.txt', 'w') as f:
    f.write('\n'.join(sorted(hosts)))
" 2>/dev/null

nmap -sV --open -T4 --min-parallelism 10 \
  -iL "$SESSION_DIR/hostnames.txt" \
  -oA "$SESSION_DIR/nmap-output"
```

Read `$SESSION_DIR/nmap-output.nmap` using the Read tool. For each host, note:
- Open ports and services
- Service versions (for CVE correlation in /vuln-scan)
- Unexpected services (e.g. port 22 exposed on a web server, port 3306 MySQL accessible externally)

_update_state "port_scan"

## Step 7: Tech detection

```bash
nuclei -l "$SESSION_DIR/live-urls.txt" \
  -t technologies/ \
  -o "$SESSION_DIR/nuclei-tech.json" -json -silent
```

Read `nuclei-tech.json`. Extract detected technologies.
Merge with `known_tech` from the engagement plan to build the full tech stack picture.

_update_state "tech_detection"

## Step 8: IDOR/BOLA candidate flagging

Flag endpoints with ID-like URL patterns for manual review. This is NOT a finding — it is a manual review list. BOLA/IDOR requires authentication context that automated tools cannot provide.

```bash
grep -E '(/[0-9]+(/|$)|/[0-9a-f-]{36}(/|$)|\?.*[Ii][Dd]=)' \
  "$SESSION_DIR/live-urls.txt" \
  > "$SESSION_DIR/idor-candidates.txt" 2>/dev/null || true

IDOR_COUNT=$(wc -l < "$SESSION_DIR/idor-candidates.txt" 2>/dev/null | tr -d ' ' || echo 0)
echo "IDOR CANDIDATES: $IDOR_COUNT endpoints flagged for manual review"
```

_update_state "idor_flag"

## Step 9: Asset classification

Read nmap output, nuclei-tech output, and httpx output (already loaded). For each live host, classify:

| Signals | Classification |
|---------|---------------|
| Title contains "admin", "dashboard", "panel", port 8080/8443 | `admin-panel` |
| `api` in hostname or `/api/`, `/v1/`, `/graphql` in paths | `api-endpoint` |
| `/login`, `/auth`, `/oauth` paths | `auth-service` |
| WordPress, Drupal, Joomla detected | `cms` |
| S3, GCS, Azure Blob URLs found in responses | `cloud-storage` |
| Default nginx/Apache page, no title | `generic-web` |
| Anything not matched above | `unknown` |

Also note WAF status per asset (from waf-detection.json).

## Step 10: Write findings-recon.json

Use the Write tool to create `session/{engagement_id}/findings-recon.json`:

```json
{
  "target": "{primary target}",
  "timestamp": "{ISO8601}",
  "phase": "recon",
  "session_id": "{engagement_id}",
  "subdomain_sources": {
    "subfinder": "{N}",
    "crtsh": "{N}",
    "hackertarget": "{N}",
    "total_unique": "{N}"
  },
  "assets": [
    {
      "host": "{hostname}",
      "ip": "{resolved IP or null}",
      "ports": [80, 443],
      "tech": ["{detected tech}"],
      "classification": "{admin-panel | api-endpoint | auth-service | cms | cloud-storage | generic-web | unknown}",
      "waf": "{WAF vendor or null}",
      "scope_verified": true
    }
  ],
  "findings": [
    {
      "id": "{uuid}",
      "type": "subdomain | service | credential_exposure | email_exposure | waf | info",
      "severity": "info | low | medium | high | critical",
      "host": "{hostname}",
      "port": 443,
      "title": "{finding title}",
      "evidence": "{what was observed}",
      "source": "subfinder | crtsh | hackertarget | github | phonebook | wafw00f | nmap | nuclei",
      "recommendation": "{what to do}",
      "review_recommended": false,
      "review_reason": null
    }
  ],
  "osint": {
    "github_hits": "{N code search results with sensitive patterns}",
    "github_secrets_verified": "{N trufflehog verified secrets}",
    "emails_discovered": "{N}",
    "phonebook_enabled": true
  },
  "idor_candidates_file": "session/{engagement_id}/idor-candidates.txt",
  "idor_candidate_count": "{N}",
  "summary": {
    "total_subdomains": "{N}",
    "in_scope": "{N}",
    "live_hosts": "{N}",
    "classified_assets": "{N}",
    "waf_protected": "{N}"
  }
}
```

Notable finding examples to include:
- GitHub credential exposure (severity: high/critical, source: github, review_recommended: true)
- Exposed admin panel (severity: high)
- Dev/staging environment externally accessible (severity: medium)
- Verified trufflehog secret (severity: critical, review_recommended: false — it's verified)
- WAF detected (severity: info, source: wafw00f, review_recommended: true)
- Email addresses from phonebook (severity: info, review_recommended: true)
- Unexpected open ports (severity: medium)
- Outdated server software version (severity: info, review_recommended: true)

Mark `review_recommended: true` where automated detection may be imprecise. Never remove findings — add the flag and explain in `review_reason`.

_update_state "findings_written"

## Step 11: Print recon summary

```
Recon Complete — {engagement_id}
============================================
Target:          {primary target}
Subdomains:      {total} found across {N} sources
  subfinder:     {N}
  crt.sh:        {N}
  HackerTarget:  {N}
  In scope:      {N}

OSINT:
  GitHub hits:   {N} code search results
  Secrets:       {N} verified (trufflehog)
  Emails:        {N} discovered (phonebook.cz)

Live hosts:     {N}
WAF detected:   {N} hosts ({WAF vendors})
IDOR candidates: {N} → session/{id}/idor-candidates.txt

Assets classified:
  {count} admin-panel
  {count} api-endpoint
  {count} auth-service
  {count} cms
  {count} generic-web

Notable findings:
  {list top 3-5 by severity}

Output: session/{engagement_id}/findings-recon.json

Next step: run /vuln-scan to begin vulnerability scanning.
```

If IDOR candidates > 0:
"Review session/{id}/idor-candidates.txt manually — these endpoints may be vulnerable to BOLA/IDOR but require authenticated testing."

If GitHub secrets found:
"[CRITICAL] Verified secrets found in GitHub. Review session/{id}/github-recon/trufflehog-secrets.json immediately — revoke any exposed credentials before proceeding."

If WAF detected:
"WAF detected on {N} hosts. /vuln-scan will use conservative rate limits on protected hosts."

## Error handling

**crt.sh timeout**: If curl returns no data or times out, warn and continue with subfinder results.

**HackerTarget rate limit**: If response contains "API count" error, warn: "HackerTarget rate limit hit. Set HACKERTARGET_API_KEY in ~/.infosec-suite/config for unlimited queries."

**GitHub API rate limit**: If response contains `"message":"API rate limit exceeded"`, warn and stop GitHub searches. Set GITHUB_TOKEN in ~/.infosec-suite/config.

**phonebook.cz API failure**: If PHONEBOOK_API_KEY is set but request fails, warn with the API response and continue without phonebook data.

**wafw00f not installed**: Skip WAF detection with warn. Install: `pip3 install wafw00f`.

**trufflehog not found**: Skip secret scanning step only. `go install github.com/trufflesecurity/trufflehog/v3@latest`

**nmap no targets**: If `hostnames.txt` is empty, skip port scanning and warn.

**nuclei templates missing**: Run `nuclei -update-templates -silent` before tech detection. If that fails, skip and warn.

**Partial results**: Always write whatever data exists to `findings-recon.json` before failing. Partial data is better than no data.

**Permission denied on write**: Report exact error and session directory path.

## API key setup reference

All API keys and tokens live in `~/.infosec-suite/config` (plain key=value format):

```
GITHUB_TOKEN=ghp_your_token_here
PHONEBOOK_API_KEY=your_intelx_key_here
HACKERTARGET_API_KEY=your_key_here
PREPARER_NAME=Your Full Name
EVIDENCE_MAX_CHARS=500
```

Create the file if it doesn't exist:
```bash
mkdir -p ~/.infosec-suite
touch ~/.infosec-suite/config
chmod 600 ~/.infosec-suite/config
```
