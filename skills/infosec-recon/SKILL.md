---
name: infosec-recon
version: 1.1.0
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

# /infosec-recon

Reconnaissance phase — maps the full attack surface before vulnerability scanning.

## Phases

1. Load engagement plan
2. Passive subdomain enumeration (subfinder + crt.sh + HackerTarget)
3. JavaScript and source file mining (katana + secret patterns)
4. Scope filtering
5. OSINT intelligence gathering (GitHub exposure + phonebook.cz)
6. Cloud storage discovery (S3/GCS/Azure bucket guessing)
7. DNS and email security checks (zone transfer, DMARC, SPF)
8. Live host probing (httpx)
9. WAF detection (wafw00f)
10. Port scanning (nmap)
11. Tech detection (nuclei)
12. IDOR/BOLA candidate flagging
13. Asset classification + findings-recon.json
14. Print summary

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

```bash
# Derive SCOPE_FILE early so Step 1.5 (JS mining) can use it before Step 2 defines it
SCOPE_FILE=$(python3 -c "
import json, sys
try:
    print(json.load(open('$PLAN_FILE'))['scope_file'])
except Exception as e:
    sys.exit(1)
" 2>/dev/null || echo "$SESSION_DIR/scope.txt")
```

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

Tell the operator: "Running without an engagement plan. Results will be saved to session/{ENGAGEMENT_ID}/. For full engagement tracking, run /infosec-plan first."

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
  python3 -c "
import sys, re
t = '${TARGET}'
# Use re.escape so TARGET metacharacters (+ * . etc.) don't inject regex
pat = re.compile(r'(^|\.)' + re.escape(t) + r'$', re.I)
for line in sys.stdin:
    line = line.strip()
    if line and pat.search(line):
        print(line)
" \
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

## Step 1.5: JavaScript and source file mining

Mine JS bundles and page source from discovered hosts for hidden API endpoints and exposed secrets.
Skip if `type` is `cloud` (no HTTP surfaces to crawl).

```bash
TYPE=$(python3 -c "import json; print(json.load(open('$PLAN_FILE')).get('type','web_app'))" 2>/dev/null || echo "web_app")

if [ "$TYPE" != "cloud" ] && command -v katana &>/dev/null; then
  echo "[JS mining] Extracting endpoints from JavaScript files..."

  katana \
    -l "$SESSION_DIR/subdomains-inscope.txt" \
    -jc \
    -d 2 \
    -silent \
    -rate-limit "$MAX_RPS" \
    -o "${SESSION_DIR}/js-katana-raw.txt" \
    2>/dev/null || true

  # Extract API/admin paths from discovered URLs
  grep -E '(/api/|/v[0-9]+/|/graphql|/admin|/internal|/debug|/swagger|/openapi|/actuator|/metrics|/health|/config)' \
    "${SESSION_DIR}/js-katana-raw.txt" 2>/dev/null | sort -u \
    > "$SESSION_DIR/js-endpoints.txt" || true

  JS_COUNT=$(wc -l < "$SESSION_DIR/js-endpoints.txt" 2>/dev/null | tr -d ' ' || echo 0)
  echo "[JS] $JS_COUNT API/admin endpoints extracted from JS"

  # Add newly discovered in-scope endpoints to live-urls.txt
  python3 - << 'PYEOF'
import sys
scope_file = sys.argv[1]
katana_file = sys.argv[2]
live_urls_file = sys.argv[3]

try:
    scope = set(open(scope_file).read().splitlines())
except:
    scope = set()

new_urls = []
try:
    with open(katana_file) as f:
        for url in f:
            url = url.strip()
            if not url or '://' not in url:
                continue
            host = url.split('/')[2].split(':')[0]
            if any(host == s or host.endswith('.' + s) for s in scope):
                new_urls.append(url)
except:
    pass

existing = set()
try:
    existing = set(open(live_urls_file).read().splitlines())
except:
    pass

added = 0
with open(live_urls_file, 'a') as f:
    for u in new_urls:
        if u not in existing:
            f.write(u + '\n')
            added += 1

print(f'[JS] {added} new in-scope URLs appended to live-urls.txt')
PYEOF
"$SCOPE_FILE" "${SESSION_DIR}/js-katana-raw.txt" "$SESSION_DIR/live-urls.txt"

  # Scan JS files for hardcoded secrets (heuristic — requires manual verification)
  python3 - << 'PYEOF'
import re, json, sys
import urllib.request, ssl

SESSION_DIR = sys.argv[1]
SECRET_PATTERNS = [
    (r'(?i)api[_-]?key["\'\s]*[:=]["\'\s]*([A-Za-z0-9_\-]{20,})', 'api_key'),
    (r'(?i)secret[_-]?key["\'\s]*[:=]["\'\s]*([A-Za-z0-9_\-]{20,})', 'secret_key'),
    (r'(?i)access[_-]?token["\'\s]*[:=]["\'\s]*([A-Za-z0-9_\-\.]{20,})', 'access_token'),
    (r'eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*', 'jwt_token'),
    (r'AKIA[0-9A-Z]{16}', 'aws_access_key'),
    (r'(?i)password["\'\s]*[:=]["\'\s]*([^\s"\']{8,})', 'password'),
]

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

js_urls = []
try:
    with open(f'{SESSION_DIR}/js-katana-raw.txt') as f:
        js_urls = [l.strip() for l in f if '.js' in l and l.strip()][:25]
except:
    pass

findings = []
for url in js_urls:
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, context=ctx, timeout=10) as r:
            content = r.read(200000).decode('utf-8', errors='ignore')
        for pattern, ptype in SECRET_PATTERNS:
            for m in re.finditer(pattern, content):
                findings.append({'url': url, 'type': ptype, 'match': m.group()[:80]})
    except:
        pass

with open(f'{SESSION_DIR}/js-secrets.txt', 'w') as f:
    for fn in findings:
        f.write(f'{fn["type"]}|{fn["url"]}|{fn["match"]}\n')

if findings:
    print(f'[JS SECRETS] {len(findings)} potential secrets — review {SESSION_DIR}/js-secrets.txt')
    for fn in findings[:5]:
        print(f'  [{fn["type"]}] {fn["url"]}')
else:
    print('[JS SECRETS] No obvious secrets in sampled JS files')
PYEOF
"$SESSION_DIR"

else
  echo "[JS mining] Skipping — katana not installed or cloud-only engagement"
fi
```

For each entry in `js-secrets.txt`, write a HIGH severity finding with `review_recommended: true` (heuristic patterns — always verify manually before reporting).

_update_state "js_mining"

## Step 2: Scope filtering

**Critical — this is the legal scope enforcement boundary.**

```bash
SCOPE_FILE=$(python3 -c "
import json, sys
try:
    plan = json.load(open('$PLAN_FILE'))
    print(plan['scope_file'])
except Exception as e:
    print(f'ERROR: {e}', file=sys.stderr)
    sys.exit(1)
")

# Validate scope.txt is non-empty and well-formed before filtering
python3 - << 'PYEOF'
import sys, re

scope_file = sys.argv[1]
target     = sys.argv[2]

try:
    lines = [l.strip() for l in open(scope_file) if l.strip() and not l.startswith('#')]
except Exception as e:
    print(f'ERROR: Cannot read scope file: {e}')
    sys.exit(1)

if not lines:
    print(f'ERROR: scope.txt is empty. Add at least one in-scope domain or IP before scanning.')
    sys.exit(1)

# Validate each entry is a valid domain, IP, or CIDR using ipaddress for IP/CIDR
# (the simplified IPv6 regex '^[a-fA-F0-9:]+$' matched invalid addresses like ':::::::')
import ipaddress as _ip

DOMAIN_RE = re.compile(
    r'^(\*\.)?'
    r'([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
)

def _valid_entry(entry):
    if DOMAIN_RE.match(entry):
        return True
    try:
        _ip.ip_network(entry, strict=False)  # accepts IPv4, IPv4 CIDR, IPv6, IPv6 CIDR
        return True
    except ValueError:
        return False

invalid = [l for l in lines if not _valid_entry(l)]
if invalid:
    print(f'WARN: {len(invalid)} scope entries look malformed (check manually): {invalid[:5]}')

# Verify primary target appears in scope
found = any(target == l or target.endswith('.' + l) or l == '*.' + '.'.join(target.split('.')[1:])
            for l in lines)
if not found:
    print(f'ERROR: Primary target "{target}" is not covered by scope.txt entries: {lines}')
    print('Add the primary target domain to scope.txt before scanning.')
    sys.exit(1)

print(f'[Scope] {len(lines)} entries validated. Primary target "{target}" is in scope.')
PYEOF
"$SCOPE_FILE" "$TARGET" || {
  echo "Scope validation failed — halting. Fix scope.txt and retry."
  exit 1
}

# CIDR-aware scope filter — handles domains, wildcards, IPs, and CIDR ranges.
# grep -Fxf does exact-string matching only; it can't match hostnames against CIDR ranges.
python3 - << 'PYEOF'
import sys, ipaddress

scope_file = sys.argv[1]
raw_file   = sys.argv[2]
out_file   = sys.argv[3]

try:
    scope = [l.strip() for l in open(scope_file) if l.strip() and not l.startswith('#')]
except Exception as e:
    print(f'[WARN] Cannot read scope file: {e}', file=sys.stderr)
    scope = []

def in_scope(host):
    for entry in scope:
        entry_clean = entry.lstrip('*.')
        if host == entry_clean or host.endswith('.' + entry_clean):
            return True
        try:
            network = ipaddress.ip_network(entry, strict=False)
            try:
                if ipaddress.ip_address(host) in network:
                    return True
            except ValueError:
                pass
        except ValueError:
            pass
    return False

try:
    hosts = [l.strip() for l in open(raw_file) if l.strip()]
except:
    hosts = []

inscope = [h for h in hosts if in_scope(h)]
with open(out_file, 'w') as f:
    f.write('\n'.join(inscope) + ('\n' if inscope else ''))
print(f'[Scope] {len(inscope)}/{len(hosts)} hosts in scope (CIDR-aware filter)')
PYEOF
"$SCOPE_FILE" "$SESSION_DIR/subdomains-raw.txt" "$SESSION_DIR/subdomains-inscope.txt"

# Include primary target if not already present (it passed scope validation above)
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

  # Extract search ID and surface any API errors explicitly
  SEARCH_ID=$(echo "$SEARCH_RESP" | python3 -c "
import json, sys
try:
    data = json.loads(sys.stdin.read())
    sid = data.get('id', '')
    # Surface API error messages (e.g. invalid key, quota exceeded)
    if not sid:
        err = data.get('error') or data.get('message') or data.get('status', '')
        if err:
            print(f'[phonebook.cz] API error: {err}', file=sys.stderr)
    print(sid or '')
except Exception as e:
    print(f'[phonebook.cz] Parse error: {e}', file=sys.stderr)
    print('')
" 2>&1 | tee /dev/stderr | tail -1 || echo "")
  # Strip any warning lines from SEARCH_ID — keep only the ID value
  SEARCH_ID=$(echo "$SEARCH_ID" | grep -v '^\[phonebook' | tail -1 | tr -d ' ')

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
    # Surface raw response so operator can diagnose the problem
    echo "[phonebook.cz] Search initiation failed."
    echo "  Raw API response: $(echo "$SEARCH_RESP" | head -c 300)"
    echo "  Likely causes: invalid API key, quota exceeded, or network issue."
    echo "  Verify your key at https://intelx.io/account?tab=developer"
  fi
fi
```

Read `phonebook-results.json` using the Read tool. Extract:
- Email addresses → add as INFO findings with `review_recommended: true` (useful for phishing context, social engineering)
- Discovered subdomains → add to `subdomains-inscope.txt` IF they pass scope filtering
- Any credentials/leaked data → HIGH severity finding

_update_state "osint_phonebook"

## Step 3c: Cloud storage discovery

Enumerate publicly accessible cloud storage buckets using target-derived naming patterns.
Run for all engagement types — cloud storage exposures are common even for web-app-only targets.

```bash
TARGET_SHORT=$(echo "$TARGET" | sed 's/\..*//')
echo "[Cloud Storage] Testing bucket patterns for ${TARGET_SHORT}..."

python3 - << 'PYEOF'
import urllib.request, ssl, sys, json

TARGET_SHORT = sys.argv[1]
SESSION_DIR  = sys.argv[2]

names = [
    TARGET_SHORT,
    f"{TARGET_SHORT}-backup", f"{TARGET_SHORT}-dev", f"{TARGET_SHORT}-staging",
    f"{TARGET_SHORT}-prod", f"{TARGET_SHORT}-data", f"{TARGET_SHORT}-files",
    f"{TARGET_SHORT}-uploads", f"{TARGET_SHORT}-assets", f"{TARGET_SHORT}-static",
    f"{TARGET_SHORT}-media", f"{TARGET_SHORT}-logs", f"{TARGET_SHORT}-config",
    f"{TARGET_SHORT}-internal", f"{TARGET_SHORT}-private", f"{TARGET_SHORT}-api",
    f"{TARGET_SHORT}-web", f"{TARGET_SHORT}-images", f"{TARGET_SHORT}-archive",
]

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

findings = []

for name in names:
    for provider, url in [
        ('s3',    f'https://{name}.s3.amazonaws.com/'),
        ('gcs',   f'https://storage.googleapis.com/{name}/'),
        ('azure', f'https://{name}.blob.core.windows.net/{name}/'),
    ]:
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'InfoSec-Suite'})
            with urllib.request.urlopen(req, context=ctx, timeout=8) as r:
                body = r.read(500).decode('utf-8', errors='ignore')
                is_listing = any(k in body for k in ('ListBucketResult', 'EnumerationResults', 'Contents'))
                sev = 'critical' if is_listing else 'high'
                findings.append({'provider': provider, 'bucket': name, 'url': url,
                                  'status': r.status, 'listing': is_listing, 'severity': sev})
                flag = '  [LISTING ENABLED]' if is_listing else ''
                print(f'[CLOUD] {sev.upper()} {provider}:{name} HTTP {r.status}{flag}')
        except urllib.error.HTTPError as e:
            if e.code == 403:
                # Bucket exists but access denied — note it
                findings.append({'provider': provider, 'bucket': name, 'url': url,
                                  'status': 403, 'listing': False, 'severity': 'info',
                                  'note': 'Bucket exists, access denied'})
        except:
            pass

with open(f'{SESSION_DIR}/cloud-storage-findings.json', 'w') as f:
    json.dump({'total': len(findings), 'findings': findings}, f, indent=2)

accessible = [f for f in findings if f['status'] != 403]
if accessible:
    print(f'[CLOUD] {len(accessible)} accessible buckets → {SESSION_DIR}/cloud-storage-findings.json')
else:
    print('[CLOUD] No accessible buckets found with common naming patterns')
PYEOF
"$TARGET_SHORT" "$SESSION_DIR"
```

For each finding with `listing: true` → CRITICAL finding: `cloud_storage_public_listing`.
For each finding with `status: 200` but no listing → HIGH finding: `cloud_storage_public_access`.
For each finding with `status: 403` → INFO finding: `cloud_storage_exists` (bucket exists, closed — note for cloud engagement scope).

_update_state "cloud_storage"

## Step 3d: DNS and email security checks

Test for DNS zone transfer and email spoofing protection. Missing controls enable phishing and domain hijacking.

```bash
echo "[DNS Security] Checking zone transfer and email security for ${TARGET}..."

# Zone transfer attempt
DIG_AXFR=$(dig AXFR "@$(dig NS ${TARGET} +short | head -1)" "$TARGET" +noall +answer 2>/dev/null || true)
if echo "$DIG_AXFR" | grep -qE '\s(A|AAAA|CNAME|MX|TXT)\s'; then
  echo "[DNS] CRITICAL: Zone transfer succeeded for ${TARGET}"
  echo "$DIG_AXFR" > "$SESSION_DIR/dns-zone-transfer.txt"
  ZONE_TRANSFER=true
else
  echo "[DNS] Zone transfer blocked (expected)"
  ZONE_TRANSFER=false
fi

# DMARC
DMARC=$(dig TXT "_dmarc.${TARGET}" +short 2>/dev/null | tr -d '"' | head -1 || true)
if [ -z "$DMARC" ]; then
  echo "[DNS] HIGH: No DMARC record — email spoofing as ${TARGET} is possible"
  DMARC_STATUS="missing"
elif echo "$DMARC" | grep -qi "p=none"; then
  echo "[DNS] MEDIUM: DMARC p=none (monitoring only) — spoofing not blocked"
  DMARC_STATUS="monitor_only"
else
  echo "[DNS] DMARC: $DMARC"
  DMARC_STATUS="ok"
fi

# SPF
SPF=$(dig TXT "$TARGET" +short 2>/dev/null | grep -i 'v=spf1' | tr -d '"' | head -1 || true)
if [ -z "$SPF" ]; then
  echo "[DNS] MEDIUM: No SPF record — email spoofing risk"
  SPF_STATUS="missing"
elif echo "$SPF" | grep -q '+all'; then
  echo "[DNS] HIGH: SPF uses +all — permits any sender"
  SPF_STATUS="permissive"
else
  echo "[DNS] SPF: $SPF"
  SPF_STATUS="ok"
fi

# DKIM (probe common selectors)
DKIM_FOUND=false
for selector in default google selector1 selector2 mail s1 s2 k1 smtp; do
  DKIM=$(dig TXT "${selector}._domainkey.${TARGET}" +short 2>/dev/null | grep 'p=' | head -1 || true)
  if [ -n "$DKIM" ]; then
    echo "[DNS] DKIM found (selector: ${selector})"
    DKIM_FOUND=true
    break
  fi
done
$DKIM_FOUND || echo "[DNS] INFO: No common DKIM selector found — may use custom selector"
```

Write findings to `findings-recon.json` by status:
- `ZONE_TRANSFER=true` → CRITICAL: `dns_zone_transfer_exposed`
- `DMARC_STATUS=missing` → HIGH: `dmarc_missing`
- `DMARC_STATUS=monitor_only` → MEDIUM: `dmarc_policy_none`
- `SPF_STATUS=missing` → MEDIUM: `spf_missing`
- `SPF_STATUS=permissive` → HIGH: `spf_plus_all`

_update_state "dns_security"

## Step 3e: Subdomain takeover (dangling CNAME detection)

Check every in-scope subdomain for CNAMEs pointing at cloud/SaaS services that no longer have a matching resource — a classic subdomain takeover condition.

```bash
python3 - << 'PYEOF'
import subprocess, json, sys, os, re

SESSION_DIR = sys.argv[1]

# Services whose CNAMEs indicate potential takeover if the resource is gone
TAKEOVER_SIGNATURES = {
    'amazonaws.com':        ('S3 / Elastic Beanstalk / CloudFront',  'NoSuchBucket|NoSuchDistribution|404|InvalidBucketName'),
    'azurewebsites.net':    ('Azure App Service',                     'does not exist|404'),
    'cloudapp.azure.com':   ('Azure Cloud App',                       '404'),
    'azureedge.net':        ('Azure CDN',                             '404'),
    'github.io':            ('GitHub Pages',                          "There isn't a GitHub Pages site here|404"),
    'herokuapp.com':        ('Heroku',                                'No such app|404'),
    'fastly.net':           ('Fastly CDN',                            'Fastly error: unknown domain|404'),
    'ghost.io':             ('Ghost CMS',                             "The thing you were looking for is no longer here|404"),
    'pantheonsite.io':      ('Pantheon',                              '404 error unknown site|404'),
    'shopify.com':          ('Shopify',                               'Sorry, this shop is currently unavailable|404'),
    'bitbucket.io':         ('Bitbucket Pages',                       'Repository not found|404'),
    'surge.sh':             ('Surge.sh',                              "project not found|404"),
    'netlify.app':          ('Netlify',                               "Not Found|404"),
    'vercel.app':           ('Vercel',                                "The deployment could not be found|404"),
    'readthedocs.io':       ('ReadTheDocs',                           'unknown to Read the Docs|404'),
    'zendesk.com':          ('Zendesk',                               'Help Center Closed|404'),
    'freshdesk.com':        ('Freshdesk',                             "We couldn't find|404"),
    'statuspage.io':        ('Statuspage.io',                         'You are being redirected|404'),
    'airee.ru':             ('Airee CDN',                             'Ошибка|404'),
}

subdomains = []
try:
    with open(os.path.join(SESSION_DIR, 'subdomains-inscope.txt')) as f:
        subdomains = [l.strip() for l in f if l.strip()]
except:
    pass

findings = []

for subdomain in subdomains:
    # Resolve CNAME
    try:
        r = subprocess.run(
            ['dig', 'CNAME', subdomain, '+short'],
            capture_output=True, text=True, timeout=10
        )
        cname = r.stdout.strip().rstrip('.')
    except:
        continue

    if not cname:
        continue

    # Check if CNAME points to a known cloud service
    matched_service = None
    matched_sig = None
    for domain_suffix, (service, sig) in TAKEOVER_SIGNATURES.items():
        if cname.endswith(domain_suffix) or domain_suffix in cname:
            matched_service = service
            matched_sig = sig
            break

    if not matched_service:
        continue

    # Probe the subdomain for the unclaimed-resource fingerprint
    try:
        probe = subprocess.run(
            ['curl', '-s', '--max-time', '10', '-L', '-o', '-',
             '-w', '\nHTTP_CODE:%{http_code}', f'http://{subdomain}'],
            capture_output=True, text=True, timeout=15
        )
        body = probe.stdout
        http_code = ''
        for line in body.splitlines():
            if line.startswith('HTTP_CODE:'):
                http_code = line.split(':', 1)[1].strip()
        body_lower = body.lower()
    except:
        body_lower = ''
        http_code = ''

    # Check fingerprints (any match → likely unclaimed)
    fingerprints = [f.strip() for f in matched_sig.split('|')]
    hit = any(fp.lower() in body_lower for fp in fingerprints if not fp.isdigit())
    hit = hit or (http_code in ('404', '410') and matched_service in ('GitHub Pages', 'Netlify', 'Vercel', 'Surge.sh'))

    if hit:
        findings.append({
            'subdomain': subdomain,
            'cname': cname,
            'service': matched_service,
            'http_code': http_code,
            'severity': 'high',
            'type': 'subdomain_takeover',
            'evidence': f'CNAME {subdomain} → {cname} ({matched_service}); fingerprint matched',
            'recommendation': (f'Remove dangling DNS record for {subdomain} or register the '
                               f'{matched_service} resource it points to before an attacker does.'),
            'review_recommended': True,
            'review_reason': 'Automated detection — verify the resource is genuinely unclaimed before reporting.',
        })
        print(f'[TAKEOVER] HIGH {subdomain} → {cname} ({matched_service}) HTTP {http_code}')
    else:
        print(f'[TAKEOVER] {subdomain} → {cname} ({matched_service}): no unclaimed fingerprint (HTTP {http_code})')

with open(os.path.join(SESSION_DIR, 'subdomain-takeover.json'), 'w') as f:
    json.dump({'total': len(findings), 'findings': findings}, f, indent=2)

if findings:
    print(f'\n[TAKEOVER] {len(findings)} potential subdomain takeover(s) found.')
    print(f'           Review {SESSION_DIR}/subdomain-takeover.json and verify manually.')
else:
    print('[TAKEOVER] No dangling CNAMEs detected.')
PYEOF
"$SESSION_DIR"
```

Add each finding from `subdomain-takeover.json` to `findings-recon.json` as severity `high`, `review_recommended: true`.

_update_state "subdomain_takeover"

## Step 4: Live host probing

```bash
httpx -l "$SESSION_DIR/subdomains-inscope.txt" \
  -silent -status-code -title -tech-detect \
  -timeout 10 \
  -o "$SESSION_DIR/live-hosts.json" -json

LIVE=$(python3 -c "
import os
path = '$SESSION_DIR/live-hosts.json'
if not os.path.exists(path):
    print(0)
else:
    lines = open(path).read().strip().split('\n')
    print(sum(1 for l in lines if l.strip()))
" 2>/dev/null || echo 0)
echo "HTTPX: $LIVE live hosts"

if [ "$LIVE" -eq 0 ]; then
  echo ""
  echo "=============================="
  echo " ERROR: No live HTTP/HTTPS hosts found."
  echo " Check that targets are reachable and"
  echo " that scope.txt contains valid in-scope hosts."
  echo " Stopping recon — nothing to scan."
  echo "=============================="
  # Write partial findings so /infosec-report has context
  _update_state "live_host_probe"
  exit 1
fi
```

Note: httpx with `-json` writes NDJSON (one JSON object per line). Use `python3 -c "import json; data=[json.loads(l) for l in open(f) if l.strip()]"` when processing.

_update_state "live_host_probe"

## Step 5: WAF detection

Identify Web Application Firewalls protecting each live host. WAF presence affects subsequent scanning strategy — rate limits, evasion, and template selection in /infosec-vuln-scan.

```bash
python3 -c "
import json
urls = []
for line in open('$SESSION_DIR/live-hosts.json'):
    line = line.strip()
    if not line:
        continue
    try:
        obj = json.loads(line)
        url = obj.get('url','')
        if url:
            urls.append(url)
    except json.JSONDecodeError:
        pass  # skip malformed/truncated NDJSON lines
with open('$SESSION_DIR/live-urls.txt', 'w') as f:
    f.write('\n'.join(urls) + ('\n' if urls else ''))
" 2>/dev/null || true

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
- This informs /infosec-vuln-scan: protected hosts may need rate limit reduction and evasion-aware templates

_update_state "waf_detection"

## Step 6: Port scanning

```bash
python3 -c "
import json
hosts = set()
for line in open('$SESSION_DIR/live-hosts.json'):
    line = line.strip()
    if not line:
        continue
    try:
        obj = json.loads(line)
        h = obj.get('host','')
        if h:
            hosts.add(h)
    except json.JSONDecodeError:
        pass  # skip malformed/truncated NDJSON lines
with open('$SESSION_DIR/hostnames.txt', 'w') as f:
    f.write('\n'.join(sorted(hosts)))
" 2>/dev/null || true

nmap -sV --open -T4 --min-parallelism 10 \
  -iL "$SESSION_DIR/hostnames.txt" \
  -oA "$SESSION_DIR/nmap-output"
```

Read `$SESSION_DIR/nmap-output.nmap` using the Read tool. For each host, note:
- Open ports and services
- Service versions (for CVE correlation in /infosec-vuln-scan)
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

Next step: run /infosec-vuln-scan to begin vulnerability scanning.
```

If IDOR candidates > 0:
"Review session/{id}/idor-candidates.txt manually — these endpoints may be vulnerable to BOLA/IDOR but require authenticated testing."

If GitHub secrets found:
"[CRITICAL] Verified secrets found in GitHub. Review session/{id}/github-recon/trufflehog-secrets.json immediately — revoke any exposed credentials before proceeding."

If WAF detected:
"WAF detected on {N} hosts. /infosec-vuln-scan will use conservative rate limits on protected hosts."

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
