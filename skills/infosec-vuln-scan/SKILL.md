---
name: infosec-vuln-scan
version: 1.1.0
description: |
  Vulnerability scanning skill. Reads findings-recon.json from /infosec-recon,
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

# /infosec-vuln-scan

Vulnerability scanning phase — exploits the attack surface mapped by /infosec-recon.

## Phases

1. Load engagement plan + recon findings
2. Cloud credential check (cloud/combined engagements only)
3. Template selection based on tech stack + engagement type
4. Active configuration testing (CORS, security headers, TLS, cookies, JWT, rate limits, GraphQL)
5. Nuclei vulnerability scan
6. Severity classification and false-positive flagging
7. Write findings-vulns.json (merging active config findings)
8. Print scan summary

## Step 0: Load engagement plan and recon findings

```bash
if [ -f .active-session ]; then
  SESSION_DIR=$(cat .active-session | tr -d '[:space:]')
  PLAN_FILE="$SESSION_DIR/engagement-plan.json"
  RECON_FILE="$SESSION_DIR/findings-recon.json"
else
  echo "ERROR: No active session found. Run /infosec-plan first, or provide engagement_id= param."
  exit 1
fi

if [ ! -f "$PLAN_FILE" ]; then
  echo "ERROR: engagement-plan.json not found at $PLAN_FILE"
  echo "Run /infosec-plan to create an engagement plan."
  exit 1
fi

if [ ! -f "$RECON_FILE" ]; then
  echo "ERROR: findings-recon.json not found at $RECON_FILE"
  echo "Run /infosec-recon before /infosec-vuln-scan."
  exit 1
fi

# Resume support — check for partially completed scan
STATE_FILE="$SESSION_DIR/vuln-state.json"
if [ -f "$STATE_FILE" ]; then
  COMPLETED=$(python3 -c "
import json
d=json.load(open('$STATE_FILE'))
steps=d.get('completed_steps', [])
print(len(steps))
" 2>/dev/null || echo 0)
  LAST_STEP=$(python3 -c "
import json
d=json.load(open('$STATE_FILE'))
steps=d.get('completed_steps', [])
print(steps[-1] if steps else 'none')
" 2>/dev/null || echo "none")
  echo "RESUMING vuln-scan: $COMPLETED steps completed. Last: $LAST_STEP"
fi
```

State update helper for vuln-scan — use after each major step:

```bash
_vuln_update_state() {
  local step="$1"
  local ts
  ts=$(date +%s)
  if [ -f "$STATE_FILE" ]; then
    python3 - <<EOF
import json
with open('$STATE_FILE') as f:
    d = json.load(f)
steps = d.get('completed_steps', [])
if '$step' not in steps:
    steps.append('$step')
d['completed_steps'] = steps
d['last_updated'] = $ts
with open('$STATE_FILE', 'w') as f:
    json.dump(d, f, indent=2)
EOF
  else
    python3 -c "
import json
json.dump({'completed_steps': ['$step'], 'last_updated': $ts},
          open('$STATE_FILE', 'w'), indent=2)
"
  fi
}
```

Skip any step whose name appears in `completed_steps` inside `vuln-state.json`. Steps are: `tech_merge`, `cloud_creds`, `template_select`, `active_config`, `nuclei_scan`, `merge_findings`, `findings_written`.

If resuming, announce: "Resuming vuln-scan — skipping {N} already completed steps."

Read both files using the Read tool. Extract:
- From plan: `engagement_id`, `type`, `methodology`, `known_tech[]`, `sensitive_paths[]`, `rate_limit`, `rules.max_requests_per_second`
- From recon: `assets[]` (classifications + tech), `findings[]` (existing findings), `summary.live_hosts`

## Step 0.5: Merge nuclei tech detection into known_tech

nuclei-tech.json from recon contains tech detected during the live-host sweep. Merge it with `known_tech[]` from the plan so template selection uses the full observed tech stack, not just what was declared upfront.

```bash
python3 - << 'PYEOF'
import json, os, sys

SESSION_DIR = sys.argv[1]
PLAN_FILE   = sys.argv[2]

tech_file = os.path.join(SESSION_DIR, 'nuclei-tech.json')
detected = set()

if os.path.exists(tech_file):
    try:
        with open(tech_file) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    # nuclei NDJSON: matcher-name or template-id carries tech name
                    name = (entry.get('matcher-name') or
                            entry.get('template-id', '').split('/')[-1])
                    if name:
                        detected.add(name.lower().strip())
                except json.JSONDecodeError:
                    pass
    except Exception as e:
        print(f'[WARN] Could not read nuclei-tech.json: {e}')

try:
    plan = json.load(open(PLAN_FILE))
    plan_tech = [t.lower().strip() for t in plan.get('known_tech', [])]
    merged = sorted(set(plan_tech) | detected)
    print(f'[Tech] Plan declared: {plan_tech}')
    print(f'[Tech] Nuclei detected: {sorted(detected)}')
    print(f'[Tech] Merged known_tech: {merged}')
    # Write merged list back to plan for downstream consumers
    plan['known_tech'] = merged
    json.dump(plan, open(PLAN_FILE, 'w'), indent=2)
    print(f'[Tech] engagement-plan.json updated with merged tech list ({len(merged)} entries)')
except Exception as e:
    print(f'[WARN] Could not update known_tech in plan: {e}')
PYEOF
"$SESSION_DIR" "$PLAN_FILE"
```

**Proceed to Step 2 using the updated `known_tech[]` list** (now includes both declared and detected tech).

```bash
_vuln_update_state "tech_merge"
```

## Step 1: Cloud credential check (cloud/combined only)

Skip this step if `type` is `web_app` or `api`.

For cloud and combined engagements, verify credentials before scanning. **Halt if any required provider credentials are missing or invalid — do not silently continue with empty results.**

### AWS

```bash
# Check credential sources; retry up to 3 times for transient network errors
if [ -f "$HOME/.aws/credentials" ] || { [ -n "${AWS_ACCESS_KEY_ID:-}" ] && [ -n "${AWS_SECRET_ACCESS_KEY:-}" ]; }; then
  AWS_OK=false
  for _attempt in 1 2 3; do
    RESULT=$(aws sts get-caller-identity 2>&1)
    if echo "$RESULT" | jq -e '.Account' &>/dev/null; then
      ACCOUNT=$(echo "$RESULT" | jq -r '.Account')
      echo "AWS: authenticated as account $ACCOUNT"
      AWS_OK=true
      break
    fi
    echo "[WARN] AWS auth attempt $_attempt/3 failed: $RESULT"
    [ "$_attempt" -lt 3 ] && sleep 3
  done
  $AWS_OK || echo "AWS_AUTH_FAILED: $RESULT"
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
-t http/misconfiguration/authentication/    # API2: Broken Authentication — token validation, default creds
-t http/misconfiguration/rate-limit/        # API4: Unrestricted Resource Consumption — missing rate limits
-t http/vulnerabilities/ssrf/               # API7: SSRF — fetch/redirect/webhook parameter injection
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

### Security configuration templates (all engagement types)

Always append — these cover attack surface present regardless of tech stack:

```
-t ssl/                                                    # TLS: weak ciphers, BEAST, POODLE, expired certs, HSTS preload
-t http/misconfiguration/http-missing-security-headers/    # CSP, HSTS, X-Frame-Options, Permissions-Policy, Referrer-Policy
-t http/misconfiguration/cors/                             # CORS wildcard, null origin, credentialed cross-origin
-t http/misconfiguration/cookie-flags/                     # Missing HttpOnly, Secure, SameSite on auth cookies
```

### Injection completeness (all engagement types)

Supplement the base `vulnerabilities/` set with targeted injection templates:

```
-t http/vulnerabilities/xxe/      # XML External Entity — XML endpoints + content-type coercion
-t http/vulnerabilities/ssti/     # Server-Side Template Injection — Jinja2, Twig, FreeMarker, Pebble
-t http/vulnerabilities/generic/  # Command injection, header injection, CRLF
```

### API Security Top 10 additions (api + combined engagements)

```
-t http/misconfiguration/graphql/ # GraphQL introspection enabled, batch abuse, field suggestions
-t http/misconfiguration/jwt/     # JWT alg:none, weak HMAC, missing expiry, kid injection
```

Tell the operator: "Selected {N} template categories for {methodology} scan. Tech-specific additions: {list}."

```bash
_vuln_update_state "template_select"
```

## Step 2.5: Active configuration testing

Direct curl-based checks for issues nuclei templates may not catch due to dynamic context requirements.
Run before the nuclei scan so findings are available during classification (Step 5).

```bash
ACTIVE_CONFIG_FINDINGS=()
```

### CORS misconfiguration

```bash
python3 - << 'PYEOF'
import json, subprocess, sys

SESSION_DIR = sys.argv[1]
MAX_URLS = 20

urls = []
try:
    with open(f'{SESSION_DIR}/live-urls.txt') as f:
        urls = [l.strip() for l in f if l.strip()][:MAX_URLS]
except:
    pass

findings = []

for url in urls:
    for origin, label in [
        ('https://evil.attacker.com', 'arbitrary'),
        ('null', 'null_origin'),
    ]:
        try:
            r = subprocess.run(
                ['curl', '-s', '-I', '-H', f'Origin: {origin}', '--max-time', '10', url],
                capture_output=True, text=True, timeout=15
            )
            acao, acac = '', False
            for line in r.stdout.splitlines():
                ll = line.lower()
                if 'access-control-allow-origin:' in ll:
                    acao = line.split(':', 1)[1].strip()
                if 'access-control-allow-credentials: true' in ll:
                    acac = True
            # Use exact comparison — substring match (e.g. 'evil.attacker.com' in acao)
            # would false-positive on 'notevil.attacker.com.trusted.com'
            acao_norm = acao.lower().rstrip('/')
            origin_norm = origin.lower().rstrip('/')
            reflected = (acao_norm == origin_norm or
                         acao == '*' or
                         (label == 'null_origin' and acao_norm == 'null'))
            if reflected:
                sev = 'critical' if acac else ('high' if label == 'null_origin' else 'medium')
                findings.append({
                    'url': url, 'origin_tested': origin, 'acao': acao,
                    'credentials': acac, 'severity': sev, 'type': 'cors_misconfiguration',
                    'evidence': f'Origin: {origin} → ACAO: {acao}, ACAC: {acac}',
                    'recommendation': 'Explicitly allowlist trusted origins. Never reflect Origin header. '
                                      'Remove wildcard ACAO when ACAC: true is set.',
                })
        except:
            pass

for f in findings:
    cred = ' + credentials' if f['credentials'] else ''
    print(f'[CORS] {f["severity"].upper()} {f["url"]}: {f["origin_tested"]} origin reflected{cred}')

if not findings:
    print('[CORS] No CORS misconfigurations found')

with open(f'{SESSION_DIR}/active-config-cors.json', 'w') as out:
    json.dump(findings, out, indent=2)
PYEOF
"$SESSION_DIR"
```

### Security headers

```bash
python3 - << 'PYEOF'
import subprocess, json, sys

SESSION_DIR = sys.argv[1]
REQUIRED = {
    'strict-transport-security': ('low',  'Missing HSTS — connections can be downgraded to HTTP'),
    'x-frame-options':           ('low',  'Missing X-Frame-Options — clickjacking risk'),
    'x-content-type-options':    ('low',  'Missing X-Content-Type-Options — MIME sniffing'),
    'content-security-policy':   ('low',  'Missing CSP — XSS severity containment absent'),
    'permissions-policy':        ('info', 'Missing Permissions-Policy'),
    'referrer-policy':           ('info', 'Missing Referrer-Policy — may leak URLs in Referer'),
}

urls = []
try:
    with open(f'{SESSION_DIR}/live-urls.txt') as f:
        urls = [l.strip() for l in f if l.strip() and l.strip().startswith('https://')][:10]
except:
    pass

findings = []
for url in urls:
    try:
        r = subprocess.run(
            ['curl', '-s', '-I', '--max-time', '10', '-L', url],
            capture_output=True, text=True, timeout=15
        )
        present = {ln.split(':')[0].lower().strip() for ln in r.stdout.splitlines() if ':' in ln}
        for hdr, (sev, msg) in REQUIRED.items():
            if hdr not in present:
                findings.append({'url': url, 'type': 'missing_security_header',
                                  'header': hdr, 'severity': sev,
                                  'evidence': f'Header absent: {hdr}',
                                  'recommendation': f'Add response header: {hdr}'})
    except:
        pass

for f in findings[:15]:
    print(f'[HEADER] {f["severity"].upper()} {f["url"]}: {f["header"]}')
if not findings:
    print('[HEADER] All required security headers present')

with open(f'{SESSION_DIR}/active-config-headers.json', 'w') as out:
    json.dump(findings, out, indent=2)
PYEOF
"$SESSION_DIR"
```

### Cookie flag analysis

```bash
python3 - << 'PYEOF'
import subprocess, json, sys

SESSION_DIR = sys.argv[1]
urls = []
try:
    with open(f'{SESSION_DIR}/live-urls.txt') as f:
        urls = [l.strip() for l in f if l.strip()][:15]
except:
    pass

AUTH_KEYWORDS = ('session', 'token', 'auth', 'jwt', 'sid', 'id', 'csrf', 'remember')
findings = []

for url in urls:
    try:
        r = subprocess.run(
            ['curl', '-s', '-I', '-c', '/dev/null', '--max-time', '10', '-L', url],
            capture_output=True, text=True, timeout=15
        )
        for line in r.stdout.splitlines():
            if not line.lower().startswith('set-cookie:'):
                continue
            raw = line
            name = raw.split('=')[0].split(':')[-1].strip()
            flags = raw.lower()
            is_auth = any(k in name.lower() for k in AUTH_KEYWORDS)
            missing = []
            if 'httponly' not in flags:
                missing.append('HttpOnly')
            if 'secure' not in flags and url.startswith('https://'):
                missing.append('Secure')
            if 'samesite' not in flags:
                missing.append('SameSite')
            if missing:
                sev = 'medium' if is_auth else 'low'
                findings.append({
                    'url': url, 'cookie': name, 'missing_flags': missing,
                    'type': 'insecure_cookie_flags', 'severity': sev,
                    'evidence': f'Set-Cookie: {raw[:120]}',
                    'recommendation': f'Add flags to {name} cookie: {", ".join(missing)}'
                })
    except:
        pass

for f in findings[:20]:
    print(f'[COOKIE] {f["severity"].upper()} {f["url"]} cookie={f["cookie"]}: '
          f'missing {", ".join(f["missing_flags"])}')
if not findings:
    print('[COOKIE] No missing cookie flags found')

with open(f'{SESSION_DIR}/active-config-cookies.json', 'w') as out:
    json.dump(findings, out, indent=2)
PYEOF
"$SESSION_DIR"
```

### Rate limiting (authentication endpoints)

```bash
python3 - << 'PYEOF'
import subprocess, json, sys

SESSION_DIR = sys.argv[1]
urls = []
try:
    with open(f'{SESSION_DIR}/live-urls.txt') as f:
        urls = [l.strip() for l in f if l.strip()]
except:
    pass

auth_urls = [u for u in urls if any(
    k in u.lower() for k in ('/login', '/auth', '/signin', '/token',
                              '/password', '/reset', '/register', '/signup'))][:5]

findings = []
for url in auth_urls:
    codes = []
    for _ in range(25):
        try:
            r = subprocess.run(
                ['curl', '-s', '-o', '/dev/null', '-w', '%{http_code}',
                 '--max-time', '5', '-X', 'POST', url],
                capture_output=True, text=True, timeout=8
            )
            codes.append(r.stdout.strip())
        except:
            pass
    if codes and not any(c in ('429', '503') for c in codes):
        findings.append({
            'url': url, 'type': 'missing_rate_limit', 'severity': 'medium',
            'evidence': f'25 rapid POST requests — response codes: {list(set(codes))}',
            'recommendation': 'Implement rate limiting (429 Too Many Requests) on authentication endpoints.'
        })
        print(f'[RATELIMIT] MEDIUM {url}: no rate limit (codes: {set(codes)})')
    elif codes:
        print(f'[RATELIMIT] {url}: rate limit present')

if not auth_urls:
    print('[RATELIMIT] No auth endpoints in live-urls.txt to test')

with open(f'{SESSION_DIR}/active-config-ratelimit.json', 'w') as out:
    json.dump(findings, out, indent=2)
PYEOF
"$SESSION_DIR"
```

### GraphQL endpoint discovery

```bash
python3 - << 'PYEOF'
import subprocess, json, sys

SESSION_DIR = sys.argv[1]
GRAPHQL_PATHS = ['/graphql', '/api/graphql', '/v1/graphql', '/query', '/gql',
                 '/graphql/v1', '/api/v1/graphql', '/graphiql', '/playground']
INTROSPECTION = '{"query":"{ __schema { types { name } } }"}'

urls = []
try:
    with open(f'{SESSION_DIR}/live-urls.txt') as f:
        urls = [l.strip() for l in f if l.strip()]
except:
    pass

origins = set()
for u in urls:
    if '://' in u:
        origins.add(u.split('/')[0] + '//' + u.split('/')[2])

findings = []
for origin in list(origins)[:10]:
    for path in GRAPHQL_PATHS:
        url = origin.rstrip('/') + path
        try:
            r = subprocess.run(
                ['curl', '-s', '-X', 'POST', '-H', 'Content-Type: application/json',
                 '-d', INTROSPECTION, '--max-time', '10', url],
                capture_output=True, text=True, timeout=15
            )
            if '"__schema"' in r.stdout or ('"data"' in r.stdout and '__' in r.stdout):
                findings.append({
                    'url': url, 'type': 'graphql_introspection_enabled',
                    'severity': 'medium',
                    'evidence': r.stdout[:300],
                    'recommendation': 'Disable GraphQL introspection in production.'
                })
                print(f'[GRAPHQL] MEDIUM {url}: introspection enabled')
                break
        except:
            pass

if not findings:
    print('[GRAPHQL] No GraphQL endpoints found or introspection disabled')

with open(f'{SESSION_DIR}/active-config-graphql.json', 'w') as out:
    json.dump(findings, out, indent=2)
PYEOF
"$SESSION_DIR"
```

### TLS/SSL configuration

```bash
# nuclei ssl/ templates cover weak protocols and cipher suites
# testssl.sh provides deeper analysis if installed
if command -v testssl.sh &>/dev/null; then
  while IFS= read -r url; do
    domain=$(echo "$url" | sed 's|https://||' | cut -d'/' -f1)
    testssl.sh --severity HIGH --quiet --json \
      --logfile "$SESSION_DIR/testssl-${domain//:/-}.json" \
      "$domain" 2>/dev/null || true
  done < <(grep '^https://' "$SESSION_DIR/live-urls.txt" 2>/dev/null | head -5)
  echo "[TLS] testssl.sh complete"
else
  echo "[TLS] testssl.sh not installed — TLS covered by nuclei ssl/ templates (apt install testssl.sh for deeper analysis)"
fi
```

Collect all active config findings files for inclusion in `findings-vulns.json` at Step 6:

```bash
ACTIVE_CONFIG_FILES=(
  "$SESSION_DIR/active-config-cors.json"
  "$SESSION_DIR/active-config-headers.json"
  "$SESSION_DIR/active-config-cookies.json"
  "$SESSION_DIR/active-config-ratelimit.json"
  "$SESSION_DIR/active-config-graphql.json"
)
echo "[Active Config] Tests complete"
```

```bash
_vuln_update_state "active_config"
```

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

Combine `sensitive_paths[]` from the plan into a nuclei exclusion pattern.
Pass each path as a separate flag to avoid substring collisions (e.g. `/payment`
must not silently exclude `/repayment` or `/api/payments`).

```bash
EXCLUDE_FLAG=""
while IFS= read -r _path; do
  [ -n "$_path" ] && EXCLUDE_FLAG="$EXCLUDE_FLAG -exclude-matchers path:${_path}"
done < <(jq -r '.sensitive_paths[] // empty' "$PLAN_FILE" 2>/dev/null)
```

### Pre-scan: verify live-urls.txt is non-empty

```bash
LIVE_URLS="$SESSION_DIR/live-urls.txt"
if [ ! -s "$LIVE_URLS" ]; then
  echo "[WARN] live-urls.txt is empty — no live hosts to scan. Check that /infosec-recon completed successfully."
  _vuln_update_state "nuclei_scan"
  # Write empty findings-vulns.json so /infosec-report doesn't error
  python3 -c "
import json, datetime
json.dump({'target':'','timestamp':datetime.datetime.utcnow().isoformat(),
           'phase':'vuln-scan','findings':[],'summary':{'total_findings':0,
           'by_severity':{'critical':0,'high':0,'medium':0,'low':0,'info':0},
           'review_recommended_count':0}},
          open('$SESSION_DIR/findings-vulns.json','w'), indent=2)
print('[WARN] Empty findings-vulns.json written — no hosts were scanned.')
"
  exit 0
fi
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
  2>"$SESSION_DIR/nuclei-stderr.log" || true

# Removed -silent: errors and warnings must be visible to the operator
if [ -s "$SESSION_DIR/nuclei-stderr.log" ]; then
  echo "[nuclei] Errors/warnings captured during scan:"
  head -20 "$SESSION_DIR/nuclei-stderr.log"
fi
```

Replace `{TEMPLATE_FLAGS}` with the `-t category/` flags built in Step 2.

If nuclei-output.json is missing or empty after the scan, report it to the operator — do not silently continue with zero findings.

```bash
_vuln_update_state "nuclei_scan"
```

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

4. Cross-reference with recon findings — if /infosec-recon already flagged the same host:port issue, note it in `review_reason`.

## Step 5: Merge active config findings

Before writing the final findings file, load all active config findings and append them to the nuclei findings list.

```bash
python3 - << 'PYEOF'
import json, os, sys, uuid

SESSION_DIR = sys.argv[1]
nuclei_file = os.path.join(SESSION_DIR, 'nuclei-output.json')
config_files = [
    os.path.join(SESSION_DIR, f) for f in [
        'active-config-cors.json', 'active-config-headers.json',
        'active-config-cookies.json', 'active-config-ratelimit.json',
        'active-config-graphql.json'
    ]
]

# Load nuclei findings (NDJSON)
nuclei_findings = []
try:
    with open(nuclei_file) as f:
        for line in f:
            line = line.strip()
            if line:
                nuclei_findings.append(json.loads(line))
except:
    pass

# Load and normalize active config findings
extra_findings = []
for cf in config_files:
    try:
        data = json.load(open(cf))
        items = data if isinstance(data, list) else data.get('findings', [])
        for item in items:
            extra_findings.append({
                'id': str(uuid.uuid4()),
                'type': 'configuration',
                'severity': item.get('severity', 'low'),
                'host': item.get('url', '').split('/')[2] if '://' in item.get('url', '') else '',
                'port': 443,
                'title': item.get('type', 'misconfiguration').replace('_', ' ').title(),
                'evidence': item.get('evidence', '')[:500],
                'cve': None,
                'template_id': item.get('type', ''),
                'recommendation': item.get('recommendation', ''),
                'review_recommended': item.get('type', '') in (
                    'missing_security_header', 'insecure_cookie_flags'),
                'review_reason': 'Informational — may be acceptable by policy' if item.get(
                    'type', '') in ('missing_security_header', 'insecure_cookie_flags') else None,
                'source': 'active_config',
                'url': item.get('url', ''),
            })
    except:
        pass

print(f'[Merge] {len(nuclei_findings)} nuclei findings + {len(extra_findings)} active config findings')

# Write combined file for Step 6
merged = nuclei_findings  # nuclei findings kept in NDJSON format for classifier
with open(os.path.join(SESSION_DIR, 'active-config-merged.json'), 'w') as f:
    json.dump(extra_findings, f, indent=2)

print(f'[Merge] Active config findings written to active-config-merged.json')
PYEOF
"$SESSION_DIR"
```

Read `active-config-merged.json`. Classify each entry through the same review logic as nuclei findings (Step 4) and include them in `findings-vulns.json`.

```bash
_vuln_update_state "merge_findings"
```

## Step 6: Write findings-vulns.json

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

```bash
_vuln_update_state "findings_written"
```

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
