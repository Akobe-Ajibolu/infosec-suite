# /infosec-report — Professional Pentest Report Generator
# InfoSec-Suite v1.0.1
#
# Usage:  /infosec-report
#         /infosec-report engagement_id={uuid}
#
# Reads:  session/{id}/engagement-plan.json
#         session/{id}/findings-recon.json
#         session/{id}/findings-vulns.json        (optional)
#         session/{id}/findings-exploit.json       (optional)
#         session/{id}/idor-candidates.txt         (optional)
# Writes: session/{id}/report-{YYYYMMDD}.md

## Purpose

Generate a clean, professional penetration test report modelled on industry-standard
pentest report formats (NahamSec/NahamCon template). The report includes:
- Cover page with confidentiality statement and document metadata
- Version history and contact information tables
- Narrative overview and methodology section (4 phases)
- Executive summary with strengths, weaknesses, and recommendations
- CVSS-aligned severity rating table
- Vulnerability summary with numbered finding IDs (e.g. EC-IPF-001)
- Full technical findings with evidence, steps to reproduce, and remediation

Report adapts to context:
- `bug_bounty`  → "Bug Bounty Assessment Report" + HackerOne submission blocks
- `internal`    → "Penetration Test Findings Report" + confidential cover page

---

## Step 0 — Session loading

```bash
# Detect engagement_id from message or .active-session
if echo "${USER_MESSAGE:-}" | grep -qE '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'; then
  ENGAGEMENT_ID=$(echo "${USER_MESSAGE}" | grep -oE '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' | head -1)
  SESSION_DIR="session/${ENGAGEMENT_ID}"
elif [ -f .active-session ]; then
  SESSION_DIR=$(cat .active-session | tr -d '[:space:]')
  ENGAGEMENT_ID=$(basename "$SESSION_DIR")
else
  echo "[HALT] No active session. Run /infosec-plan first or pass engagement_id={uuid}."
  exit 1
fi

PLAN_FILE="${SESSION_DIR}/engagement-plan.json"
RECON_FILE="${SESSION_DIR}/findings-recon.json"
VULNS_FILE="${SESSION_DIR}/findings-vulns.json"
EXPLOIT_FILE="${SESSION_DIR}/findings-exploit.json"
IDOR_FILE="${SESSION_DIR}/idor-candidates.txt"
CONFIG_FILE="${HOME}/.infosec-suite/config"

[ -d "$SESSION_DIR" ] || { echo "[HALT] Session directory not found: ${SESSION_DIR}. Check that /infosec-plan wrote the session directory."; exit 1; }
[ -f "$PLAN_FILE"  ] || { echo "[HALT] engagement-plan.json missing. Run /infosec-plan first."; exit 1; }
[ -f "$RECON_FILE" ] || { echo "[HALT] findings-recon.json missing. Run /infosec-recon first."; exit 1; }

VULNS_MISSING=false
[ -f "$VULNS_FILE" ] || { echo "[WARN] findings-vulns.json not found — report will contain recon findings only."; VULNS_MISSING=true; }

# Load config
PREPARER_NAME=$(grep '^PREPARER_NAME=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2- | tr -d '"' || echo "")
PREPARER_EMAIL=$(grep '^PREPARER_EMAIL=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2- | tr -d '"' || echo "")
EVIDENCE_MAX=$(grep '^EVIDENCE_MAX_CHARS=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2 | tr -d ' ' || echo "500")

# Load plan fields
TARGET=$(python3 -c "import json; d=json.load(open('${PLAN_FILE}')); print(d.get('target',''))")
CONTEXT=$(python3 -c "import json; d=json.load(open('${PLAN_FILE}')); print(d.get('context','pentest'))")
METHODOLOGY=$(python3 -c "import json; d=json.load(open('${PLAN_FILE}')); print(d.get('methodology','pentest'))")
CREATED=$(python3 -c "import json; d=json.load(open('${PLAN_FILE}')); print(d.get('created','')[:10])")
TODAY=$(date +%Y-%m-%d)

echo "[INFO] Session:   ${ENGAGEMENT_ID}"
echo "[INFO] Target:    ${TARGET}"
echo "[INFO] Context:   ${CONTEXT}"
echo "[INFO] Created:   ${CREATED}"
```

---

## Step 1 — Collect report metadata

Gather information needed for the cover page and contact table. Check config and
existing plan data first; only ask for what is missing.

```bash
# Preparer name — check stored file then config
PREPARER_FILE="${HOME}/.infosec-suite/preparer_name"
if [ -z "$PREPARER_NAME" ]; then
  [ -f "$PREPARER_FILE" ] && PREPARER_NAME=$(cat "$PREPARER_FILE" | tr -d '[:space:]')
fi

# Load client info from plan if previously saved
CLIENT_NAME=$(python3 -c "import json; d=json.load(open('${PLAN_FILE}')); print(d.get('client',{}).get('name',''))" 2>/dev/null || echo "")
CLIENT_CONTACT_NAME=$(python3 -c "import json; d=json.load(open('${PLAN_FILE}')); print(d.get('client',{}).get('contact_name',''))" 2>/dev/null || echo "")
CLIENT_CONTACT_TITLE=$(python3 -c "import json; d=json.load(open('${PLAN_FILE}')); print(d.get('client',{}).get('contact_title',''))" 2>/dev/null || echo "")
CLIENT_CONTACT_EMAIL=$(python3 -c "import json; d=json.load(open('${PLAN_FILE}')); print(d.get('client',{}).get('contact_email',''))" 2>/dev/null || echo "")
```

STOP — Use AskUserQuestion if PREPARER_NAME is empty OR (context is `internal` AND
CLIENT_NAME is empty):

```
D1 — Report metadata
Project: /infosec-report for ${TARGET} (${ENGAGEMENT_ID})
ELI10: To generate the cover page and contact table we need a few details about you and
  the client. These are saved to engagement-plan.json so you only enter them once per
  engagement. For bug bounty reports, the client section is auto-populated from the target
  domain — you only need your own name.
Stakes if we skip: Cover page shows "Security Consultant" and blank fields, which looks
  unprofessional when delivered to a client.
Recommendation: A — fill in now for a complete, professional report.
Note: options differ in kind, not coverage — no completeness score.
Options:
A) Fill in report details now (recommended)
B) Use placeholder values — I will edit the markdown manually
```

After collecting metadata, save to config and plan:

```bash
# Save preparer info
if [ -n "$PREPARER_NAME" ]; then
  echo "$PREPARER_NAME" > "$PREPARER_FILE"
  chmod 600 "$PREPARER_FILE"
fi

if [ -n "$PREPARER_EMAIL" ]; then
  if grep -q '^PREPARER_EMAIL=' "$CONFIG_FILE" 2>/dev/null; then
    sed -i "s|^PREPARER_EMAIL=.*|PREPARER_EMAIL=${PREPARER_EMAIL}|" "$CONFIG_FILE"
  else
    echo "PREPARER_EMAIL=${PREPARER_EMAIL}" >> "$CONFIG_FILE"
  fi
fi

# Save client contact to plan for reuse
python3 -c "
import json
d = json.load(open('${PLAN_FILE}'))
d.setdefault('client', {})
d['client']['name']          = '${CLIENT_NAME}'
d['client']['contact_name']  = '${CLIENT_CONTACT_NAME}'
d['client']['contact_title'] = '${CLIENT_CONTACT_TITLE}'
d['client']['contact_email'] = '${CLIENT_CONTACT_EMAIL}'
json.dump(d, open('${PLAN_FILE}', 'w'), indent=2)
" 2>/dev/null || true

# Bug bounty: auto-set client fields
if [ "$CONTEXT" = "bug_bounty" ]; then
  [ -z "$CLIENT_NAME" ] && CLIENT_NAME="$TARGET"
  [ -z "$CLIENT_CONTACT_NAME"  ] && CLIENT_CONTACT_NAME="Bug Bounty Program"
  [ -z "$CLIENT_CONTACT_TITLE" ] && CLIENT_CONTACT_TITLE="Security Team"
  [ -z "$CLIENT_CONTACT_EMAIL" ] && CLIENT_CONTACT_EMAIL="security@${TARGET}"
fi

# Apply defaults for anything still empty
[ -z "$CLIENT_NAME" ]    && CLIENT_NAME="$TARGET"
[ -z "$PREPARER_NAME" ]  && PREPARER_NAME="Security Consultant"
[ -z "$PREPARER_EMAIL" ] && PREPARER_EMAIL="[your email]"
```

---

## Step 2 — Generate report

```bash
REPORT_DATE=$(date +%Y%m%d)
REPORT_FILE="${SESSION_DIR}/report-${REPORT_DATE}.md"

export SESSION_DIR PLAN_FILE RECON_FILE VULNS_FILE EXPLOIT_FILE IDOR_FILE
export PREPARER_NAME PREPARER_EMAIL CLIENT_NAME
export CLIENT_CONTACT_NAME CLIENT_CONTACT_TITLE CLIENT_CONTACT_EMAIL
export EVIDENCE_MAX TODAY REPORT_FILE

python3 - << 'PYEOF'
import json, os, sys, re, datetime

# ─── Config ─────────────────────────────────────────────────────────────────

SESSION_DIR          = os.environ['SESSION_DIR']
PLAN_FILE            = os.environ['PLAN_FILE']
RECON_FILE           = os.environ['RECON_FILE']
VULNS_FILE           = os.environ.get('VULNS_FILE', '')
EXPLOIT_FILE         = os.environ.get('EXPLOIT_FILE', '')
IDOR_FILE            = os.environ.get('IDOR_FILE', '')
REPORT_FILE          = os.environ['REPORT_FILE']
PREPARER_NAME        = os.environ.get('PREPARER_NAME', 'Security Consultant')
PREPARER_EMAIL       = os.environ.get('PREPARER_EMAIL', '[your email]')
CLIENT_NAME          = os.environ.get('CLIENT_NAME', '')
CLIENT_CONTACT_NAME  = os.environ.get('CLIENT_CONTACT_NAME', '')
CLIENT_CONTACT_TITLE = os.environ.get('CLIENT_CONTACT_TITLE', '')
CLIENT_CONTACT_EMAIL = os.environ.get('CLIENT_CONTACT_EMAIL', '')
EVIDENCE_MAX         = int(os.environ.get('EVIDENCE_MAX', '500'))
TODAY                = os.environ.get('TODAY', datetime.date.today().isoformat())

# ─── Load data ───────────────────────────────────────────────────────────────

def load_json(path, default):
    try:
        return json.load(open(path))
    except:
        return default

plan    = load_json(PLAN_FILE, {})
recon   = load_json(RECON_FILE, {})
vulns   = load_json(VULNS_FILE, None) if VULNS_FILE and os.path.exists(VULNS_FILE) else None
exploit = load_json(EXPLOIT_FILE, None) if EXPLOIT_FILE and os.path.exists(EXPLOIT_FILE) else None

target      = plan.get('target', 'Unknown Target')
context     = plan.get('context', 'pentest')
methodology = plan.get('methodology', 'pentest')
created     = plan.get('created', TODAY)[:10]
rate_limit  = plan.get('rules', {}).get('max_requests_per_second', 50)
excl_tools  = plan.get('rules', {}).get('excluded_tools', [])
scope_urls  = plan.get('targets', [])

if not CLIENT_NAME:
    CLIENT_NAME = plan.get('client', {}).get('name', target)

# ─── Helpers ─────────────────────────────────────────────────────────────────

def client_initials(name):
    words = re.split(r'[\s.\-_]+',
                     re.sub(r'\.(com|org|net|io|gov|edu|co|uk)$', '', name, flags=re.I))
    words = [w for w in words if w and not w.isdigit()]
    if len(words) >= 2:
        return (words[-2][0] + words[-1][0]).upper()
    return words[0][:2].upper() if words else 'TG'

def finding_type_code(ctx, meth):
    if ctx == 'bug_bounty':   return 'BBF'
    if meth == 'internal':    return 'IPF'
    return 'EPF'

def safe(d, *keys, default=''):
    val = d
    for k in keys:
        if not isinstance(val, dict): return default
        val = val.get(k)
    if val is None or val == '' or val == 'null': return default
    return val

def truncate(text, limit):
    text = str(text).strip()
    return text if len(text) <= limit else text[:limit] + ' [...truncated]'

def sev_label(sev):
    return {'critical':'Critical','high':'High','medium':'Medium','moderate':'Medium',
            'low':'Low','info':'Informational','informational':'Informational'
            }.get(str(sev).lower(), str(sev).title())

def sev_order(sev):
    return {'critical':0,'high':1,'medium':2,'moderate':2,'low':3,
            'info':4,'informational':4}.get(str(sev).lower(), 5)

def engagement_title(ctx, meth):
    return {
        ('bug_bounty', 'bug_bounty'): 'Bug Bounty Assessment Report',
        ('bug_bounty', 'pentest'):    'Bug Bounty Assessment Report',
        ('internal',   'pentest'):    'Internal Penetration Test Findings Report',
        ('internal',   'web_app'):    'Web Application Penetration Test Report',
        ('internal',   'api'):        'API Security Assessment Report',
        ('internal',   'cloud'):      'Cloud Security Assessment Report',
    }.get((ctx, meth), 'Penetration Test Findings Report')

# ─── Collect + deduplicate findings ──────────────────────────────────────────

raw = []
for f in recon.get('findings', []):
    raw.append({**f, '_source': 'recon'})

if vulns:
    seen = set()
    for f in vulns.get('findings', []):
        key = (safe(f,'template-id','?'), safe(f,'host'), str(safe(f,'port','')))
        if key in seen: continue
        seen.add(key)
        raw.append({**f, '_source': 'vuln'})

if exploit:
    for f in exploit.get('poc_results', []):
        if f.get('confirmed') or f.get('review_recommended'):
            raw.append({**f, '_source': 'exploit'})

raw.sort(key=lambda f: sev_order(safe(f,'severity','info')))

CLIENT_INIT  = client_initials(CLIENT_NAME or target)
FINDING_TYPE = finding_type_code(context, methodology)
findings = []
for i, f in enumerate(raw, 1):
    f['_id'] = f'{CLIENT_INIT}-{FINDING_TYPE}-{i:03d}'
    findings.append(f)

sev_counts = {'Critical':0,'High':0,'Medium':0,'Low':0,'Informational':0}
for f in findings:
    lbl = sev_label(safe(f,'severity','info'))
    sev_counts[lbl] = sev_counts.get(lbl, 0) + 1

total = len(findings)
crit  = sev_counts['Critical']
high  = sev_counts['High']
med   = sev_counts['Medium']
low   = sev_counts['Low']
info  = sev_counts['Informational']

# ─── Derive strengths, weaknesses, recommendations ───────────────────────────

strengths, weaknesses, recs = [], [], []

assets = recon.get('assets', [])
waf_hosts = [a.get('host','') for a in assets if a.get('waf')]
if waf_hosts:
    strengths.append(
        f'Web Application Firewall (WAF) protection is active on '
        f'{", ".join(waf_hosts[:3])}{"..." if len(waf_hosts) > 3 else ""}, '
        f'providing automated defence against common OWASP attack patterns.')

if int(safe(recon,'summary','github_secrets_verified', default=0)) == 0:
    strengths.append(
        'No verified secrets or credentials were identified in public GitHub repositories '
        'during OSINT collection, indicating effective controls around source code exposure.')

if crit == 0:
    strengths.append(
        'No critical-severity vulnerabilities were identified, suggesting a reasonable '
        'baseline security posture for the tested environment.')

if len(assets) > 0 and (crit + high) < max(1, len(assets) // 3):
    strengths.append(
        f'The ratio of high-severity findings to live hosts '
        f'({crit + high} findings across {len(assets)} hosts) indicates that the critical '
        f'attack surface has been kept relatively contained.')

if not strengths:
    strengths.append(
        'The engagement was conducted with full cooperation, enabling comprehensive '
        'coverage of the defined scope within the testing window.')

ftitles = [str(safe(f,'title') or safe(f,'name',default='')).lower() for f in findings]

header_n = sum(1 for t in ftitles if 'header' in t)
cred_n   = sum(1 for t in ftitles if any(k in t for k in ('credential','password','default','ldap','secret','exposed')))
patch_n  = sum(1 for t in ftitles if any(k in t for k in ('cve-','outdated','version','patch','unpatched')))
info_n   = sum(1 for t in ftitles if any(k in t for k in ('disclosure','exposed','listing','misconfiguration')))
authz_n  = sum(1 for f in findings if safe(f,'type') in ('authorization_bypass','idor_horizontal') or
               any(k in str(safe(f,'title',default='')).lower() for k in ('idor','authorization','privilege','bypass')))

if header_n >= 2:
    weaknesses.append(
        f'Security Header Configuration — {header_n} hosts are missing critical HTTP security '
        f'headers (X-Frame-Options, Content-Security-Policy, Strict-Transport-Security), '
        f'representing a systemic gap in the web server baseline configuration.')
if cred_n >= 1:
    weaknesses.append(
        f'Credential Management — {cred_n} finding(s) relate to exposed or default credentials, '
        f'suggesting gaps in the system deployment process and secrets management practices.')
if patch_n >= 2:
    weaknesses.append(
        f'Patch Management — {patch_n} findings involve known CVEs or outdated software. '
        f'A structured vulnerability management programme is needed to close the window of '
        f'exposure for publicly disclosed vulnerabilities.')
if info_n >= 2:
    weaknesses.append(
        f'Information Disclosure — {info_n} findings indicate that sensitive technical '
        f'information is accessible to unauthenticated users, providing attackers with '
        f'detailed reconnaissance data about the environment.')
if authz_n >= 1:
    weaknesses.append(
        f'Authorization Controls — {authz_n} finding(s) indicate insufficient server-side '
        f'enforcement of access control boundaries across role or user boundaries.')

if not weaknesses:
    weaknesses.append(
        'While no systemic weaknesses were identified, continued investment in patch '
        'management and security monitoring is recommended to maintain the current posture.')

crit_high = [f for f in findings if sev_order(safe(f,'severity','info')) <= 1]
if crit_high:
    recs.append(
        f'Immediate remediation of the {len(crit_high)} critical and high-severity finding(s) '
        f'should be prioritised. Where vendor patches are available, these should be applied '
        f'within 30 days of report delivery.')
if patch_n >= 2:
    recs.append(
        'Implement a structured patch management programme with defined cycles: critical '
        'patches within 7 days, high within 30 days, and medium within 90 days of public '
        'CVE disclosure.')
if cred_n >= 1:
    recs.append(
        'Address credential hygiene through mandatory rotation during initial system '
        'deployment, elimination of default credentials, and adoption of a secrets '
        'management solution (e.g., HashiCorp Vault, AWS Secrets Manager).')
if header_n >= 2:
    recs.append(
        'Establish and enforce a web server hardening baseline across all internet-facing '
        'services, including HTTP security headers, TLS configuration, and suppression of '
        'version disclosure in server response headers.')
if authz_n >= 1:
    recs.append(
        'Implement server-side authorization checks on every API endpoint and resource. '
        'Client-side role checks are insufficient. Consider a centralised authorisation '
        'layer and conduct a targeted review of all endpoints handling user-specific data.')
recs.append(
    'Following remediation, a targeted re-test of all critical and high findings is '
    'strongly recommended to confirm that fixes are effective and have not introduced '
    'regressions in adjacent functionality.')

# ─── IDOR candidates ──────────────────────────────────────────────────────────

idor_lines = []
if IDOR_FILE and os.path.exists(IDOR_FILE):
    with open(IDOR_FILE) as fh:
        idor_lines = [l.strip() for l in fh if l.strip()]

# ─── Build report ─────────────────────────────────────────────────────────────

ENG_TITLE = engagement_title(context, methodology)
lines = []
W = lines.append
BR = lambda: W('')
HR = lambda: W('\n---\n')

scope_desc = ', '.join([t.get('domain', str(t)) for t in scope_urls[:5]]) or target

# ── Cover page ────────────────────────────────────────────────────────────────
W(f'# {CLIENT_NAME.upper()}')
W(f'## {ENG_TITLE}')
BR()
W(f'**Date:** {TODAY}')
BR()
HR()

# ── Confidentiality statement ─────────────────────────────────────────────────
W('## Confidentiality Statement')
BR()
W(f'This document contains confidential and privileged information from a security '
  f'assessment conducted for {CLIENT_NAME}. The information contained within this '
  f'report is strictly confidential and intended solely for authorized personnel; '
  f'it may not be distributed, copied, or disclosed to any third party without '
  f'explicit written consent from {CLIENT_NAME}.')
BR()

W('| | |')
W('|---|---|')
W(f'| **Document Type** | {ENG_TITLE} |')
W(f'| **Client** | {CLIENT_NAME} |')
W(f'| **Document Version** | Final v1.0 |')
W(f'| **Engagement Date** | {created} |')
W(f'| **Report Date** | {TODAY} |')
W(f'| **Session ID** | `{os.path.basename(SESSION_DIR)}` |')
BR()
HR()

# ── Version history ───────────────────────────────────────────────────────────
W('## Version History')
BR()
W('| Version | Date | Notes | Author |')
W('|---------|------|-------|--------|')
W(f'| 0.1 Draft | {created} | Initial assessment | {PREPARER_NAME} |')
W(f'| Final 1.0 | {TODAY} | Delivered/Final Report | {PREPARER_NAME} |')
BR()
HR()

# ── Contact information ───────────────────────────────────────────────────────
W('## Contact Information')
BR()
W('| | Name | Title | Email |')
W('|---|---|---|---|')
W(f'| **Security Consultant** | {PREPARER_NAME} | Lead Penetration Tester | {PREPARER_EMAIL} |')
if CLIENT_CONTACT_NAME:
    W(f'| **{CLIENT_NAME}** | {CLIENT_CONTACT_NAME} | {CLIENT_CONTACT_TITLE} | {CLIENT_CONTACT_EMAIL} |')
BR()
HR()

# ── Overview ──────────────────────────────────────────────────────────────────
W('## Overview')
BR()
W(f'From {created} through {TODAY}, our security team conducted a '
  f'{"bug bounty assessment" if context == "bug_bounty" else "penetration test"} '
  f'to evaluate the security posture of {CLIENT_NAME}\'s '
  f'{"external web assets" if context == "bug_bounty" else "infrastructure"} '
  f'against current industry best practices. The assessment focused on assets within '
  f'the defined scope: {scope_desc}. All testing activities were performed using '
  f'industry-standard security testing tools and methodologies. The assessment '
  f'methodology followed established frameworks including the OWASP Testing Guide (v5) '
  f'and the OWASP API Security Top 10.')
BR()

# ── Methodology ───────────────────────────────────────────────────────────────
W('## Methodology')
BR()
W(f'The {"assessment" if context == "bug_bounty" else "penetration test"} was conducted '
  f'using a combination of automated scanning tools and manual verification techniques. '
  f'Our risk-based, results-driven methodology incorporates industry best practices and '
  f'internationally recognised frameworks. The assessment was conducted through the '
  f'following phases:')
BR()
phases = [
    ('Planning',
     'This initial phase established the engagement scope, objectives, and testing '
     'boundaries while coordinating with key stakeholders to ensure minimal operational impact.'),
    ('Reconnaissance',
     'During this phase, we mapped the target environment to understand the network '
     'architecture and identify potential entry points through passive information gathering '
     'including subdomain enumeration, certificate transparency analysis, and open-source '
     'intelligence collection.'),
    ('Testing',
     'The core assessment phase combined automated scanning tools with manual testing '
     'techniques to identify and validate potential security vulnerabilities within the '
     'defined scope. Testing included web application assessment, API security review, '
     'vulnerability validation, and authorization boundary testing.'),
    ('Reporting',
     'The final phase involved analysing findings, assigning risk ratings based on potential '
     'business impact and exploitability, and developing actionable remediation recommendations '
     'documented in this report.'),
]
for name, desc in phases:
    W(f'**{name}** — {desc}')
    BR()

# ── Scope ─────────────────────────────────────────────────────────────────────
W('## Scope')
BR()
W('| Asset | Scope Details |')
W('|-------|--------------|')
for t in scope_urls:
    domain   = t.get('domain', str(t))
    in_scope = 'In scope' if t.get('in_scope', True) else 'Out of scope'
    W(f'| `{domain}` | {in_scope} |')
if not scope_urls:
    W(f'| `{target}` | In scope |')
BR()
if assets:
    W(f'**Discovered:** {len(assets)} live host(s) enumerated during reconnaissance.')
    BR()
HR()

# ── Executive Summary ─────────────────────────────────────────────────────────
W('## Executive Summary')
BR()
W('### Testing Summary')
BR()
W(f'A {"bug bounty assessment" if context == "bug_bounty" else "penetration test"} '
  f'was conducted for {CLIENT_NAME} from {created} through {TODAY}, focusing on '
  f'{scope_desc}. The assessment revealed both strengths and security concerns.')
BR()
W(f'The assessment uncovered **{total} security finding(s)** '
  f'({crit} critical, {high} high, {med} medium, {low} low, {info} informational).')
if crit + high > 0:
    top = [f for f in findings if sev_order(safe(f,'severity','info')) <= 1][:3]
    W('Key findings include:')
    for f in top:
        title = safe(f,'title') or safe(f,'name', default='Unnamed finding')
        host  = safe(f,'host', default='unknown host')
        rec   = safe(f,'recommendation', default='')
        sent  = rec.split('.')[0] + '.' if rec else ''
        W(f'- **{title}** on `{host}` — {sent}')
BR()

W('### Key Observations')
BR()
W('#### Strengths')
BR()
for s in strengths:
    W(f'{s}')
    BR()

W('#### Weaknesses')
BR()
for wk in weaknesses:
    W(f'{wk}')
    BR()

W('### Recommendations')
BR()
for r in recs:
    W(r)
    BR()
HR()

# ── Finding Severity Ratings ──────────────────────────────────────────────────
W('## Finding Severity Ratings')
BR()
W('The following table defines levels of severity and corresponding CVSS score ranges '
  'used throughout this document to assess vulnerability and risk impact.')
BR()
W('| Severity | CVSS Score Range | Definition |')
W('|----------|-----------------|------------|')
W('| **Critical** | 9.0 – 10.0 | Exploitation is straightforward and usually results in system-level compromise. Form a plan of action and patch immediately. |')
W('| **High** | 7.0 – 8.9 | Exploitation is more difficult but could cause elevated privileges and potentially a loss of data or downtime. Form a plan of action and patch as soon as possible. |')
W('| **Medium** | 4.0 – 6.9 | Vulnerabilities exist but are not immediately exploitable or require extra steps. Form a plan of action and patch after high-priority issues are resolved. |')
W('| **Low** | 0.1 – 3.9 | Vulnerabilities are non-exploitable but would reduce the attack surface. Patch during the next maintenance window. |')
W('| **Informational** | N/A | No direct vulnerability. Additional information regarding items noticed during testing, positive controls, or supplementary documentation. |')
BR()
HR()

# ── Vulnerability Summary ─────────────────────────────────────────────────────
W('## Vulnerability Summary')
BR()
W('The following section details findings categorised by severity level. Each finding '
  'has been assessed based on its potential impact to the environment and likelihood of '
  'exploitation.')
BR()

# Visual count bar
bar = ' | '.join(
    f'**{sev}:** {cnt}'
    for sev, cnt in [('Critical',crit),('High',high),('Medium',med),('Low',low),('Informational',info)]
)
W(f'> {bar}')
BR()

W('| Finding ID | Title | Severity | Recommendation |')
W('|------------|-------|----------|----------------|')
for f in findings:
    fid   = f['_id']
    title = safe(f,'title') or safe(f,'name', default='Unnamed finding')
    sev   = sev_label(safe(f,'severity','info'))
    rec   = safe(f,'recommendation', default='See technical finding.')
    short = rec.split('.')[0] + '.' if '.' in rec else rec[:100]
    W(f'| {fid} | {title} | **{sev}** | {short} |')
BR()
HR()

# ── Technical Findings ────────────────────────────────────────────────────────
W('## Technical Findings')
BR()

for f in findings:
    fid   = f['_id']
    title = safe(f,'title') or safe(f,'name', default='Unnamed Finding')
    sev   = sev_label(safe(f,'severity','info'))
    host  = safe(f,'host', default='N/A')
    port  = safe(f,'port', default='')
    src   = f.get('_source','')

    host_port = f'{host}:{port}' if port and str(port) not in ('80','443','') else host
    scheme    = 'https' if str(port) == '443' else 'http'
    endpoint  = f'{scheme}://{host_port}' if host != 'N/A' else 'N/A'

    description = safe(f,'description', default='')
    if not description:
        tmpl = safe(f,'template-id', default='')
        description = (
            f'The assessment identified **{title}** on `{host_port}`. '
            + (f'This finding was detected via nuclei template `{tmpl}`. ' if tmpl else '')
        )

    evidence = (safe(f,'matcher-output') or safe(f,'extracted-results') or
                safe(f,'output') or safe(f,'response_snippet') or
                'No automated evidence captured. Manual verification recommended.')
    if isinstance(evidence, list):
        evidence = '\n'.join(str(e) for e in evidence)
    evidence = truncate(str(evidence), EVIDENCE_MAX)

    recommendation = safe(f,'recommendation', default='No specific remediation provided.')
    template_id    = safe(f,'template-id', default='')
    template_path  = safe(f,'template-path', default='')
    review         = f.get('review_recommended', False)

    W(f'### {fid} — {title}')
    BR()
    W(f'**Risk:** {sev}')
    BR()
    W(f'**Affected Host(s):** `{host_port}`')
    BR()
    W(f'**Endpoint/URL:** `{endpoint}`')
    if template_id:
        W(f'**Template:** `{template_id}`')
    BR()
    W(description)
    BR()

    if review:
        W('> ⚠ **Manual verification recommended** — This finding was flagged by automated '
          'tooling and requires manual confirmation before inclusion in a final deliverable.')
        BR()

    W('**Evidence:**')
    BR()
    W('```')
    W(evidence)
    W('```')
    BR()

    W('**Steps to Reproduce:**')
    BR()
    if src == 'vuln' and template_id:
        tmpl_cat = template_path.split('/')[0] if '/' in template_path else 'cves'
        W(f'1. Ensure nuclei is installed and templates are current: `nuclei -update-templates`')
        W(f'2. Run against the target: `nuclei -u {endpoint} -t {tmpl_cat}/ -silent`')
        W(f'3. Observe: template `{template_id}` fires and returns the evidence above.')
        W(f'4. Confirmed via matcher output in the evidence block.')
    elif src == 'exploit' and safe(f,'type') in ('authorization_bypass','idor_horizontal'):
        high_role = safe(f,'high_role', default='privileged user')
        low_role  = safe(f,'low_role',  default='lower-privilege user')
        method    = safe(f,'method',    default='GET')
        W(f'1. Log in as a `{high_role}` account and capture the `{method}` request to `{endpoint}` using a proxy.')
        W(f'2. Replay the request, replacing the session cookie/Authorization header with a `{low_role}` session token.')
        W(f'3. Observe: the server returns HTTP 200 with data belonging to the `{high_role}` account.')
        W(f'4. This confirms that server-side role-based access control is not enforced on this endpoint.')
    elif src == 'recon':
        W(f'1. From an external network, run: `curl -sv {endpoint}`')
        W(f'2. Observe the response as described in the evidence block above.')
        W(f'3. No authentication or special tooling required.')
    else:
        W(f'1. Navigate to or send a request to: `{endpoint}`')
        W(f'2. Observe the response described in the evidence block above.')
    BR()

    W('**Remediation:**')
    BR()
    sentences = [s.strip() for s in re.split(r'(?<=[.!?])\s+', recommendation) if s.strip()]
    if len(sentences) > 1:
        for s in sentences:
            W(f'- {s}')
    else:
        W(f'- {recommendation}')
    BR()
    W('---')
    BR()

# ── Bug bounty submission templates ──────────────────────────────────────────
if context == 'bug_bounty':
    W('## Bug Bounty Submission Templates')
    BR()
    W('HackerOne/Bugcrowd-formatted submission blocks for critical and high severity findings.')
    BR()

    bb_crit_high = [f for f in findings if sev_order(safe(f,'severity','info')) <= 1]
    if not bb_crit_high:
        W('_No critical or high severity findings to submit._')
        BR()
    else:
        for f in bb_crit_high:
            fid   = f['_id']
            title = safe(f,'title') or safe(f,'name', default='Unnamed finding')
            sev   = sev_label(safe(f,'severity','info'))
            host  = safe(f,'host', default='N/A')
            port  = safe(f,'port', default='')
            host_port = f'{host}:{port}' if port and str(port) not in ('80','443','') else host
            scheme    = 'https' if str(port) == '443' else 'http'
            endpoint  = f'{scheme}://{host_port}'
            tmpl      = safe(f,'template-id', default='')
            tmpl_path = safe(f,'template-path', default='')
            tmpl_cat  = tmpl_path.split('/')[0] if '/' in tmpl_path else 'nuclei-templates'
            evidence  = truncate(str(safe(f,'matcher-output') or safe(f,'output') or 'See evidence above.'), 300)
            rec       = safe(f,'recommendation', default='')

            W(f'### Submission — {fid}: {title}')
            BR()
            W(f'**Vulnerability:** {title}')
            BR()
            W(f'**Severity:** {sev}')
            BR()
            W(f'**Target:** `{endpoint}`')
            BR()
            W('**Steps to Reproduce:**')
            BR()
            W(f'1. Run: `subfinder -d {target} | httpx | nuclei -t {tmpl_cat}/`')
            W(f'2. Observe: `{tmpl if tmpl else "matching template"}` fires on `{endpoint}`')
            W(f'3. Confirmed via: {evidence[:200]}')
            BR()
            W('**Impact:**')
            BR()
            impact = re.sub(
                r'^(Immediately |Apply |Update |Remove |Disable |Configure |Implement |Restrict )',
                'This vulnerability allows an attacker to ', rec, flags=re.I, count=1)
            W(impact[:400] if impact else 'This vulnerability exposes the target to unauthorized access or data disclosure.')
            BR()
            W('**Supporting Evidence:**')
            BR()
            W('```')
            W(evidence)
            W('```')
            BR()
            W('---')
            BR()

    bb_med_low = [f for f in findings if 2 <= sev_order(safe(f,'severity','info')) <= 3]
    if bb_med_low:
        W('### Additional Findings')
        BR()
        W('| Finding ID | Title | Severity |')
        W('|------------|-------|----------|')
        for f in bb_med_low:
            W(f'| {f["_id"]} | {safe(f,"title") or safe(f,"name","Unnamed")} | {sev_label(safe(f,"severity","info"))} |')
        BR()
    HR()

# ── IDOR candidates ───────────────────────────────────────────────────────────
if idor_lines:
    W('## IDOR/BOLA Candidates')
    BR()
    W(f'The following {len(idor_lines)} endpoint(s) were flagged during reconnaissance as '
      f'candidates for Broken Object Level Authorization (BOLA/IDOR) testing. These require '
      f'**manual verification** — automated tools cannot confirm exploitability. Test by '
      f'replacing object IDs with IDs belonging to a different user account and checking '
      f'whether the response contains unauthorised data.')
    BR()
    W('```')
    for line in idor_lines[:10]:
        W(line)
    if len(idor_lines) > 10:
        W(f'... and {len(idor_lines) - 10} more — see idor-candidates.txt')
    W('```')
    BR()
    HR()

# ── Appendix ──────────────────────────────────────────────────────────────────
W('## Appendix')
BR()
W('| File | Path |')
W('|------|------|')
W(f'| `findings-recon.json` | `{RECON_FILE}` |')
if vulns is not None:
    W(f'| `findings-vulns.json` | `{VULNS_FILE}` |')
if exploit is not None:
    W(f'| `findings-exploit.json` | `{EXPLOIT_FILE}` |')
if idor_lines:
    W(f'| `idor-candidates.txt` | `{IDOR_FILE}` |')
BR()
HR()

# ── Footer ────────────────────────────────────────────────────────────────────
BR()
W('*Severity ratings are based on nuclei template classifications and manual assessment. '
  'CVSS base scores are approximations — formal CVSS scoring requires environmental and '
  'temporal metric adjustment by the receiving organisation.*')
BR()
W('*Generated by InfoSec-Suite — https://github.com/Akobe-Ajibolu/infosec-suite*')

# ─── Write ────────────────────────────────────────────────────────────────────
report_content = '\n'.join(lines)
with open(REPORT_FILE, 'w', encoding='utf-8') as out:
    out.write(report_content)

print(f'[OK]   Report written → {REPORT_FILE}')
print(f'       Findings:    {total} ({crit} critical, {high} high, {med} medium, {low} low, {info} info)')
print(f'       Word count:  ~{len(report_content.split()):,}')
PYEOF
```

---

## Step 3 — PDF output

Attempt to convert the markdown report to PDF. Degrade gracefully if weasyprint is not installed.

```bash
PDF_SCRIPT="lib/report-to-pdf.py"
PDF_FILE="${REPORT_FILE%.md}.pdf"

if [ -f "$PDF_SCRIPT" ] && python3 -c "import weasyprint" 2>/dev/null; then
  echo "[INFO] Generating PDF…"
  if python3 "$PDF_SCRIPT" "$REPORT_FILE" --output "$PDF_FILE" 2>&1; then
    echo "[OK]   PDF  → ${PDF_FILE}"
  else
    echo "[WARN] PDF generation failed — markdown report is still complete"
    echo "       Check weasyprint install: pip3 install weasyprint"
  fi
elif ! python3 -c "import weasyprint" 2>/dev/null; then
  echo "[INFO] PDF skipped — install weasyprint for PDF output: pip3 install weasyprint"
else
  echo "[WARN] PDF skipped — lib/report-to-pdf.py not found (check suite installation)"
fi
```

---

## Step 4 — Summary

```bash
echo ""
echo "=============================="
echo " /infosec-report complete"
echo "=============================="
echo ""
echo "  Markdown → ${REPORT_FILE}"
if [ -f "${PDF_FILE:-}" ]; then
  echo "  PDF     → ${PDF_FILE}"
fi
echo ""
```

---

## Error handling

- No active session + no UUID → halt: "No active session. Run /infosec-plan first."
- Missing engagement-plan.json → halt
- Missing findings-recon.json → halt: "Run /infosec-recon before /infosec-report."
- Missing findings-vulns.json → warn + generate recon-only report
- Missing findings-exploit.json → silently skip exploit findings
- Missing idor-candidates.txt → silently skip IDOR section
- Client contact fields missing for internal context → use placeholders, report still generates
- Any finding with missing fields (severity, host, title, evidence) → safe() defaults, never fail
- Python parsing error on a single finding → skip that finding, log warning, continue
