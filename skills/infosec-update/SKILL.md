---
name: infosec-update
version: 1.0.1
description: |
  Check for InfoSec-Suite updates and apply them. Shows what changed between
  local and remote, re-runs setup if tool installations changed.
triggers:
  - update infosec-suite
  - check for updates
  - upgrade infosec
  - infosec update
---

# /infosec-update

Check for and apply InfoSec-Suite updates.

## Step 1: Force update check

```bash
SUITE_DIR=$(dirname "$(dirname "$(readlink -f "${BASH_SOURCE[0]:-$0}")")" 2>/dev/null || \
            dirname "$(dirname "$(pwd)/skills/infosec-update/SKILL.md")" 2>/dev/null || echo ".")
UPDATE_RESULT=$(bash "$SUITE_DIR/bin/infosec-update-check" --force 2>/dev/null || echo "NO_REMOTE")
echo "UPDATE_RESULT: $UPDATE_RESULT"
VERSION=$(cat "$SUITE_DIR/VERSION" 2>/dev/null | tr -d '[:space:]' || echo "unknown")
echo "LOCAL_VERSION: $VERSION"
```

Parse `UPDATE_RESULT`:

- `UP_TO_DATE <version>` → tell the operator: "InfoSec-Suite v<version> is already up to date." **Stop here.**
- `NO_REMOTE` → tell the operator: "Cannot check for updates — no git remote configured. Pull manually from the InfoSec-Suite repository." **Stop here.**
- `UPGRADE_AVAILABLE <version> <N>` → continue to Step 2.

## Step 2: Show what changed

```bash
cd "$SUITE_DIR"
BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "master")
REMOTE=$(git remote 2>/dev/null | head -1 || echo "origin")

echo "=== Incoming commits ==="
git log HEAD.."$REMOTE/$BRANCH" --oneline --no-color 2>/dev/null | head -30

echo ""
echo "=== Files changed ==="
git diff HEAD.."$REMOTE/$BRANCH" --name-only 2>/dev/null | head -40

echo ""
echo "=== Active session check ==="
cat .active-session 2>/dev/null && echo "" || echo "no active session"
ls session/ 2>/dev/null | head -5 || echo "no sessions"
```

Show the commit list and changed files to the operator.

If `.active-session` exists and the session directory it points to contains `state.json` or `vuln-state.json`, print a one-line warning:
"Active engagement session detected — updating mid-engagement is safe, but do not interrupt a running skill."

## Step 3: Confirm

Ask the operator using AskUserQuestion:

- Question: "InfoSec-Suite has <N> new commit(s). Apply update now?"
- Options:
  - Yes, update now
  - No, skip for now

If **No**: stop. Tell the operator they can run `/infosec-update` at any time to apply updates.

If **Yes**: continue to Step 4.

## Step 4: Pull

```bash
cd "$SUITE_DIR"
git pull --ff-only 2>&1
PULL_EXIT=$?
echo "PULL_EXIT: $PULL_EXIT"
```

If `PULL_EXIT` is non-zero, stop and tell the operator:
"Pull failed — the repo may have local modifications or a non-linear history. Run `git status` in the InfoSec-Suite directory to investigate."

## Step 5: Re-run setup

Check whether `setup` or `lib/tool-check.sh` changed in the pulled commits — if so, new tools may need installing:

```bash
cd "$SUITE_DIR"
SETUP_CHANGED=$(git diff HEAD@{1} HEAD --name-only 2>/dev/null | grep -cE '^(setup|lib/tool-check\.sh)$' || echo 0)
echo "SETUP_CHANGED: $SETUP_CHANGED"
```

**Always** re-run setup (it is idempotent — already-installed tools are skipped quickly):

```bash
bash "$SUITE_DIR/setup"
```

This re-registers skills so any new skills added in the update are immediately available.

## Step 6: Confirm and clear cache

```bash
rm -f "$HOME/.infosec-suite/.last-update-check"
NEW_VERSION=$(cat "$SUITE_DIR/VERSION" 2>/dev/null | tr -d '[:space:]' || echo "unknown")
echo "Updated to: $NEW_VERSION"
```

Tell the operator: "InfoSec-Suite updated to v<NEW_VERSION>. All skills reloaded."

If `SETUP_CHANGED` was non-zero, add: "Tool installations were refreshed — new dependencies have been installed."
