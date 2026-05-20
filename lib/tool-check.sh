#!/usr/bin/env bash
# tool-check.sh — verify and install InfoSec-Suite dependencies
# Called by setup and by individual skills at start
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

ok()   { echo -e "${GREEN}[OK]${NC}    $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC}  $*"; }
fail() { echo -e "${RED}[FAIL]${NC}  $*" >&2; exit 1; }
info() { echo -e "        $*"; }

# ---------------------------------------------------------------------------
# Go — minimum 1.21, install from tarball (NOT apt which gives 1.18)
# ---------------------------------------------------------------------------

GO_MIN_MAJOR=1
GO_MIN_MINOR=21

_go_version_ok() {
  local ver
  ver=$(go version 2>/dev/null | grep -oP 'go\K[0-9]+\.[0-9]+' | head -1) || return 1
  local major minor
  major=$(echo "$ver" | cut -d. -f1)
  minor=$(echo "$ver" | cut -d. -f2)
  [ "$major" -gt "$GO_MIN_MAJOR" ] || { [ "$major" -eq "$GO_MIN_MAJOR" ] && [ "$minor" -ge "$GO_MIN_MINOR" ]; }
}

install_go() {
  info "Downloading Go 1.21 from go.dev …"
  local arch
  arch=$(uname -m)
  case "$arch" in
    x86_64)  arch="amd64" ;;
    aarch64) arch="arm64" ;;
    *) fail "Unsupported architecture: $arch" ;;
  esac

  local tarball="go1.21.13.linux-${arch}.tar.gz"
  local url="https://go.dev/dl/${tarball}"

  curl -fsSL "$url" -o "/tmp/${tarball}" || fail "Failed to download Go from $url"
  sudo rm -rf /usr/local/go
  sudo tar -C /usr/local -xzf "/tmp/${tarball}"
  rm -f "/tmp/${tarball}"

  # Refresh PATH in the current shell so subsequent go install calls work
  export PATH="$PATH:/usr/local/go/bin"

  # Persist for future shells
  if ! grep -q '/usr/local/go/bin' /etc/environment 2>/dev/null; then
    echo 'PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/go/bin"' \
      | sudo tee /etc/environment > /dev/null
  fi

  # Also add to ~/.bashrc and ~/.zshrc if present
  for rc in "$HOME/.bashrc" "$HOME/.zshrc"; do
    if [ -f "$rc" ] && ! grep -q '/usr/local/go/bin' "$rc"; then
      echo 'export PATH="$PATH:/usr/local/go/bin"' >> "$rc"
    fi
  done
}

check_go() {
  if _go_version_ok; then
    ok "Go $(go version | grep -oP 'go\K[0-9]+\.[0-9]+\.[0-9]+')"
    return 0
  fi

  local current
  current=$(go version 2>/dev/null | grep -oP 'go\K[0-9]+\.[0-9]+' || echo "not installed")
  warn "Go ${current} found — need >= ${GO_MIN_MAJOR}.${GO_MIN_MINOR}. Installing from tarball…"
  install_go

  if ! _go_version_ok; then
    echo ""
    echo "  Go installed to /usr/local/go but your current shell PATH hasn't been updated."
    echo "  Run the following, then re-run setup:"
    echo ""
    echo "    export PATH=\$PATH:/usr/local/go/bin"
    echo ""
    fail "Shell restart required before Go tools can be installed."
  fi

  ok "Go $(go version | grep -oP 'go\K[0-9]+\.[0-9]+\.[0-9]+')"
}

# ---------------------------------------------------------------------------
# ProjectDiscovery tools — must be installed via go install, NOT apt
# ---------------------------------------------------------------------------

_go_install() {
  local name="$1"
  local pkg="$2"
  # Ensure Go bin dir is on PATH
  export PATH="$PATH:$(go env GOPATH)/bin:/usr/local/go/bin"
  if command -v "$name" &>/dev/null; then
    ok "$name"
    return 0
  fi
  info "Installing $name via go install…"
  go install -v "$pkg" 2>&1 | tail -5
  if ! command -v "$name" &>/dev/null; then
    # Try adding GOPATH/bin explicitly and retry
    export PATH="$PATH:$(go env GOPATH)/bin"
    hash -r 2>/dev/null || true
  fi
  command -v "$name" &>/dev/null || fail "$name install failed — check go install output above"
  ok "$name"
}

check_subfinder() {
  _go_install subfinder "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
}

check_httpx() {
  _go_install httpx "github.com/projectdiscovery/httpx/cmd/httpx@latest"
}

check_nuclei() {
  _go_install nuclei "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
  # Update templates after install; templates live at ~/.local/share/nuclei-templates/
  if [ ! -d "$HOME/.local/share/nuclei-templates" ]; then
    info "Downloading nuclei templates (first run)…"
    nuclei -update-templates -silent 2>/dev/null || warn "nuclei -update-templates failed — run manually: nuclei -update-templates"
  else
    ok "nuclei-templates ($(ls "$HOME/.local/share/nuclei-templates" | wc -l | tr -d ' ') dirs)"
  fi
}

# ---------------------------------------------------------------------------
# apt-installable tools
# ---------------------------------------------------------------------------

_apt_install() {
  local name="$1"
  local pkg="${2:-$1}"
  if command -v "$name" &>/dev/null; then
    ok "$name"
    return 0
  fi
  info "Installing $pkg via apt-get…"
  sudo apt-get install -y "$pkg" -qq || fail "apt-get install $pkg failed"
  ok "$name"
}

check_nmap()   { _apt_install nmap; }
check_jq()     { _apt_install jq; }
check_curl()   { _apt_install curl; }
check_git()    { _apt_install git; }

# ---------------------------------------------------------------------------
# Optional cloud CLIs — warn only, don't fail
# ---------------------------------------------------------------------------

check_cloud_optional() {
  local missing=()
  command -v aws   &>/dev/null || missing+=("aws-cli")
  command -v gcloud &>/dev/null || missing+=("gcloud")
  command -v az    &>/dev/null || missing+=("az (azure-cli)")

  if [ ${#missing[@]} -gt 0 ]; then
    warn "Cloud CLIs not found: ${missing[*]}"
    info "Install them if you plan to run cloud engagements:"
    info "  AWS:   https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html"
    info "  GCP:   https://cloud.google.com/sdk/docs/install"
    info "  Azure: https://learn.microsoft.com/en-us/cli/azure/install-azure-cli"
  else
    ok "Cloud CLIs (aws, gcloud, az)"
  fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
  echo ""
  echo "InfoSec-Suite — dependency check"
  echo "================================="

  check_go
  check_curl
  check_git
  check_jq
  check_nmap
  check_subfinder
  check_httpx
  check_nuclei
  check_cloud_optional

  echo ""
  echo "All required tools are ready."
}

main "$@"
