#!/usr/bin/env bash
# tool-check.sh — verify and install InfoSec-Suite dependencies
# Called by setup and by individual skills at start
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Will be updated to --break-system-packages on PEP 668 systems (Kali 2024+ / Debian Bookworm)
PIP_FLAGS=""

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

  export PATH="$PATH:/usr/local/go/bin"

  if ! grep -q '/usr/local/go/bin' /etc/environment 2>/dev/null; then
    echo 'PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/go/bin"' \
      | sudo tee /etc/environment > /dev/null
  fi

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
  export PATH="$PATH:$(go env GOPATH)/bin:/usr/local/go/bin"
  if command -v "$name" &>/dev/null; then
    ok "$name"
    return 0
  fi
  info "Installing $name via go install…"
  go install -v "$pkg" 2>&1 | tail -5
  if ! command -v "$name" &>/dev/null; then
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
  if [ ! -d "$HOME/.local/share/nuclei-templates" ]; then
    info "Downloading nuclei templates (first run)…"
    nuclei -update-templates -silent 2>/dev/null || warn "nuclei -update-templates failed — run manually: nuclei -update-templates"
  else
    ok "nuclei-templates ($(ls "$HOME/.local/share/nuclei-templates" | wc -l | tr -d ' ') dirs)"
  fi
}

check_trufflehog() {
  _go_install trufflehog "github.com/trufflesecurity/trufflehog/v3@latest"
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

check_nmap()        { _apt_install nmap; }
check_jq()          { _apt_install jq; }
check_curl()        { _apt_install curl; }
check_git()         { _apt_install git; }
check_python3()     { _apt_install python3; }
check_python3_pip() { _apt_install pip3 python3-pip; }
check_unzip()       { _apt_install unzip; }

# ---------------------------------------------------------------------------
# pip-installable tools
# ---------------------------------------------------------------------------

_pip_install() {
  local name="$1"
  local pkg="${2:-$1}"
  if command -v "$name" &>/dev/null; then
    ok "$name"
    return 0
  fi
  info "Installing $pkg via pip3…"
  # shellcheck disable=SC2086
  pip3 install --quiet $PIP_FLAGS "$pkg" 2>/dev/null || pip3 install $PIP_FLAGS "$pkg" || { warn "$name install failed via pip3"; return 1; }
  hash -r 2>/dev/null || true
  command -v "$name" &>/dev/null || { warn "$name not on PATH after pip install — try: pip3 install --user $pkg"; return 1; }
  ok "$name"
}

check_wafw00f() {
  _pip_install wafw00f
}

# ---------------------------------------------------------------------------
# Exploit toolchain
# ---------------------------------------------------------------------------

check_ffuf() {
  _go_install ffuf "github.com/ffuf/ffuf/v2@latest"
}

check_katana() {
  _go_install katana "github.com/projectdiscovery/katana/cmd/katana@latest"
}

check_dalfox() {
  _go_install dalfox "github.com/hahwul/dalfox/v2@latest"
}

check_interactsh() {
  _go_install interactsh-client "github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"
}

check_sqlmap() {
  _apt_install sqlmap
}

check_mitmproxy() {
  if command -v mitmdump &>/dev/null; then
    ok "mitmproxy ($(mitmdump --version 2>/dev/null | head -1 | grep -oP '[0-9]+\.[0-9]+\.[0-9]+' || echo 'installed'))"
    return 0
  fi
  info "Installing mitmproxy via pip3…"
  # shellcheck disable=SC2086
  pip3 install --quiet $PIP_FLAGS mitmproxy 2>/dev/null || pip3 install $PIP_FLAGS mitmproxy || { warn "mitmproxy install failed — run: pip3 install $PIP_FLAGS mitmproxy"; return 1; }
  command -v mitmdump &>/dev/null || { warn "mitmproxy installed but mitmdump not on PATH — try: pip3 install --user mitmproxy"; return 1; }
  ok "mitmproxy"
}

check_playwright() {
  if python3 -c "import playwright" 2>/dev/null; then
    ok "playwright (python)"
    # Ensure chromium browser binary is installed
    if ! python3 -c "from playwright.sync_api import sync_playwright; p = sync_playwright().start(); print(p.chromium.executable_path)" 2>/dev/null | grep -q chromium 2>/dev/null; then
      info "Installing Playwright Chromium browser…"
      python3 -m playwright install chromium --with-deps 2>/dev/null || \
        playwright install chromium 2>/dev/null || \
        warn "Playwright Chromium install failed — run: playwright install chromium --with-deps"
    fi
    return 0
  fi
  info "Installing playwright via pip3…"
  # shellcheck disable=SC2086
  pip3 install --quiet $PIP_FLAGS playwright 2>/dev/null || pip3 install $PIP_FLAGS playwright || { warn "playwright install failed — run: pip3 install $PIP_FLAGS playwright"; return 1; }
  info "Installing Playwright Chromium browser (~130 MB)…"
  python3 -m playwright install chromium --with-deps 2>/dev/null || \
    playwright install chromium 2>/dev/null || \
    warn "Chromium install failed — run: playwright install chromium --with-deps"
  ok "playwright"
}

check_seclists() {
  if [ -d /usr/share/seclists ]; then
    ok "SecLists ($(ls /usr/share/seclists | wc -l | tr -d ' ') dirs)"
    return 0
  fi
  info "Installing SecLists via apt-get…"
  sudo apt-get install -y seclists -qq 2>/dev/null || {
    warn "SecLists not available via apt — install manually: sudo apt-get install seclists"
    info "ffuf and LFI fuzzing will use a minimal built-in wordlist as fallback"
    return 0
  }
  ok "SecLists"
}

# ---------------------------------------------------------------------------
# Cloud CLIs — auto-install (required for cloud/combined engagements)
# ---------------------------------------------------------------------------

install_aws_cli() {
  info "Installing AWS CLI v2…"
  local arch
  arch=$(uname -m)
  case "$arch" in
    x86_64)  arch="x86_64" ;;
    aarch64) arch="aarch64" ;;
    *) warn "Unsupported architecture for AWS CLI: $arch"; return 1 ;;
  esac
  curl -fsSL "https://awscli.amazonaws.com/awscli-exe-linux-${arch}.zip" -o "/tmp/awscliv2.zip" || { warn "Failed to download AWS CLI"; return 1; }
  unzip -q /tmp/awscliv2.zip -d /tmp/awscli-install
  sudo /tmp/awscli-install/aws/install --update 2>/dev/null || sudo /tmp/awscli-install/aws/install
  rm -rf /tmp/awscliv2.zip /tmp/awscli-install
}

check_aws() {
  if command -v aws &>/dev/null; then
    ok "aws-cli ($(aws --version 2>&1 | head -1 | cut -d' ' -f1,2))"
    return 0
  fi
  warn "AWS CLI not found — installing…"
  install_aws_cli && ok "aws-cli" || warn "AWS CLI install failed. Install manually: https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html"
}

install_gcloud() {
  info "Installing Google Cloud SDK…"
  # Add Google Cloud apt repo
  curl -fsSL https://packages.cloud.google.com/apt/doc/apt-key.gpg \
    | sudo gpg --dearmor -o /usr/share/keyrings/cloud.google.gpg 2>/dev/null || true
  echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" \
    | sudo tee /etc/apt/sources.list.d/google-cloud-sdk.list > /dev/null
  sudo apt-get update -qq
  sudo apt-get install -y google-cloud-cli -qq || { warn "gcloud install failed via apt"; return 1; }
}

check_gcloud() {
  if command -v gcloud &>/dev/null; then
    ok "gcloud ($(gcloud version 2>/dev/null | head -1))"
    return 0
  fi
  warn "gcloud not found — installing…"
  install_gcloud && ok "gcloud" || warn "gcloud install failed. Install manually: https://cloud.google.com/sdk/docs/install"
}

install_azure_cli() {
  info "Installing Azure CLI…"
  curl -fsSL https://aka.ms/InstallAzureCLIDeb | sudo bash || { warn "Azure CLI install failed"; return 1; }
}

check_azure() {
  if command -v az &>/dev/null; then
    ok "az (azure-cli $(az version 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('azure-cli',''))" 2>/dev/null || echo ''))"
    return 0
  fi
  warn "Azure CLI not found — installing…"
  install_azure_cli && ok "az (azure-cli)" || warn "Azure CLI install failed. Install manually: https://learn.microsoft.com/en-us/cli/azure/install-azure-cli"
}

install_pacu() {
  info "Installing Pacu (AWS exploitation framework)…"
  # Try pip3 first
  pip3 install --quiet pacu 2>/dev/null && command -v pacu &>/dev/null && return 0

  # Git clone fallback
  if [ ! -d /opt/pacu ]; then
    sudo git clone https://github.com/RhinoSecurityLabs/pacu.git /opt/pacu 2>/dev/null || { warn "Pacu git clone failed"; return 1; }
  fi
  pip3 install --quiet -r /opt/pacu/requirements.txt 2>/dev/null || pip3 install -r /opt/pacu/requirements.txt

  # Create wrapper script
  sudo tee /usr/local/bin/pacu > /dev/null << 'PACU_WRAPPER'
#!/usr/bin/env bash
cd /opt/pacu
exec python3 cli.py "$@"
PACU_WRAPPER
  sudo chmod +x /usr/local/bin/pacu
}

check_pacu() {
  if command -v pacu &>/dev/null; then
    ok "pacu"
    return 0
  fi
  warn "Pacu not found — installing…"
  install_pacu && ok "pacu" || warn "Pacu install failed. Install manually: pip3 install pacu"
}

# ---------------------------------------------------------------------------
# PDF report tools — required for lib/report-to-pdf.py
# ---------------------------------------------------------------------------

check_markdown_pkg() {
  if python3 -c "import markdown" 2>/dev/null; then
    ok "python3-markdown"
    return 0
  fi
  info "Installing Markdown Python package via pip3…"
  # shellcheck disable=SC2086
  pip3 install --quiet $PIP_FLAGS Markdown 2>/dev/null || pip3 install $PIP_FLAGS Markdown || { warn "Markdown install failed — run: pip3 install $PIP_FLAGS Markdown"; return 1; }
  python3 -c "import markdown" 2>/dev/null || { warn "Markdown installed but not importable — check Python environment"; return 1; }
  ok "python3-markdown"
}

check_weasyprint() {
  if python3 -c "import weasyprint" 2>/dev/null; then
    ok "weasyprint"
    return 0
  fi
  info "Installing weasyprint via pip3 (HTML → PDF converter)…"
  # weasyprint requires pango/cairo system libs on some distros
  sudo apt-get install -y -qq libpango-1.0-0 libpangocairo-1.0-0 libcairo2 libgdk-pixbuf-2.0-0 \
    libffi-dev shared-mime-info 2>/dev/null || true
  # shellcheck disable=SC2086
  pip3 install --quiet $PIP_FLAGS weasyprint 2>/dev/null || pip3 install $PIP_FLAGS weasyprint || { warn "weasyprint install failed — run: pip3 install $PIP_FLAGS weasyprint"; return 1; }
  python3 -c "import weasyprint" 2>/dev/null || { warn "weasyprint installed but not importable — check Python environment"; return 1; }
  ok "weasyprint"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
  echo ""
  echo "InfoSec-Suite — dependency check"
  echo "================================="

  # Refresh package lists — required on fresh installs before any apt-get install
  info "Refreshing apt package lists…"
  sudo apt-get update -qq 2>/dev/null || warn "apt-get update failed — package installs may fail on stale lists"

  # Core requirements
  check_go
  check_curl
  check_git
  check_jq
  check_unzip
  check_python3
  check_python3_pip

  # Detect PEP 668 (Kali 2024+ / Debian Bookworm — pip3 requires --break-system-packages)
  if pip3 install --dry-run pip 2>&1 | grep -q 'externally-managed-environment'; then
    PIP_FLAGS="--break-system-packages"
    info "Detected externally-managed Python — using --break-system-packages for pip installs"
  fi

  check_nmap

  # ProjectDiscovery toolchain
  check_subfinder
  check_httpx
  check_nuclei

  # OSINT + web recon tools
  check_trufflehog
  check_wafw00f

  # Exploit toolchain
  echo ""
  echo "Exploit tools (required for /exploit)"
  echo "--------------------------------------"
  check_ffuf
  check_katana
  check_dalfox
  check_interactsh
  check_sqlmap
  check_mitmproxy
  check_playwright
  check_seclists

  # Cloud CLIs + exploitation
  echo ""
  echo "Cloud tools (required for cloud/combined engagements)"
  echo "------------------------------------------------------"
  check_aws
  check_gcloud
  check_azure
  check_pacu

  # PDF report tools
  echo ""
  echo "PDF report tools (required for /report PDF output)"
  echo "----------------------------------------------------"
  check_markdown_pkg
  check_weasyprint

  echo ""
  echo "All required tools are ready."
}

main "$@"
