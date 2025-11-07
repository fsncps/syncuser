#!/usr/bin/env bash
set -Eeuo pipefail

APP_NAME="syncuser"
CONF_SUBDIR=".config/${APP_NAME}"
SHARE_BASE="${HOME}/.local/share/${APP_NAME}" # <-- top-level (logs, venv, etc)
PKG_DST="${SHARE_BASE}/${APP_NAME}"           # <-- .../syncuser/syncuser (python package root)
BIN_DST="${HOME}/.local/bin"
WRAPPER="${BIN_DST}/${APP_NAME}"
REQ_FILE="requirements.txt"

# Flags
RECREATE_VENV=0
QUIET=0
UNINSTALL=0

while (($#)); do
   case "$1" in
   --recreate-venv) RECREATE_VENV=1 ;;
   --quiet | -q) QUIET=1 ;;
   --uninstall) UNINSTALL=1 ;;
   *)
      echo "Unknown arg: $1" >&2
      exit 2
      ;;
   esac
   shift
done

ts() { date '+%Y-%m-%d %H:%M:%S'; }
log() { ((QUIET)) || printf '%s %s\n' "$(ts)" "$*"; }
ok() { log "[ok]   $*"; }
info() { log "[info] $*"; }
err() { printf '%s [err]  %s\n' "$(ts)" "$*" >&2; }

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
REPO_ROOT="${SCRIPT_DIR}"

CONF_SRC="${REPO_ROOT}/.config/${APP_NAME}"
PKG_SRC="${REPO_ROOT}/.local/share/${APP_NAME}/${APP_NAME}" # your repo has the package here

die() {
   err "$*"
   exit 1
}

# ----- uninstall -----
if ((UNINSTALL)); then
   info "Uninstalling ${APP_NAME} from user dirs"
   rm -f "${WRAPPER}" || true
   rm -rf "${SHARE_BASE}" || true
   ok "Removed wrapper and share dir"
   exit 0
fi

# ----- checks -----
command -v python3 >/dev/null 2>&1 || die "python3 not found"
python3 -c "import venv" 2>/dev/null || die "python venv module not available (install python3-venv)"

# ----- create dirs -----
mkdir -p "${HOME}/${CONF_SUBDIR}" "${SHARE_BASE}" "${BIN_DST}"

# ----- copy config (lists + toml) -----
if [ -d "${CONF_SRC}" ]; then
   cp -a "${CONF_SRC}/." "${HOME}/${CONF_SUBDIR}/"
   ok "installed config → ${HOME}/${CONF_SUBDIR}"
else
   info "no ${CONF_SRC} found; skipping config copy"
fi

# ----- copy python package to ~/.local/share/syncuser/syncuser -----
if [ ! -d "${PKG_SRC}" ]; then
   die "Missing package source: ${PKG_SRC}"
fi

# Clean destination package dir but keep siblings (like .venv, logs)
rm -rf "${PKG_DST}"
mkdir -p "${PKG_DST}"
# copy package tree
if command -v rsync >/dev/null 2>&1; then
   rsync -a --delete --exclude='__pycache__' --exclude='*.pyc' "${PKG_SRC}/" "${PKG_DST}/"
else
   cp -a "${PKG_SRC}/." "${PKG_DST}/"
   # best-effort cleanup
   find "${PKG_DST}" -type d -name __pycache__ -prune -exec rm -rf {} + 2>/dev/null || true
   find "${PKG_DST}" -type f -name '*.pyc' -delete 2>/dev/null || true
fi
ok "installed runtime → ${PKG_DST}"

# ----- venv -----
VENV_DIR="${SHARE_BASE}/.venv"
if ((RECREATE_VENV)) && [ -d "${VENV_DIR}" ]; then
   info "Recreating venv (${VENV_DIR})"
   rm -rf "${VENV_DIR}"
fi

if [ ! -x "${VENV_DIR}/bin/python3" ]; then
   info "Creating venv at ${VENV_DIR}"
   python3 -m venv "${VENV_DIR}"
fi

# ----- ensure venv can import the share base without PYTHONPATH -----
# Write a sitecustomize .pth pointing to ~/.local/share/syncuser
SITE_PACKAGES="$(
   "${VENV_DIR}/bin/python3" - <<'PY'
import sys, sysconfig, os
print(sysconfig.get_paths()['purelib'])
PY
)"
mkdir -p "${SITE_PACKAGES}"
echo "${SHARE_BASE}" >"${SITE_PACKAGES}/syncuser_base.pth"
ok "site-packages path added → ${SITE_PACKAGES}/syncuser_base.pth"

# Upgrade pip, install deps
"${VENV_DIR}/bin/python3" -m pip install --upgrade pip wheel >/dev/null
if [ -f "${REPO_ROOT}/${REQ_FILE}" ]; then
   info "Installing requirements.txt into venv"
   "${VENV_DIR}/bin/python3" -m pip install -r "${REPO_ROOT}/${REQ_FILE}"
   ok "dependencies installed"
else
   info "No ${REQ_FILE}; skipping dependency install"
fi

# ----- wrapper (~/.local/bin/syncuser) -----
cat >"${WRAPPER}" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

APP_NAME="syncuser"
BASE="${HOME}/.local/share/${APP_NAME}"
VENV="${BASE}/.venv"
PY="${VENV}/bin/python3"

# Ensure venv exists
if [ ! -x "${PY}" ]; then
  echo "[err] ${PY} missing; run install.sh first" >&2
  exit 1
fi

# Make python see the local share base so "python -m syncuser" resolves the package
if [ -z "${PYTHONPATH:-}" ]; then
  export PYTHONPATH="${BASE}"
else
  export PYTHONPATH="${BASE}:${PYTHONPATH}"
fi

# Optional default log location (your app can read SYNCUSER_LOG if desired)
# export SYNCUSER_LOG="${BASE}/syncuser.log"

exec "${PY}" -m syncuser "$@"
EOF
chmod +x "${WRAPPER}"
ok "installed wrapper → ${WRAPPER}"

# ----- friendly footer -----
echo
ok "Install complete."
info "Run: syncuser --help"
info "Recreate venv later with: ./install.sh --recreate-venv"
info "Uninstall with: ./install.sh --uninstall"
