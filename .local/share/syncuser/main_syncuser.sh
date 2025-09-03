#!/usr/bin/env bash
set -euo pipefail

# Modules live here
RUNTIME_DIR="${HOME}/.local/share/syncuser"
CFG_DIR="${HOME}/.config/syncuser"

APP_LIST="${CFG_DIR}/appconfig.list"
BIN_LIST="${CFG_DIR}/bin.list"
CERT_LIST="${CFG_DIR}/certs.list"
DOTS_LIST="${CFG_DIR}/dotfiles.list"

OVERWRITE=0
MODULES=()
TARGET_USER=""
TARGET_HOST=""

die() {
   printf '[err] %s\n' "$*" >&2
   exit 1
}
info() { printf '[info] %s\n' "$*"; }
warn() { printf '[warn] %s\n' "$*" >&2; }

print_usage() {
   printf '%s\n' \
      "Usage: syncuser dest_user[@dest_host] [options]" \
      "" \
      "Options:" \
      "  -M, --MODULE {appconfig|dotfiles|certs|bin}  (can be repeated)" \
      "  -O, --OVERWRITE                              force overwrite for selected modules" \
      "  -h, --help" \
      "" \
      "Examples:" \
      "  syncuser alice@ace" \
      "  syncuser alice" \
      "  syncuser alice@ace -M bin" \
      "  syncuser alice@ace -M appconfig -O"
}

# Robust local/remote home resolution
resolve_home() {
   local user="$1" host="${2:-}"
   local h=""

   if [[ -z "$host" ]]; then
      # ---- LOCAL ----
      # 1) getent (preferred)
      if command -v getent >/dev/null 2>&1; then
         h="$(getent passwd "$user" | awk -F: '{print $6}')"
      fi
      # 2) tilde expansion (~user) via bash (works even if $HOME is unset)
      if [[ -z "$h" ]]; then
         case "$user" in
         *[!A-Za-z0-9._-]*) h="" ;; # refuse weird usernames for safety
         *) h="$(bash -lc "printf %s ~${user}" 2>/dev/null || true)" ;;
         esac
      fi
      # 3) same-user fallback
      if [[ -z "$h" && "$user" == "$(id -un)" && -n "${HOME:-}" ]]; then
         h="$HOME"
      fi
      printf '%s' "$h"
   else
      # ---- REMOTE ----
      # 1) getent on remote
      h="$(ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new \
         "${user}@${host}" "getent passwd '${user}' | awk -F: '{print \$6}'" 2>/dev/null || true)"
      # 2) tilde expansion on remote
      if [[ -z "$h" ]]; then
         h="$(ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new \
            "${user}@${host}" "bash -lc 'printf %s ~${user}'" 2>/dev/null || true)"
      fi
      printf '%s' "$h"
   fi
}

run_module() {
   local mod="$1" list="$2" script="$3"
   if [[ ! -r "$list" ]]; then
      warn "list not found: $list (skipping $mod)"
      return 0
   fi
   info "== $mod =="
   "${RUNTIME_DIR}/${script}" "$list"
}

# Early help
if [[ $# -eq 0 || "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
   print_usage
   exit 0
fi

# Target parsing
TARGET_SPEC="$1"
shift
if [[ "$TARGET_SPEC" == *"@"* ]]; then
   TARGET_USER="${TARGET_SPEC%@*}"
   TARGET_HOST="${TARGET_SPEC#*@}"
else
   TARGET_USER="$TARGET_SPEC"
   TARGET_HOST=""
fi
[[ -n "$TARGET_USER" ]] || die "dest_user required"

# Options
while [[ $# -gt 0 ]]; do
   case "$1" in
   -M | --MODULE)
      [[ $# -ge 2 ]] || die "missing module after $1"
      MODULES+=("$2")
      shift 2
      ;;
   -O | --OVERWRITE)
      OVERWRITE=1
      shift
      ;;
   -h | --help)
      print_usage
      exit 0
      ;;
   *) die "Unknown arg: $1" ;;
   esac
done

TARGET_HOME="$(resolve_home "$TARGET_USER" "$TARGET_HOST")" || die "cannot resolve home"
[[ -n "$TARGET_HOME" ]] || die "empty TARGET_HOME"

export SYNCUSER_TARGET_USER="$TARGET_USER"
export SYNCUSER_TARGET_HOST="$TARGET_HOST"
export SYNCUSER_TARGET_HOME="$TARGET_HOME"
export SYNCUSER_OVERWRITE="$OVERWRITE"

# Defaults
if [[ ${#MODULES[@]} -eq 0 ]]; then
   MODULES=(appconfig dotfiles certs bin)
fi

for m in "${MODULES[@]}"; do
   case "$m" in
   appconfig) run_module appconfig "$APP_LIST" "sync_appconfig.sh" ;;
   dotfiles) run_module dotfiles "$DOTS_LIST" "sync_dotfiles.sh" ;;
   certs) run_module certs "$CERT_LIST" "sync_certs.sh" ;;
   bin) run_module bin "$BIN_LIST" "sync_bin.sh" ;;
   *) warn "unknown module: $m" ;;
   esac
done

info "all done."
