#!/usr/bin/env bash
set -euo pipefail

LOCAL_USER="$(id -un)"
LOCAL_HOME="${HOME:-$(getent passwd "$LOCAL_USER" | cut -d: -f6)}"
if [[ -z "$LOCAL_HOME" ]]; then
   # last resort: ask the shell to expand ~ for the current user
   LOCAL_HOME="$(bash -lc 'printf %s ~')"
fi

die() {
   printf '[err] %s\n' "$*" >&2
   exit 1
}
info() { printf '[info] %s\n' "$*"; }
warn() { printf '[warn] %s\n' "$*" >&2; }

# Non-sudo command runner (local or remote)
_on_target() {
   local cmd="$1"
   if [[ -z "${SYNCUSER_TARGET_HOST:-}" ]]; then
      bash -lc "$cmd"
   else
      ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new \
         "${SYNCUSER_TARGET_USER}@${SYNCUSER_TARGET_HOST}" "$cmd"
   fi
}

# Local-only sudo helper (NEVER sudo on remote by default)
_on_target_sudo_local() {
   local cmd="$1"
   if [[ -z "${SYNCUSER_TARGET_HOST:-}" ]]; then
      bash -lc "$cmd" 2>/dev/null || sudo bash -lc "$cmd"
   else
      warn "remote sudo disabled (skipping): $cmd"
      return 1
   fi
}

# Map absolute SRC to DEST:
# - if under caller's $HOME → replace with $SYNCUSER_TARGET_HOME
# - else (absolute like /opt/...) → preserve path on target
map_target_path() {
   local src="$1"
   if [[ "$src" == "$HOME"* ]]; then
      printf '%s' "${SYNCUSER_TARGET_HOME}${src#$HOME}"
   elif [[ "$src" = /* ]]; then
      printf '%s' "$src"
   else
      return 1 # lists must be absolute
   fi
}

# Make dir on target: try as user; if local and denied, sudo; if remote and denied, warn.
_target_mkdir_p() {
   local dir="$1"
   if _on_target "mkdir -p '$dir' 2>/dev/null"; then
      return 0
   fi
   # permission fallback
   if [[ -z "${SYNCUSER_TARGET_HOST:-}" ]]; then
      _on_target_sudo_local "mkdir -p '$dir'"
   else
      warn "permission denied creating '$dir' on remote; not using sudo remotely"
      return 1
   fi
}

# rsync with permission fallback:
# - try direct to dest
# - if LOCAL and denied -> sudo rsync directly to dest (no temp under target home)
# - if REMOTE and denied -> warn/skip (no remote sudo by default)
_rsync_into_place() {
   local src="$1" dest="$2" opts="$3"

   if [[ -z "${SYNCUSER_TARGET_HOST:-}" ]]; then
      # LOCAL
      if rsync $opts "$src" "$dest" 2>/dev/null; then
         return 0
      fi
      # fallback: sudo rsync (handles files/dirs correctly)
      if command -v sudo >/dev/null 2>&1; then
         sudo rsync $opts "$src" "$dest"
         return $?
      else
         warn "rsync to '$dest' failed and sudo not available; skipping"
         return 1
      fi
   else
      # REMOTE
      if rsync -e "ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new" $opts "$src" "${SYNCUSER_TARGET_USER}@${SYNCUSER_TARGET_HOST}:$dest" 2>/dev/null; then
         return 0
      fi
      warn "permission denied writing '$dest' on remote; not using sudo remotely"
      return 1
   fi
}

# chown recursively; only local will try sudo
_chown_target_r() {
   local path="$1" owner="${2:-${SYNCUSER_TARGET_USER}:users}"
   if _on_target "chown -R '$owner' '$path' 2>/dev/null"; then
      return 0
   fi
   _on_target_sudo_local "chown -R '$owner' '$path'" || true
}

# iterate non-comment, non-empty lines
each_line() { grep -vE '^[[:space:]]*(#|$)' "$1" || true; }

# --- add near the top (after die/info/warn) ---
# Local identity (don’t trust $HOME blindly)
# Trim leading/trailing whitespace
_trim_ws() {
   local s="$1"
   s="${s#"${s%%[![:space:]]*}"}" # ltrim
   s="${s%"${s##*[![:space:]]}"}" # rtrim
   printf '%s' "$s"
}

# Expand ~, ~user, $HOME, ${HOME} at the start of a path (no eval)
_expand_home() {
   local p="$(_trim_ws "$1")"
   case "$p" in
   "~/"*)
      printf '%s' "${LOCAL_HOME}${p#\~}"
      return 0
      ;;
   "~"*"/"*)
      # ~user/...
      local u rest
      u="${p#\~}"
      u="${u%%/*}"
      rest="${p#~${u}}"
      # home of that user via passwd
      local uh
      uh="$(getent passwd "$u" | cut -d: -f6)"
      if [[ -n "$uh" ]]; then printf '%s' "${uh}${rest}"; else printf '%s' "$p"; fi
      return 0
      ;;
   "\$HOME/"*)
      printf '%s' "${LOCAL_HOME}${p#\$HOME}"
      return 0
      ;;
   "\${HOME}/"*)
      printf '%s' "${LOCAL_HOME}${p#\${HOME}}"
      return 0
      ;;
   *)
      printf '%s' "$p"
      return 0
      ;;
   esac
}

# Map absolute SRC to DEST:
# - if under *local* home → replace with target’s home
# - else (absolute like /opt/...) → preserve path on target
map_target_path() {
   local src="$1"
   if [[ "$src" == "$LOCAL_HOME"* ]]; then
      printf '%s' "${SYNCUSER_TARGET_HOME}${src#$LOCAL_HOME}"
   elif [[ "$src" = /* ]]; then
      printf '%s' "$src"
   else
      return 1 # lists must be absolute after expansion
   fi
}
