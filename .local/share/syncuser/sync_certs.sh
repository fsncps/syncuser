#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"

LIST="${1:-}"
[[ -n "$LIST" ]] || die "missing certs list"

if [[ "${SYNCUSER_OVERWRITE:-0}" -eq 1 ]]; then
   RSYNC_OPTS="-azH"
   MODE="overwrite"
else
   RSYNC_OPTS="-azH --ignore-existing"
   MODE="once"
fi

each_line "$LIST" | while IFS= read -r SRC; do
   SRC="$(_expand_home "$SRC")"
   if [[ ! -e "$SRC" ]]; then
      warn "missing source: $SRC"
      continue
   fi
   if ! DEST="$(map_target_path "$SRC")"; then
      warn "not absolute or unmappable (skip): $SRC"
      continue
   fi

   _target_mkdir_p "$(dirname "$DEST")" || {
      warn "mkdir failed (skip): $(dirname "$DEST")"
      continue
   }
   if ! _rsync_into_place "$SRC" "$DEST" "$RSYNC_OPTS"; then
      warn "rsync failed (skip): $SRC -> $DEST"
      continue
   fi

   # tighten perms for files (dirs left alone)
   _on_target "if [ -f '$DEST' ]; then chmod 600 '$DEST'; fi 2>/dev/null" || _on_target_sudo_local "if [ -f '$DEST' ]; then chmod 600 '$DEST'; fi" || true
   info "cert ${MODE}: $DEST"
done
