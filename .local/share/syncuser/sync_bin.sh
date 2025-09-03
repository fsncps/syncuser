#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"

LIST="${1:-}"
[[ -n "$LIST" ]] || die "missing bin list"

RSYNC_OPTS="-azH"

each_line "$LIST" | while IFS= read -r SRC; do
   SRC="$(_expand_home "$SRC")"
   if [[ ! -f "$SRC" ]]; then
      warn "not a file: $SRC"
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

   _on_target "chmod 0755 '$DEST' 2>/dev/null" || _on_target_sudo_local "chmod 0755 '$DEST'" || true
   info "bin installed: $DEST"
done
