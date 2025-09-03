#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"

LIST="${1:-}"
[[ -n "$LIST" ]] || die "missing dotfiles list"

if [[ "${SYNCUSER_OVERWRITE:-0}" -eq 1 ]]; then
   # overwrite regardless of mtime (includes dotfiles)
   RSYNC_OPTS="-azH"
   MODE="overwrite"
else
   # update-in-place: copy only when source is newer than target
   RSYNC_OPTS="-azHu"
   MODE="update"
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

   info "dotfile ${MODE}: $DEST"
done
