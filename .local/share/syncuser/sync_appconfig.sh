#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"

LIST="${1:-}"
[[ -n "$LIST" ]] || die "missing appconfig list"

# overwrite + delete missing; enforce dest_user:users
RSYNC_OPTS="-azH --delete"

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

   # Attempt chown; remote sudo is disabled, so this will warn if not allowed
   _chown_target_r "$(dirname "$DEST")" "${SYNCUSER_TARGET_USER}:users"

   info "appconfig synced: $DEST"
done
