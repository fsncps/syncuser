#!/usr/bin/env bash
set -euo pipefail

# repo-relative sources
SRC_CFG_DIR="./.config/syncuser"
SRC_LIB_DIR="./.local/share/syncuser"
SRC_WRAPPER="./.local/bin/syncuser" # tiny wrapper in repo (execs main in share/)

# destinations in the current user's $HOME
DST_CFG_DIR="${HOME}/.config/syncuser"
DST_LIB_DIR="${HOME}/.local/share/syncuser"
DST_BIN_DIR="${HOME}/.local/bin"

mkdir -p "${DST_CFG_DIR}" "${DST_LIB_DIR}" "${DST_BIN_DIR}"

# 1) copy config lists (ALWAYS overwrite)
for f in appconfig.list bin.list certs.list dotfiles.list; do
   if [[ -f "${SRC_CFG_DIR}/${f}" ]]; then
      install -m 0644 -D "${SRC_CFG_DIR}/${f}" "${DST_CFG_DIR}/${f}"
      echo "[ok]   installed ${DST_CFG_DIR}/${f}"
   else
      echo "[warn] missing in repo: ${SRC_CFG_DIR}/${f}" >&2
   fi
done

# 2) copy runtime scripts (ALWAYS overwrite; use find to avoid empty-glob issues)
while IFS= read -r -d '' sh; do
   install -m 0755 -D "$sh" "${DST_LIB_DIR}/$(basename "$sh")"
   echo "[ok]   installed runtime: ${DST_LIB_DIR}/$(basename "$sh")"
done < <(find "${SRC_LIB_DIR}" -maxdepth 1 -type f -name '*.sh' -print0)

# 3) install wrapper into ~/.local/bin/syncuser (ALWAYS overwrite)
if [[ -f "${SRC_WRAPPER}" ]]; then
   install -m 0755 -D "${SRC_WRAPPER}" "${DST_BIN_DIR}/syncuser"
   echo "[ok]   installed ${DST_BIN_DIR}/syncuser"
else
   # fallback: create wrapper on the fly
   cat >"${DST_BIN_DIR}/syncuser" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
exec "${HOME}/.local/share/syncuser/main_syncuser.sh" "$@"
EOF
   chmod 0755 "${DST_BIN_DIR}/syncuser"
   echo "[ok]   created wrapper ${DST_BIN_DIR}/syncuser"
fi

echo
echo "Add to PATH if needed: export PATH=\"${DST_BIN_DIR}:\$PATH\""
