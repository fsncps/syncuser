from __future__ import annotations
import os
from functools import lru_cache

from functools import lru_cache


def _blacklist_file() -> str:
    xdg = os.environ.get("XDG_CONFIG_HOME")
    if not xdg:
        xdg = os.path.join(os.path.expanduser("~"), ".config")
    return os.path.join(xdg, "syncuser", "blacklist")


@lru_cache(maxsize=1)
def read_blacklist() -> list[str]:
    """
    Read ~/.config/syncuser/blacklist (or $XDG_CONFIG_HOME/syncuser/blacklist).
    Lines: paths (recommended absolute, supports $HOME and ~). Blank/# ignored.
    Returned as normalized absolute paths (no trailing slash normalization applied).
    """
    path = _blacklist_file()
    try:
        with open(path, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except FileNotFoundError:
        return []

    out: list[str] = []
    for raw in lines:
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        s = os.path.expandvars(os.path.expanduser(s))
        # If user accidentally writes relative entries, interpret them from $HOME.
        if not os.path.isabs(s):
            s = os.path.join(os.path.expanduser("~"), s)
        out.append(os.path.normpath(s))
    return out


def blacklist_excludes_for_src_dir(src_dir: str) -> list[str]:
    """
    Convert absolute blacklist paths under src_dir into rsync --exclude patterns
    relative to src_dir.

    Example:
      src_dir = /home/u/.bashrc.d
      bl      = /home/u/.bashrc.d/secrets/
      => exclude: "secrets/"  (and "secrets/***")
    """
    src_dir = os.path.normpath(src_dir)
    prefix = src_dir + os.sep
    pats: list[str] = []

    for b in read_blacklist():
        b_norm = os.path.normpath(b)

        # exact match: blacklist the whole src_dir itself (cannot be expressed cleanly
        # as an exclude inside itself); let caller decide higher up.
        if b_norm == src_dir:
            # best-effort: exclude everything inside, resulting in a near-noop transfer
            pats.append("*")
            continue

        if not b_norm.startswith(prefix):
            continue

        rel = os.path.relpath(b_norm, src_dir).replace(os.sep, "/")
        # If user indicated a directory with trailing '/', preserve that intention.
        # (We can't trust normpath for trailing slash, so re-check raw form.)
        is_dir_intended = b.endswith("/") or b.endswith(os.sep)
        if is_dir_intended and not rel.endswith("/"):
            rel += "/"

        pats.append(rel)

        # For directory excludes, also exclude all contents explicitly (rsync usually
        # handles this, but this makes intent unambiguous across patterns).
        if rel.endswith("/"):
            pats.append(rel + "***")
    return pats
