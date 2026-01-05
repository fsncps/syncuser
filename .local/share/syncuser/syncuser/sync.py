from __future__ import annotations
import re
import shlex
import subprocess
import os
from functools import lru_cache
from typing import Sequence
from .config import General, Module

# rsync --stats parsers (still used for directory summaries)
_RE_XFER = re.compile(r"Number of regular files transferred:\s+(\d+)")
_RE_DEL = re.compile(r"Number of deleted files:\s+(\d+)")


def parse_stats(rsync_output: str) -> tuple[int, int]:
    """Return (files_transferred, files_deleted) from rsync --stats output."""
    m1 = _RE_XFER.search(rsync_output)
    m2 = _RE_DEL.search(rsync_output)
    transferred = int(m1.group(1)) if m1 else 0
    deleted = int(m2.group(1)) if m2 else 0
    return transferred, deleted


def _slash_dir(p: str) -> str:
    # keep "user@host:/abs" intact; just ensure final slash
    return p.rstrip("/") + "/"


def run_capture(
    cmd: Sequence[str], *, echo: bool, echo_cmd: bool
) -> tuple[int, str, str]:
    if echo_cmd:
        print("$", " ".join(shlex.join(c) if " " in c else c for c in cmd))
    p = subprocess.run(cmd, check=False, text=True, capture_output=True)
    if echo and p.stdout:
        print(p.stdout, end="")
    if echo and p.stderr:
        print(p.stderr, end="")
    return p.returncode, p.stdout or "", p.stderr or ""


def parse_itemize(text: str) -> dict[str, int]:
    """
    Parse rsync itemize stream from --out-format='%i %n' (plus legacy '*deleting ' lines).
    Counts:
      - created: codes with '++++' (new on target)
      - updated: codes starting with '>' but not '++++'
      - deleted: explicit '*deleting ' lines (rsync prints these even with out-format)
    """
    created = updated = deleted = 0
    for line in text.splitlines():
        if not line:
            continue
        if line.startswith("*deleting "):
            deleted += 1
            continue
        parts = line.split(maxsplit=1)
        code = parts[0]
        if not code:
            continue
        if code[0] == ">":
            if "++++" in code:
                created += 1
            else:
                updated += 1
    return {"created": created, "updated": updated, "deleted": deleted}


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


def _blacklist_excludes_for_src_dir(src_dir: str) -> list[str]:
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


def build_rsync_cmd(
    g: General,
    m: Module,
    *,
    src_path: str,  # absolute local path
    dst_path: str,  # absolute local OR "user@host:/abs"
    dst_host: str | None,  # None => local; not None => remote
    force_overwrite: bool,
    chown: str | None,  # "user:group" if we want --chown
    rsync_path: str | None = None,  # e.g. "sudo rsync" for remote elevation
    ssh_extra: list[str] | None = None,  # extra ssh -o options (e.g., ControlPath)
) -> list[str]:
    remote = dst_host is not None
    cmd: list[str] = [g.rsync_bin, "-aHAX", "--inplace"]

    cmd += ["--itemize-changes", "--out-format=%i %n"]

    if remote and g.lan_progress:
        cmd += ["--info=progress2"]

    cmd += ["--stats"]
    if g.show_stats:
        cmd += ["--human-readable"]

    if m.mirror and not force_overwrite:
        cmd += ["--delete", "--delete-excluded", "--delete-missing-args"]

    if not force_overwrite:
        if not m.overwrite_all:
            cmd += ["--ignore-existing"]
        if m.overwrite_if_newer_mtime:
            cmd += ["--update"]

    if m.backup:
        cmd += ["--backup"]
        if m.backup_suffix:
            cmd += [f"--suffix={m.backup_suffix}"]

    # Excludes from config
    for pat in g.exclude:
        cmd += ["--exclude", pat]

    # Global blacklist excludes (only meaningful when syncing a directory)
    if os.path.isdir(src_path):
        for pat in _blacklist_excludes_for_src_dir(src_path):
            cmd += ["--exclude", pat]

    if remote:
        cmd += ["--partial"]
        if rsync_path:
            cmd += ["--rsync-path", rsync_path]
        if ssh_extra:
            import shlex as _shlex

            ssh_parts = ["ssh", *ssh_extra]
            cmd += ["-e", " ".join(_shlex.quote(p) for p in ssh_parts)]

    if g.verbose:
        cmd.append("-v")
    if g.dry_run:
        cmd.append("--dry-run")

    if chown:
        cmd += [f"--chown={chown}"]

    if os.path.isdir(src_path):
        src_path = _slash_dir(src_path)
        dst_path = _slash_dir(dst_path)
    cmd += [src_path, dst_path]

    return cmd
