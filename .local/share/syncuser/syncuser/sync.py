from __future__ import annotations
import re
import shlex
import subprocess
import os
from typing import Sequence
from .config import General, Module
from .tools.blacklist import blacklist_excludes_for_src_dir
from .tools.misc import rsync_supports_mkpath


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
    if rsync_supports_mkpath(g.rsync_bin):
        cmd += ["--mkpath"]

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
        for pat in blacklist_excludes_for_src_dir(src_path):
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
