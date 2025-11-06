from __future__ import annotations
import re
import shlex
import subprocess
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
        # Expect "%i %n" (itemize codes + space + path)
        # Examples: ">f++++ path", ">f.st.. path", ".d..t... dir/"
        parts = line.split(maxsplit=1)
        code = parts[0]
        if not code:
            continue
        if code[0] == ">":
            if "++++" in code:
                created += 1
            else:
                updated += 1
        # we ignore pure '.' entries (no change)
    return {"created": created, "updated": updated, "deleted": deleted}


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
    ssh_extra: list[str] | None = None,  # NEW: extra ssh -o options (e.g., ControlPath)
) -> list[str]:
    remote = dst_host is not None
    cmd: list[str] = [g.rsync_bin, "-aHAX", "--inplace"]

    # Deterministic per-item stream, independent of -v:
    cmd += ["--itemize-changes", "--out-format=%i %n"]

    if remote and g.lan_progress:
        cmd += ["--info=progress2"]

    # Keep --stats for directory totals
    cmd += ["--stats"]
    if g.show_stats:
        cmd += ["--human-readable"]

    # Mirror
    if m.mirror and not force_overwrite:
        cmd += ["--delete", "--delete-excluded", "--delete-missing-args"]

    # Overwrite policy
    if not force_overwrite:
        if not m.overwrite_all:
            cmd += ["--ignore-existing"]
        if m.overwrite_if_newer_mtime:
            cmd += ["--update"]

    # Backups
    if m.backup:
        cmd += ["--backup"]
        if m.backup_suffix:
            cmd += [f"--suffix={m.backup_suffix}"]

    # Excludes
    for pat in g.exclude:
        cmd += ["--exclude", pat]

    if remote:
        cmd += ["--partial"]
        if rsync_path:
            cmd += ["--rsync-path", rsync_path]
        if ssh_extra:
            import shlex

            ssh_parts = ["ssh", *ssh_extra]
            cmd += ["-e", " ".join(shlex.quote(p) for p in ssh_parts)]

    if g.verbose:
        cmd.append("-v")
    if g.dry_run:
        cmd.append("--dry-run")

    if chown:
        cmd += [f"--chown={chown}"]

    cmd += [src_path, dst_path]
    return cmd
