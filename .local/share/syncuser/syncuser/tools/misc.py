# syncuser/tools/misc.py
from __future__ import annotations
import os, re, subprocess
from pathlib import Path
from shutil import which

from functools import lru_cache

# ---- deps ----
import re
from dataclasses import dataclass

USER_AT_HOST_RE = re.compile(r"^(?P<user>[^@:\s]+)(?:@(?P<host>[^:\s]+))?$")


@dataclass(frozen=True)
class Target:
    user: str
    host: str | None  # None => localhost


# rsync --stats parsers (still used for directory summaries)
_RE_XFER = re.compile(r"Number of regular files transferred:\s+(\d+)")
_RE_DEL = re.compile(r"Number of deleted files:\s+(\d+)")


def rsync_supports_mkpath(rsync_bin: str) -> bool:
    try:
        p = subprocess.run(
            [rsync_bin, "--version"], check=False, text=True, capture_output=True
        )
    except Exception:
        return False
    s = (p.stdout or "") + "\n" + (p.stderr or "")
    return "--mkpath" in s


@lru_cache(maxsize=1)
def _use_mkpath_default() -> bool:
    # cache per-process; good enough
    return True  # overridden below in build_rsync_cmd by checking actual rsync_bin


def ensure_dst_dir(
    g: General,
    *,
    src_path: str,
    dst_path: str,
    dst_host: str | None,
    ssh_extra: list[str] | None,
    dst_user: str | None = None,
    use_sudo: bool = False,
) -> None:
    if os.path.isdir(src_path):
        dst_dir = dst_path.rstrip("/")
    else:
        dst_dir = os.path.dirname(dst_path.rstrip("/"))

    if not dst_dir:
        return

    if dst_host is None:
        os.makedirs(dst_dir, exist_ok=True)
        return

    target = f"{dst_user}@{dst_host}" if dst_user else dst_host
    remote_cmd = ["mkdir", "-p", dst_dir]
    if use_sudo:
        remote_cmd = ["sudo", *remote_cmd]

    ssh_cmd = ["ssh", *(ssh_extra or []), target, *remote_cmd]
    subprocess.run(ssh_cmd, check=False, text=True, capture_output=True)


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


def parse_stats(rsync_output: str) -> tuple[int, int]:
    """Return (files_transferred, files_deleted) from rsync --stats output."""
    m1 = _RE_XFER.search(rsync_output)
    m2 = _RE_DEL.search(rsync_output)
    transferred = int(m1.group(1)) if m1 else 0
    deleted = int(m2.group(1)) if m2 else 0
    return transferred, deleted


def parse_target(spec: str) -> "Target":
    m = USER_AT_HOST_RE.match(spec.strip())
    if not m:
        raise SystemExit(f"Invalid target '{spec}'. Use username[@hostname].")
    return Target(user=m.group("user"), host=m.group("host"))


def ensure_deps(*bins: str) -> None:
    miss = [b for b in bins if which(b) is None]
    if miss:
        raise SystemExit(f"Missing required executables: {', '.join(miss)}")


# ---- paths & mapping ----


def expand_abs(path_str: str) -> str:
    s = os.path.expandvars(os.path.expanduser(path_str.strip()))
    p = Path(s)
    if not p.is_absolute():
        raise SystemExit(
            f"List entry must expand to an absolute path: {path_str!r} → {s!r}"
        )
    return str(p)


def expand_for_invoker(pathlike, *, src_home: str) -> Path:
    s = str(pathlike).replace("$HOME", src_home)
    if s.startswith("~"):
        s = src_home + s[1:]
    return Path(s)


def expand_for_source(path_str: str, src_home: str) -> str:
    s = os.path.expandvars(path_str.strip()).replace("$HOME", src_home)
    if s.startswith("~"):
        s = src_home + s[1:]
    p = Path(s)
    if not p.is_absolute():
        raise SystemExit(
            f"List entry must expand to an absolute path: {path_str!r} → {s!r}"
        )
    return str(p)


def path_is_under(abs_src: str, src_home: str) -> bool:
    try:
        Path(abs_src).resolve().relative_to(Path(src_home).resolve())
        return True
    except Exception:
        return False


def map_src_to_dest(abs_src: str, src_home: str, dest_home: str) -> str:
    try:
        rel = str(Path(abs_src).resolve().relative_to(Path(src_home).resolve()))
    except Exception:
        raise SystemExit(f"Path {abs_src} is not under source home {src_home}")
    return str(Path(dest_home) / rel)


def count_sync_files(abs_path: Path, exclude_patterns: tuple[str, ...]) -> int:
    import fnmatch

    if not abs_path.exists():
        return 0
    if abs_path.is_file():
        return (
            0
            if any(fnmatch.fnmatch(abs_path.name, pat) for pat in exclude_patterns)
            else 1
        )
    total = 0
    for root, dirs, files in os.walk(abs_path, followlinks=False):
        dirs[:] = [
            d
            for d in dirs
            if not any(fnmatch.fnmatch(d, pat) for pat in exclude_patterns)
        ]
        for fname in files:
            if any(fnmatch.fnmatch(fname, pat) for pat in exclude_patterns):
                continue
            total += 1
    return total


def read_list_file(path: Path, *, logger: logging.Logger | None = None) -> list[str]:
    """
    Read a module list file. If not found, log an error and return [] so the caller
    can SKIP the module instead of exiting the whole run.
    """
    if not path.exists():
        if logger:
            logger.error(f"(skip) list file not found: {path}")
        return []

    out: list[str] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        s = raw.strip()
        if s and not s.startswith("#"):
            out.append(s)
    return out


# ---- bytes / stats ----


def human_bytes(num: float) -> str:
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if num < 1024:
            return f"{num:,.1f} {unit}"
        num /= 1024
    return f"{num:,.1f} PiB"


_RSPEED_RE = re.compile(r"speedup is ([0-9.]+)", re.I)
_RBYTES_RE = re.compile(r"Total transferred file size:\s*([\d,]+) bytes", re.I)


def extract_summary_stats(out: str) -> dict[str, float]:
    stats = {"bytes": 0.0, "deleted": 0.0, "speedup": 0.0}
    m = _RBYTES_RE.search(out)
    stats["bytes"] = float(m.group(1).replace(",", "")) if m else 0.0
    m = _RSPEED_RE.search(out)
    stats["speedup"] = float(m.group(1)) if m else 0.0
    m = re.search(r"Number of deleted files:\s*([0-9]+)", out)
    stats["deleted"] = float(m.group(1)) if m else 0.0
    return stats


# ---- tiny helpers ----


def shq(s: str) -> str:
    return "'" + s.replace("'", "'\\''") + "'"


def resolve_env_path(s: str) -> str:
    return os.path.expandvars(s).replace("$HOME", os.path.expanduser("~"))


def src_file_mtime(abs_path: str) -> float | None:
    p = Path(abs_path)
    return p.stat().st_mtime if p.exists() and p.is_file() else None
