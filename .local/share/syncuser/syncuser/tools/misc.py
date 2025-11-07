# syncuser/tools/misc.py
from __future__ import annotations
import os, re
from pathlib import Path
from shutil import which

# ---- deps ----
import re
from dataclasses import dataclass

USER_AT_HOST_RE = re.compile(r"^(?P<user>[^@:\s]+)(?:@(?P<host>[^:\s]+))?$")


@dataclass(frozen=True)
class Target:
    user: str
    host: str | None  # None => localhost


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


def read_list_file(path: Path) -> list[str]:
    if not path.exists():
        raise SystemExit(f"List file not found: {path}")
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
