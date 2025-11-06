from __future__ import annotations
import os, pwd, grp, re, socket, subprocess, tempfile
from dataclasses import dataclass
from pathlib import Path
from shutil import which
from typing import List, Tuple
import shlex
import os, socket, subprocess, shlex, re
from typing import Optional, Sequence


USER_AT_HOST_RE = re.compile(r"^(?P<user>[^@:\s]+)(?:@(?P<host>[^:\s]+))?$")


@dataclass(frozen=True)
class Target:
    user: str
    host: str | None  # None => localhost


def parse_target(spec: str) -> Target:
    m = USER_AT_HOST_RE.match(spec.strip())
    if not m:
        raise SystemExit(f"Invalid target '{spec}'. Use username[@hostname].")
    return Target(user=m.group("user"), host=m.group("host"))


# ---------- deps / reachability ----------


def ensure_deps(*bins: str) -> None:
    missing = [b for b in bins if which(b) is None]
    if missing:
        raise SystemExit(f"Missing required executables: {', '.join(missing)}")


def host_reachable(ssh_dest: str, timeout_s: int = 5) -> bool:
    # try ssh 'true'
    if which("ssh"):
        cmd = [
            "ssh",
            "-o",
            "BatchMode=yes",
            "-o",
            f"ConnectTimeout={timeout_s}",
            ssh_dest,
            "true",
        ]
        try:
            return (
                subprocess.run(
                    cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                ).returncode
                == 0
            )
        except Exception:
            pass
    # TCP/22 fallback (user@host -> host)
    host = ssh_dest.split("@", 1)[-1]
    try:
        with socket.create_connection((host, 22), timeout=timeout_s):
            return True
    except OSError:
        return False


# ---------- home / group resolution (local or remote) ----------


def resolve_home(
    *, user: str, host: Optional[str], ssh_extra: Optional[list[str]] = None
) -> str:
    """
    Local: return ~user using Python.
    Remote: echo $HOME from the remote login shell of `user`.
    """
    if host is None:
        if user == "" or user is None:
            user = os.environ.get("USER") or ""
        if user and user != (os.environ.get("USER") or ""):
            # Try pwd for other local users
            import pwd  # type: ignore

            return pwd.getpwnam(user).pw_dir  # may raise KeyError
        return str(Path.home())
    # Remote
    cmd = _ssh_cmd(user, host, ssh_extra=ssh_extra) + ["printf", "%s", "$HOME"]
    p = subprocess.run(cmd, text=True, capture_output=True)
    if p.returncode != 0:
        raise SystemExit(f"Failed to query $HOME for {user}@{host}.")
    return p.stdout.strip()


def resolve_primary_group(
    *, user: str, host: Optional[str], ssh_extra: Optional[list[str]] = None
) -> str:
    """
    Local: use `id -gn user` (or current).
    Remote: run `id -gn` as that login.
    """
    if host is None:
        who = user or (os.environ.get("USER") or "")
        if who:
            p = subprocess.run(["id", "-gn", who], text=True, capture_output=True)
        else:
            p = subprocess.run(["id", "-gn"], text=True, capture_output=True)
        if p.returncode != 0:
            raise SystemExit("Failed to resolve primary group (local).")
        return p.stdout.strip()
    # Remote
    cmd = _ssh_cmd(user, host, ssh_extra=ssh_extra) + ["id", "-gn"]
    p = subprocess.run(cmd, text=True, capture_output=True)
    if p.returncode != 0:
        raise SystemExit(f"Failed to resolve primary group for {user}@{host}.")
    return p.stdout.strip()


def dest_path_exists(
    user: str, host: Optional[str], path: str, *, ssh_extra: Optional[list[str]] = None
) -> bool:
    if host is None:
        return Path(path).exists()
    cmd = _ssh_cmd(user, host, ssh_extra=ssh_extra) + ["test", "-e", path]
    p = subprocess.run(cmd, text=True, capture_output=True)
    return p.returncode == 0


def dest_file_mtime(
    user: str, host: Optional[str], path: str, *, ssh_extra: Optional[list[str]] = None
) -> Optional[float]:
    """
    Returns epoch seconds (float) or None if file doesn't exist or isn't a regular file.
    """
    if host is None:
        p = Path(path)
        if not p.exists() or not p.is_file():
            return None
        return p.stat().st_mtime
    # Remote
    # stat -c %Y prints epoch seconds; returns nonzero if no such file
    cmd = _ssh_cmd(user, host, ssh_extra=ssh_extra) + ["stat", "-c", "%Y", path]
    p = subprocess.run(cmd, text=True, capture_output=True)
    if p.returncode != 0:
        return None
    try:
        return float(p.stdout.strip())
    except Exception:
        return None


def has_passwordless_sudo_remote(
    user: str, host: str, *, ssh_extra: Optional[list[str]] = None
) -> bool:
    """
    Check if `sudo -n true` succeeds remotely (no password prompt).
    """
    cmd = _ssh_cmd(user, host, ssh_extra=ssh_extra) + ["sudo", "-n", "true"]
    p = subprocess.run(cmd, text=True, capture_output=True)
    return p.returncode == 0


# ---------- path expansion / mapping ----------


def expand_abs(path_str: str) -> str:
    s = os.path.expandvars(os.path.expanduser(path_str.strip()))
    p = Path(s)
    if not p.is_absolute():
        raise SystemExit(
            f"List entry must expand to an absolute path: {path_str!r} → {s!r}"
        )
    return str(p)


def map_src_to_dest(abs_src: str, src_home: str, dest_home: str) -> str:
    """
    Map /SOURCE_HOME/xyz -> /DEST_HOME/xyz. Errors if abs_src isn't under src_home.
    """
    try:
        rel = str(Path(abs_src).resolve().relative_to(Path(src_home).resolve()))
    except Exception:
        raise SystemExit(f"Path {abs_src} is not under source home {src_home}")
    return str(Path(dest_home) / rel)


# ---------- sudo prefix decision for local cross-user ----------


def sudo_prefix_if_needed(dest_user: str) -> List[str]:
    me = pwd.getpwuid(os.getuid()).pw_name
    if dest_user != me:
        ensure_deps("sudo")
        return ["sudo", "--"]
    return []


# ---------- file counting (local; applies rsync-like excludes) ----------


def count_sync_files(abs_path: Path, exclude_patterns: tuple[str, ...]) -> int:
    """
    Count regular files under abs_path (local), ignoring names that match any exclude pattern.
    Simple fnmatch semantics for excludes (close enough for dotfiles/appconfig).
    """
    import fnmatch

    if not abs_path.exists():
        return 0
    if abs_path.is_file():
        name = abs_path.name
        return 0 if any(fnmatch.fnmatch(name, pat) for pat in exclude_patterns) else 1
    total = 0
    base = abs_path
    for root, dirs, files in os.walk(base, followlinks=False):
        # filter-out excluded dirs quickly (best-effort)
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
    """Read a .list file: one absolute path per line; allow blanks and # comments."""
    if not path.exists():
        raise SystemExit(f"List file not found: {path}")
    items: list[str] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        items.append(s)
    return items


def is_ip_literal(host: str) -> bool:
    # naive check: IPv4/IPv6 characters only
    return all(c.isdigit() or c in ".:;" for c in host)


def resolve_host_ip(host: str) -> str | None:
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None


def has_passwordless_sudo_local() -> bool:
    if which("sudo") is None:
        return False
    try:
        return (
            subprocess.run(
                ["sudo", "-n", "true"],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            ).returncode
            == 0
        )
    except Exception:
        return False


# --- terminal capability detection ---
def _isatty(stream) -> bool:
    try:
        return stream.isatty()
    except Exception:
        return False


def supports_color(stream=None) -> bool:
    stream = stream or sys.stderr
    if not _isatty(stream):
        return False
    if os.environ.get("TERM", "") == "dumb":
        return False
    return True


def supports_truecolor() -> bool:
    ct = (os.environ.get("COLORTERM", "") or "").lower()
    if "truecolor" in ct or "24bit" in ct:
        return True
    # common truecolor terminals
    if os.environ.get("TERM_PROGRAM") in {"iTerm.app", "WezTerm", "Apple_Terminal"}:
        return True
    if os.environ.get("WT_SESSION"):  # Windows Terminal
        return True
    # tmux can pass truecolor through when configured; heuristically allow
    if "tmux" in (os.environ.get("TERM") or "") and ("truecolor" in ct):
        return True
    return False


def _kv_lines(pairs: list[tuple[str, str]], *, key_width: int = 16) -> str:
    return "\n".join(f"{(k + ':') if k else '':<{key_width}} {v}" for k, v in pairs)


# --- color building ---
ANSI_RESET = "\x1b[0m"

ANSI_SIMPLE_FG = {
    "black": 30,
    "red": 31,
    "green": 32,
    "yellow": 33,
    "blue": 34,
    "magenta": 35,
    "cyan": 36,
    "white": 37,
    "bright_black": 90,
    "bright_red": 91,
    "bright_green": 92,
    "bright_yellow": 93,
    "bright_blue": 94,
    "bright_magenta": 95,
    "bright_cyan": 96,
    "bright_white": 97,
}


def _hex_to_rgb(hex_color: str) -> Tuple[int, int, int]:
    s = hex_color.strip().lstrip("#")
    if len(s) == 3:
        s = "".join(ch * 2 for ch in s)
    if len(s) != 6:
        raise ValueError(f"Bad hex color: {hex_color}")
    r = int(s[0:2], 16)
    g = int(s[2:4], 16)
    b = int(s[4:6], 16)
    return r, g, b


def colorize(text: str, fg: str | None = None, *, bold: bool = False) -> str:
    """
    fg can be a named color from ANSI_SIMPLE_FG or a hex like '#ffcc00'.
    Uses truecolor if available; otherwise falls back to simple ANSI.
    """
    seqs = []
    if bold:
        seqs.append("1")

    if fg:
        if fg.startswith("#"):
            if supports_truecolor():
                r, g, b = _hex_to_rgb(fg)
                seqs.append(f"38;2;{r};{g};{b}")
            else:
                # fallback to the closest “sane” simple color
                # (yellow for warm, red for strong red, etc.)
                try:
                    r, g, b = _hex_to_rgb(fg)
                    if r > 200 and g < 80:  # strong red
                        code = ANSI_SIMPLE_FG["red"]
                    elif r > 200 and g > 160:  # warm yellow
                        code = ANSI_SIMPLE_FG["yellow"]
                    elif g > 160 and r < 80:  # green-ish
                        code = ANSI_SIMPLE_FG["green"]
                    elif b > 160 and r < 80:  # blue-ish
                        code = ANSI_SIMPLE_FG["blue"]
                    else:
                        code = ANSI_SIMPLE_FG["white"]
                except Exception:
                    code = ANSI_SIMPLE_FG["white"]
                seqs.append(str(code))
        else:
            code = ANSI_SIMPLE_FG.get(fg.lower())
            if code is not None:
                seqs.append(str(code))

    if not seqs:
        return text
    return f"\x1b[{';'.join(seqs)}m{text}{ANSI_RESET}"


def src_file_mtime(abs_path: str) -> float | None:
    p = Path(abs_path)
    if not p.exists() or not p.is_file():
        return None
    try:
        return p.stat().st_mtime
    except Exception:
        return None


def ping_rtt_ms(host: str, *, timeout_s: float = 1.5) -> tuple[bool, Optional[float]]:
    """Ping once and return (reachable, rtt_ms) with whatever precision ping prints."""
    cmd = ["ping", "-n", "-c", "1", "-W", str(int(timeout_s)), host]
    try:
        p = subprocess.run(cmd, text=True, capture_output=True, check=False)
    except FileNotFoundError:
        return False, None

    if p.returncode != 0:
        return False, None

    m = re.search(r"time[=<]\s*([\d.]+)\s*ms", p.stdout)
    if not m:
        return False, None

    try:
        rtt = float(m.group(1))  # keep ping’s own decimal precision
    except ValueError:
        return False, None
    return True, rtt


def tcp_port_open(host: str, port: int, *, timeout_s: float = 2.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout_s):
            return True
    except OSError:
        return False


def ssh_key_auth_works(user: str, host: str, *, timeout_s: float = 4.0) -> bool:
    cmd = [
        _ssh_bin(),
        "-o",
        "BatchMode=yes",
        "-o",
        "PasswordAuthentication=no",
        "-o",
        f"ConnectTimeout={int(timeout_s)}",
        f"{user}@{host}",
        "true",
    ]
    p = subprocess.run(cmd, text=True, capture_output=True)
    return p.returncode == 0


def _ssh_bin() -> str:
    return os.environ.get("SYNCUSER_SSH_BIN", "ssh")


def _ssh_cmd(
    user: str, host: str, *, ssh_extra: Optional[list[str]] = None
) -> list[str]:
    cmd = [_ssh_bin()]
    if ssh_extra:
        cmd += ssh_extra
    cmd.append(f"{user}@{host}")
    return cmd


def start_ssh_master(user: str, host: str, *, persist: str = "15m") -> str:
    control_dir = Path.home() / ".ssh" / "cm"
    control_dir.mkdir(parents=True, exist_ok=True)
    sock = str(control_dir / f"syncuser-{os.getpid()}-{user}@{host}.sock")

    cmd = [
        _ssh_bin(),
        "-o",
        "ControlMaster=yes",
        "-o",
        f"ControlPath={sock}",
        "-o",
        f"ControlPersist={persist}",
        f"{user}@{host}",
        "-N",
        "-f",
    ]
    subprocess.run(cmd, check=True)
    return sock


def stop_ssh_master(control_path: str) -> None:
    try:
        subprocess.run(
            [
                _ssh_bin(),
                "-O",
                "exit",
                "-o",
                f"ControlPath={control_path}",
                "dummy@dummy",
            ],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except Exception:
        pass


def ssh_opts_with_control(control_path: Optional[str]) -> list[str]:
    return ["-o", f"ControlPath={control_path}"] if control_path else []
