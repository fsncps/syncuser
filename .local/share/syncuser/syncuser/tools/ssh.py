# syncuser/tools/ssh.py
from __future__ import annotations
import subprocess, socket, time, os
from typing import Tuple, Optional, Dict, Any, List
from pathlib import Path

# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class PreflightFailure(Exception):
    def __init__(self, exit_code: int, message: str):
        super().__init__(message)
        self.exit_code = exit_code
        self.message = message


# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------


def _ssh_cmd(user: str, host: str, extra: Optional[list[str]] = None) -> list[str]:
    """Base ssh command, no logging."""
    cmd = ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no"]
    if extra:
        cmd += extra
    cmd.append(f"{user}@{host}")
    return cmd


def host_header(host: str) -> str:
    """Return host with optional resolved IP if available."""
    try:
        ip = socket.gethostbyname(host)
        return f"{host} [{ip}]"
    except Exception:
        return host


def tcp_port_open(host: str, port: int, *, timeout_s: float = 2.0) -> bool:
    """Simple TCP connect test."""
    try:
        with socket.create_connection((host, port), timeout=timeout_s):
            return True
    except Exception:
        return False


def ping_rtt_ms(host: str, *, timeout_s: float = 1.5) -> tuple[bool, Optional[float]]:
    """Return (reachable, rtt_ms). Uses system ping one-shot."""
    cmd = ["ping", "-c", "1", "-W", str(int(timeout_s)), host]
    try:
        p = subprocess.run(cmd, text=True, capture_output=True, check=False)
    except FileNotFoundError:
        return False, None
    if p.returncode != 0:
        return False, None
    import re

    m = re.search(r"time[=<]\s*([\d.]+)\s*ms", p.stdout)
    rtt = float(m.group(1)) if m else None
    return True, rtt


# ---------------------------------------------------------------------------
# SSH ControlMaster helpers
# ---------------------------------------------------------------------------


def _control_path(user: str, host: str) -> str:
    """Unique control path per user/host."""
    base = Path.home() / ".ssh" / "cm"
    base.mkdir(parents=True, exist_ok=True)
    return str(base / f"cm_{user}_{host}")


def start_ssh_master(
    user: str, host: str, *, persist: str = "15m"
) -> tuple[list[str], str]:
    """Start or reuse SSH ControlMaster; return (extra_opts, control_path)."""
    path = _control_path(user, host)
    extra = [
        "-o",
        f"ControlPath={path}",
        "-o",
        "ControlMaster=auto",
        "-o",
        f"ControlPersist={persist}",
    ]
    # launch background master if not alive
    try:
        subprocess.run(
            ["ssh", "-MNf", *extra, f"{user}@{host}"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    except Exception:
        pass
    return extra, path


def stop_ssh_master(control_path: str) -> None:
    """Stop ControlMaster socket if running."""
    if not control_path:
        return
    try:
        subprocess.run(
            ["ssh", "-O", "exit", "-S", control_path, "dummy@dummy"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Authentication check
# ---------------------------------------------------------------------------


def ssh_key_auth_works(user: str, host: str, *, timeout_s: float = 4.0) -> bool:
    """Attempt a key-based auth dry test (no command)."""
    try:
        p = subprocess.run(
            [
                "ssh",
                "-o",
                "BatchMode=yes",
                "-o",
                f"ConnectTimeout={int(timeout_s)}",
                f"{user}@{host}",
                "exit",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        return p.returncode == 0
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Preflight main entry
# ---------------------------------------------------------------------------


def preflight_connect(
    user: str,
    host: str,
    *,
    resumed: bool,
    persist: str = "15m",
    timeout_ping: float = 1.5,
    timeout_port: float = 2.0,
) -> tuple[list[str], Optional[str], Dict[str, Any]]:
    """
    Perform connectivity & auth checks and start ControlMaster.
    Returns (ssh_extra, control_path, report_dict).
    Does NOT log — only returns data for log_utils.
    """

    hdr = host_header(host)
    icmp_ok, rtt = ping_rtt_ms(host, timeout_s=timeout_ping)
    route = (
        f"online (ping {rtt:.3f} ms)"
        if (icmp_ok and rtt is not None)
        else "ICMP blocked or unknown"
    )

    ssh_up = tcp_port_open(host, 22, timeout_s=timeout_port)
    if not ssh_up:
        raise PreflightFailure(3, f"Cannot reach SSH on {host}:22 (user {user}).")

    # control master
    ssh_extra, control_path = start_ssh_master(user, host, persist=persist)

    # key auth check
    keys_ok = ssh_key_auth_works(user, host, timeout_s=4.0)

    report = {
        "host_hdr": hdr,
        "remote_user": user,
        "route": route,
        "ssh_up": ssh_up,
        "logon_result": (
            "Key-based auth: OK."
            if keys_ok
            else "Key-based auth: not available. Prompted password."
        ),
    }

    return ssh_extra, control_path, report


# ---------------------------------------------------------------------------
# Remote filesystem helpers used elsewhere
# ---------------------------------------------------------------------------


def dest_path_exists(
    user: str, host: Optional[str], path: str, *, ssh_extra: Optional[list[str]] = None
) -> bool:
    """Check if destination path exists (remote or local)."""
    if not host:
        return Path(path).exists()
    cmd = _ssh_cmd(user, host, ssh_extra) + ["test", "-e", path]
    p = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return p.returncode == 0


def dest_file_mtime(
    user: str, host: Optional[str], path: str, *, ssh_extra: Optional[list[str]] = None
) -> Optional[float]:
    """Get remote file mtime."""
    if not host:
        try:
            return Path(path).stat().st_mtime
        except Exception:
            return None
    cmd = _ssh_cmd(user, host, ssh_extra) + ["stat", "-c", "%Y", path]
    p = subprocess.run(cmd, text=True, capture_output=True)
    try:
        return float(p.stdout.strip()) if p.returncode == 0 else None
    except Exception:
        return None
