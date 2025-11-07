# syncuser/tools/ssh.py
from __future__ import annotations
import os, re, socket, subprocess
from pathlib import Path
from typing import Optional
from . import log_utils


class PreflightFailure(Exception):
    def __init__(self, exit_code: int, message: str):
        super().__init__(message)
        self.exit_code = exit_code
        self.message = message


def _ssh_bin() -> str:
    return os.environ.get("SYNCUSER_SSH_BIN", "ssh")


def _ssh_cmd(user: str, host: str, ssh_extra: Optional[list[str]] = None) -> list[str]:
    return [_ssh_bin(), *(ssh_extra or []), f"{user}@{host}"]


# ---- reachability / route-to-host ----


def tcp_port_open(host: str, port: int, *, timeout_s: float = 2.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout_s):
            return True
    except OSError:
        return False


def ping_rtt_ms(host: str, *, timeout_s: float = 1.5) -> tuple[bool, float | None]:
    cmd = ["ping", "-n", "-c", "1", "-W", str(int(timeout_s)), host]
    try:
        p = subprocess.run(cmd, text=True, capture_output=True, check=False)
    except FileNotFoundError:
        return False, None
    if p.returncode != 0:
        return False, None
    m = re.search(r"time[=<]\s*([\d.]+)\s*ms", p.stdout)
    return (True, float(m.group(1))) if m else (False, None)


def host_header(host: str | None) -> str:
    if host is None:
        return "localhost"
    try:
        ip = socket.gethostbyname(host)
        return host if host == ip else f"{host} [{ip}]"
    except Exception:
        return host


# ---- SSH auth / multiplexing ----


def ssh_key_auth_works(user: str, host: str, *, timeout_s: float = 4.0) -> bool:
    p = subprocess.run(
        [
            _ssh_bin(),
            "-o",
            "BatchMode=yes",
            "-o",
            "PasswordAuthentication=no",
            "-o",
            f"ConnectTimeout={int(timeout_s)}",
            f"{user}@{host}",
            "true",
        ],
        text=True,
        capture_output=True,
    )
    return p.returncode == 0


def start_ssh_master(user: str, host: str, *, persist: str = "15m") -> str:
    control_dir = Path.home() / ".ssh" / "cm"
    control_dir.mkdir(parents=True, exist_ok=True)
    sock = str(control_dir / f"syncuser-{os.getpid()}-{user}@{host}.sock")
    subprocess.run(
        [
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
        ],
        check=True,
    )
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


# ---- remote fs queries ----


def dest_path_exists(
    user: str, host: Optional[str], path: str, *, ssh_extra: Optional[list[str]] = None
) -> bool:
    if host is None:
        from pathlib import Path

        return Path(path).exists()
    p = subprocess.run(
        _ssh_cmd(user, host, ssh_extra) + ["test", "-e", path],
        text=True,
        capture_output=True,
    )
    return p.returncode == 0


def dest_file_mtime(
    user: str, host: Optional[str], path: str, *, ssh_extra: Optional[list[str]] = None
) -> float | None:
    if host is None:
        from pathlib import Path

        p = Path(path)
        return p.stat().st_mtime if p.exists() and p.is_file() else None
    r = subprocess.run(
        _ssh_cmd(user, host, ssh_extra) + ["stat", "-c", "%Y", path],
        text=True,
        capture_output=True,
    )
    if r.returncode != 0:
        return None
    try:
        return float(r.stdout.strip())
    except Exception:
        return None


# ---- one-call remote preflight (adds to buffer, raises on failure) ----


def preflight_connect(
    user: str,
    host: str,
    *,
    buf: log_utils.StateBuffer,
    resumed: bool,
    persist: str = "15m",
    timeout_ping: float = 1.5,
    timeout_port: float = 2.0,
) -> tuple[list[str], str]:
    host_hdr = host_header(host)
    icmp_ok, rtt = ping_rtt_ms(host, timeout_s=timeout_ping)
    route = (
        f"online (ping {rtt:.3f} ms)"
        if (icmp_ok and rtt is not None)
        else "ICMP blocked or unknown"
    )
    ssh_up = tcp_port_open(host, 22, timeout_s=timeout_port)
    if not resumed:
        buf.add_kv_pairs(
            [
                ("Host", host_hdr or "?"),
                ("Remote user", user),
                ("Route to host", route),
                ("SSH port 22", "open" if ssh_up else "closed/unreachable"),
                ("Logon", "attempting keyfile logon.."),
            ]
        )
    if not ssh_up:
        raise PreflightFailure(3, f"Cannot reach SSH on {host}:22 (user {user}).")

    keys_ok = ssh_key_auth_works(user, host, timeout_s=4.0)
    if not resumed:
        buf.add_kv_pairs(
            [
                (
                    "Logon",
                    (
                        "Key-based auth: OK."
                        if keys_ok
                        else "Key-based auth: not available. Prompted password."
                    ),
                )
            ]
        )

    try:
        control_path = start_ssh_master(user, host, persist=persist)
        ssh_extra = ssh_opts_with_control(control_path)
        if not resumed:
            buf.add_kv_pairs([("Logon", "Authenticated. SSH ControlMaster active.")])
    except Exception:
        raise PreflightFailure(
            4, "Authentication failed before remote queries (ControlMaster setup)."
        )

    return ssh_extra, control_path
