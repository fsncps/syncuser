# syncuser/tools/identity.py
from __future__ import annotations
import os, sys, pwd, subprocess, shutil
from pathlib import Path
from typing import Optional

# ---- identity / uid ----


def invoking_user() -> str:
    try:
        if os.geteuid() == 0:
            su = os.environ.get("SUDO_USER")
            if su:
                return su
    except AttributeError:
        pass
    try:
        return pwd.getpwuid(os.getuid()).pw_name
    except Exception:
        return os.environ.get("USER") or "unknown"


def is_unix_root() -> bool:
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


# ---- home / group ----


def resolve_home(
    *, user: str, host: Optional[str], ssh_extra: Optional[list[str]] = None
) -> str:
    if host is None:
        if not user or user == (os.environ.get("USER") or ""):
            return str(Path.home())
        return pwd.getpwnam(user).pw_dir
    from .ssh import _ssh_cmd

    p = subprocess.run(
        _ssh_cmd(user, host, ssh_extra) + ["printf", "%s", "$HOME"],
        text=True,
        capture_output=True,
    )
    if p.returncode != 0:
        raise SystemExit(f"Failed to query $HOME for {user}@{host}.")
    return p.stdout.strip()


def resolve_primary_group(
    *, user: str, host: Optional[str], ssh_extra: Optional[list[str]] = None
) -> str:
    if host is None:
        who = user or (os.environ.get("USER") or "")
        p = subprocess.run(
            ["id", "-gn", who] if who else ["id", "-gn"], text=True, capture_output=True
        )
        if p.returncode != 0:
            raise SystemExit("Failed to resolve primary group (local).")
        return p.stdout.strip()
    from .ssh import _ssh_cmd

    p = subprocess.run(
        _ssh_cmd(user, host, ssh_extra) + ["id", "-gn"], text=True, capture_output=True
    )
    if p.returncode != 0:
        raise SystemExit(f"Failed to resolve primary group for {user}@{host}.")
    return p.stdout.strip()


def local_home_of(user: str) -> str:
    try:
        return pwd.getpwnam(user).pw_dir
    except KeyError:
        return str(Path(f"~{user}").expanduser())


def resolve_dest(
    user: str, host: Optional[str], *, ssh_extra: Optional[list[str]] = None
) -> tuple[str, str]:
    """Return (dest_home, dest_primary_group) for local or remote."""
    dest_home = (
        local_home_of(user)
        if host is None
        else resolve_home(user=user, host=host, ssh_extra=ssh_extra)
    )
    dest_group = resolve_primary_group(user=user, host=host, ssh_extra=ssh_extra)
    return dest_home, dest_group


# ---- permissions & sudo ----


def local_perm_info(dest_home: str, *, sudo_active: bool) -> tuple[str, bool, bool]:
    if not os.path.isdir(dest_home):
        return ("-", False, False)
    try:
        mode = f"{os.stat(dest_home).st_mode & 0o777:o}"
    except Exception:
        return ("-", False, True)
    return (
        (mode, True, True)
        if sudo_active
        else (mode, os.access(dest_home, os.W_OK | os.X_OK), True)
    )


def has_passwordless_sudo_local() -> bool:
    if shutil.which("sudo") is None:
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


def has_passwordless_sudo_remote(
    user: str, host: str, *, ssh_extra: Optional[list[str]] = None
) -> bool:
    from .ssh import _ssh_cmd

    p = subprocess.run(
        _ssh_cmd(user, host, ssh_extra) + ["sudo", "-n", "true"],
        text=True,
        capture_output=True,
    )
    return p.returncode == 0


# ---- sudo re-exec ----


def reexec_with_sudo(
    *, extra_args: list[str] | None, base: str, elevation_flag: str, state_env: str
) -> "NoReturn":
    if os.environ.get(elevation_flag) == "1":
        print(
            "Permission:   ERROR: Elevation loop detected. Aborting.", file=sys.stderr
        )
        os._exit(1)
    venv_py = os.path.join(base, ".venv", "bin", "python3")
    if not os.path.exists(venv_py):
        print(f"[err] venv python not found: {venv_py}", file=sys.stderr)
        os._exit(1)
    env = os.environ.copy()
    env.update(
        {
            "PYTHONPATH": f"{base}:{env.get('PYTHONPATH','')}",
            "SYNCUSER_BASE": base,
            elevation_flag: "1",
        }
    )
    preserve = f"HOME,PYTHONPATH,SYNCUSER_BASE,{elevation_flag}"
    if state_env in env:
        preserve += "," + state_env
    sudo = shutil.which("sudo") or "/usr/bin/sudo"
    argv = [
        sudo,
        f"--preserve-env={preserve}",
        venv_py,
        "-m",
        "syncuser",
        *(extra_args or sys.argv[1:]),
    ]
    os.execvpe(sudo, argv, env)  # no return
