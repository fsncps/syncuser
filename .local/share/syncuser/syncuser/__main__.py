# __main__.py (drop-in)
from __future__ import annotations
import argparse, os, sys, errno, subprocess, shutil, logging, time, re, pwd
from dataclasses import replace
from pathlib import Path
from typing import List, Tuple

from .config import load_config
from .log import setup_logging
from .tools import (
    parse_target,
    ensure_deps,
    resolve_home,
    resolve_primary_group,
    map_src_to_dest,
    count_sync_files,
    read_list_file,
    is_ip_literal,
    resolve_host_ip,
    has_passwordless_sudo_local,
    has_passwordless_sudo_remote,
    dest_path_exists,
    dest_file_mtime,
    src_file_mtime,
    ping_rtt_ms,
    tcp_port_open,
    ssh_key_auth_works,
    start_ssh_master,
    stop_ssh_master,
    ssh_opts_with_control,
    _kv_lines,
)
from .sync import build_rsync_cmd, run_capture, parse_stats, parse_itemize

# ----- constants / env keys -----
ELEVATION_ENV_FLAG = "SYNCUSER_ELEVATED"
STATE_ENV = "SYNCUSER_STATE_FILE"
SYNCUSER_BASE = os.environ.get("SYNCUSER_BASE") or os.path.expanduser("~/.local/share/syncuser")

log = logging.getLogger(__name__)

_RSPEED_RE = re.compile(r"speedup is ([0-9.]+)", re.I)
_RBYTES_RE = re.compile(r"Total transferred file size:\s*([\d,]+) bytes", re.I)

def _resolve_env_path(s: str) -> str:
    return os.path.expandvars(s).replace("$HOME", os.path.expanduser("~"))

# ----- state buffer for cross-reexec header continuity -----
class StateBuffer:
    def __init__(self, path: Path):
        self.path = path
        self.lines: list[str] = []

    def add(self, line: str) -> None:
        self.lines.append(line)

    def add_kv_pairs(self, pairs: list[tuple[str, str]]) -> None:
        # reuse your kv formatting
        from .tools import _kv_lines as kv
        self.lines.extend(kv(pairs).splitlines())

    def write_and_close(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text("\n".join(self.lines) + "\n", encoding="utf-8")

    def read_and_clear(self) -> list[str]:
        if not self.path.exists():
            return []
        text = self.path.read_text(encoding="utf-8")
        try:
            self.path.unlink()
        except Exception:
            pass
        return text.rstrip("\n").splitlines() if text else []


# ----- helpers -----
def expand_for_invoker(pathlike, *, src_home: str) -> Path:
    """Expand ~ and $HOME but force them to the invoking user's home."""
    s = str(pathlike)
    s = s.replace("$HOME", src_home)
    if s.startswith("~"):
        s = src_home + s[1:]
    return Path(s)


def shq(s: str) -> str:
    return "'" + s.replace("'", "'\\''") + "'"


def _local_perm_info(dest_home: str, *, sudo_active: bool) -> Tuple[str, bool, bool]:
    """Return (mode_str, ok, exists) for a local target dir."""
    if not os.path.isdir(dest_home):
        return ("-", False, False)
    try:
        st = os.stat(dest_home)
        mode = f"{st.st_mode & 0o777:o}"
    except Exception:
        return ("-", False, True)
    if sudo_active:
        return (mode, True, True)
    ok = os.access(dest_home, os.W_OK | os.X_OK)
    return (mode, ok, True)


def _remote_perm_info(
    user: str, host: str, dest_home: str, *, ssh_extra: list[str], sudo_allowed: bool
) -> Tuple[str, bool, bool]:
    """Return (mode_str, ok, exists) for a remote target dir."""
    rc, _, _ = run_capture(
        ["ssh", *ssh_extra, f"{user}@{host}", "--", "sh", "-lc", f"[ -d {shq(dest_home)} ]"],
        echo=False,
        echo_cmd=False,
    )
    if rc != 0:
        return ("-", False, False)

    rc, out, _ = run_capture(
        ["ssh", *ssh_extra, f"{user}@{host}", "--", "sh", "-lc", f"stat -c %a {shq(dest_home)} || stat -f %Mp%Lp {shq(dest_home)}"],
        echo=False,
        echo_cmd=False,
    )
    mode = out.strip() if rc == 0 and out.strip() else "-"

    rc, _, _ = run_capture(
        ["ssh", *ssh_extra, f"{user}@{host}", "--", "sh", "-lc", f"[ -w {shq(dest_home)} ] && [ -x {shq(dest_home)} ]"],
        echo=False,
        echo_cmd=False,
    )
    ok = (rc == 0) or bool(sudo_allowed)
    return (mode, ok, True)


def _invoking_user() -> str:
    try:
        euid = os.geteuid()
    except AttributeError:
        euid = None
    if euid == 0:
        su = os.environ.get("SUDO_USER")
        if su:
            return su
    try:
        return pwd.getpwuid(os.getuid()).pw_name
    except Exception:
        return os.environ.get("USER") or "unknown"


def _host_header(host: str | None) -> str:
    if host is None:
        return "localhost"
    if is_ip_literal(host):
        return host
    ip = resolve_host_ip(host)
    return f"{host} [{ip}]" if ip else host


def _is_local_target(host: str | None) -> bool:
    return host is None


def _is_unix_root() -> bool:
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def _expand_for_source(path_str: str, src_home: str) -> str:
    s = path_str.strip()
    s = os.path.expandvars(s)
    s = s.replace("$HOME", src_home)
    if s.startswith("~"):
        s = src_home + s[1:]
    p = Path(s)
    if not p.is_absolute():
        raise SystemExit(f"List entry must expand to an absolute path: {path_str!r} → {s!r}")
    return str(p)


def reexec_with_sudo(extra_args: list[str] | None = None) -> "NoReturn":
    """Exec into sudo + venv python, preserving our env (HOME too!) and state file."""
    if os.environ.get(ELEVATION_ENV_FLAG) == "1":
        print("Permission:   ERROR: Elevation loop detected. Aborting.", file=sys.stderr)
        os._exit(1)

    base = SYNCUSER_BASE
    venv_py = os.path.join(base, ".venv", "bin", "python3")
    if not os.path.exists(venv_py):
        print(f"[err] venv python not found: {venv_py}", file=sys.stderr)
        os._exit(1)

    env = os.environ.copy()
    # Make module path discoverable and keep HOME pinned to invoker's home
    env["PYTHONPATH"] = f"{base}:{env.get('PYTHONPATH','')}"
    env["SYNCUSER_BASE"] = base
    env[ELEVATION_ENV_FLAG] = "1"
    # IMPORTANT: preserve HOME so defaults point to invoker's config, not /root
    preserve = "HOME,PYTHONPATH,SYNCUSER_BASE," + ELEVATION_ENV_FLAG
    if STATE_ENV in env:
        preserve += "," + STATE_ENV

    sudo = shutil.which("sudo") or "/usr/bin/sudo"
    argv = [sudo, f"--preserve-env={preserve}", venv_py, "-m", "syncuser"]
    argv += (extra_args or sys.argv[1:])

    # Replace current process; no parent to throw tracebacks
    os.execvpe(sudo, argv, env)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="syncuser",
        description=(
            "Sync modules from current user's home to username[@hostname]'s home.\n"
            "Usage: syncuser username[@hostname] [-M name] [-O]"
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument(
        "-c",
        "--config",
        type=Path,
        default=Path("~/.config/syncuser/syncuser_conf.toml").expanduser(),
        help="Path to the syncuser TOML configuration.",
    )
    p.add_argument(
        "-M",
        "--module",
        action="append",
        default=[],
        help="Sync only the named module (repeatable).",
    )
    p.add_argument(
        "-O",
        "--overwrite",
        action="store_true",
        help="Force overwrite on destination (ignore module policy).",
    )
    p.add_argument(
        "-n",
        "--dry-run",
        action="store_true",
        help="Do not make changes; show what would be done.",
    )
    p.add_argument(
        "-q", "--no-verbose", action="store_true", help="Quiet rsync output (omit -v)."
    )
    p.add_argument(
        "-S",
        "--sudo",
        action="store_true",
        help="Prompt for sudo password if passwordless sudo is unavailable (local or remote).",
    )
    p.add_argument(
        "-s",
        "--silent",
        action="store_true",
        help="Produce no output at all; rely on exit code only.",
    )
    p.add_argument(
        "target",
        help="Destination as username[@hostname]. If hostname is omitted, localhost is used.",
    )
    args = p.parse_args()
    t = parse_target(args.target)
    args.target_user, args.target_host = t.user, t.host
    return args


def main() -> int:
    args = parse_args()

    # --- invoking user + real home (survives sudo) ---
    src_user = _invoking_user()
    src_home = resolve_home(user=src_user, host=None)

    # Keep defaults pinned to invoker's home (so expanduser inside helpers points there)
    os.environ["HOME"] = src_home
    os.environ.setdefault("XDG_CONFIG_HOME", str(Path(src_home) / ".config"))

    # Force default config path to invoker's home if user didn't override -c
    default_cfg_cur_home = Path("~/.config/syncuser/syncuser_conf.toml").expanduser()
    if args.config == default_cfg_cur_home:
        args.config = expand_for_invoker(args.config, src_home=src_home)
    cfg_path = Path(args.config)

    # --- load config (from invoker) ---
    g, modules = load_config(cfg_path)
    # rewrite frozen modules with list_file pinned to invoker's home
    # AFTER (keeps Path; read_list_file(Path) works)
    modules = [
        replace(m, list_file=expand_for_invoker(m.list_file, src_home=src_home))
        for m in modules
    ]


    start_time = time.time()
    total_transferred_bytes = 0.0
    total_deleted_files = 0
    total_dirs = 0
    total_files = 0

    effective_verbose = (not args.no_verbose) and g.verbose and (not args.silent)
    g = replace(g, dry_run=(args.dry_run or g.dry_run), verbose=effective_verbose)

    logger = setup_logging(g.log_file, g.verbose, silent=args.silent)
    globals()["log"] = logger

    # ----- state buffer path (under invoker's home) -----
    state_file = Path(os.environ.get(STATE_ENV, "")) if os.environ.get(STATE_ENV) else Path(src_home) / ".local/state/syncuser/header.tmp"
    buf = StateBuffer(state_file)
    # If child run (after sudo), read previous header but DO NOT print yet; we append and flush once.
    resumed_lines = buf.read_and_clear()
    if resumed_lines:
        buf.lines.extend(resumed_lines)

    resumed = bool(resumed_lines)

    control_path: str | None = None
    try:
        # --- deps ---
        ensure_deps(g.rsync_bin)
        if args.target_host:
            ensure_deps("ssh")

        icmp_ok = None
        rtt = None
        ssh_up = None
        ssh_extra: list[str] = []

        # ----- Build banner/preamble into buffer (no printing yet) -----
# ----- Build banner/preamble into buffer (no printing yet) -----
        if not resumed:
            buf.add("┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓")
            buf.add("┃                   SYNCUSER                    ┃")
            buf.add("┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛")
            buf.add_kv_pairs([("Config", str(cfg_path))])

        if args.target_host:
            host_hdr = _host_header(args.target_host)
            route = "ICMP blocked or unknown"
            icmp_ok, rtt = ping_rtt_ms(args.target_host, timeout_s=1.5)
            if icmp_ok and rtt is not None:
                route = f"online (ping {rtt:.3f} ms)"
            ssh_up = tcp_port_open(args.target_host, 22, timeout_s=2.0)
            if not resumed:
                buf.add_kv_pairs([
                    ("Host", host_hdr or "?"),
                    ("Remote user", args.target_user),
                    ("Route to host", route),
                    ("SSH port 22", "open" if ssh_up else "closed/unreachable"),
                    ("Logon", "attempting keyfile logon.."),
                ])
            if not tcp_port_open(args.target_host, 22, timeout_s=2.0):
                # flush and abort
                for line in buf.lines:
                    if line.startswith(("┏","┃","┗")): logger.title(line)
                    else: logger.info(line)
                logger.error(f"Cannot reach SSH on {args.target_host}:22 (user {args.target_user}).")
                return 3
            keys_ok = ssh_key_auth_works(args.target_user, args.target_host, timeout_s=4.0)
            if not resumed:
                buf.add_kv_pairs([("Logon", "Key-based auth: OK." if keys_ok else "Key-based auth: not available. Prompted password.")])
            try:
                control_path = start_ssh_master(args.target_user, args.target_host, persist="15m")
                ssh_extra = ssh_opts_with_control(control_path)
                if not resumed:
                    buf.add_kv_pairs([("Logon", "Authenticated. SSH ControlMaster active.")])
            except subprocess.CalledProcessError:
                for line in buf.lines:
                    if line.startswith(("┏","┃","┗")): logger.title(line)
                    else: logger.info(line)
                logger.error("Authentication failed before remote queries (ControlMaster setup).")
                return 4
        else:
            if not resumed:
                buf.add_kv_pairs([("Host", "(local)"), ("Logon", "Local session")])


        # ----- destination identity -----
        if _is_local_target(args.target_host):
            # For local dest, ignore HOME; resolve via pwd for the target user
            try:
                dest_home = pwd.getpwnam(args.target_user).pw_dir
            except KeyError:
                # fallback to your helper if user missing
                dest_home = resolve_home(user=args.target_user, host=None)
        else:
            dest_home = resolve_home(user=args.target_user, host=args.target_host, ssh_extra=ssh_extra)  # type: ignore[arg-type]

        dest_group = resolve_primary_group(user=args.target_user, host=args.target_host, ssh_extra=ssh_extra)  # type: ignore[arg-type]

        # ----- sudo allowance -----
        if args.target_host:
            pwless = has_passwordless_sudo_remote(args.target_user, args.target_host, ssh_extra=ssh_extra)  # type: ignore[arg-type]
        else:
            pwless = has_passwordless_sudo_local()
        sudo_allowed = pwless or args.sudo or g.prompt_sudo_passwd

        # ----- SUDO/Target + Permission (still buffered) -----
        where = "remote" if args.target_host else "local"
        target_header_path = f"{args.target_user}@{args.target_host}:{dest_home}" if args.target_host else dest_home
        sudo_active = _is_unix_root()
        sudo_mode_display = "YES" if sudo_active else "NO"
        # Only add SUDO/Target if we didn't already print them in the previous pass
        buf.add_kv_pairs([("SUDO", sudo_mode_display), ("Target", f"{target_header_path} ({where})")])


        if _is_local_target(args.target_host):
            mode, ok, exists = _local_perm_info(dest_home, sudo_active=_is_unix_root())
            if not exists:
                for line in buf.lines:
                    if line.startswith(("┏","┃","┗")): logger.title(line)
                    else: logger.info(line)
                logger.error(f"Target does not exist: {dest_home}")
                return 1
            if ok:
                buf.add(f"Permission:      {mode} (OK)")
            else:
                if sudo_allowed:
                    buf.add("Permission:      ERROR: Permission denied at target.")
                    buf.add("Permission:      Restarting with sudo…")
                    # persist buffer and exec; child will read, append, and flush later
                    os.environ[STATE_ENV] = str(state_file)
                    buf.write_and_close()
                    reexec_with_sudo(["--sudo", *sys.argv[1:]])
                else:
                    for line in buf.lines:
                        if line.startswith(("┏","┃","┗")): logger.title(line)
                        else: logger.info(line)
                    logger.error("Permission:      ERROR: Permission denied at target and sudo not allowed.")
                    return 5
        else:
            # --- remote target: trust resolve_home() and skip permission stat checks ---
            if not dest_home:
                for line in buf.lines:
                    if line.startswith(("┏","┃","┗")):
                        logger.title(line)
                    else:
                        logger.info(line)
                logger.error(f"Could not resolve remote home for {args.target_user}@{args.target_host}")
                return 1

            buf.add(f"Permission:      assumed OK (remote target preflight skipped)")


        # ----- At this point, we are allowed to proceed; FLUSH header once -----
        if not args.silent:
            for line in buf.lines:
                if line.startswith(("┏","┃","┗")):
                    logger.title(line)
                else:
                    logger.info(line)

        # ----- filter modules -----
        if args.module:
            wanted = set(args.module)
            modules = [m for m in modules if m.name in wanted]
            if not modules:
                logger.error(f"No matching modules for: {', '.join(sorted(wanted))}")
                return 2

        echo_cmd = g.verbose and (not args.silent)
        echo_rsync = g.verbose and (not args.silent)

        # local sudo prefix
        sudo_prefix: List[str] = []
        if not args.target_host and (args.target_user != _invoking_user()) and sudo_allowed:
            sudo_prefix = ["sudo", "--"]

        # remote rsync-path (sudo on the remote if allowed)
        rsync_path = "sudo rsync" if (args.target_host and sudo_allowed) else None

        rc_all = 0

        try:
            for m in modules:
                logger.title(f"\n=== Module: {m.name} ===")

                items_raw = read_list_file(m.list_file)
                if not items_raw:
                    logger.warning(f"(skip) list empty: {m.list_file}")
                    continue

                for raw in items_raw:
                    disp = raw.strip()
                    abs_src = _expand_for_source(disp, src_home)

                    # ensure mapping from src_home
                    if not Path(abs_src).resolve().is_relative_to(Path(src_home).resolve()):
                        logger.error(f"{disp}: must reside under source home {src_home}. Skipping.")
                        continue

                    abs_dst = map_src_to_dest(abs_src, src_home, dest_home).replace("$HOME", dest_home)

                    # Preflight
                    src_is_file = Path(abs_src).is_file()
                    src_exists = Path(abs_src).exists()
                    src_mtime = src_file_mtime(abs_src) if src_is_file else None

                    dest_existed_before = dest_path_exists(
                        args.target_user, args.target_host, abs_dst, ssh_extra=ssh_extra  # type: ignore[arg-type]
                    )
                    dest_mtime_before = (
                        dest_file_mtime(args.target_user, args.target_host, abs_dst, ssh_extra=ssh_extra)  # type: ignore[arg-type]
                        if src_is_file
                        else None
                    )

                    dst_path_for_rsync = (
                        f"{args.target_user}@{args.target_host}:{abs_dst}" if args.target_host else abs_dst
                    )

                    total_files = count_sync_files(Path(abs_src), tuple(g.exclude))

                    chown_str = f"{args.target_user}:{dest_group}" if sudo_allowed else None
                    chown_note = f" (chown {chown_str})" if chown_str else ""

                    cmd = build_rsync_cmd(
                        g,
                        m,
                        src_path=abs_src,
                        dst_host=args.target_host,
                        dst_path=dst_path_for_rsync,
                        force_overwrite=args.overwrite,
                        chown=chown_str,
                        rsync_path=rsync_path,
                        ssh_extra=ssh_extra,
                    )
                    if sudo_prefix:
                        cmd = sudo_prefix + cmd

                    rc, out, err = run_capture(cmd, echo=echo_rsync, echo_cmd=echo_cmd)

                    combined = f"{out}\n{err}"
                    it = parse_itemize(combined)
                    created_count = it["created"]
                    updated_count = it["updated"]
                    deleted_count = it["deleted"]

                    transferred_stats, deleted_stats = parse_stats(combined)
                    is_dir = Path(abs_src).is_dir()

                    stats = _extract_summary_stats(out + "\n" + err)
                    total_transferred_bytes += stats["bytes"]
                    total_deleted_files += int(stats["deleted"])

                    if is_dir:
                        copied = created_count + updated_count
                        if copied == 0:
                            copied = transferred_stats
                        deleted_total = deleted_stats
                        skipped = max(0, total_files - copied) if total_files > 0 else 0
                        if copied > 0:
                            logger.transfer(f"{_resolve_env_path(disp)}: DIR; {copied} copied, {deleted_total} deleted, {skipped} skipped.{chown_note}")
                        elif deleted_total > 0:
                            logger.notice(f"{_resolve_env_path(disp)}: DIR; {copied} copied, {deleted_total} deleted, {skipped} skipped.{chown_note}")
                        else:
                            logger.notice(f"{_resolve_env_path(disp)}: DIR; {copied} copied, {deleted_total} deleted, {skipped} skipped.{chown_note}")
                    else:
                        source_missing = not src_exists
                        if source_missing:
                            if m.mirror and deleted_count > 0 and rc == 0:
                                logger.notice(f"{_resolve_env_path(disp)}: Target obsolete. DELETED file.{chown_note}")
                            else:
                                logger.warning(f"{_resolve_env_path(disp)}: Neither source nor target file found. SKIPPING.")
                        else:
                            transferred_any = (created_count + updated_count) > 0 or transferred_stats > 0
                            if transferred_any:
                                if not dest_existed_before:
                                    logger.transfer(f"{_resolve_env_path(disp)}: Target not found. CREATED new file.{chown_note}")
                                else:
                                    if (
                                        src_mtime is not None
                                        and dest_mtime_before is not None
                                        and src_mtime > dest_mtime_before
                                    ):
                                        logger.transfer(f"{_resolve_env_path(disp)}: Target out of date. UPDATED file.{chown_note}")
                                    else:
                                        logger.transfer(f"{_resolve_env_path(disp)}: Target out of date. UPDATED file.{chown_note}")
                            else:
                                if dest_existed_before:
                                    if (
                                        src_mtime is not None
                                        and dest_mtime_before is not None
                                        and src_mtime <= dest_mtime_before
                                    ):
                                        logger.notice(f"{_resolve_env_path(disp)}: Target identical, SKIPPED file.")
                                    else:
                                        logger.notice(f"{_resolve_env_path(disp)}: Target identical, SKIPPED file.")
                                else:
                                    logger.notice(f"{_resolve_env_path(disp)}: SKIPPED file.")
                    if rc != 0:
                        rc_all = rc

        except PermissionError:
            # We only re-exec in the explicit early check; if we get here, just bubble up
            raise
        except OSError as e:
            if e.errno == errno.EACCES and _is_local_target(args.target_host) and not _is_unix_root():
                # Persist and exec (rare fallback)
                os.environ[STATE_ENV] = str(state_file)
                buf.add("Permission:   ERROR during operation; restarting with sudo…")
                buf.write_and_close()
                reexec_with_sudo(["--sudo", *sys.argv[1:]])
            raise

        elapsed = time.time() - start_time
        logger.title("\n=== Summary ===")
        logger.info(_kv_lines([
            ("Modules processed",   str(len(modules))),
            ("Directories synced",  str(total_dirs)),
            ("Files processed",     str(total_files)),
            ("Files deleted",       str(total_deleted_files)),
            ("Payload transferred", _human_bytes(total_transferred_bytes)),
            ("Elapsed time",        f"{elapsed:,.1f} s"),
            ("Average throughput",  _human_bytes(total_transferred_bytes / elapsed) + "/s" if elapsed > 0 else "n/a"),
        ]))
        return rc_all

    finally:
        if control_path:
            stop_ssh_master(control_path)


def _extract_summary_stats(out: str) -> dict[str, float]:
    stats = {"bytes": 0.0, "deleted": 0.0, "speedup": 0.0}
    m = _RBYTES_RE.search(out)
    if m:
        stats["bytes"] = float(m.group(1).replace(",", ""))
    m = _RSPEED_RE.search(out)
    if m:
        stats["speedup"] = float(m.group(1))
    deleted_match = re.search(r"Number of deleted files:\s*([0-9]+)", out)
    if deleted_match:
        stats["deleted"] = float(deleted_match.group(1))
    return stats


def _human_bytes(num: float) -> str:
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if num < 1024:
            return f"{num:,.1f} {unit}"
        num /= 1024
    return f"{num:,.1f} PiB"


if __name__ == "__main__":
    raise SystemExit(main())

