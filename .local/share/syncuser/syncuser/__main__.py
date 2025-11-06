# __main__.py (drop-in)
from __future__ import annotations
import argparse, os, pwd, sys, errno, subprocess
from dataclasses import replace
from pathlib import Path
from typing import List
import time
import re

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

ELEVATION_ENV_FLAG = "SYNCUSER_ELEVATED"


def _render_header(
    *,
    target_path: str,
    where: str,
    host_hdr: str,
    config_path: Path,
    dry_run: bool,
    modules_selected: list[str] | None,
    overwrite: bool,
    sudo_mode: str,
) -> str:
    lines: list[str] = []
    lines.append(f"SUDO   : {sudo_mode}")
    lines.append(f"Target : {target_path} ({where})")
    if dry_run:
        lines.append("DRY RUN. rsync transfer forecast only.")
    if modules_selected:
        lines.append(f"Modules: {', '.join(modules_selected)}")
    if overwrite:
        lines.append("OVERWRITING EVERYTHING.")
    return "\n".join(lines)


def _module_title(name: str) -> str:
    return f"\n=== Module: {name} ==="


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
        import pwd  # lazy import for windows compat
        return pwd.getpwuid(os.getuid()).pw_name  # type: ignore[attr-defined]
    except Exception:
        return os.environ.get("USER") or "unknown"


def _host_header(host: str | None) -> str:
    if host is None:
        return "localhost"
    if is_ip_literal(host):
        return host
    ip = resolve_host_ip(host)
    return f"{host} [{ip}]" if ip else host


_RSPEED_RE = re.compile(r"speedup is ([0-9.]+)", re.I)
_RBYTES_RE = re.compile(r"Total transferred file size:\s*([\d,]+) bytes", re.I)


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


def _is_local_target(host: str | None) -> bool:
    return host is None


def _is_unix_root() -> bool:
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def _reexec_with_sudo(argv: list[str], *, log, reason_path: str | None = None) -> "NoReturn":
    if os.environ.get(ELEVATION_ENV_FLAG) == "1":
        log.error("Elevation loop detected; already attempted sudo. Aborting.")
        raise SystemExit(1)
    if reason_path:
        log.error(f"{reason_path}: Permission denied.")
    log.notice("Resetting application with --sudo flag...")
    new_env = dict(os.environ)
    new_env[ELEVATION_ENV_FLAG] = "1"
    py = sys.executable
    new_argv = argv[1:]
    if "--sudo" not in new_argv and "-S" not in new_argv:
        new_argv = ["--sudo", *new_argv]
    cmd = ["sudo", "-E", py, "-m", "syncuser", *new_argv]
    os.execve("/usr/bin/sudo", cmd, new_env)


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


def main() -> int:
    args = parse_args()
    g, modules = load_config(args.config)

    start_time = time.time()
    total_transferred_bytes = 0.0
    total_deleted_files = 0
    total_dirs = 0
    total_files = 0

    effective_verbose = (not args.no_verbose) and g.verbose and (not args.silent)
    g = replace(g, dry_run=(args.dry_run or g.dry_run), verbose=effective_verbose)

    log = setup_logging(g.log_file, g.verbose, silent=args.silent)

    control_path: str | None = None
    try:
        # --- deps & reachability ---
        ensure_deps(g.rsync_bin)
        if args.target_host:
            ensure_deps("ssh")

            # Early status block
            if not args.silent:
                host_hdr = _host_header(args.target_host)
                box = [
                    "┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓",
                    "┃                   SYNCUSER                    ┃",
                    "┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛",
                ]
                log.title("\n".join(box))

                icmp_ok, rtt = ping_rtt_ms(args.target_host, timeout_s=1.5)
                route = f"online (ping {rtt} ms)" if (icmp_ok and rtt is not None) else "ICMP blocked or unknown"
                ssh_up = tcp_port_open(args.target_host, 22, timeout_s=2.0)
                ssh_line = "open" if ssh_up else "closed/unreachable"

                log.info(_kv_lines([
                    ("Config",       str(args.config)),
                    ("Host",         host_hdr),
                    ("Remote user",  args.target_user),
                    ("Route to host",route),
                    ("SSH port 22",  ssh_line),
                    ("Logon",        "attempting keyfile logon.."),
                ]))


            if not tcp_port_open(args.target_host, 22, timeout_s=2.0):
                if not args.silent:
                    log.error(f"Cannot reach SSH on {args.target_host}:22 (user {args.target_user}).")
                return 3

            keys_ok = ssh_key_auth_works(args.target_user, args.target_host, timeout_s=4.0)
            if not args.silent:
                log.info(_kv_lines([("Logon", "Key-based auth: OK." if keys_ok else "Key-based auth: not available. Will allow password prompt.")]))

            # Bring up ControlMaster now (this is where password prompt happens if keys fail)
            try:
                control_path = start_ssh_master(args.target_user, args.target_host, persist="15m")
                if not args.silent:
                    log.info(_kv_lines([("Logon", "Authenticated. SSH ControlMaster active.")]))
            except subprocess.CalledProcessError:
                if not args.silent:
                    log.error("Authentication failed before remote queries (ControlMaster setup).")
                return 4

        # ----- Resolve identities/homes -----
        src_user = _invoking_user()
        src_home = resolve_home(user=src_user, host=None)

        ssh_extra = ssh_opts_with_control(control_path) if args.target_host else []

        dest_home = resolve_home(user=args.target_user, host=args.target_host, ssh_extra=ssh_extra)  # type: ignore[arg-type]
        dest_group = resolve_primary_group(user=args.target_user, host=args.target_host, ssh_extra=ssh_extra)  # type: ignore[arg-type]

        # --- EARLY ELEVATION for local runs ---
        if _is_local_target(args.target_host) and not _is_unix_root():
            needs_elevate = args.target_user != src_user
            try:
                if not os.path.exists(dest_home) or not os.access(dest_home, os.R_OK):
                    needs_elevate = True
            except Exception:
                needs_elevate = True
            pwless_local = has_passwordless_sudo_local()
            may_prompt = args.sudo or g.prompt_sudo_passwd
            if needs_elevate and (pwless_local or may_prompt):
                _reexec_with_sudo(sys.argv, log=log, reason_path=dest_home)

        # --- sudo capability (for banner + rsync) ---
        if args.target_host:
            pwless = has_passwordless_sudo_remote(args.target_user, args.target_host, ssh_extra=ssh_extra)  # type: ignore[arg-type]
        else:
            pwless = has_passwordless_sudo_local()
        sudo_allowed = pwless or args.sudo or g.prompt_sudo_passwd
        sudo_mode = "YES" if (pwless or _is_unix_root()) else ("YES (prompt)" if sudo_allowed else "NO")

        # --- header ---
        if not args.silent:
            where = "remote" if args.target_host else "local"
            target_header_path = f"{args.target_user}@{args.target_host}:{dest_home}" if args.target_host else dest_home
            header_pairs = [
                ("SUDO",   sudo_mode),
                ("Target", f"{target_header_path} ({where})"),
            ]
            if g.dry_run:
                header_pairs.append(("Note", "DRY RUN. rsync transfer forecast only."))
            if args.module:
                header_pairs.append(("Modules", ", ".join(m.name for m in modules)))
            if args.overwrite:
                header_pairs.append(("Note", "OVERWRITING EVERYTHING."))
            log.info(_kv_lines(header_pairs))


        # --- filter modules ---
        if args.module:
            wanted = set(args.module)
            modules = [m for m in modules if m.name in wanted]
            if not modules:
                if not args.silent:
                    log.error(f"No matching modules for: {', '.join(sorted(wanted))}")
                return 2

        echo_cmd = g.verbose and (not args.silent)
        echo_rsync = g.verbose and (not args.silent)

        # local sudo prefix
        sudo_prefix: List[str] = []
        if not args.target_host and (args.target_user != src_user) and sudo_allowed:
            sudo_prefix = ["sudo", "--"]

        # remote rsync-path (sudo on the remote if allowed)
        rsync_path = "sudo rsync" if (args.target_host and sudo_allowed) else None

        rc_all = 0

        try:
            for m in modules:
                if not args.silent:
                    log.title(_module_title(m.name))

                items_raw = read_list_file(m.list_file)
                if not items_raw:
                    if not args.silent:
                        log.info(f"(skip) list empty: {m.list_file}")
                    continue

                for raw in items_raw:
                    disp = raw.strip()
                    abs_src = _expand_for_source(disp, src_home)

                    # ensure mapping from src_home
                    if not Path(abs_src).resolve().is_relative_to(Path(src_home).resolve()):
                        if not args.silent:
                            log.error(f"{disp}: must reside under source home {src_home}. Skipping.")
                        continue

                    abs_dst = map_src_to_dest(abs_src, src_home, dest_home).replace("$HOME", dest_home)

                    # Preflight for single-file classification
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
                        ssh_extra=ssh_extra,  # ensure rsync reuses the ControlMaster
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
                        if not args.silent:
                            if copied > 0:
                                log.transfer(f"{disp}: DIR; {copied} copied, {deleted_total} deleted, {skipped} skipped.{chown_note}")
                            elif deleted_total > 0:
                                log.notice(f"{disp}: DIR; {copied} copied, {deleted_total} deleted, {skipped} skipped.{chown_note}")
                            else:
                                log.info(f"{disp}: DIR; {copied} copied, {deleted_total} deleted, {skipped} skipped.{chown_note}")
                    else:
                        source_missing = not src_exists
                        if source_missing:
                            if m.mirror and deleted_count > 0 and rc == 0:
                                if not args.silent:
                                    log.notice(f"{disp}: Target obsolete. DELETED file.{chown_note}")
                            else:
                                if not args.silent:
                                    log.warning(f"{disp}: Neither source nor target file found. SKIPPING.")
                        else:
                            transferred_any = (created_count + updated_count) > 0 or transferred_stats > 0
                            if transferred_any:
                                if not dest_existed_before:
                                    if not args.silent:
                                        log.transfer(f"{disp}: Target not found. CREATED new file.{chown_note}")
                                else:
                                    if (
                                        src_mtime is not None
                                        and dest_mtime_before is not None
                                        and src_mtime > dest_mtime_before
                                    ):
                                        if not args.silent:
                                            log.transfer(f"{disp}: Target out of date. UPDATED file.{chown_note}")
                                    else:
                                        if not args.silent:
                                            log.transfer(f"{disp}: Target out of date. UPDATED file.{chown_note}")
                            else:
                                if dest_existed_before:
                                    if (
                                        src_mtime is not None
                                        and dest_mtime_before is not None
                                        and src_mtime <= dest_mtime_before
                                    ):
                                        if not args.silent:
                                            log.info(f"{disp}: Target identical, SKIPPED file.")
                                    else:
                                        if not args.silent:
                                            log.info(f"{disp}: Target identical, SKIPPED file.")
                                else:
                                    if not args.silent:
                                        log.info(f"{disp}: SKIPPED file.")
                    if rc != 0:
                        rc_all = rc

        except PermissionError as e:
            if _is_local_target(args.target_host) and not _is_unix_root():
                _reexec_with_sudo(sys.argv, log=log, reason_path=(e.filename or "Filesystem access"))
            raise
        except OSError as e:
            if (
                e.errno == errno.EACCES
                and _is_local_target(args.target_host)
                and not _is_unix_root()
            ):
                _reexec_with_sudo(sys.argv, log=log, reason_path=getattr(e, "filename", "Filesystem access"))
            raise

        elapsed = time.time() - start_time
        log.title("\n=== Summary ===")
        log.info(_kv_lines([
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


if __name__ == "__main__":
    raise SystemExit(main())

