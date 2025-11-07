from __future__ import annotations
import argparse, os, sys, time
from dataclasses import replace
from pathlib import Path
from typing import List

from .config import load_config
from .log import setup_logging
from .tools import ssh, identity, misc, log_utils
from .sync import build_rsync_cmd, run_capture, parse_stats, parse_itemize

ELEVATION_ENV_FLAG = "SYNCUSER_ELEVATED"
STATE_ENV = "SYNCUSER_STATE_FILE"
SYNCUSER_BASE = os.environ.get("SYNCUSER_BASE") or os.path.expanduser(
    "~/.local/share/syncuser"
)


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
    t = misc.parse_target(args.target)
    args.target_user, args.target_host = t.user, t.host
    return args


def main() -> int:
    args = parse_args()

    # ---- invoker and HOME pinning ----
    src_user = identity.invoking_user()
    src_home = identity.resolve_home(user=src_user, host=None)
    os.environ["HOME"] = src_home
    os.environ.setdefault("XDG_CONFIG_HOME", str(Path(src_home) / ".config"))

    # ---- config path (pin to invoker if default used) ----
    default_cfg = Path("~/.config/syncuser/syncuser_conf.toml").expanduser()
    if args.config == default_cfg:
        args.config = misc.expand_for_invoker(args.config, src_home=src_home)
    cfg_path = Path(args.config)

    # ---- load config ----
    g, modules = load_config(cfg_path)
    modules = [
        replace(m, list_file=misc.expand_for_invoker(m.list_file, src_home=src_home))
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

    # ---- buffered header ----
    state_file = (
        Path(os.environ.get(STATE_ENV, ""))
        if os.environ.get(STATE_ENV)
        else Path(src_home) / ".local/state/syncuser/header.tmp"
    )
    buf = log_utils.StateBuffer(state_file)
    resumed_lines = buf.read_and_clear()
    if resumed_lines:
        buf.lines.extend(resumed_lines)
    resumed = bool(resumed_lines)
    log_utils.add_banner(buf, cfg_path, resumed=resumed)

    control_path: str | None = None
    try:
        # ---- deps ----
        misc.ensure_deps(g.rsync_bin)
        if args.target_host:
            misc.ensure_deps("ssh")

        ssh_extra: list[str] = []

        # ---- remote preflight or local note ----
        if args.target_host:
            try:
                ssh_extra, control_path = ssh.preflight_connect(
                    args.target_user,
                    args.target_host,
                    buf=buf,
                    resumed=resumed,
                    persist="15m",
                )
            except ssh.PreflightFailure as e:
                log_utils.buffer_flush(buf, logger)
                logger.error(e.message)
                return e.exit_code
        else:
            if not resumed:
                buf.add_kv_pairs([("Host", "(local)"), ("Logon", "Local session")])

        # ---- destination identity ----
        dest_home, dest_group = identity.resolve_dest(
            args.target_user, args.target_host, ssh_extra=ssh_extra
        )

        # ---- sudo allowance ----
        if args.target_host:
            pwless = identity.has_passwordless_sudo_remote(args.target_user, args.target_host, ssh_extra=ssh_extra)  # type: ignore[arg-type]
        else:
            pwless = identity.has_passwordless_sudo_local()
        sudo_allowed = pwless or args.sudo or g.prompt_sudo_passwd

        # ---- header SUDO/Target + local perm handling ----
        where = "remote" if args.target_host else "local"
        target_header_path = (
            f"{args.target_user}@{args.target_host}:{dest_home}"
            if args.target_host
            else dest_home
        )
        sudo_active = identity.is_unix_root()
        buf.add_kv_pairs(
            [
                ("SUDO", "YES" if sudo_active else "NO"),
                ("Target", f"{target_header_path} ({where})"),
            ]
        )

        if args.target_host is None:
            mode, ok, exists = identity.local_perm_info(
                dest_home, sudo_active=sudo_active
            )
            if not exists:
                log_utils.buffer_flush(buf, logger)
                logger.error(f"Target does not exist: {dest_home}")
                return 1
            if ok:
                buf.add(f"Permission:      {mode} (OK)")
            else:
                if sudo_allowed:
                    buf.add("Permission:      ERROR: Permission denied at target.")
                    buf.add("Permission:      Restarting with sudo…")
                    os.environ[STATE_ENV] = str(state_file)
                    buf.write_and_close()
                    identity.reexec_with_sudo(
                        extra_args=["--sudo", *sys.argv[1:]],
                        base=SYNCUSER_BASE,
                        elevation_flag=ELEVATION_ENV_FLAG,
                        state_env=STATE_ENV,
                    )
                else:
                    log_utils.buffer_flush(buf, logger)
                    logger.error(
                        "Permission:      ERROR: Permission denied at target and sudo not allowed."
                    )
                    return 5
        else:
            if not dest_home:
                log_utils.buffer_flush(buf, logger)
                logger.error(
                    f"Could not resolve remote home for {args.target_user}@{args.target_host}"
                )
                return 1
            buf.add("Permission:      assumed OK (remote target preflight skipped)")

        # ---- flush header once ----
        if not args.silent:
            log_utils.buffer_flush(buf, logger)

        # ---- module filter ----
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
        if (
            (args.target_host is None)
            and (args.target_user != identity.invoking_user())
            and sudo_allowed
        ):
            sudo_prefix = ["sudo", "--"]

        # remote rsync-path (sudo on the remote if allowed)
        rsync_path = "sudo rsync" if (args.target_host and sudo_allowed) else None

        rc_all = 0

        try:
            for m in modules:
                logger.title(f"\n=== Module: {m.name} ===")

                items_raw = misc.read_list_file(m.list_file)
                if not items_raw:
                    logger.warning(f"(skip) list empty: {m.list_file}")
                    continue

                for raw in items_raw:
                    disp = raw.strip()
                    abs_src = misc.expand_for_source(disp, src_home)

                    if not misc.path_is_under(abs_src, src_home):
                        logger.error(
                            f"{disp}: must reside under source home {src_home}. Skipping."
                        )
                        continue

                    abs_dst = misc.map_src_to_dest(
                        abs_src, src_home, dest_home
                    ).replace("$HOME", dest_home)

                    src_is_file = Path(abs_src).is_file()
                    src_exists = Path(abs_src).exists()
                    src_mtime = misc.src_file_mtime(abs_src) if src_is_file else None

                    dest_existed_before = ssh.dest_path_exists(args.target_user, args.target_host, abs_dst, ssh_extra=ssh_extra)  # type: ignore[arg-type]
                    dest_mtime_before = ssh.dest_file_mtime(args.target_user, args.target_host, abs_dst, ssh_extra=ssh_extra) if src_is_file else None  # type: ignore[arg-type]

                    dst_path_for_rsync = (
                        f"{args.target_user}@{args.target_host}:{abs_dst}"
                        if args.target_host
                        else abs_dst
                    )

                    total_files = misc.count_sync_files(Path(abs_src), tuple(g.exclude))

                    chown_str = (
                        f"{args.target_user}:{dest_group}" if sudo_allowed else None
                    )
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

                    stats = misc.extract_summary_stats(combined)
                    total_transferred_bytes += stats["bytes"]
                    total_deleted_files += int(stats["deleted"])

                    if is_dir:
                        copied = created_count + updated_count
                        if copied == 0:
                            copied = transferred_stats
                        deleted_total = deleted_stats
                        skipped = max(0, total_files - copied) if total_files > 0 else 0
                        msg = f"{misc.resolve_env_path(disp)}: DIR; {copied} copied, {deleted_total} deleted, {skipped} skipped.{chown_note}"
                        (logger.transfer if copied > 0 else logger.notice)(msg)
                    else:
                        source_missing = not src_exists
                        if source_missing:
                            if m.mirror and deleted_count > 0 and rc == 0:
                                logger.notice(
                                    f"{misc.resolve_env_path(disp)}: Target obsolete. DELETED file.{chown_note}"
                                )
                            else:
                                logger.warning(
                                    f"{misc.resolve_env_path(disp)}: Neither source nor target file found. SKIPPING."
                                )
                        else:
                            transferred_any = (
                                created_count + updated_count
                            ) > 0 or transferred_stats > 0
                            if transferred_any:
                                if not dest_existed_before:
                                    logger.transfer(
                                        f"{misc.resolve_env_path(disp)}: Target not found. CREATED new file.{chown_note}"
                                    )
                                else:
                                    logger.transfer(
                                        f"{misc.resolve_env_path(disp)}: Target out of date. UPDATED file.{chown_note}"
                                    )
                            else:
                                if dest_existed_before:
                                    logger.notice(
                                        f"{misc.resolve_env_path(disp)}: Target identical, SKIPPED file."
                                    )
                                else:
                                    logger.notice(
                                        f"{misc.resolve_env_path(disp)}: SKIPPED file."
                                    )

                    if rc != 0:
                        rc_all = rc

        except PermissionError:
            raise
        except OSError as e:
            import errno as _errno

            if (
                e.errno == _errno.EACCES
                and (args.target_host is None)
                and not identity.is_unix_root()
            ):
                os.environ[STATE_ENV] = str(state_file)
                buf.add("Permission:   ERROR during operation; restarting with sudo…")
                buf.write_and_close()
                identity.reexec_with_sudo(
                    extra_args=["--sudo", *sys.argv[1:]],
                    base=SYNCUSER_BASE,
                    elevation_flag=ELEVATION_ENV_FLAG,
                    state_env=STATE_ENV,
                )
            raise

        elapsed = time.time() - start_time
        logger.title("\n=== Summary ===")
        logger.info(
            log_utils.kv_lines(
                [
                    ("Modules processed", str(len(modules))),
                    ("Directories synced", str(total_dirs)),
                    ("Files processed", str(total_files)),
                    ("Files deleted", str(total_deleted_files)),
                    ("Payload transferred", misc.human_bytes(total_transferred_bytes)),
                    ("Elapsed time", f"{elapsed:,.1f} s"),
                    (
                        "Average throughput",
                        (
                            (misc.human_bytes(total_transferred_bytes / elapsed) + "/s")
                            if elapsed > 0
                            else "n/a"
                        ),
                    ),
                ]
            )
        )
        return rc_all

    finally:
        if control_path:
            ssh.stop_ssh_master(control_path)


if __name__ == "__main__":
    raise SystemExit(main())
