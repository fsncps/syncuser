# syncuser/tools/log_utils.py
from __future__ import annotations
import os, sys
from pathlib import Path
from typing import Optional, Tuple, Literal

HEADER_ALIGN = 18  # shared alignment width for all headers

# -------------------------------------------------------------------
# header buffer
# -------------------------------------------------------------------


class StateBuffer:
    def __init__(self, path: Path):
        self.path = path
        self.lines: list[str] = []

    def add(self, line: str) -> None:
        self.lines.append(line)

    def add_kv_pairs(
        self, pairs: list[tuple[str, str]], *, width: int | None = None
    ) -> None:
        self.lines.extend(kv_lines(pairs, width=width).splitlines())

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


def buffer_flush(buf: StateBuffer, logger) -> None:
    for line in buf.lines:
        (logger.title if line.startswith(("┏", "┃", "┗")) else logger.info)(line)


def add_banner(buf: StateBuffer, cfg_path: Path, *, resumed: bool) -> None:
    if resumed:
        return
    buf.add("┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓")
    buf.add("┃                   SYNCUSER                    ┃")
    buf.add("┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛")
    buf.add_kv_pairs([("Config", str(cfg_path))], width=HEADER_ALIGN)


def add_permission_header(
    buf: StateBuffer,
    *,
    is_remote: bool,
    permission_ok: bool,
    mode: str | None = None,
    will_reexec: bool = False,
) -> None:
    """
    Render the aligned Permission header lines.

    - Remote: prints the 'assumed OK' line (preflight skipped).
    - Local & permission_ok: prints '<mode> (OK)'.
    - Local & !permission_ok: prints 'ERROR: Permission denied at target.' and,
      if will_reexec is True, a 'Restarting with sudo…' line.

    No control flow, no return value: main() remains in charge of reexec/exit.
    """
    if is_remote:
        add_permission_remote_assumed(buf)
        return

    if permission_ok:
        add_permission_ok(buf, mode or "-")
        return

    # local + not ok
    add_permission_error(buf, "Permission denied at target.")
    if will_reexec:
        add_permission_restarting(buf)


# -------------------------------------------------------------------
# key/value formatter
# -------------------------------------------------------------------


def kv_lines(pairs: list[tuple[str, str]], *, width: int | None = None) -> str:
    if not pairs:
        return ""
    if width is None:
        width = max(len(k) for k, _ in pairs)
    return "\n".join(f"{k + ':':<{width+2}} {v}" for k, v in pairs)


# -------------------------------------------------------------------
# color helpers (unchanged)
# -------------------------------------------------------------------

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


def _hex_to_rgb(hex_color: str) -> tuple[int, int, int]:
    s = hex_color.strip().lstrip("#")
    s = s if len(s) == 6 else "".join(ch * 2 for ch in s)
    r, g, b = int(s[0:2], 16), int(s[2:4], 16), int(s[4:6], 16)
    return r, g, b


def _isatty(stream) -> bool:
    try:
        return stream.isatty()
    except Exception:
        return False


def supports_color(stream=None) -> bool:
    stream = stream or sys.stderr
    return bool(_isatty(stream) and os.environ.get("TERM", "") != "dumb")


def supports_truecolor() -> bool:
    ct = (os.environ.get("COLORTERM", "") or "").lower()
    if "truecolor" in ct or "24bit" in ct:
        return True
    if os.environ.get("TERM_PROGRAM") in {"iTerm.app", "WezTerm", "Apple_Terminal"}:
        return True
    if os.environ.get("WT_SESSION"):
        return True
    return "tmux" in (os.environ.get("TERM") or "") and ("truecolor" in ct)


def colorize(text: str, fg: str | None = None, *, bold: bool = False) -> str:
    seq = ["1"] if bold else []
    if fg:
        if fg.startswith("#"):
            if supports_truecolor():
                r, g, b = _hex_to_rgb(fg)
                seq.append(f"38;2;{r};{g};{b}")
            else:
                try:
                    r, g, b = _hex_to_rgb(fg)
                    code = (
                        31
                        if r > 200 and g < 80
                        else (
                            33
                            if r > 200 and g > 160
                            else (
                                32
                                if g > 160 and r < 80
                                else 34 if b > 160 and r < 80 else 37
                            )
                        )
                    )
                except Exception:
                    code = 37
                seq.append(str(code))
        else:
            code = ANSI_SIMPLE_FG.get(fg.lower())
            if code is not None:
                seq.append(str(code))
    return f"\x1b[{';'.join(seq)}m{text}{ANSI_RESET}" if seq else text


# -------------------------------------------------------------------
# high-level header helpers
# -------------------------------------------------------------------


def add_local_session(buf: StateBuffer) -> None:
    buf.add_kv_pairs(
        [("Host", "(local)"), ("Logon", "Local session")],
        width=HEADER_ALIGN,
    )


def add_preflight(
    buf: StateBuffer, *, host: str, remote_user: str, route: str, ssh_up: bool
) -> None:
    buf.add_kv_pairs(
        [
            ("Host", host or "?"),
            ("Remote user", remote_user),
            ("Route to host", route),
            ("SSH port 22", "open" if ssh_up else "closed/unreachable"),
            ("Logon", "attempting keyfile logon.."),
        ],
        width=HEADER_ALIGN,
    )


def add_logon_result(buf: StateBuffer, message: str) -> None:
    buf.add_kv_pairs([("Logon", message)], width=HEADER_ALIGN)


def add_identity(
    buf: StateBuffer, *, sudo_active: bool, target_header_path: str, where: str
) -> None:
    buf.add_kv_pairs(
        [
            ("SUDO", "YES" if sudo_active else "NO"),
            ("Target", f"{target_header_path} ({where})"),
        ],
        width=HEADER_ALIGN,
    )


# ---- permission lines ----


def add_permission_ok(buf: StateBuffer, mode: str) -> None:
    buf.add_kv_pairs([("Permission", f"{mode} (OK)")], width=HEADER_ALIGN)


def add_permission_error(buf: StateBuffer, message: str) -> None:
    buf.add_kv_pairs([("Permission", f"ERROR: {message}")], width=HEADER_ALIGN)


def add_permission_restarting(buf: StateBuffer) -> None:
    buf.add_kv_pairs([("Permission", "Restarting with sudo…")], width=HEADER_ALIGN)


def add_permission_remote_assumed(buf: StateBuffer) -> None:
    buf.add_kv_pairs(
        [("Permission", "assumed OK (remote target preflight skipped)")],
        width=HEADER_ALIGN,
    )


# ---- runtime flags ----


def add_runtime_flags(
    buf: StateBuffer, *, modules: list[str] | None, overwrite: bool, dry_run: bool
) -> None:
    kv: list[Tuple[str, str]] = []
    mod_value = "all" if not modules else ", ".join(modules)
    kv.append(("Modules", mod_value))
    if overwrite:
        kv.append(("Overwrite All", "YES (override policy)"))
    if dry_run:
        kv.append(("Dry Run", "YES (simulate transfers)"))
    if kv:
        buf.add_kv_pairs(kv, width=HEADER_ALIGN)


# -------------------------------------------------------------------
# dry-run tag helpers
# -------------------------------------------------------------------


def dryrun_suffix(enabled: bool) -> str:
    return " -- [DRY RUN]" if enabled else ""


def with_dry_tag(msg: str, *, dry_run: bool) -> str:
    return f"{msg}{dryrun_suffix(dry_run)}"
