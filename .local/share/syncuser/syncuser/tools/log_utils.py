# syncuser/tools/log_utils.py
from __future__ import annotations
import os, sys, re
from pathlib import Path

# ---- header buffer / banner lines ----


class StateBuffer:
    def __init__(self, path: Path):
        self.path = path
        self.lines: list[str] = []

    def add(self, line: str) -> None:
        self.lines.append(line)

    def add_kv_pairs(self, pairs: list[tuple[str, str]]) -> None:
        self.lines.extend(kv_lines(pairs).splitlines())

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


# ---- key/value blocks ----


def kv_lines(pairs: list[tuple[str, str]], *, key_width: int = 16) -> str:
    return "\n".join(f"{(k + ':') if k else '':<{key_width}} {v}" for k, v in pairs)


# ---- color & formatting ----

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
    s = s if len(s) == 6 else "".join(ch * 2 for ch in s)  # allow #abc
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
