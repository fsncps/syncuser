from __future__ import annotations
import logging
import sys
from pathlib import Path
from .tools import supports_color, colorize

try:
    import colorama  # type: ignore

    colorama.just_fix_windows_console()
except Exception:
    pass

# ----- custom levels -----
TITLE_LVL = 15  # between DEBUG (10) and INFO (20)
TRANSFER_LVL = 22  # between INFO (20) and WARNING (30)
NOTICE_LVL = 25  # between WARNING (30) and ERROR (40)

logging.addLevelName(TITLE_LVL, "TITLE")
logging.addLevelName(TRANSFER_LVL, "TRANSFER")
logging.addLevelName(NOTICE_LVL, "NOTICE")


def _logger_title(self, msg, *args, **kwargs):
    if self.isEnabledFor(TITLE_LVL):
        self._log(TITLE_LVL, msg, args, **kwargs)


def _logger_transfer(self, msg, *args, **kwargs):
    if self.isEnabledFor(TRANSFER_LVL):
        self._log(TRANSFER_LVL, msg, args, **kwargs)


def _logger_notice(self, msg, *args, **kwargs):
    if self.isEnabledFor(NOTICE_LVL):
        self._log(NOTICE_LVL, msg, args, **kwargs)


logging.Logger.title = _logger_title  # type: ignore[attr-defined]
logging.Logger.transfer = _logger_transfer  # type: ignore[attr-defined]
logging.Logger.notice = _logger_notice  # type: ignore[attr-defined]


# ----- coloring policy -----
# Console colors (hex) per level
CONSOLE_LINE_COLORS = {
    "TRANSFER": "#94e2d5",
    "NOTICE": "#f9e2af",
    "WARNING": "#ef9f76",
    "ERROR": "#e78284",
}

TITLE_FG = "#eff1f5"
INFO_FG = "#e6e9ef"

TIME_FMT = "%Y-%m-%d %H:%M:%S"
FULL_FMT = "%(asctime)s %(levelname)s %(message)s"
BANNER_FMT = "%(message)s"


class ColorFormatter(logging.Formatter):
    """
    Console formatter:
      - TITLE: bold, colored message only (no ts/level)
      - INFO : colored message only (no ts/level)
      - Others (NOTICE/TRANSFER/WARNING/ERROR): full line with ts/level, whole line colored
    """

    def __init__(self, fmt: str, datefmt: str | None, enable_color: bool):
        super().__init__(fmt=fmt, datefmt=datefmt)
        self.enable_color = enable_color

    def format(self, record: logging.LogRecord) -> str:
        # --- pad levelname so output aligns neatly ---
        max_len = 8  # or compute dynamically if you prefer
        record.levelname = f"{record.levelname:<{max_len}}"

        # TITLE banner: bold, no timestamp/level
        if record.levelno == TITLE_LVL:
            msg = record.getMessage()
            if self.enable_color:
                msg = colorize(msg, fg=TITLE_FG, bold=True)
            return msg

        # INFO banner: non-bold, no timestamp/level
        if record.levelno == logging.INFO and self._fmt == BANNER_FMT:
            msg = record.getMessage()
            if self.enable_color:
                msg = colorize(msg, fg=INFO_FG, bold=False)
            return msg

        # normal coloring path
        line = super().format(record)
        if self.enable_color:
            fg = CONSOLE_LINE_COLORS.get(record.levelname.strip())
            if fg:
                return colorize(line, fg=fg, bold=False)
        return line


class BannerAwareConsole(logging.StreamHandler):
    """
    Console handler:
      - TITLE printed with BANNER_FMT (no ts/level), bold, #eff1f5
      - INFO  printed with BANNER_FMT (no ts/level), non-bold, #e6e9ef
      - Others printed with FULL_FMT + TIME_FMT, whole line colored per level
    """

    def __init__(self, color_ok: bool):
        super().__init__()
        self.color_ok = color_ok
        self.banner_fmt = ColorFormatter(BANNER_FMT, None, enable_color=color_ok)
        self.full_fmt = ColorFormatter(FULL_FMT, TIME_FMT, enable_color=color_ok)

    def emit(self, record: logging.LogRecord) -> None:  # type: ignore[override]
        if record.levelno in (TITLE_LVL, logging.INFO):
            self.setFormatter(self.banner_fmt)
        else:
            self.setFormatter(self.full_fmt)
        super().emit(record)


class ExcludeLevelFilter(logging.Filter):
    """Filter out a specific level (used to drop TITLE from file logs)."""

    def __init__(self, levelno: int):
        super().__init__()
        self.levelno = levelno

    def filter(self, record: logging.LogRecord) -> bool:  # type: ignore[override]
        return record.levelno != self.levelno


def setup_logging(
    log_file: Path | None, verbose: bool, silent: bool = False
) -> logging.Logger:
    """
    - silent=True  -> no console/file output
    - verbose=True -> console DEBUG, file DEBUG
    - verbose=False-> console INFO+ (incl. TITLE), file DEBUG (if provided)
    """
    log = logging.getLogger("syncuser")
    log.setLevel(logging.DEBUG)
    log.propagate = False
    for h in list(log.handlers):
        log.removeHandler(h)

    if silent:
        log.addHandler(logging.NullHandler())
        return log

    # Console
    color_ok = supports_color(sys.stderr)
    ch = BannerAwareConsole(color_ok)
    ch.setLevel(
        logging.DEBUG if verbose else TITLE_LVL
    )  # includes TITLE + INFO; hides DEBUG unless verbose
    log.addHandler(ch)

    # File
    if log_file:
        log_path = Path(log_file).expanduser()
        log_path.parent.mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(log_path, encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fh.addFilter(ExcludeLevelFilter(TITLE_LVL))  # hide TITLE in file
        fh.setFormatter(
            logging.Formatter(FULL_FMT, TIME_FMT)
        )  # INFO and others are timestamped in file
        log.addHandler(fh)

    return log
