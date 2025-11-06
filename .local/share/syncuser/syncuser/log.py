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

# ----- levels -----
TITLE_LVL = 15  # custom (between DEBUG and INFO)
TRANSFER_LVL = 22  # custom
NOTICE_LVL = 25  # custom

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


class ColorFormatter(logging.Formatter):
    """
    Console coloring:
      TITLE   -> white, bold, no timestamp/level
      INFO    -> white, non-bold, no timestamp/level   (banner lines)
      DEBUG   -> white
      TRANSFER-> green
      NOTICE  -> sand
      WARNING -> amber
      ERROR   -> red
      CRITICAL-> red, bold
    """

    COLORS = {
        # "TITLE": "#ffffff",
        # "INFO": "#ffffff",
        # "DEBUG": "#ffffff",
        "TRANSFER": "#a6da95",
        "NOTICE": "#e5c890",
        "WARNING": "#f5c542",
        "ERROR": "#e78284",
        "CRITICAL": "#e78284",
    }

    def __init__(
        self,
        fmt: str,
        datefmt: str | None = None,
        enable: bool = True,
        for_banner: bool = False,
    ):
        super().__init__(fmt, datefmt)
        self.enable = enable
        self.for_banner = for_banner

    def format(self, record: logging.LogRecord) -> str:
        # Banner lines (TITLE / INFO): raw message, styled, no ts/level on console
        if self.for_banner and record.levelname in ("TITLE", "INFO"):
            msg = record.getMessage()
            if self.enable:
                bold = record.levelname == "TITLE"
                msg = colorize(msg, bold=bold)
            return msg

        if not self.enable:
            return super().format(record)

        orig_level = record.levelname
        color = self.COLORS.get(orig_level)
        try:
            if color:
                bold = record.levelno >= logging.CRITICAL or orig_level == "TITLE"
                record.levelname = colorize(orig_level, fg=color, bold=bold)
            return super().format(record)
        finally:
            record.levelname = orig_level


class _BannerAwareConsole(logging.StreamHandler):
    """Console handler: TITLE/INFO without timestamp/level; others colored & timestamped."""

    def __init__(self, color_ok: bool, fmt_default: str, fmt_banner: str) -> None:
        super().__init__()
        self._color_ok = color_ok
        self._fmt_default = fmt_default
        self._fmt_banner = fmt_banner

    def emit(self, record: logging.LogRecord) -> None:  # type: ignore[override]
        if record.levelname in ("TITLE", "INFO"):
            self.setFormatter(
                ColorFormatter(self._fmt_banner, enable=self._color_ok, for_banner=True)
            )
        else:
            self.setFormatter(ColorFormatter(self._fmt_default, enable=self._color_ok))
        super().emit(record)


class _ExcludeLevelFilter(logging.Filter):
    """Filter out a specific level from a handler (used to drop TITLE from file)."""

    def __init__(self, levelno: int) -> None:
        super().__init__()
        self.levelno = levelno

    def filter(self, record: logging.LogRecord) -> bool:  # type: ignore[override]
        return record.levelno != self.levelno


def setup_logging(
    log_file: Path | None, verbose: bool, silent: bool = False
) -> logging.Logger:
    """
    - silent=True  -> no console/file output at all
    - verbose=True -> console DEBUG, file DEBUG
    - verbose=False-> console INFO (but include TITLE/INFO banners), file DEBUG (if log_file set)
    """
    log = logging.getLogger("syncuser")
    log.setLevel(logging.DEBUG)
    log.propagate = False
    for h in list(log.handlers):
        log.removeHandler(h)

    if silent:
        log.addHandler(logging.NullHandler())
        return log

    fmt_default = "%(asctime)s [%(levelname)s] %(message)s"
    fmt_banner = "%(message)s"

    # console
    color_ok = supports_color(sys.stderr)
    ch = _BannerAwareConsole(color_ok, fmt_default, fmt_banner)
    ch.setLevel(logging.DEBUG if verbose else TITLE_LVL)
    log.addHandler(ch)

    # file
    if log_file:
        log_path = Path(log_file).expanduser()
        log_path.parent.mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(log_path, encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fh.addFilter(
            _ExcludeLevelFilter(TITLE_LVL)
        )  # exclude TITLE only; keep INFO banners
        fh.setFormatter(logging.Formatter(fmt_default))
        log.addHandler(fh)

    return log
