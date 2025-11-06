from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Tuple

try:
    import tomllib  # py311+
except Exception:
    import tomli as tomllib  # type: ignore

CONFIG_PATH_DEFAULT = Path("~/.config/syncuser/syncuser_conf.toml").expanduser()


@dataclass(frozen=True)
class General:
    list_dir: Path
    log_file: Path | None
    rsync_bin: str
    dry_run: bool
    verbose: bool
    lan_progress: bool
    show_stats: bool
    exclude: Tuple[str, ...]
    prompt_sudo_passwd: bool  # NEW


@dataclass(frozen=True)
class Module:
    name: str
    list_file: Path
    mirror: bool
    overwrite_if_newer_mtime: bool
    overwrite_all: bool
    backup: bool
    backup_suffix: str | None


def _as_bool(d: dict, key: str, default: bool) -> bool:
    return bool(d.get(key, default))


def load_config(path: Path = CONFIG_PATH_DEFAULT) -> tuple[General, List[Module]]:
    if not path.exists():
        raise SystemExit(f"Config not found: {path}")
    with path.open("rb") as f:
        cfg = tomllib.load(f)

    g = cfg.get("general", {})
    list_dir = Path(g.get("list_dir", "~/.config/syncuser")).expanduser()
    log_file = Path(g["log_file"]).expanduser() if g.get("log_file") else None

    general = General(
        list_dir=list_dir,
        log_file=log_file,
        rsync_bin=g.get("rsync_bin", "/usr/bin/rsync"),
        dry_run=bool(g.get("dry_run", False)),
        verbose=bool(g.get("verbose", True)),
        lan_progress=bool(g.get("lan_progress", False)),
        show_stats=bool(g.get("show_stats", False)),
        exclude=tuple(g.get("exclude", [])),
        prompt_sudo_passwd=bool(g.get("prompt_sudo_passwd", False)),  # NEW
    )

    modules_cfg: Dict[str, dict] = cfg.get("modules", {})
    if not modules_cfg:
        raise SystemExit("No modules defined under [modules]")

    modules: List[Module] = []
    for name, m in modules_cfg.items():
        list_name = m.get("list", f"{name}.list")
        modules.append(
            Module(
                name=name,
                list_file=(general.list_dir / list_name),
                mirror=_as_bool(m, "mirror", False),
                overwrite_if_newer_mtime=_as_bool(m, "overwrite_if_newer_mtime", True),
                overwrite_all=_as_bool(m, "overwrite_all", True),
                backup=_as_bool(m, "backup", False),
                backup_suffix=m.get("backup_suffix"),
            )
        )
    return general, modules
