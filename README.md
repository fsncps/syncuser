# README.toml
# -------------------------------------------------------------------
# syncuser — lightweight dotfile and app config sync utility
# -------------------------------------------------------------------

Instead of managing dotfiles and other user config and profile setup in a repo or similar, I just sync them between users and hosts. Apart from the simplicity, I found it has advantages over managing a file tree or symlinks. The body of configs grows and evolves organically, with always several different versions live, which periodically sync and merge to or from each other.

# -------------------------------------------------------------------
# Installation
# -------------------------------------------------------------------
[install]
requires = ["python >=3.9", "rsync", "ssh"]
steps = [
    "git clone https://internal.lan/repos/syncuser.git",
    "cd syncuser",
    "sudo make install"
]
notes = """
The installer places config templates under ~/.config/syncuser/ and
runtime scripts and a logfile under ~/.local/share/syncuser/.
"""

# -------------------------------------------------------------------
# Usage
# -------------------------------------------------------------------
[usage]
command = "syncuser username[@hostname] [-M name] [-O] [-c path]"
examples = [
    "syncuser alice@hal.local",
    "syncuser bob -M dotfiles",
    "syncuser root@fckp -O -M certs"
]
explanation = """
The target may be local or remote (over SSH). If -M is omitted,
all modules from the config are processed in order.
"""

# -------------------------------------------------------------------
# Options
# -------------------------------------------------------------------
[flags]
"-M" = "Select specific modules (by name) to sync."
"-O" = "One-way sync: overwrite destination without confirmation, regarless of policy."
"-c" = "Use alternate config file instead of default."
"-v" = "Verbose output (per-file transfer info)."
"-n" = "Dry run — show what would be transferred."
"-h" = "Show help and exit."

# -------------------------------------------------------------------
# Configuration
# -------------------------------------------------------------------
[config]
path = "~/.config/syncuser/syncuser_conf.toml"
example = """
[global]
rsync_opts = ["-a", "--delete", "--info=progress2"]
log_dir = "~/.local/share/syncuser/logs"

[[modules]]
name = "dotfiles"
list_file = "~/.config/syncuser/dotfiles.list"
mode = "SOFT"

[[modules]]
name = "appconfig"
list_file = "~/.config/syncuser/appconfig.list"
mode = "MIRROR"
"""
notes = """
Each module defines a list file containing relative or absolute paths.
Modes:
  - SOFT: skip missing files
  - HARD: abort on missing files
  - MIRROR: delete extraneous files on destination
"""

# -------------------------------------------------------------------
# Runtime
# -------------------------------------------------------------------
[runtime]
config_dir = "~/.config/syncuser/"
data_dir = "~/.local/share/syncuser/"
log_dir = "~/.local/share/syncuser/logs/"
executables = [
    "sync_dotfiles.sh",
    "sync_appconfig.sh",
    "sync_certs.sh",
    "main_syncuser.sh"
]
summary = """
syncuser writes detailed logs per run, including transfer statistics
(total files, deletions, bytes sent/received, duration).
"""

# -------------------------------------------------------------------
# Exit codes
# -------------------------------------------------------------------
[exit_codes]
"0" = "Success"
"1" = "Configuration or argument error"
"2" = "Sync or rsync failure"
"3" = "SSH connection failure"

# -------------------------------------------------------------------
# End
# -------------------------------------------------------------------

---
