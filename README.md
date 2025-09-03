## syncuser
Instead of managing dotfiles and other user config and profile setup in a repo or similar, I just sync them between users and hosts. Apart from the simplicity, I found it has advantages over managing a file tree or symlinks. The body of configs grows and evolves organically, with always several different versions live, which periodically sync and merge to or from each other.

There are 4 different classes of files I rsync with different rules:
- **AppConfig** folders are mirrored to the other host
- **Executables** (mostly from ~/.local/bin) are copied and overwritten, but nothing is detleted.
- **Dotfiles** are copyied and overwritten when they are newer than the version in the target profile.
- **Certs and Keys** are only copied 

## Install & run
Clone repo, then run install.sh. After that:

```bash
$ syncuser --help
Usage: syncuser dest_user[@dest_host] [options]

Options:
  -M, --MODULE {appconfig|dotfiles|certs|bin}  (can be repeated)
  -O, --OVERWRITE                              force overwrite for selected modules
  -h, --help

Examples:
syncuser alice@ace
  syncuser alice
  syncuser alice@ace -M bin
  syncuser alice@ace -M appconfig -O
```
---
