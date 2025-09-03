## syncuser
Instead of managing dotfiles and other user config and profile setup in a repo or similar, I only sync them between users and hosts. I found it's interesting and has advantages over managing a file tree or symlinks, apart from the simplicity. The body of configs grows and evolves organically, with always several different versions like, which periodically sync to or from each other.

There are 3 different classes of files I sync with different rules:
- AppConfig folders are mirrored to the other host
- Executables from ~/.local/bin are copied and overwritten, but never deleted
- Dotfiles are copyied when missing, otherwise skipped.
- Certs and Keys are only copied 

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
