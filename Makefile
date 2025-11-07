.PHONY: install reinstall uninstall

install:
	./install.sh

reinstall:
	./install.sh --recreate-venv

uninstall:
	./install.sh --uninstall

