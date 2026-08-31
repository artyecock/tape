# Makefile for tape / tape_mount_helper
#
# Targets:
#   make            - build both binaries
#   make install    - build (if needed) and install binaries, udev rules, and man page
#   make clean      - remove built binaries

CC       ?= gcc
CFLAGS   ?= -Wall -Wextra -O2
LDFLAGS  ?=
LIBS     := -lssl -lcrypto

PREFIX      ?= /usr/local
BINDIR      := $(PREFIX)/bin
MANDIR      := $(PREFIX)/share/man/man1
UDEV_RULES_DIR := /etc/udev/rules.d
TMPFILES_DIR   := /etc/tmpfiles.d

TAPE_BIN   := tape
HELPER_BIN := tape_mount_helper
MAN_PAGE   := tape.1
UDEV_RULES := 99-tape-proxy.rules
TMPFILES_CONF := tape.conf

.PHONY: all install clean uninstall

all: $(TAPE_BIN) $(HELPER_BIN)

$(TAPE_BIN): tape.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) $(LIBS)

$(HELPER_BIN): tape_mount_helper.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

install: all
	@echo "Installing binaries to $(BINDIR)..."
	install -d $(BINDIR)
	install -m 4750 -o root -g tapes $(TAPE_BIN) $(BINDIR)/$(TAPE_BIN)
	install -m 755  -o root -g root  $(HELPER_BIN) $(BINDIR)/$(HELPER_BIN)
	@echo "Installing man page to $(MANDIR)..."
	install -d $(MANDIR)
	install -m 644 $(MAN_PAGE) $(MANDIR)/$(MAN_PAGE)
	-mandb >/dev/null 2>&1 || true
	@if [ -f $(UDEV_RULES) ]; then \
		echo "Installing udev rules to $(UDEV_RULES_DIR)..."; \
		install -d $(UDEV_RULES_DIR); \
		install -m 644 $(UDEV_RULES) $(UDEV_RULES_DIR)/$(UDEV_RULES); \
		udevadm control --reload-rules 2>/dev/null || true; \
	fi
	@if [ -f $(TMPFILES_CONF) ]; then \
		echo "Installing tmpfiles.d config to $(TMPFILES_DIR)..."; \
		install -d $(TMPFILES_DIR); \
		install -m 644 $(TMPFILES_CONF) $(TMPFILES_DIR)/$(TMPFILES_CONF); \
		systemd-tmpfiles --create $(TMPFILES_DIR)/$(TMPFILES_CONF) 2>/dev/null || true; \
	fi
	@echo ""
	@echo "Install complete."
	@echo "Note: group 'tapes' must exist before this step for the setuid"
	@echo "install of $(TAPE_BIN) to succeed. Add authorized users with:"
	@echo "  usermod -aG tapes <username>"

uninstall:
	rm -f $(BINDIR)/$(TAPE_BIN) $(BINDIR)/$(HELPER_BIN)
	rm -f $(MANDIR)/$(MAN_PAGE)
	rm -f $(UDEV_RULES_DIR)/$(UDEV_RULES)
	rm -f $(TMPFILES_DIR)/$(TMPFILES_CONF)

clean:
	rm -f $(TAPE_BIN) $(HELPER_BIN)
