GO ?= go
RM ?= rm
SCDOC ?= scdoc
GOFLAGS ?=
PREFIX ?= /usr/local
BINDIR ?= bin
MANDIR ?= share/man
SYSCONFDIR ?= /etc
RUNDIR ?= /run

sharedstatedir := /var/lib
config_path := $(SYSCONFDIR)/soju/config
admin_socket_path := $(RUNDIR)/soju/admin
goflags := $(GOFLAGS) -ldflags=" \
	-X 'git.sr.ht/~emersion/soju/config.DefaultPath=$(config_path)' \
	-X 'git.sr.ht/~emersion/soju/config.DefaultUnixAdminPath=$(admin_socket_path)'"
commands := soju sojuctl sojudb
man_pages := doc/soju.1 doc/sojuctl.1

all: $(commands) $(man_pages)

soju:
	$(GO) build $(goflags) -o . ./cmd/soju ./cmd/sojudb ./cmd/sojuctl
sojudb sojuctl: soju
doc/soju.1: doc/soju.1.scd
	$(SCDOC) <doc/soju.1.scd >doc/soju.1
doc/sojuctl.1: doc/sojuctl.1.scd
	$(SCDOC) <doc/sojuctl.1.scd >doc/sojuctl.1

clean:
	$(RM) -f $(commands) $(man_pages)
install:
	mkdir -p $(DESTDIR)$(PREFIX)/$(BINDIR)
	mkdir -p $(DESTDIR)$(PREFIX)/$(MANDIR)/man1
	mkdir -p $(DESTDIR)$(SYSCONFDIR)/soju
	mkdir -p $(DESTDIR)$(sharedstatedir)/soju
	cp -f $(commands) $(DESTDIR)$(PREFIX)/$(BINDIR)
	cp -f $(man_pages) $(DESTDIR)$(PREFIX)/$(MANDIR)/man1
	[ -f $(DESTDIR)$(config_path) ] || cp -f config.in $(DESTDIR)$(config_path)

.PHONY: soju sojudb sojuctl clean install
