GO ?= go
RM ?= rm
SCDOC ?= scdoc
GOFLAGS ?=
PREFIX ?= /usr/local
BINDIR ?= bin
MANDIR ?= share/man
SYSCONFDIR ?= etc

config_path := $(DESTDIR)/$(SYSCONFDIR)/soju/config
goflags := $(GOFLAGS) \
	-ldflags="-X 'git.sr.ht/~emersion/soju/config.DefaultPath=$(config_path)'"

all: soju sojudb sojuctl doc/soju.1

soju:
	$(GO) build $(goflags) ./cmd/soju
sojudb:
	$(GO) build $(goflags) ./cmd/sojudb
sojuctl:
	$(GO) build $(goflags) ./cmd/sojuctl
doc/soju.1: doc/soju.1.scd
	$(SCDOC) <doc/soju.1.scd >doc/soju.1

clean:
	$(RM) -f soju sojudb sojuctl doc/soju.1
install:
	mkdir -p $(DESTDIR)$(PREFIX)/$(BINDIR)
	mkdir -p $(DESTDIR)$(PREFIX)/$(MANDIR)/man1
	mkdir -p $(DESTDIR)/$(SYSCONFDIR)/soju
	mkdir -p $(DESTDIR)/var/lib/soju
	cp -f soju sojudb sojuctl $(DESTDIR)$(PREFIX)/$(BINDIR)
	cp -f doc/soju.1 $(DESTDIR)$(PREFIX)/$(MANDIR)/man1
	[ -f $(config_path) ] || cp -f config.in $(config_path)

.PHONY: soju sojudb sojuctl clean install
