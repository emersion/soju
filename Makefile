.POSIX:
.SUFFIXES:

GO = go
RM = rm
SCDOC = scdoc
GOFLAGS =
PREFIX = /usr/local
BINDIR = bin
MANDIR = share/man

all: soju sojuctl doc/soju.1

soju:
	$(GO) build $(GOFLAGS) ./cmd/soju
sojuctl:
	$(GO) build $(GOFLAGS) ./cmd/sojuctl
doc/soju.1: doc/soju.1.scd
	$(SCDOC) <doc/soju.1.scd >doc/soju.1

clean:
	$(RM) -rf soju sojuctl doc/soju.1
install:
	mkdir -p $(DESTDIR)$(PREFIX)/$(BINDIR)
	mkdir -p $(DESTDIR)$(PREFIX)/$(MANDIR)/man1
	mkdir -p $(DESTDIR)/etc/soju
	mkdir -p $(DESTDIR)/var/lib/soju
	cp -f soju sojuctl $(DESTDIR)$(PREFIX)/$(BINDIR)
	cp -f doc/soju.1 $(DESTDIR)$(PREFIX)/$(MANDIR)/man1
	[ -f $(DESTDIR)/etc/soju/config ] || cp -f config.in $(DESTDIR)/etc/soju/config

.PHONY: soju sojuctl
