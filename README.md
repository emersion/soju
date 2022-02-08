# [soju]

[![builds.sr.ht status](https://builds.sr.ht/~emersion/soju/commits.svg)](https://builds.sr.ht/~emersion/soju/commits?)

A user-friendly IRC bouncer.

- Multi-user
- Support multiple clients for a single user, with proper backlog
  synchronization
- Support connecting to multiple upstream servers via a single IRC connection
  to the bouncer

## Usage

* [Getting started]
* [Man page]

## Building and installing

Dependencies:

- Go
- BSD or GNU make
- a C89 compiler (for SQLite)
- scdoc (optional, for man pages)

For end users, a `Makefile` is provided:

    make
    sudo make install

For development, you can use `go run ./cmd/soju` as usual.

To link with the system libsqlite3, set `GOFLAGS="-tags=libsqlite3"`.

## Contributing

Send patches on the [mailing list] or on [GitHub], report bugs on the
[issue tracker]. Discuss in [#soju on Libera Chat][IRC channel].

## License

AGPLv3, see LICENSE.

Copyright (C) 2020 The soju Contributors

[soju]: https://soju.im
[Getting started]: doc/getting-started.md
[Man page]: https://soju.im/doc/soju.1.html
[mailing list]: https://lists.sr.ht/~emersion/soju-dev
[GitHub]: https://github.com/emersion/soju
[issue tracker]: https://todo.sr.ht/~emersion/soju
[IRC channel]: ircs://irc.libera.chat/#soju
