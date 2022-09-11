# [soju]

[![builds.sr.ht status](https://builds.sr.ht/~emersion/soju/commits/master.svg)](https://builds.sr.ht/~emersion/soju/commits/master?)

soju is a user-friendly IRC bouncer. soju connects to upstream IRC servers on
behalf of the user to provide extra functionality. soju supports many features
such as multiple users, numerous [IRCv3] extensions, chat history playback and
detached channels. It is well-suited for both small and large deployments.

## Usage

* [Getting started]
* [Man page]

## Building and installing

Dependencies:

- Go
- BSD or GNU make
- a C89 compiler (optional, for SQLite)
- scdoc (optional, for man pages)

For end users, a `Makefile` is provided:

    make
    sudo make install

For development, you can use `go run ./cmd/soju` as usual.

To link with the system libsqlite3, set `GOFLAGS="-tags=libsqlite3"`. To disable
SQLite support, set `GOFLAGS="-tags=nosqlite"`.

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
[IRCv3]: https://ircv3.net/
