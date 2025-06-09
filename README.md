# [soju]

soju is a user-friendly IRC bouncer. soju connects to upstream IRC servers on
behalf of the user to provide extra functionality. soju supports many features
such as multiple users, numerous [IRCv3] extensions, chat history playback and
detached channels. It is well-suited for both small and large deployments.

## Usage

* [Getting started]
* [Man page]
* [User-contributed resources]

## Building and installing

Dependencies:

- Go
- BSD or GNU make
- a C89 compiler (optional, for SQLite)
- scdoc (optional, for man pages)

For end users, a `Makefile` is provided:

    make
    sudo make install

For development, you can use `go run ./cmd/soju` as usual. See the
[development setup] page.

To link with the system libsqlite3, set `GOFLAGS="-tags=libsqlite3"`. To disable
SQLite support, set `GOFLAGS="-tags=nosqlite"`. To use an alternative SQLite
library that does not require CGO, set `GOFLAGS="-tags=moderncsqlite"`. To
build with PAM authentication support, set `GOFLAGS="-tags=pam"`.

## Contributing

Send patches on [Codeberg] or on [GitHub], report bugs on the [issue tracker].
Discuss in [#soju on Libera Chat][IRC channel].

## License

AGPLv3, see LICENSE.

Copyright (C) 2020 The soju Contributors

[soju]: https://soju.im
[Getting started]: doc/getting-started.md
[Man page]: https://soju.im/doc/soju.1.html
[User-contributed resources]: contrib/README.md
[development setup]: doc/dev-setup.md
[Codeberg]: https://codeberg.org/emersion/soju
[GitHub]: https://github.com/emersion/soju
[issue tracker]: https://todo.sr.ht/~emersion/soju
[IRC channel]: ircs://irc.libera.chat/#soju
[IRCv3]: https://ircv3.net/
