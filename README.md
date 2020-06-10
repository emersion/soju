# [soju]

[![builds.sr.ht status](https://builds.sr.ht/~emersion/soju/.build.yml.svg)](https://builds.sr.ht/~emersion/soju/.build.yml?)

A user-friendly IRC bouncer.

- Multi-user
- Support multiple clients for a single user, with proper backlog
  synchronization
- Support connecting to multiple upstream servers via a single IRC connection
  to the bouncer

## Usage

    go run ./cmd/sojuctl create-user <username> -admin
    go run ./cmd/soju -listen irc+insecure://127.0.0.1:6667

Then connect with username `<username>/chat.freenode.net` and join `#soju`.

See the man page at `doc/soju.1.scd` for more information.

## Contributing

Send patches on the [mailing list] or on [GitHub], report bugs on the
[issue tracker]. Discuss in #soju on Freenode.

## License

AGPLv3, see LICENSE.

Copyright (C) 2020 Simon Ser

[soju]: https://soju.im
[mailing list]: https://lists.sr.ht/~emersion/public-inbox
[GitHub]: https://github.com/emersion/soju
[issue tracker]: https://todo.sr.ht/~emersion/soju
