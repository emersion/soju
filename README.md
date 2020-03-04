# jounce

A user-friendly IRC bouncer.

- Multi-user
- Support multiple clients for a single user, with proper backlog
  synchronization
- Support connecting to multiple upstream servers via a single IRC connection
  to the bouncer

## Usage

    sqlite3 jounce.db <schema.sql
    # Insert users, networks, channels to database
    go run ./cmd/jounce

## Contributing

Send patches on the [mailing list], report bugs on the [issue tracker].

## License

AGPLv3, see LICENSE.

Copyright (C) 2020 Simon Ser

[mailing list]: https://lists.sr.ht/~emersion/public-inbox
[issue tracker]: https://todo.sr.ht/~emersion/jounce
