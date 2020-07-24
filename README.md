# [soju]

[![builds.sr.ht status](https://builds.sr.ht/~emersion/soju/commits.svg)](https://builds.sr.ht/~emersion/soju/commits?)

A user-friendly IRC bouncer.

- Multi-user
- Support multiple clients for a single user, with proper backlog
  synchronization
- Support connecting to multiple upstream servers via a single IRC connection
  to the bouncer

## Usage

See the man page at `doc/soju.1.scd` for more information.

### Server side

To create an admin user and start soju, run these commands:

    go run ./cmd/sojuctl create-user <soju username> -admin
    go run ./cmd/soju -listen irc+insecure://127.0.0.1:6667

If you're migrating from ZNC, a tool is available to import users, networks and
channels from a ZNC config file:

    go run ./contrib/znc-import.go <znc config file>

### Client side

soju can operate in two different modes: multi upstream and single upstream.

#### Single upstream mode

In this mode, 1 upstream connection to a irc server = 1 connection to your soju
bouncer.

The easiest and fastest way to use this is to specify the address of the server
in your username in your client configuration. For example to connect to
Freenode, your username will be: `<soju username>/chat.freenode.net`. Also set
your soju password in the password field of your client configuration.

This will autoconfigure soju by adding a network with the address
`chat.freenode.net` and then autoconnect to it. You will now be able to join
any channel like you would normally do.

#### Multi upstream mode

In this mode, a single connection to your soju bouncer can handle multiple
upstream connections. You will need to manually configure each upstream
connection using the the special `BouncerServ` user.

Connect to your soju server by specifying your soju username in the username
field in your client and your password in the password field.

You should now be able to send private messages to the `BouncerServ`. You can
send it commands to configure soju. Create new networks:

    /msg BouncerServ network create -addr chat.freenode.net -name freenode
    /msg BouncerServ network create -addr irc.rizon.net -name rizon

You will now be able to join channels on these networks by specifying their
name:

    /join #soju/freenode
    /join #somechannel/rizon

#### Notes

soju will automatically save and restore the channels you were connected to.

## Contributing

Send patches on the [mailing list] or on [GitHub], report bugs on the
[issue tracker]. Discuss in #soju on Freenode.

## License

AGPLv3, see LICENSE.

Copyright (C) 2020 The soju Contributors

[soju]: https://soju.im
[mailing list]: https://lists.sr.ht/~emersion/soju-dev
[GitHub]: https://github.com/emersion/soju
[issue tracker]: https://todo.sr.ht/~emersion/soju
