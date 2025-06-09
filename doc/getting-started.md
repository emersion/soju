# Getting started

## Server side

Start by installing soju via your distribution's [package manager]. A container
image is published as [`codeberg.org/emersion/soju`]. Alternatively, you can
compile it from source (see the [README]).

To create an admin user and start soju, run these commands:

    sojudb create-user <soju username> -admin
    soju -listen irc://localhost:6667

soju will listen for unencrypted IRC connections on the default port. This is
enough for local experiments, but for a proper setup you will need to configure
TLS (e.g. by setting up a reverse proxy, or by specifying the TLS certificates
in the soju configuration file).

If you're migrating from ZNC, a tool is available to import users, networks and
channels from a ZNC config file:

    go run ./contrib/znc-import <znc config file>

## Client side

### Client supporting `soju.im/bouncer-networks`

If you are using a client supporting the `soju.im/bouncer-networks` IRC
extension (see the [client list]), then you can just connect to soju with your
username and password.

If your client doesn't provide a UI to manage IRC networks, you can talk to
`BouncerServ`. See the [man page] or use `/msg BouncerServ help`.

### Other clients

You will need to setup one separate server in your client for each server you
want soju to connect to.

The easiest way to get started is to specify the IRC server address directly in
the username in the client configuration. For example to connect to Libera Chat,
your username will be: `<soju username>/irc.libera.chat`. Also set your soju
password in the password field of your client configuration.

This will autoconfigure soju by adding a network with the address
`irc.libera.chat` and then autoconnect to it. You will now be able to join
any channel like you would normally do.

For more advanced configuration options, you can talk to `BouncerServ`. See the
[man page] or use `/msg BouncerServ help`.

If you intend to connect to the bouncer from multiple clients, you will need to
append a client name in your username. For instance, to connect from a laptop
and a workstation, you can setup each client to use the respective usernames
`<soju username>/irc.libera.chat@laptop` and
`<soju username>/irc.libera.chat@workstation`.

[package manager]: https://repology.org/project/soju/versions
[`codeberg.org/emersion/soju`]: https://codeberg.org/emersion/-/packages/container/soju/latest
[README]: ../README.md
[man page]: https://soju.im/doc/soju.1.html#IRC_SERVICE
[client list]: ../contrib/clients.md
