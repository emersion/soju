# Getting started

## Server side

To create an admin user and start soju, run these commands:

    sojuctl create-user <soju username> -admin
    soju -listen irc+insecure://127.0.0.1:6667

If you're migrating from ZNC, a tool is available to import users, networks and
channels from a ZNC config file:

    go run ./contrib/znc-import.go <znc config file>

## Client side

soju can operate in two different modes: multi upstream and single upstream.

### Single upstream mode

In this mode, 1 upstream connection to a irc server = 1 connection to your soju
bouncer.

The easiest and fastest way to use this is to specify the address of the server
in your username in your client configuration. For example to connect to
Libera Chat, your username will be: `<soju username>/irc.libera.chat`. Also set
your soju password in the password field of your client configuration.

This will autoconfigure soju by adding a network with the address
`irc.libera.chat` and then autoconnect to it. You will now be able to join
any channel like you would normally do.

### Multi upstream mode

In this mode, a single connection to your soju bouncer can handle multiple
upstream connections. You will need to manually configure each upstream
connection using the the special `BouncerServ` user.

Connect to your soju server by specifying your soju username in the username
field in your client and your password in the password field.

You should now be able to send private messages to the `BouncerServ`. You can
send it commands to configure soju. Create new networks:

    /msg BouncerServ network create -addr irc.libera.chat -name libera
    /msg BouncerServ network create -addr irc.rizon.net -name rizon

You will now be able to join channels on these networks by specifying their
name:

    /join #soju/libera
    /join #somechannel/rizon
