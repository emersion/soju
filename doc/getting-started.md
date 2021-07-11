# Getting started

For installation instructions see [INSTALL.md](../INSTALL.md)

## Migrating From ZNC

If you're migrating from ZNC, a tool is available to import users, networks and
channels from a ZNC config file:

    go run ./contrib/znc-import.go <znc config file>

## Add your first user

`sojuctl -config /etc/soju/config create-user <soju username> -admin` will add a new admin user for connecting to soju. You will be prompted for the soju user's password. The command must be run as a user with write access to the soju database.

## Connect to the running soju bouncer

Connect with the username and password you've created in the previous step. Make sure your client knows to connect on port 6697 and that TLS is enabled for the connection. You will be prompted to accept the self-signed certificate you created earlier. This will identify your soju instance to your client.

## Adding an IRC Server

Your soju instance can be managed by messaging the bot named BouncerServ. `/msg bouncerserv help` for a list of available commands.

To add a new server, Libera.chat for example, use the command `/msg bouncerserv newtwork create -addr irc.libera.chat -name libera`

## Set your SASL credentials

`/msg bouncerserv sasl set-plain libera user pass`

Notice when creating the network we named it libera, so we can use the shorter name when setting SASL commands.


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

### Detaching/Parting Channels

You can detach from a channel by including detach in the /part message e.g. `/part #soju detach`

When detached, Soju will keep your user joined to the channel and log activity, but your clients will no longer display the channel.

To fully leave a channel issue a standard `/part #soju`

## Identifying clients by name

If you use multiple clients you can identify each via the username field. `<soju username>/libera` becomes

1.  `<soju username>/libera@home`
2.  `<soju username>/libera@work`
3.  `<soju username>/libera@phone`

Naming your clients helps soju better manage history playback for you.
