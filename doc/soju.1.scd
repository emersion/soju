soju(1)

# NAME

soju - IRC bouncer

# SYNOPSIS

*soju* [options...]

# DESCRIPTION

soju is a user-friendly IRC bouncer. It connects to upstream IRC servers on
behalf of the user to provide extra features.

- Multiple separate users sharing the same bouncer, each with their own
  upstream servers
- Clients connecting to multiple upstream servers via a single connection to
  the bouncer
- Sending the backlog (messages received while the user was disconnected from
  the bouncer), with per-client buffers

When joining a channel, the channel will be saved and automatically joined on
the next connection. When registering or authenticating with NickServ, the
credentials will be saved and automatically used on the next connection if the
server supports SASL.

soju supports two connection modes:

- Single upstream mode: one downstream connection maps to one upstream
  connection. To enable this mode, connect to the bouncer with the username
  "<username>/<network>". If the bouncer isn't connected to the upstream
  server, it will get automatically added. Then channels can be joined and
  parted as if you were directly connected to the upstream server.
- Multiple upstream mode: one downstream connection maps to multiple upstream
  connections. Channels and nicks are suffixed with the network name. To join
  a channel, you need to use the suffix too: _/join #channel/network_. Same
  applies to messages sent to users.

For per-client history to work, clients need to indicate their name. This can
be done by adding a "@<client>" suffix to the username.

# OPTIONS

*-h, -help*
	Show help message and quit.

*-config* <path>
	Path to the config file.

*-debug*
	Enable debug logging (this will leak sensitive information such as
	passwords).

*-listen* <address>
	Listening address (default: ":6667").

# CONFIG FILE

The config file has one directive per line.

*listen* <address>
	Listening address (default: ":6667").

*hostname* <name>
	Server hostname (default: system hostname).

*tls* <cert> <key>
	Enable TLS support. The certificate and the key files must be PEM-encoded.

*sql* <driver> <source>
	Set the SQL driver settings. The only supported driver is "sqlite". The
	source is the path to the SQLite database file.

*log* <path>
	Path to the bouncer logs root directory, or empty to disable logging.

# IRC SERVICE

soju exposes an IRC service called *BouncerServ* to manage the bouncer.
Commands can be sent via regular private messages
(_/msg BouncerServ <command> [args...]_). Commands may be written in full or
abbreviated form, for instance *network* can be abbreviated as *net* or just
*n*.

*help* [command]
	Show a list of commands. If _command_ is specified, show a help message for
	the command.

*network create* *-addr* <addr> [options...]
	Connect to a new network at _addr_. _-addr_ is mandatory. Other options are:

	*-name* <name>
		Short network name. This will be used instead of _addr_ to refer to the
		network.

	*-username* <username>
		Connect with the specified username. By default, the nickname is used.

	*-pass* <pass>
		Connect with the specified server password.

	*-realname* <realname>
		Connect with the specified real name. By default, the nickname is used.

	*-nick* <nickname>
		Connect with the specified nickname. By default, the account's username
		is used.

*network status*
	Show a list of saved networks and their current status.

# AUTHORS

Maintained by Simon Ser <contact@emersion.fr>, who is assisted by other
open-source contributors. For more information about soju development, see
https://git.sr.ht/~emersion/soju.
