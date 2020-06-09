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
server supports SASL. When parting a channel with the reason "detach", the
channel will be detached instead of being left.

When all clients are disconnected from the bouncer, the user is automatically
marked as away.

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
	Path to the config file. If unset, a default config file is used.

*-debug*
	Enable debug logging (this will leak sensitive information such as
	passwords).

*-listen* <uri>
	Listening URI (default: ":6697").

# CONFIG FILE

The config file has one directive per line.

*listen* <uri>
	Listening URI (default: ":6697").

	The following URIs are supported:

	- _[ircs://][host][:port]_ listens with TLS over TCP (default port if
	  omitted: 6697)
	- _irc+insecure://[host][:port]_ listens with plain-text over TCP (default
	  port if omitted: 6667)
	- _wss://[host][:port]_ listens for WebSocket connections over TLS (default
	  port: 443)
	- _ws+insecure://[host][:port]_ listens for plain-text WebSocket
	  connections (default port: 80)

	If the scheme is omitted, "ircs" is assumed. If multiple *listen*
	directives are specified, soju will listen on each of them.

*hostname* <name>
	Server hostname (default: system hostname).

*tls* <cert> <key>
	Enable TLS support. The certificate and the key files must be PEM-encoded.

*sql* <driver> <source>
	Set the SQL driver settings. The only supported driver is "sqlite3". The
	source is the path to the SQLite database file. By default, the path to the
	database file is "soju.db".

*log* <path>
	Path to the bouncer logs root directory, or empty to disable logging. By
	default, logging is disabled.

*http-origin* <patterns...>
	List of allowed HTTP origins for WebSocket listeners. The parameters are
	interpreted as shell patterns, see *glob*(7).

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
	Connect to a new network at _addr_. _-addr_ is mandatory.

	_addr_ supports several connection types:

	- _[ircs://]host[:port]_ connects with TLS over TCP
	- _irc+insecure://host[:port]_ connects with plain-text TCP

	Other options are:

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

*network delete* <name>
	Disconnect and delete a network.

*network status*
	Show a list of saved networks and their current status.

*certfp generate* *[options...]* <network name>
	Generate self-signed certificate and use it for authentication.

	Generates RSA-3072 private key by default.

	Options are:

	*-key-type* <type>
		Private key algoritm to use. Valid values are: rsa, ecdsa, ed25519.
		ecdsa uses NIST P-521 curve.

	*-bits* <bits>
		Size of RSA key to generate. Ignored for other key types.

*certfp fingerprint* <network name>
	Show SHA-1 and SHA-256 fingerprints for the certificate
	currently used with the network.

*certfp reset* <network name>
	Disable SASL EXTERNAL authentication and remove stored certificate.

*user create* -username <username> -password <password> [-admin]
	Create a new soju user. Only admin users can create new accounts.

*change-password* <new password>
	Change current user password.

# AUTHORS

Maintained by Simon Ser <contact@emersion.fr>, who is assisted by other
open-source contributors. For more information about soju development, see
https://sr.ht/~emersion/soju.
