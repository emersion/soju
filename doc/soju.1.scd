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

soju will reload the TLS certificate and key when it receives the HUP signal.

Administrators can broadcast a message to all bouncer users via _/notice
$<hostname> <text>_, or via _/notice $\* <text>_ in multi-upstream mode. All
currently connected bouncer users will receive the message from the special
_BouncerServ_ service.

# OPTIONS

*-h, -help*
	Show help message and quit.

*-config* <path>
	Path to the config file. If unset, a default config file is used.

*-debug*
	Enable debug logging (this will leak sensitive information such as
	passwords).

*-listen* <uri>
	Listening URI (default: ":6697"). Can be specified multiple times.

# CONFIG FILE

The config file has one directive per line.

Example:

```
listen ircs://
tls cert.pem key.pem
hostname example.org
```

The following directives are supported:

*listen* <uri>
	Listening URI (default: ":6697").

	The following URIs are supported:

	- _[ircs://][host][:port]_ listens with TLS over TCP (default port if
	  omitted: 6697)
	- _irc+insecure://[host][:port]_ listens with plain-text over TCP (default
	  port if omitted: 6667)
	- _unix:///<path>_ listens on a Unix domain socket
	- _wss://[host][:port]_ listens for WebSocket connections over TLS (default
	  port: 443)
	- _ws+insecure://[host][:port]_ listens for plain-text WebSocket
	  connections (default port: 80)
	- _ident://[host][:port]_ listens for plain-text ident connections (default
	  port: 113)

	If the scheme is omitted, "ircs" is assumed. If multiple *listen*
	directives are specified, soju will listen on each of them.

*hostname* <name>
	Server hostname (default: system hostname).

*tls* <cert> <key>
	Enable TLS support. The certificate and the key files must be PEM-encoded.

*db* sqlite3 <path>
	Set the SQLite database path (default: "soju.db" in the current directory).

*log* fs <path>
	Path to the bouncer logs root directory, or empty to disable logging. By
	default, logging is disabled.

*http-origin* <patterns...>
	List of allowed HTTP origins for WebSocket listeners. The parameters are
	interpreted as shell patterns, see *glob*(7).

	By default, only the request host is authorized. Use this directive to
	enable cross-origin WebSockets.

*accept-proxy-ip* <cidr...>
	Allow the specified IPs to act as a proxy. Proxys have the ability to
	overwrite the remote and local connection addresses (via the X-Forwarded-\*
	HTTP header fields). The special name "localhost" accepts the loopback
	addresses 127.0.0.0/8 and ::1/128. By default, all IPs are rejected.

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

	- _[ircs://]<host>[:port]_ connects with TLS over TCP
	- _irc+insecure://<host>[:port]_ connects with plain-text TCP
	- _irc+unix:///<path>_ connects to a Unix socket

	Other options are:

	*-name* <name>
		Short network name. This will be used instead of _addr_ to refer to the
		network.

	*-username* <username>
		Connect with the specified username. By default, the nickname is used.

	*-pass* <pass>
		Connect with the specified server password.

	*-realname* <realname>
		Connect with the specified real name. By default, the account's realname
		is used if set, otherwise the network's nickname is used.

	*-nick* <nickname>
		Connect with the specified nickname. By default, the account's username
		is used.

	*-enabled* true|false
		Enable or disable the network. If the network is disabled, the bouncer
		won't connect to it. By default, the network is enabled.

	*-connect-command* <command>
		Send the specified command as a raw IRC message right after connecting
		to the server. This can be used to identify to an account when the
		server doesn't support SASL.

		For instance, to identify with _NickServ_, the following command can be
		used:

		```
		PRIVMSG NickServ :IDENTIFY <password>
		```

		The flag can be specified multiple times to send multiple IRC messages.
		To clear all commands, set it to the empty string.

*network update* <name> [options...]
	Update an existing network. The options are the same as the
	_network create_ command.

	When this command is executed, soju will disconnect and re-connect to the
	network.

*network delete* <name>
	Disconnect and delete a network.

*network status*
	Show a list of saved networks and their current status.

*channel status* [options...]
	Show a list of saved channels and their current status.

	Options:

	*-network* <name>
		Only show channels for the specified network. By default, only the
		channels in the current network are displayed.

*channel update* <name> [options...]
	Update the options of an existing channel.

	Options are:

	*-relay-detached* <mode>
		Set when to relay messages from detached channels to the user with a BouncerServ NOTICE.

		Modes are:

		*message*
			Relay any message from this channel when detached.

		*highlight*
			Relay only messages mentioning you when detached.

		*none*
			Don't relay any messages from this channel when detached.

		*default*
			Currently same as *highlight*. This is the default behaviour.

	*-reattach-on* <mode>
		Set when to automatically reattach to detached channels.

		Modes are:

		*message*
			Reattach to this channel when any message is received.

		*highlight*
			Reattach to this channel when any message mentioning you is received.

		*none*
			Never automatically reattach to this channel.

		*default*
			Currently same as *none*. This is the default behaviour.

	*-detach-after* <duration>
		Automatically detach this channel after the specified duration has elapsed without receving any message corresponding to *-detach-on*.

		Example duration values: *1h30m*, *30s*, *2.5h*.

		Setting this value to 0 will disable this behaviour, i.e. this channel will never be automatically detached. This is the default behaviour.

	*-detach-on* <mode>
		Set when to reset the auto-detach timer used by *-detach-after*, causing it to wait again for the auto-detach duration timer before detaching.
		Joining, reattaching, sending a message, or changing any channel option will reset the timer, in addition to the messages specified by the mode.

		Modes are:

		*message*
			Receiving any message from this channel will reset the auto-detach timer.

		*highlight*
			Receiving any message mentioning you from this channel will reset the auto-detach timer.

		*none*
			Receiving messages from this channel will not reset the auto-detach timer. Sending messages or joining the channel will still reset the timer.

		*default*
			Currently same as *message*. This is the default behaviour.

*certfp generate* [options...] <network name>
	Generate self-signed certificate and use it for authentication (via SASL
	EXTERNAL).

	Generates a RSA-3072 private key by default.

	Options are:

	*-key-type* <type>
		Private key algoritm to use. Valid values are: rsa, ecdsa, ed25519.
		ecdsa uses NIST P-521 curve.

	*-bits* <bits>
		Size of RSA key to generate. Ignored for other key types.

*certfp fingerprint* <network name>
	Show SHA-1 and SHA-256 fingerprints for the certificate
	currently used with the network.

*sasl set-plain* <network name> <username> <password>
	Set SASL PLAIN credentials.

*sasl reset* <network name>
	Disable SASL authentication and remove stored credentials.

*user create* -username <username> -password <password> [options...]
	Create a new soju user. Only admin users can create new accounts.
	The _-username_ and _-password_ flags are mandatory.

	Other options are:

	*-admin*
		Make the new user an administrator.

	*-realname* <realname>
		Set the user's realname. This is used as a fallback if there is no
		realname set for a network.

*user update* [-password <password>] [-realname <realname>]
	Update the current user. The options are the same as the _user create_
	command.

*user delete* <username>
	Delete a soju user. Only admins can delete accounts.

# AUTHORS

Maintained by Simon Ser <contact@emersion.fr>, who is assisted by other
open-source contributors. For more information about soju development, see
https://sr.ht/~emersion/soju.
