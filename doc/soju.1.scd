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
- Sending the backlog (messages received while the user was disconnected from
  the bouncer), with per-client buffers

To connect to the bouncer, use the bouncer username and password. To use a
client which doesn't support the _soju.im/bouncer-networks_ IRC extension,
setup one connection per server configured in soju, and indicate the network
name in the username: "<username>/<network>". Then channels can be joined and
parted as if you were directly connected to the upstream server.

For per-client history to work on clients which don't support the IRCv3
_chathistory_ extension, clients need to indicate their name. This can be done
by adding a "@<client>" suffix to the username.

When joining a channel, the channel will be saved and automatically joined on
the next connection. When registering or authenticating with NickServ, the
credentials will be saved and automatically used on the next connection if the
server supports SASL. When parting a channel with the reason "detach", the
channel will be detached instead of being left.

If a network specified in the username doesn't exist, and the network name is a
valid hostname, the network will be automatically added.

When all clients are disconnected from the bouncer, the user is automatically
marked as away by default.

soju will reload the configuration file, the TLS certificate/key and the MOTD
file when it receives the HUP signal. The configuration options _listen_, _db_
and _log_ cannot be reloaded.

Administrators can broadcast a message to all bouncer users via _/notice
$<hostname> <text>_, or via _/notice $\* <text>_ if the connection isn't bound
to a particular network. All currently connected bouncer users will receive the
message from the special _BouncerServ_ service.

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
	- _unix://<path>_ listens on a Unix domain socket
	- _https://[host][:port]_ listens for HTTPS connections (default port: 443)
	  and handles WebSocket requests at endpoint _/socket_
	- _http+insecure://[host][:port]_ listens for plain-text HTTP connections
	  (default port: 80) and handles WebSocket requests at endpoint _/socket_
	- _http+unix://<path>_ listens for plain-text HTTP connections on a Unix
	  domain socket and handles WebSocket requests at endpoint _/socket_
	- _wss://[host][:port]_ listens for WebSocket connections over TLS (default
	  port: 443)
	- _ws+insecure://[host][:port]_ listens for plain-text WebSocket
	  connections (default port: 80)
	- _ws+unix://<path>_ listens for plain-text WebSocket connections on a Unix
	  domain socket
	- _ident://[host][:port]_ listens for plain-text ident connections (default
	  port: 113)
	- _http+prometheus://localhost:<port>_ listens for plain-text HTTP
	  connections and serves Prometheus metrics (host must be "localhost")
	- _http+pprof://localhost:<port>_ listens for plain-text HTTP connections
	  and serves pprof runtime profiling data (host must be "localhost"). For
	  more information, see: <https://pkg.go.dev/net/http/pprof>.
	- _unix+admin://[path]_ listens on a Unix domain socket for administrative
	  connections, such as sojuctl (default path: /run/soju/admin)

	If the scheme is omitted, "ircs" is assumed. If multiple *listen*
	directives are specified, soju will listen on each of them.

*hostname* <name>
	Server hostname (default: system hostname).

	This should be set to a fully qualified domain name.

*title* <title>
	Server title. This will be sent as the _ISUPPORT NETWORK_ value when clients
	don't select a specific network.

*tls* <cert> <key>
	Enable TLS support. The certificate and the key files must be PEM-encoded.

*db* <driver> <source>
	Set the database location for user, network and channel storage. By default,
	a _sqlite3_ database is opened in "./soju.db".

	Supported drivers:

	- _sqlite3_ expects _source_ to be a path to the SQLite file
	- _postgres_ expects _source_ to be a space-separated list of _key=value_
	  parameters, e.g. _db postgres "host=/run/postgresql dbname=soju"_. Note
	  that _sslmode_ defaults to _require_. For more information on connection
	  strings, see:
	  <https://pkg.go.dev/github.com/lib/pq#hdr-Connection_String_Parameters>.

*message-store* <driver> [source]
	Set the database location for IRC messages. By default, an in-memory message
	database is used.

	Supported drivers:

	- _memory_ stores messages in memory. For each channel/user, only the
	  latest 4K messages are kept in memory, older messages are discarded. This
	  driver is very basic and doesn't support features such as the
	  _chathistory_ extension and search.
	- _fs_ stores messages on disk, in the same format as ZNC. _source_ is
	  required and is the root directory path for the database. This on-disk
	  format is lossy: some IRCv3 messages (e.g. TAGMSG) and all message tags
	  are discarded.
	- _db_ stores messages in the database. A full-text search index is used to
	  speed up search queries.

	(_log_ is a deprecated alias for this directive.)

*file-upload* <driver> [source]
	Set the database location for uploaded files.

	File upload requires setting up an HTTP listener (see _https://_ and
	_http+insecure://_ URIs in the _listen_ directive).

	Supported drivers:

	- _fs_ stores uploaded files on disk. _source_ is required.

*http-origin* <patterns...>
	List of allowed HTTP origins for WebSocket listeners. The parameters are
	interpreted as shell patterns, see *glob*(7).

	By default, only the request host is authorized. Use this directive to
	enable cross-origin WebSockets.

*http-ingress* <url>
	External URL on which HTTPS listeners are exposed.

	By default, this is _https://<hostname>_.

*accept-proxy-ip* <cidr...>
	Allow the specified IPs to act as a proxy. Proxys have the ability to
	overwrite the remote and local connection addresses (via the PROXY protocol,
	the Forwarded HTTP header field defined in RFC 7239 or the X-Forwarded-\*
	HTTP header fields). The special name "localhost" accepts the loopback
	addresses 127.0.0.0/8 and ::1/128.

	By default, all IPs are rejected.

*max-user-networks* <limit>
	Maximum number of enabled networks per user. By default, there is no limit.

*motd* <path>
	Path to the MOTD file. The bouncer MOTD is sent to clients which aren't
	bound to a specific network. By default, no MOTD is sent.

*upstream-user-ip* <cidr...>
	Enable per-user IP addresses. One IPv4 range and/or one IPv6 range can be
	specified in CIDR notation. One IP address per range will be assigned to
	each user and will be used as the source address when connecting to an
	upstream network.

	This can be useful to avoid having the whole bouncer banned from an upstream
	network because of one malicious user.

*disable-inactive-user* <duration>
	Disable inactive users after the specified duration.

	A user is inactive when the last downstream connection is closed.

	The duration is a positive decimal number followed by the unit "d" (days).
	For instance, "30d" disables users 30 days after they last disconnect from
	the bouncer.

*enable-user-on-auth* true|false
	Enable users when they successfully authenticate.

	This can be used together with _disable-inactive-user_ to seamlessly
	disable and re-enable users during lengthy inactivity.

	When external authentication is used (e.g. _auth oauth2_), bouncer users
	are automatically created after successful authentication.

*auth* <driver> ...
	Set the authentication method. By default, internal authentication is used.

	Supported drivers:

	*auth internal*
		Use internal authentication.
	*auth http* <url>
		Use external HTTP basic authentication. An HTTP request is made against
		the URL, passing the user credentials in an Authorization Basic header.
		The credentials are considered valid on HTTP 200; invalid on HTTP 403;
		and any other error code means an error occured.
	*auth oauth2* <url>
		Use external OAuth 2.0 authentication. The authorization server URL must
		be provided. The client ID and client secret can be provided as username
		and password in the URL. The authorization server must support OAuth 2.0
		Authorization Server Metadata (RFC 8414) and OAuth 2.0 Token
		Introspection (RFC 7662).
	*auth pam*
		Use PAM authentication.

# IRC SERVICE

soju exposes an IRC service called *BouncerServ* to manage the bouncer.
Commands can be sent via regular private messages
(_/msg BouncerServ <command> [args...]_). Commands may be written in full or
abbreviated form, for instance *network* can be abbreviated as *net* or just
*n*.

Commands are parsed according the POSIX shell rules. In particular, words can
be quoted (via double or single quotes) and a backslash escapes the next
character.

*help* [command]
	Show a list of commands. If _command_ is specified, show a help message for
	the command.

*network create* *-addr* <addr> [options...]
	Connect to a new network at _addr_. _-addr_ is mandatory.

	_addr_ supports several connection types:

	- _[ircs://]<host>[:port]_ connects with TLS over TCP
	- _irc+insecure://<host>[:port]_ connects with plain-text TCP
	- _irc+unix:///<path>_ connects to a Unix socket

	For example, to connect to Libera Chat:

	```
	net create -addr irc.libera.chat
	```

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

	*-certfp* <fingerprint>
		Instead of using certificate authorities to check the server's TLS
		certificate, check whether the server certificate matches the provided
		fingerprint. This can be used to connect to servers using self-signed
		certificates. The fingerprint format is SHA512. An empty string
		removes any previous fingerprint.

		The following command can be used to fetch the certificate fingerprint
		of an IRC server:

		```
		openssl s_client -connect irc.example.org:6697 -verify_quiet </dev/null | openssl x509 -fingerprint -sha512 -noout -in /dev/stdin
		```

	*-nick* <nickname>
		Connect with the specified nickname. By default, the account's username
		is used.

	*-auto-away* true|false
		Enable or disable the auto-away feature. If the feature is enabled, the
		user will be marked as away when all clients are disconnected from the
		bouncer. By default, auto-away is enabled.

	*-enabled* true|false
		Enable or disable the network. If the network is disabled, the bouncer
		won't connect to it. By default, the network is enabled.

	*-ignore-limit* true|false
		Ignore the max networks limit for this command.
		Only admin users can ignore the limit.

	*-connect-command* <command>
		Send the specified quoted string as a raw IRC command right after
		connecting to the server. This can be used to identify to an account
		when the server doesn't support SASL.

		For instance, to identify with _NickServ_, the following command can be
		used:

		```
		"PRIVMSG NickServ :IDENTIFY <password>"
		```

		The flag can be specified multiple times to send multiple IRC messages.
		To clear all commands, set it to the empty string.

*network update* [name] [options...]
	Update an existing network. The options are the same as the
	_network create_ command.

	When this command is executed, soju will disconnect and re-connect to the
	network.

	If _name_ is not specified, the current network is updated.

*network delete* [name]
	Disconnect and delete a network.

	If _name_ is not specified, the current network is deleted.

*network quote* [name] <command>
	Send a raw IRC line as-is to a network.

	If _name_ is not specified, the command is sent to the current network.

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

	*-detached* true|false
		Attach or detach this channel.

		A detached channel is joined but is hidden by the bouncer. This is
		useful to e.g. collect logs and highlights in low-interest or
		high-traffic channels.

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

*channel delete* <name>
	Leave and forget a channel.

*certfp generate* [options...]
	Generate self-signed certificate and use it for authentication (via SASL
	EXTERNAL).

	Generates a 3072-bit RSA private key by default.

	Options are:

	*-network* <name>
		Select a network. By default, the current network is selected, if any.

	*-key-type* <type>
		Private key algorithm to use. Valid values are: _rsa_, _ecdsa_ and
		_ed25519_. _ecdsa_ uses the NIST P-521 curve.

	*-bits* <bits>
		Size of RSA key to generate. Ignored for other key types.

*certfp fingerprint* [options...]
	Show SHA-1 and SHA-256 fingerprints for the certificate
	currently used with the network.

	Options are:

	*-network* <name>
		Select a network. By default, the current network is selected, if any.

*sasl status* [options...]
	Show current SASL status.

	Options are:

	*-network* <name>
		Select a network. By default, the current network is selected, if any.

*sasl set-plain* [options...] <username> <password>
	Set SASL PLAIN credentials.

	Options are:

	*-network* <name>
		Select a network. By default, the current network is selected, if any.

*sasl reset* [options...]
	Disable SASL authentication and remove stored credentials.

	Options are:

	*-network* <name>
		Select a network. By default, the current network is selected, if any.

*user status* [username]
	Show a list of users on this server. Only admins can query this information.

	If _username_ is specified, statistics are only displayed for this user.

*user create* -username <username> -password <password> [options...]
	Create a new soju user. Only admin users can create new accounts.
	The _-username_ and _-password_ flags are mandatory.

	Options are:

	*-username* <username>
		The bouncer username. This cannot be changed after the user has been
		created.

	*-password* <password>
		The bouncer password.

	*-disable-password*
		Disable password authentication. The user will be unable to login.

	*-admin* true|false
		Make the new user an administrator.

	*-nick* <nick>
		Set the user's nickname. This is used as a fallback if there is no
		nickname set for a network.

	*-realname* <realname>
		Set the user's realname. This is used as a fallback if there is no
		realname set for a network.

	*-enabled* true|false
		Enable or disable the user. If the user is disabled, the bouncer will
		not connect to any of their networks, and downstream connections will
		be immediately closed. By default, users are enabled.

	*-max-networks* <max-networks>
		Set a limit on the number of enabled networks this user can use. A limit
		of 0 means no network, and -1 means to default to the global
		_max-user-networks_ configuration value.

*user update* [username] [options...]
	Update a user. The options are the same as the _user create_ command.

	If _username_ is omitted, the current user is updated. Only admins can
	update other users.

	Not all flags are valid in all contexts:

	- The _-username_ flag is never valid, usernames are immutable.
	- The _-nick_ and _-realname_ flag are only valid when updating the current
	  user.
	- The _-admin_, _-enabled_ and _-max_networks_ flags are only valid when
	  updating another user.

*user delete* <username> [confirmation token]
	Delete a soju user.

	Only admins can delete other users.

*user run* <username> <command...>
	Execute a command as another user.

	Only admins can use this command.

*server status*
	Show some bouncer statistics. Only admins can query this information.

*server notice* <message>
	Broadcast a notice. All currently connected bouncer users will receive the
	message from the special _BouncerServ_ service. Only admins can broadcast a
	notice.

# AUTHORS

Maintained by Simon Ser <contact@emersion.fr>, who is assisted by other
open-source contributors. For more information about soju development, see
<https://soju.im>.

# SEE ALSO

*sojuctl*(1)
