# Clients

This page describes how to configure IRC clients to better integrate with soju.

Also see the [IRCv3 support tables] for a more general list of clients.

# [gamja]

gamja has been designed together with soju, so should have excellent
integration. gamja supports many IRCv3 features including chat history.
gamja also provides UI to manage soju networks via the
`soju.im/bouncer-networks` extension.

# [Hexchat]

Hexchat has support for a small set of IRCv3 capabilities. To prevent
automatically reconnecting to channels parted from soju, and prevent buffering
outgoing messages:

    /set irc_reconnect_rejoin off
    /set net_throttle off

# [senpai]

senpai is being developed with soju in mind, so should have excellent
integration. senpai supports many IRCv3 features including chat history.

# [Weechat]

A [Weechat script] is available to provide better integration with soju.
The script will automatically connect to all of your networks once a
single connection to soju is set up in Weechat.

On WeeChat 3.2-, no IRCv3 capabilities are enabled by default. To enable them:

    /set irc.server_default.capabilities account-notify,away-notify,cap-notify,chghost,extended-join,invite-notify,multi-prefix,server-time,userhost-in-names
    /save
    /reconnect -all

See `/help cap` for more information.

[IRCv3 support tables]: https://ircv3.net/software/clients
[gamja]: https://sr.ht/~emersion/gamja/
[senpai]: https://sr.ht/~taiite/senpai/
[Weechat]: https://weechat.org/
[Weechat script]: https://github.com/weechat/scripts/blob/master/python/soju.py
[Hexchat]: https://hexchat.github.io/
