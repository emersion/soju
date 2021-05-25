# Clients

This page describes how to configure IRC clients to better integrate with soju.

Also see the [IRCv3 support tables] for a more general list of clients.

# [gamja]

gamja has been designed together with soju, so should have excellent
integration. gamja supports many IRCv3 features including chat history.
gamja also provides UI to manage soju networks via the
`soju.im/bouncer-networks` extension.

# [senpai]

senpai is being developed with soju in mind, so should have excellent
integration. senpai supports many IRCv3 features including chat history.

# [Weechat]

By default, WeeChat doesn't request any IRCv3 capability. To enable all
supported capabilities as of WeeChat 3.1:

    /set irc.server_default.capabilities account-notify,away-notify,cap-notify,chghost,extended-join,invite-notify,multi-prefix,server-time,userhost-in-names
    /save
    /reconnect -all

See `/help cap` for more information.

[IRCv3 support tables]: https://ircv3.net/software/clients
[gamja]: https://sr.ht/~emersion/gamja/
[senpai]: https://sr.ht/~taiite/senpai/
[Weechat]: https://weechat.org/
