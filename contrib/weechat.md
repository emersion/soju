# Weechat configuration

By default, WeeChat doesn't request any IRCv3 capability. To enable all
supported capabilities as of WeeChat 3.1:

    /set irc.server_default.capabilities account-notify,away-notify,cap-notify,chghost,extended-join,invite-notify,multi-prefix,server-time,userhost-in-names
    /save
    /reconnect -all

See `/help cap` for more information.
