# Clients

This page describes how to configure IRC clients to better integrate with soju.

Also see the [IRCv3 support tables] for a more general list of clients.

# catgirl

catgirl doesn't implement cap-3.2, so many capabilities will be disabled.
catgirl developers have publicly stated that supporting bouncers such as soju
is a non-goal.

# [Emacs]

There are two clients provided with Emacs. They require some setup to work
properly.

## Erc

Create an interactive function for connecting:

```elisp
(defun run-erc ()
  (interactive)
  (erc-tls :server "<server>"
           :port 6697
           :nick "<nick>"
           :user "<username>/irc.libera.chat" ;; Example with Libera.Chat
           :password "<password>"))
```

Then run `M-x run-erc`.

## Rcirc

The only thing needed here is the general config:

```elisp
(setq rcirc-server-alist
      '(("<server>"
         :port 6697
         :encryption tls
         :nick "<nick>"
         :user-name "<username>/irc.libera.chat" ;; Example with Libera.Chat
         :password "<password>")))
```

Then run `M-x irc`.

## Circe

Circe is not provided with Emacs and so must be installed using a package manager, such as `use-package`.

```elisp
(use-package circe
  :custom
  (circe-network-options
   '(("Network"
      :host "<server>"
      :port 6697
      :tls t
      :nick "<nick>"
      :sasl-username "<username>/irc.libera.chat" ;; Example with Libera.Chat 
      :sasl-password "<password>")))))
```

Then run `M-x circe`

# [gamja]

gamja has been designed together with soju, so should have excellent
integration. gamja supports many IRCv3 features including chat history.
gamja also provides UI to manage soju networks via the
`soju.im/bouncer-networks` extension.

# [goguma]

Much like gamja, goguma has been designed together with soju, so should have
excellent integration. goguma supports many IRCv3 features including chat
history. goguma should seamlessly connect to all networks configured in soju via
the `soju.im/bouncer-networks` extension.

# [Halloy]

Halloy has support for many IRCv3 features including chat history as of release 2025.1.

Below is an example configuration to connect to soju networks:
```toml
[servers.liberachat]
nickname = "network_nickname"
username = "soju_username/irc.libera.chat"
password = "soju_password"
server = "soju_server_hostname"
port = 6697
chathistory = true
```

For more details, see the [guide on connecting to soju] and [server chathistory] found in the Halloy docs.

# [Hexchat]

Hexchat has support for a small set of IRCv3 capabilities. To prevent
automatically reconnecting to channels parted from soju, and prevent buffering
outgoing messages:

    /set irc_reconnect_rejoin off
    /set net_throttle off

# [irssi]

To connect irssi to a network, for example Libera Chat:

    /network add -user <soju user>/irc.libera.chat libera
    /server add -auto -tls -network libera <soju ip or hostname> <soju port> <soju password>

Then, to actually connect:

    /connect libera

# [senpai]

senpai is being developed with soju in mind, so should have excellent
integration. senpai supports many IRCv3 features including chat history.
senpai should seamlessly connect to all networks configured in soju via the
`soju.im/bouncer-networks` extension.

# [Weechat]

A [soju.py] Weechat script is available to provide better integration with soju.
The script will automatically connect to all of your networks once a single
connection to soju is set up in Weechat.

Additionally, [read_marker.py] can be enabled to synchronize the read marker
between multiple clients.

On WeeChat 3.2-, no IRCv3 capabilities are enabled by default. To enable them:

    /set irc.server_default.capabilities account-notify,away-notify,cap-notify,chghost,extended-join,invite-notify,multi-prefix,server-time,userhost-in-names
    /save
    /reconnect -all

See `/help cap` for more information.

[IRCv3 support tables]: https://ircv3.net/software/clients
[gamja]: https://codeberg.org/emersion/gamja
[goguma]: https://codeberg.org/emersion/goguma
[senpai]: https://sr.ht/~delthas/senpai/
[Weechat]: https://weechat.org/
[soju.py]: https://weechat.org/scripts/source/soju.py.html/
[read_marker.py]: https://weechat.org/scripts/source/read_marker.py.html/
[Halloy]: https://halloy.squidowl.org/index.html
[guide on connecting to soju]: https://halloy.squidowl.org/guides/connect-with-soju.html
[server chathistory]: https://halloy.squidowl.org/configuration/servers.html#chathistory
[Hexchat]: https://hexchat.github.io/
[hexchat password length fix]: https://github.com/hexchat/hexchat/commit/778047bc65e529804c3342ee0f3a8d5d7550fde5
[Emacs]: https://www.gnu.org/software/emacs/
[irssi]: https://irssi.org/
