# Multi-upstream mode

When setting up a new IRC client which doesn't support the
`soju.im/bouncer-networks` extension, one needs to configure as many servers as
there are networks configured in soju. Whenever a network is added or removed
from the soju configuration, all client configurations also need to be updated
accordingly. This can be cumbersome especially when dealing with many clients.

To address this issue, soju supports a _multi-upstream mode_. Instead of
configuring multiple servers in the client, only one connection to the bouncer
is required. soju will expose all channels and users from all configured
networks on this single connection. Channel names and nicknames will be suffixed
with the network name. For instance, the `#soju` channel will appear with the
name `#soju/libera`, and to talk to `emersion` on OFTC one would need to send a
message to `emersion/oftc`. The special `BouncerServ` service won't have a
suffix.

To enable this mode, connect to the bouncer with the username
`<soju username>/*`.

To add a new network, send messages to `BouncerServ`, for instance:

    /msg BouncerServ network create -addr irc.libera.chat -name libera

To join a channel or message a user, remember to use the correct suffix, for
instance:

    /join #soju/libera
    /query emersion/libera
