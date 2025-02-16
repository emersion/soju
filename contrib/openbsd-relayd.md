# Setting up OpenBSD relayd(8) with soju

[relayd(8)] can be used in front of soju to take care of TLS.

## relayd configuration

Edit this `/etc/relayd.conf`:

```relayd.conf
tcp protocol "ircs" {
        tls  keypair example.com
}

relay ircs {
        listen on 0.0.0.0 port 6697 tls
        protocol ircs

        forward to 127.0.0.1 port 6667
}

relay ircs6 {
        listen on :: port 6697 tls
        protocol ircs

        forward to 127.0.0.1 port 6667
}
```

First section declares a named "ircs" generic tcp protocol and configure it to
look for TLS files:

- /etc/ssl/name.crt
- /etc/ssl/private/name.key

Theses files may be handled by [acme-client(1)] and does not required more
permissions for soju.

The rest of the configuration file set up two relays to listen on all addresses
from both inet4 and inet6 interfaces to do TLS termination and forward traffic
to soju.

## soju configuration

```soju-config
listen irc+insecure://127.0.0.1:6667
```

The important part is to make soju listen only on local address using non-secure
irc port as the secure connection is already looked after by relayd.

[relayd(8)]: https://man.openbsd.org/relayd.8
[acme-client(1)]: https://man.openbsd.org/acme-client.1
