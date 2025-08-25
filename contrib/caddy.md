# Setting up Caddy as a proxy to soju

[Caddy] can be used in front of soju to take care of TLS. Note that this
requires [caddy-l4].

## Caddyfile

```caddy
{
    layer4 {
        example.com:6697 {
            route {
                tls {
                    connection_policy {
                        alpn irc
                    }
                }
                proxy {
                    proxy_protocol v2
                    upstream localhost:6667
                }
            }
        }
    }
}

example.com {
    @soju {
        path /socket
        path /uploads
        path /uploads/*
    }
    reverse_proxy @soju localhost:3030

    # Serve gamja files
    root * /var/www/gamja
    file_server
}
```

## soju configuration

```scfg
listen irc://localhost:6667
listen http://localhost:3030
accept-proxy-ip localhost
```

[Caddy]: https://caddyserver.com
[caddy-l4]: https://github.com/mholt/caddy-l4
