# Setting up tlstunnel with soju

[tlstunnel] can be used in front of soju to take care of TLS.

## tlstunnel configuration

```
frontend {
	listen irc.example.org:6697
	backend tcp+proxy://localhost:6667
	protocol irc
}
```

## soju configuration

```
listen irc+insecure://localhost
accept-proxy-ip localhost
```

[tlstunnel]: https://git.sr.ht/~emersion/tlstunnel
