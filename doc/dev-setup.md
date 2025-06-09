# Development setup

soju can be run as usual the same way as any other Go program via `go run`. To
create an admin user and start soju on port 6667 (for unencrypted local
connections):

    go run ./cmd/sojudb create-user <soju username> -admin
    go run ./cmd/soju -listen irc://localhost

A custom config file can be used by passing `-config`, for instance to enable
a [pprof] server:

    listen irc://localhost
    listen http+pprof://localhost:8101

[pprof]: https://pkg.go.dev/net/http/pprof
