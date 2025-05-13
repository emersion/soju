# Packaging soju

## Building

Using `make` is recommended for building. The `GOFLAGS` variable can be used to
customize flags passed to Go. In particular, `GOFLAGS="-tags=libsqlite3"` can
be used to link to the system's libsqlite3.

The `Makefile` will configure the binary with the default locations for the
config file and the admin Unix socket. These can be customized via the
`SYSCONFDIR` and `RUNDIR` variables.

## Default configuration file

`make install` will set up a default configuration file which:

- Uses a SQLite3 database in `/var/lib/soju/main.db`.
- Enables the admin Unix socket (required for `sojuctl`).

The default configuration file's template is stored in `config.in`.

## Binding to privileged ports

soju might need to bind to privileged ports: the built-in identd will need to
listen on port 113. On Linux, unless your service manager provides a way to
give extra capabilities to soju, the `CAP_NET_BIND_SERVICE` capability can be
assigned to the soju executable:

    setcap 'cap_net_bind_service=+ep' soju

## Service manager integration

soju is designed to be run as a system-wide service under a separate user
account.

SIGHUP can be sent to soju to reload the configuration file.

A template for systemd is available in `contrib/soju.service`.
