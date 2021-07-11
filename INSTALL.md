# Requirements

## Go runtime

Follow the instructions for installing go found at <https://golang.org/doc/install>

Running `go version` will confirm go has been installed successfully and you can continue.

## Install build tools

Soju uses a Makefile for building the project and needs gcc to build the go-sqlite3 library. On Debian based systems, including Ubuntu, these can be installed by running `sudo apt install make gcc`

## scdoc (optional)

Soju builds man pages using the scdoc command which can be installed with `sudo apt install scdoc` This is optional.

# Clone the soju repository

`git clone https://git.sr.ht/~emersion/soju` will create a soju directory and clone the project into it


# Building and Installing

## Run `make`

Enter the soju directory and issue the `make` command.  The included Makefile will perform the necessary steps to build the project. When make finishes you will have `soju` and `sojuctl` executables plus man pages for each.


## `make install`

Run `sudo make install` to install soju system wide.

1.  The executables will be placed in /usr/local/bin
2.  A default config file will be located at /etc/soju/config
3.  A data directory will be created at /var/lib/soju
4.  Man pages will be copied to /usr/local/share/man

You do not need to install soju system wide, but the remainder of this document assumes you have, so modify your configuration files accordingly.

# Service Confugration


## Add a system user

`sudo useradd -r soju` will create a system user account named soju. The user will not have a password set and cannot be used to log in to the system.


## Grant soju user ownership of /var/lib/soju

`sudo chown soju /var/lib/soju`


## Generate certificates

Using openssl generate a self signed certifcate clients will use to confirm they're connecting to your soju instance.

`sudo -u soju openssl req -newkey rsa:2048 -new -nodes -x509 -days 3650 -keyout /var/lib/soju/key.pem -out /var/lib/soju/cert.pem`

The command will generate certificates, owned by our soju user, and write them to the soju data directory.


## Confgiure Soju

Edit the configuration file located at `/etc/soju/config` adding the TLS directive.

```
db sqlite3 /var/lib/soju/main.db 
log fs /var/lib/soju/logs 
tls /var/lib/soju/cert.pem /var/lib/soju/key.pem 
```

By default soju will listen on all interfaces. If you want it to listen only on a specific ip address add the line `listen x.y.z.w:6697`.  You can optionally specify the hostname soju should use with `hostname example.org`.


## Create systemd service file

A systemd service file will allow systemd to manage the soju daemon service. It will be started on boot, restarted on crash (giving up after a few in a row), and let you restart the service via `systemctl restart soju` Logs from the soju service can be read with `journalctl -u soju`

1.  Place the below configuration in the file `/etc/systemd/system/soju.service`
2.  Execute `sudo systemctl enable soju.service` which will start soju when the system boots
3.  `sudo systemctl start soju.service` will immediately start the service.

```
[Unit] 
Description=Soju bouncer daemon 
After=network.target

[Service] 
Type=simple 
Restart=always 
RestartSec=15 
User=soju 
ExecStart=/usr/local/bin/soju -config /etc/soju/config
ExecReload=kill -HUP $MAINPID

[Install] 
WantedBy=multi-user.target
```

See [Getting Started](doc/getting-started.md)