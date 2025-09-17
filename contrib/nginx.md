# Setting up nginx as a proxy to soju

You can configure nginx as a proxy to soju to handle both public http/tls and also irc/tls connections.
This way we don't need to expose soju listening sockets publicly and relieve it from handling tls.
One benefit of this approach would be that soju doesn't need to be hooked into certbot, nor does it need
to be reloaded when certificates are updated.

In this example, nginx will also handle serving static files for gamja, from the `/srv/gamja` directory.

**Note:** different Linux distributions use a different configuration structure for nginx, so here we only
provide the configuration snippets for the [`http`/`server`](https://nginx.org/en/docs/http/ngx_http_core_module.html#server)
module, the [http proxy](https://nginx.org/en/docs/http/ngx_http_proxy_module.html) configuration and
the [`stream`/`server`](https://nginx.org/en/docs/stream/ngx_stream_core_module.html) module.

Please refer to your OS documentation to learn how to configure nginx, and where its config files are located.

## http server: websocket proxying

First, configure Soju to listen for websocket on the `/run/soju/http.sock` unix domain socket:
```
…
listen http+unix:///run/soju/http.sock
…
```

Then configure nginx to proxy all http traffic for the `/socket` prefix to that
unix domain socket, by using the `proxy_pass` directives. It is important to set
`client_max_body_size` be unlimited (0) to enable large uploads from users.

```
# /etc/nginx/sites-enabled/60-soju.conf
server {
  server_name chat.example.com;
  listen 80;
  listen [::]:80;

  location /socket {
    proxy_pass http://unix:/run/soju/http.sock:/socket;
    proxy_read_timeout 600s;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "Upgrade";
    proxy_set_header Forwarded ""; # prevent clients from spoofing this header, which takes precedence over X-Forwarded-*
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header Host $host;
  }

  location /uploads {
    proxy_pass http://unix:/run/soju/http.sock:/uploads;
    proxy_set_header Forwarded ""; # prevent clients from spoofing this header, which takes precedence over X-Forwarded-*
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header Host $host;
    client_max_body_size 0;
  }

  root /srv/gamja/;
}
```
All the rest of http requests will be served from staic files in the `/src/gamja` directory
(you can just copy the gamja `dist/` production files there).

Once you have the above configuration, you can run `sudo certbot --nginx -d chat.example.com`
and you'll get the configuration file updated for TLS, redirects, and some security headers.


## stream server: irc protocol proxying

Nginx, since version 1.9.0, supports the [stream](https://nginx.org/en/docs/stream/ngx_stream_core_module.html)
module, which can proxy non-http protocols. We can use that to make nginx accepts/handle the tls protocol
for the irc tcp connections.

Configure Soju to listen on the unix socket `/run/soju/irc.sock` for irc connections:
```
…
listen unix:///run/soju/irc.sock
…
```

Now configure nginx to listen on the 1667 tcp port (an an example), and proxy to soju using the "PROXY protocol".
The `ssl_certificate`, `ssl_certificate_key` and `ssl_dhparam` are copy/pasted from the http server config
(as edited by certbot).
```
# /etc/nginx/streams-enabled/60-soju.conf
server {
  listen      1667 ssl;
  listen      [::]:1667 ssl;
  proxy_pass unix:/run/soju/irc.sock;
  proxy_protocol on;

  ssl_certificate /etc/letsencrypt/live/chat.example.com/fullchain.pem;
  ssl_certificate_key /etc/letsencrypt/live/chat.example.com/privkey.pem;
  ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;
}
```


## Socket file permissions

The `/run/soju/http.sock` and `/run/soju/irc.sock` unix socket pseudo-files are created by soju,
but need to be accessible by nginx. A common solution to that issue is to run soju with the same
group as nginx is running (for example www-data in debian). In that case the unix socket file permissions
should be something like:

```
drwxr-xr-x 2 soju www-data 100 May  1 03:00 /run/soju/
srwxrwxr-x 1 soju www-data 0 May  1 03:00 /run/soju/irc.sock
srwxrwxr-x 1 soju www-data 0 May  1 03:00 /run/soju/http.sock
```
A common way to establish that when running soju under debian/ubuntu is to use the `Group=` directive
in the soju .service unit file (or a drop-in):
```
[Service]
Group=www-data
```
