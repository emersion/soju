# Setting up file uploads

Add the `file-upload` directive to your configuration file:

    file-upload fs ./uploads

Ensure an HTTP listener is set up. For instance, when using an HTTP reverse
proxy:

    listen http://localhost:8080

Configure your HTTP reverse proxy to forward requests to soju. In particular,
`/socket`, `/uploads` and `/uploads/*` need to be forwarded.

Ensure your hostname is correctly configured. If the `hostname` directive
matches your HTTP server hostname (ie, your HTTP server can be reached via
`https://<hostname>`), there is nothing to do. For more complex setups, the
`http-ingress` directive can be used.
