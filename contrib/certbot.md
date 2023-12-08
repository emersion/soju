# Setting up Certbot for soju

If you are using [Certbot] to obtain HTTPS certificates, you can set up soju
like so:

- Obtain the certificate:

      certbot certonly -d <domain>

- Allow all local users to access certificates (private keys are still
  protected):

      chmod 0755 /etc/letsencrypt/{live,archive}

- Allow the soju user to read the private key:

      chmod 0640 /etc/letsencrypt/live/<domain>/privkey.pem
      chgrp soju /etc/letsencrypt/live/<domain>/privkey.pem

- Set the `tls` directive in the soju configuration file:

      tls /etc/letsencrypt/live/<domain>/fullchain.pem /etc/letsencrypt/live/<domain>/privkey.pem

- Configure Certbot to reload soju. Edit
  `/etc/letsencrypt/renewal-hooks/post/soju.sh` and add a command to reload
  soju, for instance:

      #!/bin/sh -eu
      systemctl reload soju

  Then mark the script as executable:

      chmod 755 /etc/letsencrypt/renewal-hooks/post/soju.sh

[Certbot]: https://certbot.eff.org/
