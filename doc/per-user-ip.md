# Setting up per-user IP addresses

If your bouncer hosts many users, you may want to assign a unique IP address for
each user. This allows upstream networks to easily ban a single user when a
misbehavior is detected, instead of banning the whole bouncer.

Assuming you're running Linux and want to use the IPv6 prefix `2001:db8::/32`:

1. Setup the router to redirect ingress packets with one of these IP addresses
   as the destination to your bouncer.
2. Enable `net.ipv6.ip_nonlocal_bind=1` with `sysctl`.
3. Setup a local route for this prefix:
   `ip route add local 2001:db8::/56 dev lo`
4. Check network connectivity:
   `curl -6 --interface 2001:db8::42 https://emersion.fr`
5. Configure soju to use this IP range: `upstream-user-ip 2001:db8::/32`

The address `2001:db8::1` will be left unused. Users will be assigned IP
addresses starting from `2001:db8::2`.

The IRC `/whois` command can be used to double-check that the expected IPv6
addresses are being used.
