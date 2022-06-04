# account-required

This specification defines the informational `soju.im/account-required`
capability. If present, it indicates that the connection to the server cannot
be completed unless the clients authenticates, typically via SASL. Note, the
absence of this capability does not indicate that connection registration can
be completed without authentication; it may be disallowed due to specific
properties of the connection (e.g. an untrustworthy IP address), which will be
indicated instead by `FAIL * ACCOUNT_REQUIRED`.

Clients MUST NOT request `soju.im/account-required`; servers MUST reject any
`CAP REQ` command including this capability.
