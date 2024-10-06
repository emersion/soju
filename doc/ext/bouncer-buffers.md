---
title: Bouncer buffers extension
layout: spec
work-in-progress: true
copyrights:
  -
    name: "delthas"
    period: "2022"
    email: "delthas@dille.cc"
---

## Notes for implementing experimental vendor extension

This is an experimental specification for a vendored extension.

No guarantees are made regarding the stability of this extension.
Backwards-incompatible changes can be made at any time without prior notice.

Software implementing this work-in-progress specification MUST NOT use the
unprefixed `bouncer-buffers` CAP names. Instead, implementations SHOULD use
the `soju.im/bouncer-buffers` CAP names to be interoperable with other software
implementing a compatible work-in-progress version.

## Description

This document describes the `soju.im/bouncer-buffers` extension. This enables
clients to discover servers that are bouncers, list and edit upstream buffers
the bouncer is connected to.

Each buffer is identified by its unique network ID, and its name.
Only channel buffers are supported.

Buffers also have attributes. Attributes are encoded in the message-tag
format. Clients MUST ignore unknown attributes.

## Implementation

The `soju.im/bouncer-buffers` extension defines new `BOUNCER` subcommands.

The `soju.im/bouncer-buffers` capability MUST be negotiated. This allows the
server and client to behave differently when the client is aware of the bouncer
networks.

The `soju.im/bouncer-networks` capability MUST be negotiated. This specification
build upon the BOUNCER command introduced in that specification.

The `soju.im/bouncer-buffers-notify` capability MAY be negotiated. This allows
the client to signal that it is capable of receiving and correctly processing
bouncer buffer notifications.

### `soju.im/bouncer-buffers` batch

The `soju.im/bouncer-buffers` batch does not take any parameter and can only
contain `BOUNCER BUFFER` messages.

### New `BOUNCER` scommand

#### `LISTBUFFERS` subcommand

The `LISTBUFFERS` subcommand queries the list of upstream buffers.

    BOUNCER LISTBUFFERS

The server replies with a `soju.im/bouncer-buffers` batch, containing any
number of `BOUNCER BUFFER` messages:

    BOUNCER BUFFER <netid> <name> <attributes>

#### `CHANGEBUFFER` subcommand

The `CHANGEBUFFER` subcommand changes attributes of an existing upstream
buffer.

    BOUNCER CHANGEBUFFER <netid> <name> <attributes>

The bouncer MAY reject the change for any reason, in this case it MUST reply
with an error. At least one attribute MUST be specified by the client.

On success, the server replies with:

    BOUNCER CHANGEBUFFER <netid> <name>

#### `DELBUFFER` subcommand

The `DELBUFFER` subcommand removes an existing upstream buffer.

    BOUNCER DELBUFFER <netid> <name>

The bouncer MAY reject the change for any reason, in this case it MUST reply
with an error.

On success, the server replies with:

    BOUNCER DELNETWORK <netid> <name>

### Network notifications

If the client has negotiated the `soju.im/bouncer-buffers-notify` capability,
the server MUST send an initial batch of `BOUNCER BUFFER` messages with the
current list of buffers, and MUST send notification messages whenever a buffer
is updated or removed.

If the client has not negotiated the `soju.im/bouncer-buffers-notify`
capability, the server MUST NOT send implicit `BOUNCER BUFFER` messages.

When network attributes are updated, the bouncer MUST broadcast a
`BOUNCER BUFFER` message with the updated attributes to all connected clients
with the `soju.im/bouncer-buffers-notify` capability enabled:

    BOUNCER BUFFER <netid> <name> <attributes>

The notification SHOULD NOT contain attributes that haven't been updated. An
attribute without a value means that the attribute has been removed.

When a network is removed, the bouncer MUST broadcast a `BOUNCER BUFFER`
message with the special argument `*` to all connected clients with the
`soju.im/bouncer-buffers-notify` capability enabled:

    BOUNCER NETWORK <netid> <name> *

Buffers are added with the regular IRC `JOIN` command, so there is no
notification for that event.

### Errors

Errors are returned using the standard replies syntax, following the
`soju.im/bouncer-networks` specification.

#### `INVALID_BUFFER_NAME` error

If a client sends a subcommand with an invalid buffer name, the server MUST
reply with:

    FAIL BOUNCER INVALID_BUFFER_NAME <subcommand> <netid> <name> :Buffer not found

#### `INVALID_BUFFER_ATTRIBUTE` error

If a client sends an `ADDBUFFER` or a `CHANGEBUFFER` subcommand with an
invalid attribute, the server MUST reply with:

    FAIL BOUNCER INVALID_BUFFER_ATTRIBUTE <subcommand> <netid> <name> <attribute> :Invalid attribute value

#### `READ_ONLY_BUFFER_ATTRIBUTE` error

If a client attempts to change a read-only network attribute using the
`CHANGEBUFFER` subcommand, the server MUST reply with:

    FAIL BOUNCER READ_ONLY_BUFFER_ATTRIBUTE <subcommand> <netid> <name> <attribute> :Read-only attribute

#### `UNKNOWN_BUFFER_ATTRIBUTE` error

If a client sends a `CHANGEBUFFER` subcommand with an
unknown attribute, the server MUST reply with:

    FAIL BOUNCER UNKNOWN_BUFFER_ATTRIBUTE <subcommand> <netid> <name> <attribute> :Unknown attribute

TODO: more errors

### Standard network attributes

Bouncers MUST recognise the following network attributes:

* `pinned`: `1` if the buffer is pinned (usually shown at the top of the channel list), `0` otherwise.
* `muted`: `1` if the buffer is muted (usually has its notifications disabled), `0` otherwise.
* `detached`: `1` if the buffer is detached (joined to by the buffer but not by the clients), `0` otherwise.

TODO: more attributes

### Examples

Binding to a network:

    C: CAP LS 302
    C: NICK emersion
    C: USER emersion 0 0 :Simon
    S: CAP * LS :sasl=PLAIN soju.im/bouncer-networks soju.im/bouncer-buffers soju.im/bouncer-buffers-notify
    C: CAP REQ :sasl soju.im/bouncer-networks soju.im/bouncer-buffers
    [SASL authentication]
    C: BOUNCER BIND 42
    C: CAP END

Listing networks:

    C: BOUNCER LISTBUFFERS
    S: BATCH +asdf soju.im/bouncer-buffers
    S: @batch=asdf BOUNCER BUFFER 42 #cat pinned=1
    S: @batch=asdf BOUNCER BUFFER 43 #dog muted=1
    S: BATCH -asdf

Changing an existing network:

    C: BOUNCER CHANGEBUFFER 44 #simon pinned=1
    S: BOUNCER BUFFER 44 #simon pinned=1
    S: BOUNCER CHANGEBUFFER 44

Removing an existing network:

    C: BOUNCER DELBUFFER 44 #simon
    S: BOUNCER BUFFER 44 #simon *
    S: BOUNCER DELBUFFER 44 #simon
