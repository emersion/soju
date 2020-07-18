---
title: IDLE extension
layout: spec
work-in-progress: true
copyrights:
  -
    name: "delthas"
    period: "2021"
    email: "delthas@dille.cc"
  -
    name: "Simon Ser"
    period: "2021"
    email: "contact@emersion.fr"
---

## Description

This document describes the `IDLE` extension. It enables clients to pause
messages on the IRC connection temporarily, until the client stops idling or
until a message of interest is queued by the server. The goal is to wake up the
modem hardware less often on battery-powered devices.

If a server supports this extension, it advertises the `IDLE` token in the
`RPL_ISUPPORT` list.

The client starts idling by sending an `IDLE` command:

    IDLE

When the server receives the command, it temporarily stops sending IRC messages
on the connection. The server accumulates outgoing messages in a buffer. When
the server stops idling, the buffered messages are flushed to the connection
before any other message is sent.

The server MUST stop idling when a `PRIVMSG` or `NOTICE` targeting the client is
queued. The server MAY stop idling at any point in time, e.g. because its
outgoing buffer is full.
