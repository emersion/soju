# no-implicit-names

This specification has been superseded by the IRC `draft/no-implicit-names` extension.

## Description

This document describes the `no-implicit-names` extension. This allows clients to opt-out from the implicit `NAMES` reply servers send after `JOIN` messages.

Some clients don't need to query the list of channel members for all joined channels. Omitting this information can reduce the time taken to connect to the server, especially on mobile devices and when a large number of channels are joined.

## Implementation

The `no-implicit-names` extension introduces the `soju.im/no-implicit-names` capability. When negotiated, servers MUST NOT send an implicit `NAMES` reply after sending a `JOIN` message. Servers MUST reply to explicit `NAMES` commands sent by the client as usual.
