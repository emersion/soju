---
title: "Metadata keys"
layout: spec
copyrights:
  - name: "Simon Ser"
    period: "2025"
    email: "contact@emersion.fr"
---

## Notes for implementing experimental vendor extension

This is an experimental specification for a vendored extension.

No guarantees are made regarding the stability of this extension. Backwards-incompatible changes can be made at any time without prior notice.

Software implementing this work-in-progress specification MUST NOT use the unprefixed metadata keys. Instead, implementations SHOULD use the vendor-prefixed metadata keys to be interoperable with other software implementing a compatible work-in-progress version.

## Description

This document introduces additional [IRCv3 metadata] keys.

Key | Format | Description
----|--------|------------
`soju.im/blocked` | `0` or `1` | Whether the target has been blocked by the user, and messages originating from this source should be hidden
`soju.im/muted` | `0` or `1` | Whether the buffer has been muted by the user, and should be displayed less prominently than others with silenced notifications
`soju.im/pinned` | `0` or `1` | Whether the buffer has been pinned by the user, and should be displayed more prominently than others

[IRCv3 metadata]: https://ircv3.net/specs/extensions/metadata
