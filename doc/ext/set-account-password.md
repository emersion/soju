## Description

This document describes the `soju.im/set-account-password` extension. It
provides a command for clients to change their account password.

## Capability

This specification adds the `soju.im/set-account-password` capability which
indicates that the server accepts the `SETPASSWORD` command.

## Command

    SETPASSWORD <new-password>

The `SETPASSWORD` command requests to change the current user's account
password.

## Response

    SETPASSWORD SUCCESS

Sent by the server when the `SETPASSWORD` command succeeds.

    FAIL SETPASSWORD WEAK_PASSWORD <message>

Sent by the server if the password is considered too weak.

    FAIL SETPASSWORD UNACCEPTABLE_PASSWORD <message>

Sent by the server if the password is invalid for any reason other than
weakness.
