# read

This specification has been superseded by the IRC `draft/read-marker` extension.

## Description

This document describes the format of the `read` extension. This enables several clients of the same user connected to a bouncer to tell each other about which messages have been read in each buffer (channel or query).

These "read" receipts mean that the actual user has read the message, and is typically useful to clear highlight notifications on other clients. This specification is *not* about message delivery receipts at the client socket level.

The server as mentioned in this document refers to the IRC bouncer the clients are connected to. No messages or capabilities introduced by this specification are exchanged with the actual upstream server the bouncer is connected to.

## Implementation

The `read` extension uses the `soju.im/read` capability and introduces a new command, `READ`.

The `soju.im/read` capability MAY be negotiated, and affects which messages are sent by the server as specified below.

### `READ` Command

The `READ` command can be sent by both clients and servers.

This command has the following general syntax:

    READ <target> [<timestamp>]

The `target` parameter specifies a single buffer (channel or nickname).

The `timestamp` parameter, if specified, MUST be a literal `*`, or have the format `timestamp=YYYY-MM-DDThh:mm:ss.sssZ`, as in the [server-time](https://github.com/ircv3/ircv3-specifications/blob/master/extensions/server-time-3.2.md) extension.

#### `READ` client set command

    READ <target> <timestamp>

When sent from a client, this `READ` command signals to the server that the last message read by the user, to the best knowledge of the client, has the specified timestamp. The timestamp MUST correspond to a previous message `time` tag. The timestamp MUST NOT be a literal `*`.

The server MUST reply to a successful `READ` set command using a `READ` server command, or using an error message.

#### `READ` client get command

    READ <target>

When sent from a client, this `READ` command requests the server about the timestamp of the last message read by the user.

The server MUST reply to a successful `READ` get command using a `READ` server command, or using an error message.

#### `READ` server command

When sent from a server, the `READ` command signals to the client that the last message read by the user, to the best knowledge of the server, has the specified timestamp. In that case, the command has the following syntax:

    <prefix> READ <target> <timestamp>

The `prefix` is the prefix of the client the message is sent to.

If there is no known last message read timestamp, the `timestamp` parameter is a literal `*`. Otherwise, it is the formatted timestamp of the last read message.

#### Command flows

The server sends a `READ` command to a client in the following cases.

If the `soju.im/read` capability is negotiated, after the server sends a server `JOIN` command to the client for a corresponding channel, the server MUST send a `READ` command for that channel. The command MUST be sent before the `RPL_ENDOFNAMES` reply for that channel following the `JOIN`.

If the `soju.im/read` capability is negotiated, after the last read timestamp of a target changes, the server SHOULD send a `READ` command for that target to all the clients of the user.

#### Read timestamp notes

The last read timestamp of a target SHOULD only ever increase. If a client sends a `READ` command with a timestamp that is below or equal to the current known timestamp of the server, the server SHOULD reply with a `READ` command with the newer, previous value that was stored and ignore the client timestamp.

#### Errors and Warnings

Errors are returned using the standard replies syntax.

If the server receives a `READ` command with missing parameters, the `NEED_MORE_PARAMS` error code MUST be returned.

    FAIL READ NEED_MORE_PARAMS :Missing parameters

If the selectors were invalid, the `INVALID_PARAMS` error code SHOULD be returned.

    FAIL READ INVALID_PARAMS [invalid_parameters] :Invalid parameters

If the read timestamp cannot be set or returned due to an error, the `INTERNAL_ERROR` error code SHOULD be returned.

    FAIL READ INTERNAL_ERROR the_given_target [extra_context] :The read timestamp could not be set

### Examples

Updating the read timestamp after the user receives and reads a message
~~~~
[s] @2019-01-04T14:33:26.123Z :nick!ident@host PRIVMSG #channel :message
[c] READ #channel timestamp=2019-01-04T14:33:26.123Z
[s] :irc.host READ #channel timestamp=2019-01-04T14:33:26.123Z
~~~~

Getting the read timestamp automatically after joining a channel when the capability is negotiated
~~~~
[s] :nick!ident@host JOIN #channel
[s] :irc.host READ #channel timestamp=2019-01-04T14:33:26.123Z
~~~~

Getting the read timestamp automatically for a channel without any set timestamp
~~~~
[s] :nick!ident@host JOIN #channel
[s] :irc.host READ #channel *
~~~~

Asking the server about the read timestamp for a particular user
~~~~
[c] READ target
[s] :irc.host READ target timestamp=2019-01-04T14:33:26.123Z
~~~~

## Use Cases

Clients can know whether a user has already read newly received messages. For clients that display notifications about new messages or highlights, knowing when messages have been read can enable them to clear notifications for messages that were already read on another device.

Clients never have to actively get the read timestamp because it is provided to them on join and as updated by the server, except for user targets where they have to request the initial read timestamp by sending a `READ` client get command.

## Implementation Considerations

Server implementations can typically store a per-target timestamp variable that stores the timestamp of the last read message. When it receives a new timestamp, it can clamp it between the last read timestamp and the current time, and broadcast the new value to all clients if it was changed.

Client implementations can know when a user has read messages by using various techniques such as when the focus shifts to their window or activity, when the messages are scrolled, when the user is idle, etc. They should not assume that any message appended to the buffer is being read by the client right now, especially when the window does not have the focus or is not visible. It is indeed a best-effort value.

Clients should typically only need to use the `READ` get client command to get the initial read timestamp of user buffers they open. They will automatically receive initial channels read timestamps and updates, as well as user target timestamp updates.

## Security Considerations

No last read timestamp is ever exchanged with the actual upstream server the bouncer is connected to, so there is no privacy risk that the server might leak or use this read data to infer when the user is online.
