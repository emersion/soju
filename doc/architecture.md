# soju architecture

soju manages two types of connections:

- Upstream connections: soju maintains persistent connections to
  user-configured IRC servers
- Downstream connections: soju accepts connections from IRC clients

On startup, soju will iterate over the list of networks stored in the database
and try to open an upstream connection for each network.

## Ring buffer

In order to correctly send history to each downstream client, soju maintains
for each upstream channel a single-producer multiple-consumer ring buffer. The
network's upstream connection produces messages and multiple downstream
connections consume these messages. Each downstream client may have a different
cursor in the history: for instance a client may be 10 messages late while
another has consumed all pending messages.

## Goroutines

Each type of connection has two dedicated goroutines: the first one reads
incoming messages, the second one writes outgoing messages.

Each user has a dedicated goroutine responsible for dispatching all messages.
It communicates via channels with the per-connection reader and writer
goroutines. This allows to keep the dispatching logic simple (by avoiding any
race condition or inconsistent state) and to rate-limit each user.

The user dispatcher goroutine receives from the `user.events` channel. Upstream
and downstream message handlers are called from this goroutine, thus they can
safely access both upstream and downstream state.
