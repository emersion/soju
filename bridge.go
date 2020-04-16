package soju

import (
	"gopkg.in/irc.v3"
)

func forwardChannel(dc *downstreamConn, ch *upstreamChannel) {
	if !ch.complete {
		panic("Tried to forward a partial channel")
	}

	sendTopic(dc, ch)

	// TODO: rpl_topicwhotime
	sendNames(dc, ch)
}

func sendTopic(dc *downstreamConn, ch *upstreamChannel) {
	downstreamName := dc.marshalEntity(ch.conn, ch.Name)

	if ch.Topic != "" {
		dc.SendMessage(&irc.Message{
			Prefix:  dc.srv.prefix(),
			Command: irc.RPL_TOPIC,
			Params:  []string{dc.nick, downstreamName, ch.Topic},
		})
	} else {
		dc.SendMessage(&irc.Message{
			Prefix:  dc.srv.prefix(),
			Command: irc.RPL_NOTOPIC,
			Params:  []string{dc.nick, downstreamName, "No topic is set"},
		})
	}
}

func sendNames(dc *downstreamConn, ch *upstreamChannel) {
	// TODO: send multiple members in each message

	downstreamName := dc.marshalEntity(ch.conn, ch.Name)

	for nick, membership := range ch.Members {
		s := membership.String() + dc.marshalEntity(ch.conn, nick)

		dc.SendMessage(&irc.Message{
			Prefix:  dc.srv.prefix(),
			Command: irc.RPL_NAMREPLY,
			Params:  []string{dc.nick, string(ch.Status), downstreamName, s},
		})
	}

	dc.SendMessage(&irc.Message{
		Prefix:  dc.srv.prefix(),
		Command: irc.RPL_ENDOFNAMES,
		Params:  []string{dc.nick, downstreamName, "End of /NAMES list"},
	})
}
