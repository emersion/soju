package soju

import (
	"gopkg.in/irc.v3"
	"strings"
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
	downstreamName := dc.marshalEntity(ch.conn.network, ch.Name)

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
	downstreamName := dc.marshalEntity(ch.conn.network, ch.Name)

	emptyNameReply := &irc.Message{
		Prefix:  dc.srv.prefix(),
		Command: irc.RPL_NAMREPLY,
		Params:  []string{dc.nick, string(ch.Status), downstreamName, ""},
	}
	maxLength := maxMessageLength - len(emptyNameReply.String())

	var buf strings.Builder
	for nick, memberships := range ch.Members {
		s := memberships.Format(dc) + dc.marshalEntity(ch.conn.network, nick)

		if buf.Len() != 0 && maxLength < buf.Len()+1+len(s) {
			// There's not enough space for the next space + nick.
			dc.SendMessage(&irc.Message{
				Prefix:  dc.srv.prefix(),
				Command: irc.RPL_NAMREPLY,
				Params:  []string{dc.nick, string(ch.Status), downstreamName, buf.String()},
			})
			buf.Reset()
		}

		if buf.Len() != 0 {
			buf.WriteByte(' ')
		}
		buf.WriteString(s)
	}

	if buf.Len() != 0 {
		dc.SendMessage(&irc.Message{
			Prefix:  dc.srv.prefix(),
			Command: irc.RPL_NAMREPLY,
			Params:  []string{dc.nick, string(ch.Status), downstreamName, buf.String()},
		})
	}

	dc.SendMessage(&irc.Message{
		Prefix:  dc.srv.prefix(),
		Command: irc.RPL_ENDOFNAMES,
		Params:  []string{dc.nick, downstreamName, "End of /NAMES list"},
	})
}
