package jounce

import (
	"gopkg.in/irc.v3"
)

func forwardChannel(dc *downstreamConn, ch *upstreamChannel) {
	if !ch.complete {
		panic("Tried to forward a partial channel")
	}

	dc.SendMessage(&irc.Message{
		Prefix:  dc.prefix(),
		Command: "JOIN",
		Params:  []string{ch.Name},
	})

	if ch.Topic != "" {
		dc.SendMessage(&irc.Message{
			Prefix:  dc.srv.prefix(),
			Command: irc.RPL_TOPIC,
			Params:  []string{dc.nick, ch.Name, ch.Topic},
		})
	} else {
		dc.SendMessage(&irc.Message{
			Prefix:  dc.srv.prefix(),
			Command: irc.RPL_NOTOPIC,
			Params:  []string{dc.nick, ch.Name, "No topic is set"},
		})
	}

	// TODO: rpl_topicwhotime

	// TODO: send multiple members in each message
	for nick, membership := range ch.Members {
		s := nick
		if membership != 0 {
			s = string(membership) + nick
		}

		dc.SendMessage(&irc.Message{
			Prefix:  dc.srv.prefix(),
			Command: irc.RPL_NAMREPLY,
			Params:  []string{dc.nick, string(ch.Status), ch.Name, s},
		})
	}

	dc.SendMessage(&irc.Message{
		Prefix:  dc.srv.prefix(),
		Command: irc.RPL_ENDOFNAMES,
		Params:  []string{dc.nick, ch.Name, "End of /NAMES list"},
	})
}
