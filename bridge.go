package soju

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"gopkg.in/irc.v3"

	"git.sr.ht/~emersion/soju/xirc"
)

func forwardChannel(ctx context.Context, dc *downstreamConn, ch *upstreamChannel) {
	if !ch.complete {
		panic("Tried to forward a partial channel")
	}

	// RPL_NOTOPIC shouldn't be sent on JOIN
	if ch.Topic != "" {
		sendTopic(dc, ch)
	}

	if dc.caps.IsEnabled("soju.im/read") {
		channelCM := ch.conn.network.casemap(ch.Name)
		r, err := dc.srv.db.GetReadReceipt(ctx, ch.conn.network.ID, channelCM)
		if err != nil {
			dc.logger.Printf("failed to get the read receipt for %q: %v", ch.Name, err)
		} else {
			timestampStr := "*"
			if r != nil {
				timestampStr = fmt.Sprintf("timestamp=%s", xirc.FormatServerTime(r.Timestamp))
			}
			dc.SendMessage(&irc.Message{
				Prefix:  dc.prefix(),
				Command: "READ",
				Params:  []string{dc.marshalEntity(ch.conn.network, ch.Name), timestampStr},
			})
		}
	}

	if !dc.caps.IsEnabled("soju.im/no-implicit-names") {
		sendNames(dc, ch)
	}
}

func sendTopic(dc *downstreamConn, ch *upstreamChannel) {
	downstreamName := dc.marshalEntity(ch.conn.network, ch.Name)

	if ch.Topic != "" {
		dc.SendMessage(&irc.Message{
			Prefix:  dc.srv.prefix(),
			Command: irc.RPL_TOPIC,
			Params:  []string{dc.nick, downstreamName, ch.Topic},
		})
		if ch.TopicWho != nil {
			topicWho := dc.marshalUserPrefix(ch.conn.network, ch.TopicWho)
			topicTime := strconv.FormatInt(ch.TopicTime.Unix(), 10)
			dc.SendMessage(&irc.Message{
				Prefix:  dc.srv.prefix(),
				Command: rpl_topicwhotime,
				Params:  []string{dc.nick, downstreamName, topicWho.String(), topicTime},
			})
		}
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
	for _, entry := range ch.Members.innerMap {
		nick := entry.originalKey
		memberships := entry.value.(*memberships)
		s := memberships.Format(dc) + dc.marshalEntity(ch.conn.network, nick)

		n := buf.Len() + 1 + len(s)
		if buf.Len() != 0 && n > maxLength {
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
