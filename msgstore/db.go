package msgstore

import (
	"context"
	"time"

	"git.sr.ht/~emersion/soju/database"
	"git.sr.ht/~sircmpwn/go-bare"
	"gopkg.in/irc.v4"
)

type dbMsgID struct {
	ID bare.Uint
}

func (dbMsgID) msgIDType() msgIDType {
	return msgIDDB
}

func parseDBMsgID(s string) (msgID int64, err error) {
	var id dbMsgID
	_, _, err = ParseMsgID(s, &id)
	if err != nil {
		return 0, err
	}
	return int64(id.ID), nil
}

func formatDBMsgID(netID int64, target string, msgID int64) string {
	id := dbMsgID{bare.Uint(msgID)}
	return formatMsgID(netID, target, &id)
}

// dbMessageStore is a persistent store for IRC messages, that
// stores messages in the soju database.
type dbMessageStore struct {
	db database.Database
}

var (
	_ Store            = (*dbMessageStore)(nil)
	_ ChatHistoryStore = (*dbMessageStore)(nil)
	_ SearchStore      = (*dbMessageStore)(nil)
)

func NewDBStore(db database.Database) *dbMessageStore {
	return &dbMessageStore{
		db: db,
	}
}

func (ms *dbMessageStore) Close() error {
	return nil
}

func (ms *dbMessageStore) LastMsgID(network *database.Network, entity string, t time.Time) (string, error) {
	// TODO: what should we do with t?

	id, err := ms.db.GetMessageLastID(context.TODO(), network.ID, entity)
	if err != nil {
		return "", err
	}
	return formatDBMsgID(network.ID, entity, id), nil
}

func (ms *dbMessageStore) LoadLatestID(ctx context.Context, id string, options *LoadMessageOptions) ([]*irc.Message, error) {
	msgID, err := parseDBMsgID(id)
	if err != nil {
		return nil, err
	}

	l, err := ms.db.ListMessages(ctx, options.Network.ID, options.Entity, &database.MessageOptions{
		AfterID:  msgID,
		Limit:    options.Limit,
		TakeLast: true,
	})
	if err != nil {
		return nil, err
	}
	return l, nil
}

func (ms *dbMessageStore) Append(network *database.Network, entity string, msg *irc.Message) (string, error) {
	id, err := ms.db.StoreMessage(context.TODO(), network.ID, entity, msg)
	if err != nil {
		return "", err
	}
	return formatDBMsgID(network.ID, entity, id), nil
}

func (ms *dbMessageStore) ListTargets(ctx context.Context, network *database.Network, start, end time.Time, limit int, events bool) ([]ChatHistoryTarget, error) {
	var opts  *database.MessageOptions
	if start.Before(end) {
		opts = &database.MessageOptions{
			AfterTime:  start,
			BeforeTime: end,
			Limit:      limit,
			Events:     events,
		}
	} else {
		opts = &database.MessageOptions{
			AfterTime:  end,
			BeforeTime: start,
			Limit:      limit,
			Events:     events,
			TakeLast: true,
		}
	}
	l, err := ms.db.ListMessageLastPerTarget(ctx, network.ID, opts);
	if err != nil {
		return nil, err
	}
	targets := make([]ChatHistoryTarget, len(l))
	for i, v := range l {
		targets[i] = ChatHistoryTarget{
			Name:          v.Name,
			LatestMessage: v.LatestMessage,
		}
	}
	return targets, nil
}

func (ms *dbMessageStore) LoadBeforeTime(ctx context.Context, start, end time.Time, options *LoadMessageOptions) ([]*irc.Message, error) {
	l, err := ms.db.ListMessages(ctx, options.Network.ID, options.Entity, &database.MessageOptions{
		AfterTime:  end,
		BeforeTime: start,
		Limit:      options.Limit,
		Events:     options.Events,
		TakeLast:   true,
	})
	if err != nil {
		return nil, err
	}
	return l, nil
}

func (ms *dbMessageStore) LoadAfterTime(ctx context.Context, start, end time.Time, options *LoadMessageOptions) ([]*irc.Message, error) {
	l, err := ms.db.ListMessages(ctx, options.Network.ID, options.Entity, &database.MessageOptions{
		AfterTime:  start,
		BeforeTime: end,
		Limit:      options.Limit,
		Events:     options.Events,
	})
	if err != nil {
		return nil, err
	}
	return l, nil
}

func (ms *dbMessageStore) Search(ctx context.Context, network *database.Network, options *SearchMessageOptions) ([]*irc.Message, error) {
	l, err := ms.db.ListMessages(ctx, network.ID, options.In, &database.MessageOptions{
		AfterTime:  options.Start,
		BeforeTime: options.End,
		Limit:      options.Limit,
		Sender:     options.From,
		Text:       options.Text,
		TakeLast:   true,
	})
	if err != nil {
		return nil, err
	}
	return l, nil
}
