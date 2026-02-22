package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"codeberg.org/emersion/soju/config"
	"codeberg.org/emersion/soju/database"
	"codeberg.org/emersion/soju/msgstore"
	"codeberg.org/emersion/soju/xirc"
	"gopkg.in/irc.v4"

	"database/sql"

	_ "github.com/lib/pq"
)

const usage = `usage: quassel-import [options...] <quassel DB URL>

Create Soju users and channels for a Quassel database.

Options:

  -help             Show this help message
  -config <path>    Path to soju config file
`

func init() {
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), usage)
	}
}

var (
	// From QUASSEL/src/common/bufferinfo.h, BufferInfoType
	bufTypeStatusBuffer  uint64 = 0x01
	bufTypeChannelBuffer uint64 = 0x02
	bufTypeQueryBuffer   uint64 = 0x04
	// bufTypeGroupBuffer   uint64 = 0x08
)

func main() {
	var configPath string
	flag.StringVar(&configPath, "config", "", "path to configuration file")
	flag.Parse()

	quasselDbPath := flag.Arg(0)
	if quasselDbPath == "" {
		flag.Usage()
		os.Exit(1)
	}

	var cfg *config.Server
	if configPath != "" {
		var err error
		cfg, err = config.Load(configPath)
		if err != nil {
			log.Fatalf("failed to load config file: %v", err)
		}
	} else {
		cfg = config.Defaults()
	}

	db, err := database.Open(cfg.DB.Driver, cfg.DB.Source)
	if err != nil {
		log.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()

	// TODO(arsen): this should be able to handle SQLite QuasselCore DBs,
	// but I haven't had the opportunity to implement that yet
	qdb, err := sql.Open("postgres", quasselDbPath)
	if err != nil {
		log.Fatalf("failed to open Quassel database: %v", err)
	}
	defer qdb.Close()

	// check whether it's the same version we target
	var schemaVer string
	err = qdb.QueryRow(
		"SELECT value FROM coreinfo WHERE key = 'schemaversion'",
	).Scan(&schemaVer)
	if err != nil {
		log.Fatalf("failed to load schema ver %v", err)
	}
	if schemaVer != "31" {
		log.Fatalf("can't translate this schema version")
	}

	ctx := context.Background()

	// first things first, read the users into the DB
	userMap := make(map[int64]*database.User)
	err = loadUsers(qdb, func(id int64, username string) {
		log.Printf("Processing user %v (id=%d)", username, id)
		u := database.NewUser(username)
		if err := db.StoreUser(ctx, u); err != nil {
			log.Fatalf("failed to store user: %v", err)
		}
		userMap[id] = u
	})
	if err != nil {
		log.Fatalf("failed to load users: %v", err)
	}

	// then, their networks
	networkMap := make(map[int64]*database.Network)
	err = loadNetworks(qdb, func(network *QuasselNetwork) {
		log.Printf(
			"Processing network (id=%v, owner=%v, server=%v, identity=%v, nick=%v): %s",
			network.ID,
			network.OwnerUsername,
			network.IrcServerId,
			network.IdentityId,
			network.NickId,
			network.Name,
		)
		if networkMap[network.ID] != nil {
			log.Printf("Skipping (already added)")
			return
		}

		schema := "irc"
		if network.UseSsl {
			schema = "ircs"
		}
		newNetAddr := fmt.Sprintf(
			"%s://%s:%d",
			schema,
			network.Hostname,
			network.Port,
		)

		newNet := database.NewNetwork(newNetAddr)
		newNet.Name = network.Name

		newNet.Nick = network.Nick
		newNet.Realname = network.Realname

		if network.UseAutoIdentify && network.AutoIdentifyPassword != "" && network.AutoIdentifyService != "" {
			cmd := fmt.Sprintf(
				"PRIVMSG %s :IDENTIFY %s",
				network.AutoIdentifyService,
				network.AutoIdentifyPassword,
			)
			newNet.ConnectCommands = append(newNet.ConnectCommands, cmd)
		}

		if network.SslKey != nil && network.SslCert != nil {
			// If we have any keys present, enable SASL
			// EXTERNAL.  This mechanism is used even for
			// servers that (like OFTC) do not support SASL
			// EXTERNAL, but do have a way to authenticate
			// with client certificates anyway.
			newNet.SASL.Mechanism = "EXTERNAL"
			newNet.SASL.External.CertBlob =
				maybeDecodePem(network.SslCert)
			newNet.SASL.External.PrivKeyBlob =
				maybeConvertPkcs1to8(maybeDecodePem(network.SslKey))
		} else if network.SaslAccount != "" && network.SaslPassword != "" {
			newNet.SASL.Mechanism = "PLAIN"
			newNet.SASL.Plain.Username = network.SaslAccount
			newNet.SASL.Plain.Password = network.SaslPassword
		} else if network.UseSasl {
			log.Printf("Cannot handle SASL for this one?")
		}

		newNet.AutoAway = network.AutoAway

		if err := db.StoreNetwork(ctx, userMap[network.OwnerId].ID, newNet); err != nil {
			log.Fatalf("failed to store net: %v", err)
		}

		networkMap[network.ID] = newNet
	})

	// import joined channels
	channelMap := make(map[int64]*database.Channel)
	err = loadChannels(qdb, func(buffer *QuasselBuffer) {
		channel := &database.Channel{
			Name: buffer.Name,
		}
		if err := db.StoreChannel(ctx, networkMap[buffer.NetworkID].ID, channel); err != nil {
			log.Fatalf("failed to store channel: %v", err)
		}
		channelMap[buffer.ID] = channel
	})

	storeCfg := cfg.MsgStore
	if storeCfg.Driver == "memory" {
		return
	}

	// process logs
	storeCache := make(map[int64]msgstore.Store)
	getStore := func(user *database.User) msgstore.Store {
		switch storeCfg.Driver {
		case "db":
			if storeCache[0] == nil {
				storeCache[0] = msgstore.NewDBStore(db)
			}
			return storeCache[0]
		case "fs":
			store := storeCache[user.ID]
			if store == nil {
				store = msgstore.NewFSStore(
					storeCfg.Source,
					user,
				)
				storeCache[user.ID] = store
			}
			return store
		default:
			log.Fatalf("couldn't resolve driver %v", storeCfg.Driver)
		}
		panic("unreachable")
	}

	err = loadMessages(qdb, func(quasM *QuasselBacklogRow) {
		m := quasM.convertToIrcMsg()
		if m == nil {
			return
		}

		store := getStore(userMap[quasM.UserID])
		_, err := store.Append(ctx, networkMap[quasM.NetworkID], quasM.BufferName, m)
		if err != nil {
			log.Fatalf("failed to store message: %v", err)
		}
	})
	if err != nil {
		log.Fatalf("failed to load messages: %v", err)
	}
}

func loadUsers(qdb *sql.DB, f func(id int64, username string)) error {
	rows, err := qdb.Query("SELECT userid, username FROM quasseluser")
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var (
			id       int64
			username string
		)
		if err := rows.Scan(&id, &username); err != nil {
			return err
		}
		f(id, username)
	}

	return rows.Err()
}

type QuasselNetwork struct {
	ID          int64
	IdentityId  int
	NickId      int
	IrcServerId int

	OwnerUsername string
	OwnerId       int64
	Name          string

	// ircserver cols
	Hostname string
	Port     int
	UseSsl   bool

	Nick     string
	Realname string

	UseAutoIdentify      bool
	AutoIdentifyService  string
	AutoIdentifyPassword string

	// No cert fingerprint :-(

	// SASL
	UseSasl      bool
	SaslAccount  string
	SaslPassword string
	SslCert      []byte
	SslKey       []byte

	AutoAway bool
}

func loadNetworks(qdb *sql.DB, f func(*QuasselNetwork)) error {
	rows, err := qdb.Query(
		`SELECT n.networkid, id.identityid, idn.nickid, i.serverid,
			qu.username,
			qu.userid,
			n.networkname,

			-- ircserver cols
			i.hostname,
			i.port,
			i.ssl,

			idn.nick,
			id.realname,

			n.useautoidentify,
			COALESCE(n.autoidentifyservice, ''),
			COALESCE(n.autoidentifypassword, ''),

			-- SASL
			n.usesasl,
			COALESCE(n.saslaccount, ''),
			COALESCE(n.saslpassword, ''),
			id.sslcert,
			id.sslkey,
			id.autoawayenabled -- lossy!
		 FROM network n
			JOIN quasseluser qu USING (userid)
			JOIN ircserver i USING (networkid)
			JOIN identity id USING (identityid)
			JOIN identity_nick idn USING (identityid)
		`,
	)
	if err != nil {
		return err
	}

	for rows.Next() {
		var network QuasselNetwork
		err := rows.Scan(&network.ID, &network.IdentityId, &network.NickId,
			&network.IrcServerId, &network.OwnerUsername, &network.OwnerId,
			&network.Name, &network.Hostname, &network.Port, &network.UseSsl,
			&network.Nick, &network.Realname, &network.UseAutoIdentify,
			&network.AutoIdentifyService, &network.AutoIdentifyPassword,
			&network.UseSasl, &network.SaslAccount, &network.SaslPassword,
			&network.SslCert, &network.SslKey, &network.AutoAway)
		if err != nil {
			return err
		}
		f(&network)
	}

	return rows.Err()
}

type QuasselBuffer struct {
	Name      string
	ID        int64
	NetworkID int64
}

func loadChannels(qdb *sql.DB, f func(*QuasselBuffer)) error {
	rows, err := qdb.Query(
		`SELECT b.buffername, b.bufferid, b.networkid
			FROM buffer b
			WHERE joined AND (buffertype & $1) != 0`,
		bufTypeChannelBuffer,
	)
	if err != nil {
		return err
	}

	for rows.Next() {
		var channel QuasselBuffer
		if err := rows.Scan(&channel.Name, &channel.ID, &channel.NetworkID); err != nil {
			return err
		}
		f(&channel)
	}

	return rows.Err()
}

func loadMessages(qdb *sql.DB, f func(*QuasselBacklogRow)) error {
	rows, err := qdb.Query(
		`SELECT l.messageid,
			COALESCE(l.message, ''),
			-- Per https://doc.qt.io/qt-6/sql-driver.html#driver-specifics-qpsql-for-postgresql-version-7-3-and-above-timestamp-support-26,
			-- always UTC
			l.time AT TIME ZONE 'Etc/UTC',

			l.type,

			s.sender,

			b.buffername,
			l.bufferid,
			b.buffertype,

			qu.userid,
			b.networkid
		FROM backlog l
			JOIN buffer b USING (bufferid)
			JOIN sender s USING (senderid)
			JOIN quasseluser qu USING (userid)
		WHERE (b.buffertype & $1) != 0
		ORDER BY l.messageid ASC`,
		bufTypeChannelBuffer|bufTypeStatusBuffer|bufTypeQueryBuffer,
	)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var row QuasselBacklogRow
		err := rows.Scan(&row.MessageID, &row.Message, &row.Time, &row.Type,
			&row.Sender, &row.BufferName, &row.BufferId, &row.BufferType,
			&row.UserID, &row.NetworkID)
		if err != nil {
			return err
		}
		f(&row)
	}

	return rows.Err()
}

// Given PEM contents in maybePem, return decoded body.
func maybeDecodePem(maybePem []byte) []byte {
	p, rest := pem.Decode(maybePem)
	if p == nil {
		return rest
	}

	if len(rest) > 0 {
		log.Fatalf("decoding PEM failed (left over: %v) ;-(", len(rest))
	}

	return p.Bytes
}

// If MAYBEPKCS1 is a PKCS#1 formatted private key, convert it into a PKCS#8
// formatted key.  Do nothing otherwise.
func maybeConvertPkcs1to8(maybePkcs1 []byte) []byte {
	key, err := x509.ParsePKCS1PrivateKey(maybePkcs1)
	if err == nil {
		newBytes, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			log.Printf("Could not convert PKCS#1 key, ignoring...")
			return maybePkcs1
		}
		return newBytes
	}
	return maybePkcs1
}

type QuasselBacklogRow struct {
	MessageID int64
	Message   string
	Time      time.Time

	Type uint64

	Sender string

	BufferName string
	BufferId   int64
	BufferType uint64

	UserID    int64
	NetworkID int64
}

var (
	// From QUASSEL/src/common/message.h, Message::Type
	mTypePlain  uint64 = 0x00001
	mTypeNotice uint64 = 0x00002
	mTypeAction uint64 = 0x00004
	mTypeNick   uint64 = 0x00008
	mTypeMode   uint64 = 0x00010
	mTypeJoin   uint64 = 0x00020
	mTypePart   uint64 = 0x00040
	mTypeQuit   uint64 = 0x00080
	mTypeKick   uint64 = 0x00100
	// mTypeKill         uint64 = 0x00200
	mTypeServer       uint64 = 0x00400
	mTypeInfo         uint64 = 0x00800
	mTypeError        uint64 = 0x01000
	mTypeDayChange    uint64 = 0x02000
	mTypeTopic        uint64 = 0x04000
	mTypeNetsplitJoin uint64 = 0x08000
	mTypeNetsplitQuit uint64 = 0x10000
	mTypeInvite       uint64 = 0x20000
)

func (m *QuasselBacklogRow) convertToIrcMsg() *irc.Message {
	prefix := irc.ParsePrefix(m.Sender)
	tags := map[string]string{
		"time":              xirc.FormatServerTime(m.Time),
		"soju.im/quasselid": fmt.Sprint(m.MessageID),
	}
	paramsPlain := []string{m.BufferName, m.Message}

	switch m.Type {
	case mTypePlain, mTypeNotice:
		command := "PRIVMSG"
		if m.Type == mTypeNotice {
			command = "NOTICE"
		}
		return &irc.Message{
			Tags:    tags,
			Prefix:  prefix,
			Command: command,
			Params:  paramsPlain,
		}
	case mTypeAction:
		return &irc.Message{
			Tags:    tags,
			Prefix:  prefix,
			Command: "PRIVMSG",
			Params:  []string{m.BufferName, fmt.Sprintf("\x01ACTION %s\x01", m.Message)},
		}
	case mTypeNick:
		return &irc.Message{
			Tags:    tags,
			Prefix:  prefix,
			Command: "NICK",
			Params:  []string{m.Message},
		}
	case mTypeMode:
		return &irc.Message{
			Tags:    tags,
			Prefix:  prefix,
			Command: "MODE",
			Params:  strings.Split(m.Message, " "),
		}
	case mTypeJoin:
		return &irc.Message{
			Tags:    tags,
			Prefix:  prefix,
			Command: "JOIN",
			Params:  []string{m.Message},
		}
	case mTypePart:
		var params []string
		if m.Message != "" {
			params = []string{m.BufferName, m.Message}
		} else {
			params = []string{m.BufferName}
		}
		return &irc.Message{
			Tags:    tags,
			Prefix:  prefix,
			Command: "PART",
			Params:  params,
		}
	case mTypeQuit:
		return &irc.Message{
			Tags:    tags,
			Prefix:  prefix,
			Command: "QUIT",
			Params:  []string{m.Message},
		}
	case mTypeKick:
		return &irc.Message{
			Tags:    tags,
			Prefix:  prefix,
			Command: "KICK",
			Params: append(
				[]string{m.BufferName},
				strings.SplitN(m.Message, " ", 2)...,
			),
		}
	case mTypeTopic:
		// Too high-level in the DB.
		return nil
	case mTypeServer:
		// Simply no - search for Message::Server in
		// https://github.com/quassel/quassel/blob/e27561af02441e2199533f9085f24c33150b2efa/src/core/eventstringifier.cpp
		// There are *way* too many.
		return nil
	case mTypeError, mTypeDayChange, mTypeInvite, mTypeInfo:
		// not really important
		return nil
	case mTypeNetsplitJoin, mTypeNetsplitQuit:
		// TODO(arsen): may not be worth it, not sure how to recover
		// these correctly yet
		return nil
	default:
		panic("unhandled message type")
	}
}
