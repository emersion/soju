package soju

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

type Database interface {
	Close() error
	Stats(ctx context.Context) (*DatabaseStats, error)

	ListUsers(ctx context.Context) ([]User, error)
	GetUser(ctx context.Context, username string) (*User, error)
	StoreUser(ctx context.Context, user *User) error
	DeleteUser(ctx context.Context, id int64) error

	ListNetworks(ctx context.Context, userID int64) ([]Network, error)
	StoreNetwork(ctx context.Context, userID int64, network *Network) error
	DeleteNetwork(ctx context.Context, id int64) error
	ListChannels(ctx context.Context, networkID int64) ([]Channel, error)
	StoreChannel(ctx context.Context, networKID int64, ch *Channel) error
	DeleteChannel(ctx context.Context, id int64) error

	ListDeliveryReceipts(ctx context.Context, networkID int64) ([]DeliveryReceipt, error)
	StoreClientDeliveryReceipts(ctx context.Context, networkID int64, client string, receipts []DeliveryReceipt) error
}

type MetricsCollectorDatabase interface {
	Database
	MetricsCollector() prometheus.Collector
}

func OpenDB(driver, source string) (Database, error) {
	switch driver {
	case "sqlite3":
		return OpenSqliteDB(source)
	case "postgres":
		return OpenPostgresDB(source)
	default:
		return nil, fmt.Errorf("unsupported database driver: %q", driver)
	}
}

type DatabaseStats struct {
	Users    int64
	Networks int64
	Channels int64
}

type User struct {
	ID       int64
	Username string
	Password string // hashed
	Realname string
	Admin    bool
}

type SASL struct {
	Mechanism string

	Plain struct {
		Username string
		Password string
	}

	// TLS client certificate authentication.
	External struct {
		// X.509 certificate in DER form.
		CertBlob []byte
		// PKCS#8 private key in DER form.
		PrivKeyBlob []byte
	}
}

type Network struct {
	ID              int64
	Name            string
	Addr            string
	Nick            string
	Username        string
	Realname        string
	Pass            string
	ConnectCommands []string
	SASL            SASL
	Enabled         bool
}

func (net *Network) GetName() string {
	if net.Name != "" {
		return net.Name
	}
	return net.Addr
}

func (net *Network) URL() (*url.URL, error) {
	s := net.Addr
	if !strings.Contains(s, "://") {
		// This is a raw domain name, make it an URL with the default scheme
		s = "ircs://" + s
	}

	u, err := url.Parse(s)
	if err != nil {
		return nil, fmt.Errorf("failed to parse upstream server URL: %v", err)
	}

	return u, nil
}

func GetNick(user *User, net *Network) string {
	if net.Nick != "" {
		return net.Nick
	}
	return user.Username
}

func GetUsername(user *User, net *Network) string {
	if net.Username != "" {
		return net.Username
	}
	return GetNick(user, net)
}

func GetRealname(user *User, net *Network) string {
	if net.Realname != "" {
		return net.Realname
	}
	if user.Realname != "" {
		return user.Realname
	}
	return GetNick(user, net)
}

type MessageFilter int

const (
	// TODO: use customizable user defaults for FilterDefault
	FilterDefault MessageFilter = iota
	FilterNone
	FilterHighlight
	FilterMessage
)

func parseFilter(filter string) (MessageFilter, error) {
	switch filter {
	case "default":
		return FilterDefault, nil
	case "none":
		return FilterNone, nil
	case "highlight":
		return FilterHighlight, nil
	case "message":
		return FilterMessage, nil
	}
	return 0, fmt.Errorf("unknown filter: %q", filter)
}

type Channel struct {
	ID   int64
	Name string
	Key  string

	Detached              bool
	DetachedInternalMsgID string

	RelayDetached MessageFilter
	ReattachOn    MessageFilter
	DetachAfter   time.Duration
	DetachOn      MessageFilter
}

type DeliveryReceipt struct {
	ID            int64
	Target        string // channel or nick
	Client        string
	InternalMsgID string
}
