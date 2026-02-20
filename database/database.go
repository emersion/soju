package database

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/irc.v4"
)

var ErrDuplicateDeviceCertificate = fmt.Errorf("duplicate device certificate")

type MessageTargetLast struct {
	Name          string
	LatestMessage time.Time
}

type MessageOptions struct {
	AfterID    int64
	AfterTime  time.Time
	BeforeTime time.Time
	Limit      int
	Events     bool
	Sender     string
	Text       string
	TakeLast   bool
}

type Database interface {
	Close() error
	Stats(ctx context.Context) (*DatabaseStats, error)

	ListUsers(ctx context.Context) ([]User, error)
	GetUser(ctx context.Context, username string) (*User, error)
	StoreUser(ctx context.Context, user *User) error
	DeleteUser(ctx context.Context, id int64) error
	GetUsernameByID(ctx context.Context, id int64) (string, error)
	ListInactiveUsernames(ctx context.Context, limit time.Time) ([]string, error)

	ListNetworks(ctx context.Context, userID int64) ([]Network, error)
	StoreNetwork(ctx context.Context, userID int64, network *Network) error
	DeleteNetwork(ctx context.Context, id int64) error
	ListChannels(ctx context.Context, networkID int64) ([]Channel, error)
	StoreChannel(ctx context.Context, networKID int64, ch *Channel) error
	DeleteChannel(ctx context.Context, id int64) error

	GetDeviceCertificate(ctx context.Context, fingerprint []byte) (int64, *DeviceCertificate, error)
	ListDeviceCertificates(ctx context.Context, userID int64) ([]DeviceCertificate, error)
	StoreDeviceCertificate(ctx context.Context, userID int64, cert *DeviceCertificate) error
	DeleteDeviceCertificate(ctx context.Context, userID int64, fingerprint []byte) error

	ListDeliveryReceipts(ctx context.Context, networkID int64) ([]DeliveryReceipt, error)
	StoreClientDeliveryReceipts(ctx context.Context, networkID int64, client string, receipts []DeliveryReceipt) error

	GetReadReceipt(ctx context.Context, networkID int64, name string) (*ReadReceipt, error)
	StoreReadReceipt(ctx context.Context, networkID int64, receipt *ReadReceipt) error

	ListWebPushConfigs(ctx context.Context) ([]WebPushConfig, error)
	StoreWebPushConfig(ctx context.Context, config *WebPushConfig) error

	ListWebPushSubscriptions(ctx context.Context, userID, networkID int64) ([]WebPushSubscription, error)
	StoreWebPushSubscription(ctx context.Context, userID, networkID int64, sub *WebPushSubscription) error
	DeleteWebPushSubscription(ctx context.Context, id int64) error

	GetMessageLastID(ctx context.Context, networkID int64, name string) (int64, error)
	GetMessageTarget(ctx context.Context, networkID int64, target string) (*MessageTarget, error)
	ListMessageTargets(ctx context.Context, networkID int64) ([]MessageTarget, error)
	StoreMessageTarget(ctx context.Context, networkID int64, mt *MessageTarget) error
	StoreMessages(ctx context.Context, networkID int64, name string, msgs []*irc.Message) ([]int64, error)
	ListMessageLastPerTarget(ctx context.Context, networkID int64, options *MessageOptions) ([]MessageTargetLast, error)
	ListMessages(ctx context.Context, networkID int64, name string, options *MessageOptions) ([]*irc.Message, error)
}

type MetricsCollectorDatabase interface {
	Database
	RegisterMetrics(r prometheus.Registerer) error
}

func Open(driver, source string) (Database, error) {
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
	ID                     int64
	Username               string
	Password               string // hashed
	Nick                   string
	Realname               string
	Admin                  bool
	Enabled                bool
	DownstreamInteractedAt time.Time
	MaxNetworks            int
}

func NewUser(username string) *User {
	return &User{
		Username:    username,
		Enabled:     true,
		MaxNetworks: -1,
	}
}

func (u *User) CheckPassword(password string) (upgraded bool, err error) {
	if u.Password == "" {
		return false, fmt.Errorf("password auth disabled")
	}

	err = bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(password))
	if err != nil {
		return false, fmt.Errorf("wrong password: %v", err)
	}

	passCost, err := bcrypt.Cost([]byte(u.Password))
	if err != nil {
		return false, fmt.Errorf("invalid password cost: %v", err)
	}

	if passCost < bcrypt.DefaultCost {
		return true, u.SetPassword(password)
	}
	return false, nil
}

func (u *User) SetPassword(password string) error {
	hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %v", err)
	}
	u.Password = string(hashed)
	return nil
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
	CertFP          string
	SASL            SASL
	AutoAway        bool
	Enabled         bool
}

func NewNetwork(addr string) *Network {
	return &Network{
		Addr:     addr,
		AutoAway: true,
		Enabled:  true,
	}
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
		// This is a raw domain name, make it a URL with the default scheme
		s = "ircs://" + s
	}

	u, err := url.Parse(s)
	if err != nil {
		return nil, fmt.Errorf("failed to parse upstream server URL: %v", err)
	}
	switch u.Scheme {
	case "irc+unix", "unix":
		u.Path = u.Host + u.Path
		u.Host = ""
	}

	return u, nil
}

func GetNick(user *User, net *Network) string {
	if net != nil && net.Nick != "" {
		return net.Nick
	}
	if user.Nick != "" {
		return user.Nick
	}
	return user.Username
}

func GetUsername(user *User, net *Network) string {
	if net != nil && net.Username != "" {
		return net.Username
	}
	return GetNick(user, net)
}

func GetRealname(user *User, net *Network) string {
	if net != nil && net.Realname != "" {
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

type DeviceCertificate struct {
	ID          int64
	Label       string
	Fingerprint []byte // SHA-512 hash
	LastUsed    time.Time
	LastIP      string
}

func (cert *DeviceCertificate) MarkUsed(addr net.Addr) {
	cert.LastUsed = time.Now()
	switch a := addr.(type) {
	case *net.TCPAddr:
		cert.LastIP = a.IP.String()
	case *net.UDPAddr:
		cert.LastIP = a.IP.String()
	default:
		cert.LastIP = ""
	}
}

type DeliveryReceipt struct {
	ID            int64
	Target        string // channel or nick
	Client        string
	InternalMsgID string
}

type ReadReceipt struct {
	ID        int64
	Target    string // channel or nick
	Timestamp time.Time
}

type WebPushConfig struct {
	ID        int64
	VAPIDKeys struct {
		Public, Private string
	}
}

type WebPushSubscription struct {
	ID                   int64
	Endpoint             string
	CreatedAt, UpdatedAt time.Time // read-only

	Keys struct {
		Auth   string
		P256DH string
		VAPID  string
	}
}

type MessageTarget struct {
	ID      int64
	Target  string
	Pinned  bool
	Muted   bool
	Blocked bool
}

func toNullString(s string) sql.NullString {
	return sql.NullString{
		String: s,
		Valid:  s != "",
	}
}

func toNullTime(t time.Time) sql.NullTime {
	return sql.NullTime{
		Time:  t,
		Valid: !t.IsZero(),
	}
}
