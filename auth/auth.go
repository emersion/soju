package auth

import (
	"context"
	"fmt"
	"net"
	"net/http"

	"codeberg.org/emersion/soju/database"
)

const ContextDownstreamAddressKey = "downstream-address"

type Authenticator struct {
	Plain       PlainAuthenticator
	OAuthBearer OAuthBearerAuthenticator
}

type PlainAuthenticator interface {
	AuthPlain(ctx context.Context, db database.Database, username, password string) error
}

type OAuthBearerAuthenticator interface {
	AuthOAuthBearer(ctx context.Context, db database.Database, token string) (username string, err error)
}

type OAuthPlainAuthenticator struct {
	OAuthBearer OAuthBearerAuthenticator
}

func (auth OAuthPlainAuthenticator) AuthPlain(ctx context.Context, db database.Database, username, password string) error {
	effectiveUsername, err := auth.OAuthBearer.AuthOAuthBearer(ctx, db, password)
	if err != nil {
		return err
	}

	if username != effectiveUsername {
		return newInvalidCredentialsError(fmt.Errorf("username mismatch (OAuth 2.0 server returned %q)", effectiveUsername))
	}

	return nil
}

type Driver string

const (
	DriverInternal = Driver("internal")
	DriverPAM      = Driver("pam")
	DriverHTTP     = Driver("http")
	DriverOAuth2   = Driver("oauth2")
)

func New(driver Driver, source string) (*Authenticator, error) {
	switch driver {
	case DriverInternal:
		return NewInternal(), nil
	case DriverHTTP:
		return newHTTP(source)
	case DriverOAuth2:
		return newOAuth2(source)
	case DriverPAM:
		return newPAM()
	default:
		return nil, fmt.Errorf("unknown auth driver %q", driver)
	}
}

// Error is an authentication error.
type Error struct {
	// Internal error cause. This will not be revealed to the user.
	InternalErr error
	// Message which can safely be sent to the user without compromising
	// security.
	ExternalMsg string
}

func (err *Error) Error() string {
	return err.InternalErr.Error()
}

func (err *Error) Unwrap() error {
	return err.InternalErr
}

// newInvalidCredentialsError wraps the provided error into an Error and
// indicates to the user that the provided credentials were invalid.
func newInvalidCredentialsError(err error) *Error {
	return &Error{
		InternalErr: err,
		ExternalMsg: "Invalid credentials",
	}
}

func setHTTPForwardedHeader(ctx context.Context, req *http.Request) {
	addr, ok := ctx.Value(ContextDownstreamAddressKey).(string)
	if !ok || addr == "" {
		return
	}

	forwarded := fmt.Sprintf("for=%q", addr)
	forwardedForHost, _, _ := net.SplitHostPort(addr)
	req.Header.Set("Forwarded", forwarded)
	req.Header.Set("X-Forwarded-For", forwardedForHost)
}
