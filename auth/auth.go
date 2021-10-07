package auth

import (
	"context"
	"fmt"

	"git.sr.ht/~emersion/soju/database"
)

type Authenticator interface{}

type PlainAuthenticator interface {
	AuthPlain(ctx context.Context, db database.Database, username, password string) error
}

type OAuthBearerAuthenticator interface {
	AuthOAuthBearer(ctx context.Context, db database.Database, token string) (username string, err error)
}

func New(driver, source string) (Authenticator, error) {
	switch driver {
	case "internal":
		return NewInternal(), nil
	case "oauth2":
		return newOAuth2(source)
	case "pam":
		return newPAM()
	case "srht":
		return newSrht(), nil
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
