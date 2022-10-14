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
	default:
		return nil, fmt.Errorf("unknown auth driver %q", driver)
	}
}
