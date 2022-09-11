package auth

import (
	"context"
	"fmt"

	"git.sr.ht/~emersion/soju/database"
)

type PlainAuthenticator interface {
	AuthPlain(ctx context.Context, db database.Database, username, password string) error
}

func New(driver, source string) (PlainAuthenticator, error) {
	switch driver {
	case "internal":
		return NewInternal(), nil
	case "oauth2":
		return newOAuth2(source)
	default:
		return nil, fmt.Errorf("unknown auth driver %q", driver)
	}
}
