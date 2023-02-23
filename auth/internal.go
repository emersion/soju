package auth

import (
	"context"
	"fmt"

	"git.sr.ht/~emersion/soju/database"
)

type internal struct{}

func NewInternal() PlainAuthenticator {
	return internal{}
}

func (internal) AuthPlain(ctx context.Context, db database.Database, username, password string) error {
	u, err := db.GetUser(ctx, username)
	if err != nil {
		return newInvalidCredentialsError(fmt.Errorf("user not found: %w", err))
	}

	upgraded, err := u.CheckPassword(password)
	if err != nil {
		return newInvalidCredentialsError(err)
	}

	if upgraded {
		if err := db.StoreUser(ctx, u); err != nil {
			return err
		}
	}

	return nil
}
