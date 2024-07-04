//go:build pam

package auth

import (
	"context"
	"fmt"

	"github.com/msteinert/pam/v2"

	"codeberg.org/emersion/soju/database"
)

type pamAuth struct{}

var (
	_ PlainAuthenticator = (*pamAuth)(nil)
)

func newPAM() (Authenticator, error) {
	return pamAuth{}, nil
}

func (pamAuth) AuthPlain(ctx context.Context, db database.Database, username, password string) error {
	t, err := pam.StartFunc("login", username, func(s pam.Style, msg string) (string, error) {
		switch s {
		case pam.PromptEchoOff:
			return password, nil
		case pam.PromptEchoOn, pam.ErrorMsg, pam.TextInfo:
			return "", nil
		default:
			return "", fmt.Errorf("unsupported PAM conversation style: %v", s)
		}
	})
	if err != nil {
		return fmt.Errorf("failed to start PAM conversation: %v", err)
	}
	defer t.End()

	if err := t.Authenticate(0); err != nil {
		return newInvalidCredentialsError(fmt.Errorf("PAM auth error: %v", err))
	}

	if err := t.AcctMgmt(0); err != nil {
		return fmt.Errorf("PAM account unavailable: %v", err)
	}

	user, err := t.GetItem(pam.User)
	if err != nil {
		return fmt.Errorf("failed to get PAM user: %v", err)
	} else if user != username {
		return fmt.Errorf("PAM user doesn't match supplied username")
	}

	if err := t.End(); err != nil {
		return fmt.Errorf("failed to end PAM conversation: %v", err)
	}

	return nil
}
