//go:build !pam

package auth

import (
	"errors"
)

func newPAM() (Authenticator, error) {
	return nil, errors.New("PAM support is disabled")
}
