package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"codeberg.org/emersion/soju/database"
)

type httpAuth struct {
	url string
}

var (
	_ PlainAuthenticator = (*httpAuth)(nil)
)

func newHTTP(url string) (*Authenticator, error) {
	return &Authenticator{
		Plain: &httpAuth{
			url: url,
		},
	}, nil
}

func (auth *httpAuth) AuthPlain(ctx context.Context, db database.Database, username, password string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, auth.url, nil)
	if err != nil {
		return fmt.Errorf("failed to create HTTP auth request: %v", err)
	}
	req.SetBasicAuth(username, password)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send HTTP auth request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden {
		return newInvalidCredentialsError(errors.New("HTTP auth server returned forbidden"))
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP auth error: %v", resp.Status)
	}
	return nil
}
