package auth

import (
	"context"
	"fmt"
	"net/http"
	"os"

	"git.sr.ht/~emersion/gqlclient"

	"git.sr.ht/~emersion/soju/database"
)

type srht struct{}

var (
	_ PlainAuthenticator       = srht{}
	_ OAuthBearerAuthenticator = srht{}
)

func newSrht() Authenticator {
	return srht{}
}

func (srht) AuthPlain(ctx context.Context, db database.Database, username, password string) error {
	srhtUsername, err := srht{}.AuthOAuthBearer(ctx, db, password)
	if err != nil {
		return err
	}

	if srhtUsername != username {
		return newInvalidCredentialsError(fmt.Errorf("username doesn't match sr.ht's"))
	}
	return nil
}

func (srht) AuthOAuthBearer(ctx context.Context, db database.Database, token string) (username string, err error) {
	h := make(http.Header)
	h.Set("Authorization", "Bearer "+token)
	return checkSrhtAuth(ctx, db, h)
}

func CheckSrhtCookie(ctx context.Context, db database.Database, cookie *http.Cookie) (username string, err error) {
	h := make(http.Header)
	h.Set("Cookie", cookie.String())
	return checkSrhtAuth(ctx, db, h)
}

type srhtUserType string

const (
	srhtUserUnconfirmed      srhtUserType = "UNCONFIRMED"
	srhtUserActiveNonPaying  srhtUserType = "ACTIVE_NON_PAYING"
	srhtUserActiveFree       srhtUserType = "ACTIVE_FREE"
	srhtUserActivePaying     srhtUserType = "ACTIVE_PAYING"
	srhtUserActiveDelinquent srhtUserType = "ACTIVE_DELINQUENT"
	srhtUserAdmin            srhtUserType = "ADMIN"
	srhtUserSuspended        srhtUserType = "SUSPENDED"
)

func checkSrhtAuth(ctx context.Context, db database.Database, h http.Header) (username string, err error) {
	endpoint := "https://meta.sr.ht"
	if v, ok := os.LookupEnv("SRHT_ENDPOINT"); ok {
		endpoint = v
	}

	httpClient := http.Client{
		Transport: &headerTransport{h},
	}
	client := gqlclient.New(endpoint+"/query", &httpClient)

	op := gqlclient.NewOperation(`
		query {
			me {
				username
				userType
			}
		}
	`)

	var respData struct {
		Me struct {
			Username string
			UserType srhtUserType
		}
	}
	if err := client.Execute(ctx, op, &respData); err != nil {
		return "", &Error{
			InternalErr: fmt.Errorf("failed to check sr.ht OAuth2 access token: %w", err),
			ExternalMsg: "Invalid sr.ht OAuth 2.0 access token",
		}
	}

	username = respData.Me.Username

	if user, err := db.GetUser(ctx, username); err == nil && user.Enabled {
		// We found the user in our DB
		return username, nil
	}

	switch userType := respData.Me.UserType; userType {
	case srhtUserUnconfirmed:
		return "", &Error{
			InternalErr: fmt.Errorf("sr.ht account unconfirmed"),
			ExternalMsg: "Please confirm your sr.ht account",
		}
	case srhtUserSuspended:
		return "", &Error{
			InternalErr: fmt.Errorf("sr.ht account suspended"),
			ExternalMsg: "Your sr.ht account is suspended",
		}
	case srhtUserActiveNonPaying, srhtUserActiveDelinquent:
		if os.Getenv("SRHT_ALLOW_NON_PAYING") != "1" {
			return "", &Error{
				InternalErr: fmt.Errorf("sr.ht account non-paying"),
				ExternalMsg: "Access to chat.sr.ht requires a paid account. Please set up billing at https://meta.sr.ht/billing and try again. For more information, consult https://man.sr.ht/billing-faq.md",
			}
		}
	case srhtUserActiveFree, srhtUserActivePaying, srhtUserAdmin:
		// Allowed
	default:
		return "", fmt.Errorf("unexpected sr.ht user type %q", userType)
	}

	return username, nil
}

type headerTransport struct {
	header http.Header
}

func (t *headerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	for k, vs := range t.header {
		for _, v := range vs {
			req.Header.Set(k, v)
		}
	}
	return http.DefaultClient.Do(req)
}

func IsSrht(auth Authenticator) bool {
	_, ok := auth.(srht)
	return ok
}
