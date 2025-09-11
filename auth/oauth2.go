package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"codeberg.org/emersion/soju/database"
)

type oauth2 struct {
	introspectionURL *url.URL
	clientID         string
	clientSecret     string
}

var (
	_ OAuthBearerAuthenticator = (*oauth2)(nil)
)

func newOAuth2(authURL string) (*Authenticator, error) {
	ctx, cancel := context.WithTimeout(context.TODO(), 10*time.Second)
	defer cancel()

	u, err := url.Parse(authURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse OAuth 2.0 server URL: %v", err)
	}

	var clientID, clientSecret string
	if u.User != nil {
		clientID = u.User.Username()
		clientSecret, _ = u.User.Password()
	}

	discoveryURL := *u
	discoveryURL.User = nil
	discoveryURL.Path = path.Join("/.well-known/oauth-authorization-server", u.Path)
	server, err := discoverOAuth2(ctx, discoveryURL.String())
	if err != nil {
		return nil, fmt.Errorf("OAuth 2.0 discovery failed: %v", err)
	}

	if server.IntrospectionEndpoint == "" {
		return nil, fmt.Errorf("OAuth 2.0 server doesn't support token introspection")
	}
	introspectionURL, err := url.Parse(server.IntrospectionEndpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to parse OAuth 2.0 introspection URL")
	}

	if server.IntrospectionEndpointAuthMethodsSupported != nil {
		var supportsNone, supportsBasic bool
		for _, name := range server.IntrospectionEndpointAuthMethodsSupported {
			switch name {
			case "none":
				supportsNone = true
			case "client_secret_basic":
				supportsBasic = true
			}
		}

		if clientID == "" && !supportsNone {
			return nil, fmt.Errorf("OAuth 2.0 server requires authentication for introspection")
		}
		if clientID != "" && !supportsBasic {
			return nil, fmt.Errorf("OAuth 2.0 server doesn't support Basic HTTP authentication for introspection")
		}
	}

	return &Authenticator{
		OAuthBearer: &oauth2{
			introspectionURL: introspectionURL,
			clientID:         clientID,
			clientSecret:     clientSecret,
		},
	}, nil
}

func (auth *oauth2) AuthOAuthBearer(ctx context.Context, db database.Database, token string) (username string, err error) {
	reqValues := make(url.Values)
	reqValues.Set("token", token)

	reqBody := strings.NewReader(reqValues.Encode())

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, auth.introspectionURL.String(), reqBody)
	if err != nil {
		return "", fmt.Errorf("failed to create OAuth 2.0 introspection request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	setHTTPForwardedHeader(ctx, req)

	if auth.clientID != "" {
		req.SetBasicAuth(url.QueryEscape(auth.clientID), url.QueryEscape(auth.clientSecret))
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to send OAuth 2.0 introspection request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("OAuth 2.0 introspection error: %v", resp.Status)
	}

	var data oauth2Introspection
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return "", fmt.Errorf("failed to decode OAuth 2.0 introspection response: %v", err)
	}

	if !data.Active {
		return "", newInvalidCredentialsError(fmt.Errorf("invalid access token"))
	}
	if data.Username == "" {
		// We really need the username here, otherwise an OAuth 2.0 user can
		// impersonate any other user.
		return "", fmt.Errorf("missing username in OAuth 2.0 introspection response")
	}

	return data.Username, nil
}

type oauth2Introspection struct {
	Active   bool   `json:"active"`
	Username string `json:"username"`
}

type oauth2Server struct {
	Issuer                                    string   `json:"issuer"`
	IntrospectionEndpoint                     string   `json:"introspection_endpoint"`
	IntrospectionEndpointAuthMethodsSupported []string `json:"introspection_endpoint_auth_methods_supported"`
}

type oauth2HTTPError string

func (err oauth2HTTPError) Error() string {
	return fmt.Sprintf("OAuth 2.0 HTTP error: %v", string(err))
}

func discoverOAuth2(ctx context.Context, discoveryURL string) (*oauth2Server, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, oauth2HTTPError(resp.Status)
	}

	var data oauth2Server
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, fmt.Errorf("failed to decode response: %v", err)
	}

	if data.Issuer == "" {
		return nil, fmt.Errorf("missing issuer in response")
	}

	return &data, nil
}
