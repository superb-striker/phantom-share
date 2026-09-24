package cmd

import (
	"github.com/superb-striker/phantom-share/phantom/internal/api"
	"github.com/superb-striker/phantom-share/phantom/internal/config"
)

// newAPIClient returns a client that transparently rotates an expired access
// token and persists the new token pair before retrying the request once.
func newAPIClient() *api.Client {
	client := api.New(config.BaseURL(), config.AccessToken())
	if config.AccessToken() == "" || config.RefreshToken() == "" {
		return client
	}
	client.EnableAutoRefresh(
		config.RefreshToken(),
		func(tokens *api.TokenResponse) error {
			return config.SetCredentials(
				tokens.AccessToken,
				tokens.RefreshToken,
				config.Username(),
				config.Email(),
			)
		},
		config.ClearCredentials,
	)
	return client
}

func shortID(id string) string {
	if len(id) <= 8 {
		return id
	}
	return id[:8] + "…"
}
