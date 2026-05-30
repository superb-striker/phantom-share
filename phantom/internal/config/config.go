package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/viper"
)

const (
	KeyBaseURL      = "base_url"
	KeyAccessToken  = "access_token"
	KeyRefreshToken = "refresh_token"
	KeyUsername     = "username"
	KeyEmail        = "email"
)

// Sets up Viper to read from ~/.phantom/config.yaml.
// Call once from the root PersistentPreRun.
func Init() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	cfgDir := filepath.Join(home, ".phantom")
	if err := os.MkdirAll(cfgDir, 0700); err != nil {
		return err
	}

	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(cfgDir)

	// Env overrides: PHANTOM_BASE_URL etc.
	viper.SetEnvPrefix("PHANTOM")
	viper.AutomaticEnv()

	// Defaults
	viper.SetDefault(KeyBaseURL, "http://localhost:8000")

	// Read config; ignore "not found" on first run
	if err := viper.ReadInConfig(); err != nil {
		var notFound viper.ConfigFileNotFoundError
		if !errors.As(err, &notFound) {
			return fmt.Errorf("error reading config: %w", err)
		}
	}
	return nil
}

// Saves all viper values to disk.
func Save() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	cfgPath := filepath.Join(home, ".phantom", "config.yaml")
	return viper.WriteConfigAs(cfgPath)
}

// Saves tokens + user info and writes to disk.
func SetCredentials(accessToken, refreshToken, username, email string) error {
	viper.Set(KeyAccessToken, accessToken)
	viper.Set(KeyRefreshToken, refreshToken)
	viper.Set(KeyUsername, username)
	viper.Set(KeyEmail, email)
	return Save()
}

// Removes auth tokens but keeps base_url.
func ClearCredentials() error {
	viper.Set(KeyAccessToken, "")
	viper.Set(KeyRefreshToken, "")
	viper.Set(KeyUsername, "")
	viper.Set(KeyEmail, "")
	return Save()
}

// Returns an error if the user is not logged in.
func RequireAuth() error {
	if viper.GetString(KeyAccessToken) == "" {
		return errors.New("not logged in – run: phantom auth login or phantom auth register")
	}
	return nil
}

func BaseURL() string      { return viper.GetString(KeyBaseURL) }
func AccessToken() string  { return viper.GetString(KeyAccessToken) }
func RefreshToken() string { return viper.GetString(KeyRefreshToken) }
func Username() string     { return viper.GetString(KeyUsername) }
func Email() string        { return viper.GetString(KeyEmail) }