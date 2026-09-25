package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/viper"
)

func resetConfig(t *testing.T) string {
	t.Helper()
	viper.Reset()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("PHANTOM_BASE_URL", "")
	t.Setenv("PHANTOM_ACCESS_TOKEN", "")
	t.Setenv("PHANTOM_REFRESH_TOKEN", "")
	t.Cleanup(viper.Reset)
	return home
}

func TestInitCreatesPrivateConfigDirectoryAndDefaults(t *testing.T) {
	home := resetConfig(t)
	if err := Init(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(home, ".phantom"))
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0700 {
		t.Fatalf("config directory permissions = %o", got)
	}
	if BaseURL() != "http://localhost:8000" {
		t.Fatalf("default base URL = %q", BaseURL())
	}
}

func TestCredentialPersistenceAndClearing(t *testing.T) {
	home := resetConfig(t)
	if err := Init(); err != nil {
		t.Fatal(err)
	}
	viper.Set(KeyBaseURL, "https://api.example.test")
	if err := SetCredentials("access", "refresh", "alice", "alice@example.com"); err != nil {
		t.Fatal(err)
	}
	if AccessToken() != "access" || RefreshToken() != "refresh" || Username() != "alice" || Email() != "alice@example.com" {
		t.Fatalf("credentials did not round trip")
	}
	data, err := os.ReadFile(filepath.Join(home, ".phantom", "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, expected := range []string{"access_token: access", "refresh_token: refresh", "username: alice", "email: alice@example.com"} {
		if !strings.Contains(text, expected) {
			t.Errorf("config missing %q:\n%s", expected, text)
		}
	}
	if err := ClearCredentials(); err != nil {
		t.Fatal(err)
	}
	if AccessToken() != "" || RefreshToken() != "" || Username() != "" || Email() != "" {
		t.Fatal("credentials were not cleared")
	}
	if BaseURL() != "https://api.example.test" {
		t.Fatalf("clearing credentials changed base URL to %q", BaseURL())
	}
}

func TestInitReadsExistingConfigAndEnvironmentOverrides(t *testing.T) {
	home := resetConfig(t)
	dir := filepath.Join(home, ".phantom")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("base_url: https://file.example\naccess_token: file-token\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PHANTOM_BASE_URL", "https://env.example")
	if err := Init(); err != nil {
		t.Fatal(err)
	}
	if BaseURL() != "https://env.example" {
		t.Fatalf("environment did not override config: %q", BaseURL())
	}
	if AccessToken() != "file-token" {
		t.Fatalf("file token = %q", AccessToken())
	}
}

func TestInitRejectsMalformedConfig(t *testing.T) {
	home := resetConfig(t)
	dir := filepath.Join(home, ".phantom")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("invalid: ["), 0600); err != nil {
		t.Fatal(err)
	}
	if err := Init(); err == nil || !strings.Contains(err.Error(), "error reading config") {
		t.Fatalf("expected malformed config error, got %v", err)
	}
}

func TestRequireAuth(t *testing.T) {
	resetConfig(t)
	if err := Init(); err != nil {
		t.Fatal(err)
	}
	if err := RequireAuth(); err == nil || !strings.Contains(err.Error(), "not logged in") {
		t.Fatalf("unexpected unauthenticated result: %v", err)
	}
	viper.Set(KeyAccessToken, "token")
	if err := RequireAuth(); err != nil {
		t.Fatalf("authenticated user rejected: %v", err)
	}
}

func TestSaveReportsMissingConfigDirectory(t *testing.T) {
	resetConfig(t)
	if err := Save(); err == nil {
		t.Fatal("expected Save to fail before Init creates the directory")
	}
}
