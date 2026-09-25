package cmd

import (
	"strings"
	"testing"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/superb-striker/phantom-share/phantom/internal/config"
)

func resetFlags(command *cobra.Command) {
	command.Flags().VisitAll(func(flag *pflag.Flag) {
		_ = flag.Value.Set(flag.DefValue)
		flag.Changed = false
	})
}

func authenticated(t *testing.T) {
	t.Helper()
	viper.Reset()
	viper.Set(config.KeyBaseURL, "http://api.example.test")
	viper.Set(config.KeyAccessToken, "access")
	viper.Set(config.KeyRefreshToken, "refresh")
	viper.Set(config.KeyUsername, "alice")
	viper.Set(config.KeyEmail, "alice@example.com")
	t.Cleanup(viper.Reset)
}

func TestParseShareReference(t *testing.T) {
	tests := []struct {
		name, input, id, token string
		file                   bool
	}{
		{"text URL", "https://example.test/api/secrets/abc?token=signed%20token", "abc", "signed token", false},
		{"file URL", "https://example.test/api/secrets/abc/file?token=signed", "abc", "signed", true},
		{"browser URL", "https://example.test/api/secrets/view/abc?token=signed", "abc", "signed", false},
		{"bare ID", "  abc-123  ", "abc-123", "", false},
		{"relative URL", "/api/secrets/abc/file", "abc", "", true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			id, token, file := parseShareRef(test.input)
			if id != test.id || token != test.token || file != test.file {
				t.Fatalf("parseShareRef = %q %q %v", id, token, file)
			}
			legacyID, legacyToken := parseShareURL(test.input)
			if legacyID != test.id || legacyToken != test.token {
				t.Fatalf("parseShareURL = %q %q", legacyID, legacyToken)
			}
		})
	}
}

func TestParseTTL(t *testing.T) {
	tests := []struct {
		input     string
		hours     int
		wantError bool
	}{
		{"30m", 1, false}, {"90m", 1, false}, {"2h", 2, false},
		{"3d", 72, false}, {" 7D ", 168, false}, {"12", 12, false},
		{"bad", 0, true}, {"h", 0, true}, {"", 0, true},
	}
	for _, test := range tests {
		hours, err := parseTTL(test.input)
		if (err != nil) != test.wantError || (!test.wantError && hours != test.hours) {
			t.Errorf("parseTTL(%q) = %d, %v", test.input, hours, err)
		}
	}
}

func TestFormattingAndDisplayHelpers(t *testing.T) {
	previous := color.NoColor
	color.NoColor = true
	t.Cleanup(func() { color.NoColor = previous })
	byteTests := map[int64]string{
		0: "0 B", 1023: "1023 B", 1024: "1.0 KiB", 1536: "1.5 KiB",
		1024 * 1024: "1.0 MiB", 1024 * 1024 * 1024: "1.0 GiB",
	}
	for size, want := range byteTests {
		if got := formatBytes(size); got != want {
			t.Errorf("formatBytes(%d) = %q", size, got)
		}
	}
	if displayList(nil) != "none" || displayList([]string{"IN", "SG"}) != "IN, SG" {
		t.Fatal("displayList returned unexpected value")
	}
	value := 3
	if optionalInt(nil) != "—" || optionalInt(&value) != "3" {
		t.Fatal("optionalInt returned unexpected value")
	}
	if stringOr("first", "fallback") != "first" || stringOr("", "fallback") != "fallback" {
		t.Fatal("stringOr returned unexpected value")
	}
	if shortID("short") != "short" || shortID("123456789") != "12345678…" {
		t.Fatal("shortID returned unexpected value")
	}
	for _, action := range []string{"secret_created", "secret_viewed", "secret_deleted", "key_rotated", "user_login", "user_registered", "user_logout", "other"} {
		if !strings.Contains(formatAction(action), action) {
			t.Errorf("formatAction(%q) lost action", action)
		}
	}
}

func TestBuildPingEmail(t *testing.T) {
	message := buildPingEmail(
		"from@example.com", "to@example.com", "Subject", "https://share.example/id",
		"Personal note", "alice", "password",
	)
	for _, expected := range []string{
		"From: from@example.com\r\n", "To: to@example.com\r\n",
		"Subject: Subject\r\n", "Personal note", "https://share.example/id",
		"password-protected", "Sent by: alice", "Powered by Phantom",
	} {
		if !strings.Contains(message, expected) {
			t.Errorf("email missing %q", expected)
		}
	}
	minimal := buildPingEmail("a", "b", "c", "url", "", "a", "")
	if strings.Contains(minimal, "password-protected") || strings.Contains(minimal, "Sent by:") {
		t.Fatalf("minimal email included optional sections:\n%s", minimal)
	}
}

func TestCommandTree(t *testing.T) {
	wantRoot := []string{"admin", "audit", "auth", "config", "delete", "get", "health", "info", "list", "ping", "policy", "quota", "restore", "share", "stats", "update", "version", "versions", "views", "rotate-key"}
	for _, name := range wantRoot {
		if command, _, err := rootCmd.Find([]string{name}); err != nil || command == nil || command.Name() != name {
			t.Errorf("root command %q not registered", name)
		}
	}
	if command, _, _ := rootCmd.Find([]string{"auth", "refresh"}); command != nil && command.Name() == "refresh" {
		t.Fatal("user-facing auth refresh command is registered")
	}
	for _, name := range []string{"login", "logout", "register", "request-verification", "verify-email", "whoami"} {
		command, _, err := authCmd.Find([]string{name})
		if err != nil || command.Name() != name {
			t.Errorf("auth command %q not registered", name)
		}
	}
	for _, name := range []string{"cleanup", "quota", "role", "toggle", "users"} {
		command, _, err := adminCmd.Find([]string{name})
		if err != nil || command.Name() != name {
			t.Errorf("admin command %q not registered", name)
		}
	}
}

func TestArgumentValidators(t *testing.T) {
	tests := []struct {
		name      string
		command   *cobra.Command
		args      []string
		wantError bool
	}{
		{"get missing", getCmd, nil, true}, {"get exact", getCmd, []string{"id"}, false},
		{"update missing", updateCmd, nil, true}, {"update max", updateCmd, []string{"id", "content", "extra"}, true},
		{"restore missing", restoreCmd, []string{"id"}, true}, {"policy extra", policyCmd, []string{"id", "extra"}, true},
		{"audit optional", auditCmd, nil, false}, {"ping exact", pingCmd, []string{"url"}, false},
		{"config URL missing", configSetURLCmd, nil, true}, {"config URL exact", configSetURLCmd, []string{"https://example"}, false},
	}
	for _, test := range tests {
		var err error
		if test.command.Args != nil {
			err = test.command.Args(test.command, test.args)
		}
		if (err != nil) != test.wantError {
			t.Errorf("%s error = %v", test.name, err)
		}
	}
}

func TestProtectedCommandsRejectMissingAuthentication(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)
	tests := []struct {
		name    string
		command *cobra.Command
		args    []string
	}{
		{"share", shareCmd, []string{"secret"}}, {"list", listCmd, nil},
		{"delete", deleteCmd, []string{"id"}}, {"rotate", rotateKeyCmd, []string{"id"}},
		{"update", updateCmd, []string{"id", "new"}}, {"versions", versionsCmd, []string{"id"}},
		{"restore", restoreCmd, []string{"id", "1"}}, {"policy", policyCmd, []string{"id"}},
		{"quota", quotaCmd, nil}, {"views", viewsCmd, []string{"id"}},
		{"audit", auditCmd, nil}, {"admin users", adminUsersCmd, nil},
		{"admin cleanup", adminCleanupCmd, nil}, {"admin role", adminRoleCmd, []string{"id", "user"}},
		{"admin toggle", adminToggleCmd, []string{"12345678"}}, {"admin quota", adminQuotaCmd, []string{"id"}},
		{"whoami", authWhoamiCmd, nil}, {"request verification", requestVerificationCmd, nil},
	}
	for _, test := range tests {
		resetFlags(test.command)
		err := test.command.RunE(test.command, test.args)
		if err == nil || !strings.Contains(err.Error(), "not logged in") {
			t.Errorf("%s error = %v", test.name, err)
		}
	}
}

func TestLocalValidationErrors(t *testing.T) {
	authenticated(t)
	tests := []struct {
		name     string
		command  *cobra.Command
		args     []string
		setup    func()
		contains string
	}{
		{"share mode", shareCmd, []string{"secret"}, func() { _ = shareCmd.Flags().Set("location-mode", "invalid") }, "location-mode"},
		{"share file and text", shareCmd, []string{"secret"}, func() { _ = shareCmd.Flags().Set("file", "x") }, "either a secret"},
		{"share encrypted nonce missing", shareCmd, []string{"secret"}, func() { _ = shareCmd.Flags().Set("client-encrypted", "true") }, "client-nonce"},
		{"share nonce without mode", shareCmd, []string{"secret"}, func() { _ = shareCmd.Flags().Set("client-nonce", "nonce") }, "client-encrypted"},
		{"share no content", shareCmd, nil, func() {}, "provide a secret"},
		{"share bad expiry", shareCmd, []string{"secret"}, func() { _ = shareCmd.Flags().Set("expires", "tomorrow") }, "invalid --expires"},
		{"file notification", shareCmd, nil, func() { _ = shareCmd.Flags().Set("file", "x"); _ = shareCmd.Flags().Set("notify", "a@example.com") }, "do not support"},
		{"update expected version", updateCmd, []string{"id", "new"}, func() {}, "expected-version"},
		{"update mixed file", updateCmd, []string{"id", "new"}, func() { _ = updateCmd.Flags().Set("expected-version", "1"); _ = updateCmd.Flags().Set("file", "x") }, "cannot be combined"},
		{"update mixed content file", updateCmd, []string{"id", "new"}, func() {
			_ = updateCmd.Flags().Set("expected-version", "1")
			_ = updateCmd.Flags().Set("content-file", "x")
		}, "not both"},
		{"update missing content", updateCmd, []string{"id"}, func() { _ = updateCmd.Flags().Set("expected-version", "1") }, "provide new text"},
		{"restore invalid version", restoreCmd, []string{"id", "zero"}, func() {}, "positive integer"},
		{"policy mode", policyCmd, []string{"id"}, func() { _ = policyCmd.Flags().Set("location-mode", "invalid") }, "location-mode"},
		{"admin role", adminRoleCmd, []string{"id", "owner"}, func() {}, "invalid role"},
		{"admin quota empty", adminQuotaCmd, []string{"id"}, func() {}, "set --max-secrets"},
		{"admin quota zero", adminQuotaCmd, []string{"id"}, func() { _ = adminQuotaCmd.Flags().Set("max-secrets", "0") }, "at least 1"},
		{"ping recipient", pingCmd, []string{"url"}, func() {}, "--to is required"},
		{"ping sender", pingCmd, []string{"url"}, func() { _ = pingCmd.Flags().Set("to", "a@example.com") }, "sender address"},
	}
	for _, test := range tests {
		resetFlags(test.command)
		test.setup()
		err := test.command.RunE(test.command, test.args)
		if err == nil || !strings.Contains(err.Error(), test.contains) {
			t.Errorf("%s error = %v, want %q", test.name, err, test.contains)
		}
	}
}
