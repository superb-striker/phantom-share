package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/smtp"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/superb-striker/phantom-share/phantom/internal/config"
)

type recordedRequest struct {
	Method string
	URI    string
	Body   string
}

type commandBackend struct {
	testing  *testing.T
	server   *httptest.Server
	mu       sync.Mutex
	requests []recordedRequest
}

func newCommandBackend(t *testing.T) *commandBackend {
	backend := &commandBackend{testing: t}
	backend.server = httptest.NewServer(http.HandlerFunc(backend.serveHTTP))
	t.Cleanup(backend.server.Close)
	return backend
}

func (backend *commandBackend) serveHTTP(w http.ResponseWriter, request *http.Request) {
	body, _ := io.ReadAll(request.Body)
	backend.mu.Lock()
	backend.requests = append(backend.requests, recordedRequest{request.Method, request.URL.RequestURI(), string(body)})
	backend.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")

	path := request.URL.Path
	switch {
	case request.Method == http.MethodPost && path == "/api/auth/register":
		writeJSON(w, userJSON("registered"))
	case request.Method == http.MethodPost && path == "/api/auth/login":
		writeJSON(w, `{"access_token":"access","refresh_token":"refresh","expires_in":900}`)
	case request.Method == http.MethodPost && path == "/api/auth/logout":
		w.WriteHeader(http.StatusNoContent)
	case request.Method == http.MethodGet && path == "/api/auth/me":
		writeJSON(w, userJSON("alice"))
	case request.Method == http.MethodPost && (path == "/api/auth/verification/request" || path == "/api/auth/verification/confirm"):
		writeJSON(w, `{"message":"ok"}`)
	case request.Method == http.MethodPost && path == "/api/secrets/files":
		writeJSON(w, `{"secret_id":"file-id","share_url":"http://share/api/secrets/file-id/file?token=signed","signed_token":"signed","version":1,"size":12}`)
	case request.Method == http.MethodPut && path == "/api/secrets/file-id/file":
		writeJSON(w, `{"secret_id":"file-id","version":2,"size":12}`)
	case request.Method == http.MethodGet && path == "/api/secrets/file-id/file":
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Disposition", `attachment; filename="download.txt"`)
		fmt.Fprint(w, "downloaded file")
	case request.Method == http.MethodPost && path == "/api/secrets":
		writeJSON(w, `{"secret_id":"text-id","share_url":"http://share/api/secrets/text-id?token=signed","signed_token":"signed","expires_at":"2026-12-01T00:00:00Z"}`)
	case request.Method == http.MethodGet && path == "/api/secrets":
		writeJSON(w, `{"items":[{"id":"text-id","created_at":"2026-01-01T00:00:00Z","expires_at":"2026-12-01T00:00:00Z","viewed":false,"view_count":0,"max_views":3,"password_protected":false,"notify_on_view":false}],"total":1,"page":1,"page_size":20}`)
	case request.Method == http.MethodGet && strings.HasSuffix(path, "/info"):
		payload := "text"
		if strings.Contains(path, "file-id") {
			payload = "file"
		}
		writeJSON(w, fmt.Sprintf(`{"exists":true,"created_at":"2026-01-01T00:00:00Z","expires_at":"2026-12-01T00:00:00Z","viewed":false,"view_count":0,"max_views":3,"current_version":1,"payload_type":%q,"policy_version":1}`, payload))
	case request.Method == http.MethodPost && path == "/api/secrets/text-id":
		writeJSON(w, `{"content":"retrieved secret","created_at":"2026-01-01T00:00:00Z","expires_at":"2026-12-01T00:00:00Z","views_remaining":2,"version":1}`)
	case request.Method == http.MethodDelete && path == "/api/secrets/text-id":
		w.WriteHeader(http.StatusNoContent)
	case request.Method == http.MethodPost && path == "/api/secrets/text-id/rotate-key":
		writeJSON(w, `{"secret_id":"text-id","new_key_version":2,"rotated_at":"2026-01-01T00:00:00Z"}`)
	case request.Method == http.MethodPut && path == "/api/secrets/text-id":
		writeJSON(w, `{"secret_id":"text-id","version":2,"updated_at":"2026-01-01T00:00:00Z"}`)
	case request.Method == http.MethodGet && path == "/api/secrets/text-id/versions":
		writeJSON(w, `{"current_version":2,"items":[{"version":2,"plaintext_size":10,"change_note":"new","created_at":"2026-01-01T00:00:00Z","is_current":true}]}`)
	case request.Method == http.MethodPost && path == "/api/secrets/text-id/versions/1/restore":
		writeJSON(w, `{"secret_id":"text-id","version":3,"updated_at":"2026-01-01T00:00:00Z"}`)
	case request.Method == http.MethodPut && path == "/api/secrets/text-id/access-policy":
		writeJSON(w, `{"secret_id":"text-id","allowed_cidrs":["10.0.0.0/8"],"allowed_countries":["IN"],"location_policy_mode":"all","geoip_fail_closed":true,"policy_version":2,"share_url":"http://share/new"}`)
	case request.Method == http.MethodGet && path == "/api/secrets/text-id/views":
		writeJSON(w, `{"items":[{"id":1,"viewer_email":"recipient@example.com","email_verified":true,"viewed_at":"2026-01-01T00:00:00Z","content_version":2}],"total":1,"page":1,"page_size":20,"retain_until":"2027-01-01T00:00:00Z"}`)
	case request.Method == http.MethodGet && path == "/api/quota":
		writeJSON(w, quotaJSON())
	case request.Method == http.MethodPatch && strings.HasSuffix(path, "/quota"):
		writeJSON(w, quotaJSON())
	case request.Method == http.MethodGet && path == "/api/admin/audit-logs":
		writeJSON(w, `{"items":[{"id":1,"action":"secret_viewed","severity":"info","actor_id":"12345678-aaaa","actor_ip":"127.0.0.1","secret_id":"text-id-long","metadata":{},"created_at":"2026-01-01T00:00:00Z"}],"total":1,"page":1,"page_size":50}`)
	case request.Method == http.MethodDelete && path == "/api/admin/cleanup":
		writeJSON(w, `{"secrets_deleted":1,"sessions_deleted":2,"users_deleted":3,"ran_at":"2026-01-01T00:00:00Z"}`)
	case request.Method == http.MethodGet && path == "/api/admin/users":
		writeJSON(w, `{"items":[{"id":"12345678-aaaa","email":"user@example.com","username":"user","role":"user","is_active":true,"created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z"}],"total":1,"page":1,"page_size":50}`)
	case request.Method == http.MethodPatch && strings.HasSuffix(path, "/role"):
		writeJSON(w, `{"id":"12345678-aaaa","email":"user@example.com","username":"user","role":"admin","is_active":true,"created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z"}`)
	case request.Method == http.MethodPatch && strings.HasSuffix(path, "/switch"):
		writeJSON(w, `{"user_id":"12345678-aaaa","is_active":false,"delete_after":"2026-01-03T00:00:00Z"}`)
	case request.Method == http.MethodGet && path == "/api/stats":
		writeJSON(w, `{"total_secrets_created":10,"total_secrets_viewed":5,"active_secrets":4}`)
	case request.Method == http.MethodGet && path == "/health":
		writeJSON(w, `{"api":"ok","database":"ok"}`)
	default:
		backend.testing.Errorf("unhandled request %s %s", request.Method, request.URL.RequestURI())
		w.WriteHeader(http.StatusNotFound)
		writeJSON(w, `{"detail":"not found"}`)
	}
}

func writeJSON(w http.ResponseWriter, value string) { _, _ = io.WriteString(w, value) }
func userJSON(username string) string {
	return fmt.Sprintf(`{"id":"12345678-aaaa","email":"%s@example.com","username":%q,"role":"user","is_active":true,"is_verified":true,"created_at":"2026-01-01T00:00:00Z"}`, username, username)
}
func quotaJSON() string {
	return `{"active_secrets":1,"file_bytes":12,"max_active_secrets":10,"max_file_bytes":1000}`
}

func setupCommandEnvironment(t *testing.T, baseURL string) {
	t.Helper()
	viper.Reset()
	t.Setenv("HOME", t.TempDir())
	if err := config.Init(); err != nil {
		t.Fatal(err)
	}
	viper.Set(config.KeyBaseURL, baseURL)
	viper.Set(config.KeyAccessToken, "access")
	viper.Set(config.KeyRefreshToken, "refresh")
	viper.Set(config.KeyUsername, "alice")
	viper.Set(config.KeyEmail, "alice@example.com")
	oldNoColor := color.NoColor
	color.NoColor = true
	t.Cleanup(func() { color.NoColor = oldNoColor; viper.Reset() })
}

func captureCommand(t *testing.T, run func() error) (string, error) {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	oldStdout, oldColor := os.Stdout, color.Output
	os.Stdout, color.Output = writer, writer
	runErr := run()
	writer.Close()
	os.Stdout, color.Output = oldStdout, oldColor
	data, readErr := io.ReadAll(reader)
	reader.Close()
	if readErr != nil {
		t.Fatal(readErr)
	}
	return string(data), runErr
}

func runCommand(t *testing.T, command *cobra.Command, args []string, setup func(), want string) {
	t.Helper()
	resetFlags(command)
	if setup != nil {
		setup()
	}
	output, err := captureCommand(t, func() error { return command.RunE(command, args) })
	if err != nil {
		t.Fatalf("%s failed: %v", command.Name(), err)
	}
	if want != "" && !strings.Contains(output, want) {
		t.Fatalf("%s output missing %q:\n%s", command.Name(), want, output)
	}
}

func TestSuccessfulCommandWorkflows(t *testing.T) {
	backend := newCommandBackend(t)
	setupCommandEnvironment(t, backend.server.URL)

	// Interactive auth commands use injected prompts while preserving their real HTTP and persistence paths.
	viper.Set(config.KeyAccessToken, "")
	viper.Set(config.KeyRefreshToken, "")
	oldText, oldSecret := promptText, promptSecret
	promptText = func(label string) string {
		if label == "Username" {
			return "registered"
		}
		return "registered@example.com"
	}
	promptSecret = func(string) string { return "password" }
	t.Cleanup(func() { promptText, promptSecret = oldText, oldSecret })
	runCommand(t, authRegisterCmd, nil, nil, "Account created")
	promptText = func(string) string { return "alice@example.com" }
	runCommand(t, authLoginCmd, nil, nil, "Logged in as alice")

	runCommand(t, authWhoamiCmd, nil, nil, "Current user")
	runCommand(t, requestVerificationCmd, nil, nil, "Verification requested")
	promptSecret = func(string) string { return "verification-code" }
	runCommand(t, verifyEmailCmd, nil, nil, "Email verified")

	runCommand(t, shareCmd, []string{"secret"}, func() { _ = shareCmd.Flags().Set("max-views", "3") }, "Secret created")
	runCommand(t, infoCmd, []string{"text-id"}, nil, "Secret info")
	runCommand(t, getCmd, []string{"text-id"}, nil, "retrieved secret")
	runCommand(t, listCmd, nil, nil, "Your secrets")
	runCommand(t, rotateKeyCmd, []string{"text-id"}, nil, "Encryption key rotated")
	runCommand(t, updateCmd, []string{"text-id", "new content"}, func() { _ = updateCmd.Flags().Set("expected-version", "1") }, "updated to version 2")
	runCommand(t, versionsCmd, []string{"text-id"}, nil, "current: 2")
	runCommand(t, restoreCmd, []string{"text-id", "1"}, nil, "restored as new version 3")
	runCommand(t, policyCmd, []string{"text-id"}, func() {
		_ = policyCmd.Flags().Set("allow-cidr", "10.0.0.0/8")
		_ = policyCmd.Flags().Set("allow-country", "IN")
	}, "Access policy updated")
	runCommand(t, viewsCmd, []string{"text-id"}, nil, "recipient@example.com")
	runCommand(t, quotaCmd, nil, nil, "Your quota")

	file := filepath.Join(t.TempDir(), "upload.txt")
	if err := os.WriteFile(file, []byte("file payload"), 0600); err != nil {
		t.Fatal(err)
	}
	runCommand(t, shareCmd, nil, func() { _ = shareCmd.Flags().Set("file", file) }, "File secret created")
	runCommand(t, updateCmd, []string{"file-id"}, func() { _ = updateCmd.Flags().Set("expected-version", "1"); _ = updateCmd.Flags().Set("file", file) }, "File secret updated")
	download := filepath.Join(t.TempDir(), "download.txt")
	runCommand(t, getCmd, []string{"file-id"}, func() { _ = getCmd.Flags().Set("output", download) }, "Downloaded")
	data, err := os.ReadFile(download)
	if err != nil || string(data) != "downloaded file" {
		t.Fatalf("download = %q, %v", data, err)
	}

	runCommand(t, auditCmd, nil, nil, "secret_viewed")
	runCommand(t, adminUsersCmd, nil, nil, "user@example.com")
	runCommand(t, adminCleanupCmd, nil, nil, "Cleanup complete")
	runCommand(t, adminRoleCmd, []string{"12345678-aaaa", "admin"}, nil, "Role updated")
	runCommand(t, adminToggleCmd, []string{"12345678-aaaa"}, nil, "inactive")
	runCommand(t, adminQuotaCmd, []string{"12345678-aaaa"}, func() { _ = adminQuotaCmd.Flags().Set("max-secrets", "10") }, "Quota updated")
	runCommand(t, deleteCmd, []string{"text-id"}, nil, "Secret text-id deleted")
	runCommand(t, statsCmd, nil, nil, "Service statistics")
	runCommand(t, healthCmd, nil, nil, "Health check")

	runCommand(t, authLogoutCmd, nil, nil, "Logged out alice")
	if config.AccessToken() != "" || config.RefreshToken() != "" {
		t.Fatal("logout did not clear credentials")
	}
}

func TestConfigCommands(t *testing.T) {
	setupCommandEnvironment(t, "http://initial.example")
	runCommand(t, configShowCmd, nil, nil, "Configuration")
	runCommand(t, configSetURLCmd, []string{"https://new.example"}, nil, "API URL set")
	if config.BaseURL() != "https://new.example" {
		t.Fatalf("base URL = %q", config.BaseURL())
	}
	runCommand(t, configSetSMTPCmd, nil, func() {
		_ = configSetSMTPCmd.Flags().Set("user", "smtp-user")
		_ = configSetSMTPCmd.Flags().Set("password", "smtp-pass")
		_ = configSetSMTPCmd.Flags().Set("from", "from@example.com")
	}, "SMTP settings saved")
	if viper.GetString("smtp.user") != "smtp-user" {
		t.Fatal("SMTP settings were not persisted")
	}
}

func TestPingDelivery(t *testing.T) {
	setupCommandEnvironment(t, "http://api.example.test")
	viper.Set("smtp.host", "smtp.example.test")
	viper.Set("smtp.port", "2525")
	viper.Set("smtp.user", "smtp-user")
	viper.Set("smtp.password", "smtp-pass")
	viper.Set("smtp.from", "sender@example.com")

	oldSendMail := smtpSendMail
	t.Cleanup(func() { smtpSendMail = oldSendMail })
	var delivered string
	smtpSendMail = func(addr string, auth smtp.Auth, from string, to []string, message []byte) error {
		if addr != "smtp.example.test:2525" || auth == nil || from != "sender@example.com" || strings.Join(to, ",") != "recipient@example.com" {
			t.Fatalf("unexpected SMTP envelope: %q %#v %q %v", addr, auth, from, to)
		}
		delivered = string(message)
		return nil
	}
	runCommand(t, pingCmd, []string{"https://share.example/api/secrets/text-id?token=signed"}, func() {
		_ = pingCmd.Flags().Set("to", "recipient@example.com")
		_ = pingCmd.Flags().Set("message", "hello")
		_ = pingCmd.Flags().Set("password", "separate-password")
	}, "Email delivered")
	for _, want := range []string{"hello", "/api/secrets/view/text-id?token=signed", "password-protected"} {
		if !strings.Contains(delivered, want) {
			t.Errorf("delivered email missing %q", want)
		}
	}

	smtpSendMail = func(string, smtp.Auth, string, []string, []byte) error { return fmt.Errorf("SMTP unavailable") }
	resetFlags(pingCmd)
	_ = pingCmd.Flags().Set("to", "recipient@example.com")
	if err := pingCmd.RunE(pingCmd, []string{"https://share.example/api/secrets/file-id/file"}); err == nil || !strings.Contains(err.Error(), "SMTP unavailable") {
		t.Fatalf("SMTP failure = %v", err)
	}
}

func TestRetrieveFileModesAndCollisionProtection(t *testing.T) {
	backend := newCommandBackend(t)
	setupCommandEnvironment(t, backend.server.URL)
	client := newAPIClient()

	directory := t.TempDir()
	if err := retrieveFile(client, "file-id", "", "", directory, false); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(directory, "download.txt"))
	if err != nil || string(data) != "downloaded file" {
		t.Fatalf("directory download = %q, %v", data, err)
	}

	previousDirectory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(directory); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(previousDirectory) })
	if err := retrieveFile(client, "file-id", "", "", "", false); err == nil || !strings.Contains(err.Error(), "cannot create output file") {
		t.Fatalf("collision error = %v", err)
	}

	output, err := captureCommand(t, func() error { return retrieveFile(client, "file-id", "", "", "-", true) })
	if err != nil || output != "downloaded file" {
		t.Fatalf("raw download = %q, %v", output, err)
	}
}

func TestPromptReadsAndTrimsInput(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(writer, "  answer  \n")
	_ = writer.Close()
	oldStdin := os.Stdin
	os.Stdin = reader
	t.Cleanup(func() { os.Stdin = oldStdin; _ = reader.Close() })
	if got := prompt("Question"); got != "answer" {
		t.Fatalf("prompt = %q", got)
	}
}

func TestPromptInjectionAndLoginValidation(t *testing.T) {
	viper.Reset()
	viper.Set(config.KeyAccessToken, "existing")
	viper.Set(config.KeyUsername, "alice")
	t.Cleanup(viper.Reset)
	if err := authLoginCmd.RunE(authLoginCmd, nil); err == nil || !strings.Contains(err.Error(), "already logged in") {
		t.Fatalf("login error = %v", err)
	}
	if err := authRegisterCmd.RunE(authRegisterCmd, nil); err == nil || !strings.Contains(err.Error(), "already logged in") {
		t.Fatalf("register error = %v", err)
	}
}

func TestRegisterPasswordMismatch(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)
	oldText, oldSecret := promptText, promptSecret
	promptText = func(string) string { return "value" }
	calls := 0
	promptSecret = func(string) string {
		calls++
		if calls == 1 {
			return "one"
		}
		return "two"
	}
	t.Cleanup(func() { promptText, promptSecret = oldText, oldSecret })
	if err := authRegisterCmd.RunE(authRegisterCmd, nil); err == nil || !strings.Contains(err.Error(), "passwords do not match") {
		t.Fatalf("register error = %v", err)
	}
}

func TestCommandBackendReceivedCriticalBodies(t *testing.T) {
	backend := newCommandBackend(t)
	setupCommandEnvironment(t, backend.server.URL)
	runCommand(t, updateCmd, []string{"text-id", "updated"}, func() {
		_ = updateCmd.Flags().Set("expected-version", "1")
		_ = updateCmd.Flags().Set("note", "reason")
	}, "updated")
	runCommand(t, policyCmd, []string{"text-id"}, func() {
		_ = policyCmd.Flags().Set("location-mode", "any")
		_ = policyCmd.Flags().Set("allow-country", "SG")
	}, "updated")

	backend.mu.Lock()
	defer backend.mu.Unlock()
	var sawUpdate, sawPolicy bool
	for _, request := range backend.requests {
		if request.Method == http.MethodPut && request.URI == "/api/secrets/text-id" {
			var body map[string]any
			_ = json.Unmarshal([]byte(request.Body), &body)
			sawUpdate = body["content"] == "updated" && body["change_note"] == "reason" && body["expected_version"] == float64(1)
		}
		if request.Method == http.MethodPut && request.URI == "/api/secrets/text-id/access-policy" {
			var body map[string]any
			_ = json.Unmarshal([]byte(request.Body), &body)
			sawPolicy = body["location_policy_mode"] == "any"
		}
	}
	if !sawUpdate || !sawPolicy {
		t.Fatalf("critical request bodies missing: update=%v policy=%v", sawUpdate, sawPolicy)
	}
}
