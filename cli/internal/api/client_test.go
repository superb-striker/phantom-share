package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

func response(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func testClient(t *testing.T, check func(*http.Request)) *Client {
	t.Helper()
	client := New("http://api.example.test/", "access-token")
	client.http.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if got := request.Header.Get("Authorization"); got != "Bearer access-token" {
			t.Errorf("Authorization = %q", got)
		}
		check(request)
		return response(http.StatusOK, `{}`), nil
	})
	return client
}

func readJSON(t *testing.T, request *http.Request) map[string]any {
	t.Helper()
	if got := request.Header.Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q", got)
	}
	var body map[string]any
	if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
		t.Fatalf("decode JSON body: %v", err)
	}
	return body
}

func TestJSONAPIContracts(t *testing.T) {
	trueValue := true
	falseValue := false
	maxSecrets := 7
	maxBytes := int64(4096)

	tests := []struct {
		name       string
		method     string
		requestURI string
		body       map[string]any
		invoke     func(*Client) error
	}{
		{"register", http.MethodPost, "/api/auth/register", map[string]any{"email": "a@example.com", "username": "alice", "password": "password"}, func(c *Client) error { _, err := c.Register("a@example.com", "alice", "password"); return err }},
		{"login", http.MethodPost, "/api/auth/login", map[string]any{"email": "a@example.com", "password": "password"}, func(c *Client) error { _, err := c.Login("a@example.com", "password"); return err }},
		{"refresh", http.MethodPost, "/api/auth/refresh", map[string]any{"refresh_token": "refresh"}, func(c *Client) error { _, err := c.Refresh("refresh"); return err }},
		{"logout", http.MethodPost, "/api/auth/logout", map[string]any{"refresh_token": "refresh"}, func(c *Client) error { return c.Logout("refresh") }},
		{"me", http.MethodGet, "/api/auth/me", nil, func(c *Client) error { _, err := c.Me(); return err }},
		{"create secret", http.MethodPost, "/api/secrets", map[string]any{"content": "secret", "ttl_hours": float64(24), "password_protected": true, "access_password": "pass", "max_views": float64(2), "allowed_emails": []any{"a@example.com"}, "notify_on_view": true, "notify_email": "owner@example.com", "webhook_url": "https://hook.example", "allowed_cidrs": []any{"10.0.0.0/8"}, "allowed_countries": []any{"IN"}, "location_policy_mode": "all", "geoip_fail_closed": true, "client_encrypted": true, "client_nonce": "nonce"}, func(c *Client) error {
			_, err := c.CreateSecret(SecretCreateRequest{Content: "secret", TTLHours: 24, PasswordProtected: true, AccessPassword: "pass", MaxViews: 2, AllowedEmails: []string{"a@example.com"}, NotifyOnView: true, NotifyEmail: "owner@example.com", WebhookURL: "https://hook.example", AllowedCIDRs: []string{"10.0.0.0/8"}, AllowedCountries: []string{"IN"}, LocationPolicyMode: "all", GeoIPFailClosed: true, ClientEncrypted: true, ClientNonce: "nonce"})
			return err
		}},
		{"get secret", http.MethodPost, "/api/secrets/id?token=signed+token", map[string]any{"access_password": "pass"}, func(c *Client) error { _, err := c.GetSecret("id", "pass", "signed token"); return err }},
		{"secret info", http.MethodGet, "/api/secrets/id/info", nil, func(c *Client) error { _, err := c.SecretInfo("id"); return err }},
		{"update secret", http.MethodPut, "/api/secrets/id", map[string]any{"content": "new", "expected_version": float64(2), "change_note": "note"}, func(c *Client) error {
			_, err := c.UpdateSecret("id", SecretUpdateRequest{Content: "new", ExpectedVersion: 2, ChangeNote: "note"})
			return err
		}},
		{"list versions", http.MethodGet, "/api/secrets/id/versions", nil, func(c *Client) error { _, err := c.SecretVersions("id"); return err }},
		{"restore version", http.MethodPost, "/api/secrets/id/versions/3/restore", map[string]any{}, func(c *Client) error { _, err := c.RestoreSecretVersion("id", 3); return err }},
		{"update policy", http.MethodPut, "/api/secrets/id/access-policy", map[string]any{"allowed_cidrs": []any{"10.0.0.0/8"}, "allowed_countries": []any{"IN"}, "location_policy_mode": "any", "geoip_fail_closed": false}, func(c *Client) error {
			_, err := c.UpdateLocationPolicy("id", LocationPolicyRequest{AllowedCIDRs: []string{"10.0.0.0/8"}, AllowedCountries: []string{"IN"}, LocationPolicyMode: "any"})
			return err
		}},
		{"quota", http.MethodGet, "/api/quota", nil, func(c *Client) error { _, err := c.Quota(); return err }},
		{"update quota", http.MethodPatch, "/api/admin/users/user-id/quota", map[string]any{"max_active_secrets": float64(7), "max_file_bytes": float64(4096)}, func(c *Client) error {
			_, err := c.UpdateUserQuota("user-id", QuotaUpdateRequest{MaxActiveSecrets: &maxSecrets, MaxFileBytes: &maxBytes})
			return err
		}},
		{"list secrets", http.MethodGet, "/api/secrets?page=2&page_size=25&viewed=true&expired=false", nil, func(c *Client) error { _, err := c.ListSecrets(2, 25, &trueValue, &falseValue); return err }},
		{"delete secret", http.MethodDelete, "/api/secrets/id", nil, func(c *Client) error { return c.DeleteSecret("id") }},
		{"rotate key", http.MethodPost, "/api/secrets/id/rotate-key", map[string]any{}, func(c *Client) error { _, err := c.RotateKey("id"); return err }},
		{"stats", http.MethodGet, "/api/stats", nil, func(c *Client) error { _, err := c.Stats(); return err }},
		{"health", http.MethodGet, "/health", nil, func(c *Client) error { _, err := c.Health(); return err }},
		{"audit logs", http.MethodGet, "/api/admin/audit-logs?page=3&page_size=40&action=secret_viewed&severity=warning&actor_id=actor&secret_id=secret", nil, func(c *Client) error {
			_, err := c.AuditLogs(3, 40, "secret_viewed", "warning", "actor", "secret")
			return err
		}},
		{"admin cleanup", http.MethodDelete, "/api/admin/cleanup", nil, func(c *Client) error { _, err := c.AdminCleanup(); return err }},
		{"list users", http.MethodGet, "/api/admin/users?page=2&page_size=30", nil, func(c *Client) error { _, err := c.ListUsers(2, 30); return err }},
		{"change role", http.MethodPatch, "/api/admin/users/user-id/role", map[string]any{"role": "admin"}, func(c *Client) error { _, err := c.ChangeRole("user-id", "admin"); return err }},
		{"toggle user", http.MethodPatch, "/api/admin/users/user-id/switch", nil, func(c *Client) error { _, err := c.ToggleActivation("user-id"); return err }},
		{"secret views", http.MethodGet, "/api/secrets/id/views?page=2&page_size=50", nil, func(c *Client) error { _, err := c.SecretViews("id", 2, 50); return err }},
		{"request verification", http.MethodPost, "/api/auth/verification/request", nil, func(c *Client) error { return c.RequestEmailVerification() }},
		{"confirm verification", http.MethodPost, "/api/auth/verification/confirm", map[string]any{"code": "code"}, func(c *Client) error { return c.ConfirmEmailVerification("code") }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := testClient(t, func(request *http.Request) {
				if request.Method != test.method {
					t.Errorf("method = %s, want %s", request.Method, test.method)
				}
				if got := request.URL.RequestURI(); got != test.requestURI {
					t.Errorf("URI = %q, want %q", got, test.requestURI)
				}
				if test.body == nil {
					if request.Body != nil {
						data, _ := io.ReadAll(request.Body)
						if len(data) != 0 {
							t.Errorf("unexpected body %q", data)
						}
					}
					return
				}
				got := readJSON(t, request)
				if !mapsEqual(got, test.body) {
					t.Errorf("body = %#v, want %#v", got, test.body)
				}
			})
			if err := test.invoke(client); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func mapsEqual(left, right map[string]any) bool {
	leftJSON, _ := json.Marshal(left)
	rightJSON, _ := json.Marshal(right)
	return string(leftJSON) == string(rightJSON)
}

func TestFileAPIContracts(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.txt")
	if err := os.WriteFile(path, []byte("file payload"), 0600); err != nil {
		t.Fatal(err)
	}

	t.Run("create multipart", func(t *testing.T) {
		client := testClient(t, func(request *http.Request) {
			if request.Method != http.MethodPost || request.URL.Path != "/api/secrets/files" {
				t.Errorf("unexpected request %s %s", request.Method, request.URL.Path)
			}
			assertMultipart(t, request, "secret.txt", "file payload", map[string][]string{
				"ttl_hours": {"24"}, "max_views": {"3"}, "access_password": {"pass"},
				"change_note": {"first"}, "allowed_email": {"a@example.com", "b@example.com"},
				"allowed_cidr": {"10.0.0.0/8"}, "allowed_country": {"IN"},
				"location_policy_mode": {"all"}, "geoip_fail_closed": {"true"},
			})
		})
		_, err := client.CreateFileSecret(FileCreateRequest{FilePath: path, TTLHours: 24, MaxViews: 3, AccessPassword: "pass", AllowedEmails: []string{"a@example.com", "b@example.com"}, ChangeNote: "first", AllowedCIDRs: []string{"10.0.0.0/8"}, AllowedCountries: []string{"IN"}, LocationPolicyMode: "all", GeoIPFailClosed: true})
		if err != nil {
			t.Fatal(err)
		}
	})

	t.Run("update multipart", func(t *testing.T) {
		client := testClient(t, func(request *http.Request) {
			if request.Method != http.MethodPut || request.URL.Path != "/api/secrets/id/file" {
				t.Errorf("unexpected request %s %s", request.Method, request.URL.Path)
			}
			assertMultipart(t, request, "secret.txt", "file payload", map[string][]string{"expected_version": {"2"}, "change_note": {"updated"}})
		})
		_, err := client.UpdateFileSecret("id", path, 2, "updated")
		if err != nil {
			t.Fatal(err)
		}
	})

	t.Run("download", func(t *testing.T) {
		client := New("http://api.example.test", "access-token")
		client.http.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
			if request.Method != http.MethodGet || request.URL.RequestURI() != "/api/secrets/id/file?access_password=p%40ss&token=signed+token" {
				t.Errorf("unexpected request %s %s", request.Method, request.URL.RequestURI())
			}
			return response(http.StatusOK, "downloaded"), nil
		})
		resp, err := client.DownloadFile("id", "p@ss", "signed token")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if string(body) != "downloaded" {
			t.Fatalf("body = %q", body)
		}
	})

	t.Run("missing upload", func(t *testing.T) {
		client := New("http://api.example.test", "token")
		_, err := client.CreateFileSecret(FileCreateRequest{FilePath: filepath.Join(dir, "missing")})
		if err == nil || !strings.Contains(err.Error(), "cannot open file") {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func assertMultipart(t *testing.T, request *http.Request, filename, content string, fields map[string][]string) {
	t.Helper()
	if err := request.ParseMultipartForm(1 << 20); err != nil {
		t.Fatalf("parse multipart: %v", err)
	}
	for name, want := range fields {
		got := request.MultipartForm.Value[name]
		if strings.Join(got, "|") != strings.Join(want, "|") {
			t.Errorf("field %s = %v, want %v", name, got, want)
		}
	}
	file, header, err := request.FormFile("upload")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	data, _ := io.ReadAll(file)
	if header.Filename != filename || string(data) != content {
		t.Errorf("upload = %q %q", header.Filename, data)
	}
}

func TestResponseAndTransportErrors(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
		check  func(error) bool
	}{
		{"string detail", 400, `{"detail":"bad input"}`, func(err error) bool {
			var apiErr *APIError
			return errors.As(err, &apiErr) && apiErr.StatusCode == 400 && apiErr.Detail == "bad input"
		}},
		{"structured detail", 409, `{"detail":{"error_code":"VERSION_CONFLICT","current_version":4}}`, func(err error) bool {
			var apiErr *APIError
			return errors.As(err, &apiErr) && apiErr.ErrorCode == "VERSION_CONFLICT" && apiErr.CurrentVersion != nil && *apiErr.CurrentVersion == 4
		}},
		{"raw detail", 502, `upstream failed`, func(err error) bool {
			var apiErr *APIError
			return errors.As(err, &apiErr) && apiErr.Detail == "upstream failed"
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := New("http://api.example.test", "")
			client.http.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) { return response(test.status, test.body), nil })
			_, err := client.Health()
			if err == nil || !test.check(err) {
				t.Fatalf("unexpected error: %#v", err)
			}
			if err.Error() == "" {
				t.Fatal("API error rendered as an empty string")
			}
		})
	}
	if got := (&APIError{StatusCode: 418}).Error(); got != "HTTP 418" {
		t.Fatalf("status-only API error = %q", got)
	}

	t.Run("malformed success", func(t *testing.T) {
		client := New("http://api.example.test", "")
		client.http.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) { return response(200, `{`), nil })
		_, err := client.Health()
		if err == nil || !strings.Contains(err.Error(), "failed to parse response") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("connection failure", func(t *testing.T) {
		client := New("http://api.example.test", "")
		client.http.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, errors.New("offline") })
		_, err := client.Health()
		if err == nil || !strings.Contains(err.Error(), "API reachable") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("download API failure", func(t *testing.T) {
		client := New("http://api.example.test", "")
		client.http.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
			return response(http.StatusNotFound, `{"detail":"file missing"}`), nil
		})
		_, err := client.DownloadFile("missing", "", "")
		if err == nil || err.Error() != "file missing" {
			t.Fatalf("download error = %v", err)
		}
	})

	t.Run("multipart API and decode failures", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "upload.txt")
		if err := os.WriteFile(path, []byte("payload"), 0600); err != nil {
			t.Fatal(err)
		}
		for _, test := range []struct {
			name, body, want string
			status           int
		}{
			{"API error", `{"detail":"rejected"}`, "rejected", http.StatusBadRequest},
			{"malformed success", `{`, "failed to parse response", http.StatusOK},
		} {
			t.Run(test.name, func(t *testing.T) {
				client := New("http://api.example.test", "")
				client.http.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
					_, _ = io.Copy(io.Discard, request.Body)
					return response(test.status, test.body), nil
				})
				_, err := client.UpdateFileSecret("id", path, 1, "")
				if err == nil || !strings.Contains(err.Error(), test.want) {
					t.Fatalf("multipart error = %v", err)
				}
			})
		}
	})
}

func TestAutomaticRefreshLifecycle(t *testing.T) {
	t.Run("proactive refresh persists before request", func(t *testing.T) {
		expired := jwtWithExpiry(time.Now().Add(10 * time.Second))
		var persisted atomic.Bool
		client := New("http://api.example.test", expired)
		client.http.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
			switch request.URL.Path {
			case "/api/auth/refresh":
				return response(200, `{"access_token":"new-access","refresh_token":"new-refresh","expires_in":900}`), nil
			case "/api/auth/me":
				if !persisted.Load() {
					t.Error("request retried before tokens were persisted")
				}
				if request.Header.Get("Authorization") != "Bearer new-access" {
					t.Errorf("authorization = %q", request.Header.Get("Authorization"))
				}
				return response(200, `{}`), nil
			default:
				return response(404, ""), nil
			}
		})
		client.EnableAutoRefresh("old-refresh", func(tokens *TokenResponse) error { persisted.Store(tokens.RefreshToken == "new-refresh"); return nil }, nil)
		if _, err := client.Me(); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("bearer challenge retries once", func(t *testing.T) {
		var resourceCalls atomic.Int32
		var refreshCalls atomic.Int32
		client := New("http://api.example.test", "old-access")
		client.http.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
			if request.URL.Path == "/api/auth/refresh" {
				refreshCalls.Add(1)
				return response(200, `{"access_token":"new-access","refresh_token":"new-refresh"}`), nil
			}
			resourceCalls.Add(1)
			if request.Header.Get("Authorization") == "Bearer old-access" {
				resp := response(401, `{}`)
				resp.Header.Set("WWW-Authenticate", `Bearer realm="api"`)
				return resp, nil
			}
			return response(200, `{}`), nil
		})
		client.EnableAutoRefresh("old-refresh", func(*TokenResponse) error { return nil }, nil)
		if _, err := client.Me(); err != nil {
			t.Fatal(err)
		}
		if resourceCalls.Load() != 2 || refreshCalls.Load() != 1 {
			t.Fatalf("resource=%d refresh=%d", resourceCalls.Load(), refreshCalls.Load())
		}
	})

	t.Run("non bearer unauthorized is not refreshed", func(t *testing.T) {
		var refreshCalls atomic.Int32
		client := New("http://api.example.test", "access")
		client.http.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
			if request.URL.Path == "/api/auth/refresh" {
				refreshCalls.Add(1)
			}
			return response(401, `{"detail":"Invalid password"}`), nil
		})
		client.EnableAutoRefresh("refresh", func(*TokenResponse) error { return nil }, nil)
		_, err := client.GetSecret("id", "wrong", "")
		if err == nil || refreshCalls.Load() != 0 {
			t.Fatalf("error=%v refreshes=%d", err, refreshCalls.Load())
		}
	})

	t.Run("invalid refresh clears credentials", func(t *testing.T) {
		var cleared atomic.Bool
		client := New("http://api.example.test", jwtWithExpiry(time.Now()))
		client.http.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) { return response(401, `{"detail":"invalid"}`), nil })
		client.EnableAutoRefresh("invalid", func(*TokenResponse) error { return nil }, func() error { cleared.Store(true); return nil })
		_, err := client.Me()
		if !errors.Is(err, ErrSessionExpired) || !cleared.Load() {
			t.Fatalf("error=%v cleared=%v", err, cleared.Load())
		}
	})

	t.Run("transient refresh error keeps credentials", func(t *testing.T) {
		var cleared atomic.Bool
		client := New("http://api.example.test", jwtWithExpiry(time.Now()))
		client.http.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
			return response(http.StatusServiceUnavailable, `{"detail":"try later"}`), nil
		})
		client.EnableAutoRefresh("refresh", func(*TokenResponse) error { return nil }, func() error { cleared.Store(true); return nil })
		_, err := client.Me()
		if err == nil || !strings.Contains(err.Error(), "could not refresh session") || cleared.Load() {
			t.Fatalf("error=%v cleared=%v", err, cleared.Load())
		}
	})

	t.Run("persistence failure clears credentials", func(t *testing.T) {
		var cleared atomic.Bool
		client := New("http://api.example.test", jwtWithExpiry(time.Now()))
		client.http.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
			return response(http.StatusOK, `{"access_token":"new","refresh_token":"rotated"}`), nil
		})
		client.EnableAutoRefresh("refresh", func(*TokenResponse) error { return errors.New("disk full") }, func() error { cleared.Store(true); return nil })
		_, err := client.Me()
		if err == nil || !strings.Contains(err.Error(), "saving credentials failed") || !cleared.Load() {
			t.Fatalf("error=%v cleared=%v", err, cleared.Load())
		}
	})

	t.Run("concurrent requests rotate once", func(t *testing.T) {
		var refreshCalls atomic.Int32
		client := New("http://api.example.test", "old-access")
		client.http.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
			if request.URL.Path == "/api/auth/refresh" {
				refreshCalls.Add(1)
				time.Sleep(5 * time.Millisecond)
				return response(200, `{"access_token":"new-access","refresh_token":"new-refresh"}`), nil
			}
			if request.Header.Get("Authorization") == "Bearer old-access" {
				resp := response(401, `{}`)
				resp.Header.Set("WWW-Authenticate", "Bearer")
				return resp, nil
			}
			return response(200, `{}`), nil
		})
		client.EnableAutoRefresh("old-refresh", func(*TokenResponse) error { return nil }, nil)
		var wg sync.WaitGroup
		errorsSeen := make(chan error, 12)
		for range 12 {
			wg.Add(1)
			go func() { defer wg.Done(); _, err := client.Me(); errorsSeen <- err }()
		}
		wg.Wait()
		close(errorsSeen)
		for err := range errorsSeen {
			if err != nil {
				t.Error(err)
			}
		}
		if refreshCalls.Load() != 1 {
			t.Fatalf("refresh calls = %d", refreshCalls.Load())
		}
	})
}

func TestTokenExpiryParsing(t *testing.T) {
	deadline := time.Now().Add(time.Minute)
	if tokenExpiresSoon("not-a-jwt", deadline) {
		t.Fatal("plain token reported as expiring")
	}
	if tokenExpiresSoon("a.%%%.c", deadline) {
		t.Fatal("invalid base64 token reported as expiring")
	}
	if tokenExpiresSoon("a."+base64URLEncode([]byte(`{"sub":"user"}`))+".c", deadline) {
		t.Fatal("token without exp reported as expiring")
	}
	if !tokenExpiresSoon(jwtWithExpiry(time.Now()), deadline) {
		t.Fatal("expired token was not detected")
	}
	if tokenExpiresSoon(jwtWithExpiry(time.Now().Add(time.Hour)), deadline) {
		t.Fatal("valid token reported as expiring")
	}
}

func jwtWithExpiry(expiry time.Time) string {
	payload, _ := json.Marshal(map[string]int64{"exp": expiry.Unix()})
	return "header." + strings.TrimRight(base64URLEncode(payload), "=") + ".signature"
}

func base64URLEncode(value []byte) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	var builder strings.Builder
	for i := 0; i < len(value); i += 3 {
		remaining := len(value) - i
		chunk := uint32(value[i]) << 16
		if remaining > 1 {
			chunk |= uint32(value[i+1]) << 8
		}
		if remaining > 2 {
			chunk |= uint32(value[i+2])
		}
		builder.WriteByte(alphabet[(chunk>>18)&63])
		builder.WriteByte(alphabet[(chunk>>12)&63])
		if remaining > 1 {
			builder.WriteByte(alphabet[(chunk>>6)&63])
		}
		if remaining > 2 {
			builder.WriteByte(alphabet[chunk&63])
		}
	}
	return builder.String()
}
