package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client is a typed HTTP client for the Phantom API.
type Client struct {
	BaseURL     string
	AccessToken string
	http        *http.Client
}

func New(baseURL, accessToken string) *Client {
	return &Client{
		BaseURL:     strings.TrimRight(baseURL, "/"),
		AccessToken: accessToken,
		http:        &http.Client{Timeout: 30 * time.Second},
	}
}

// ── internal request helper ──────────────────────────────────────────────────

func (c *Client) do(method, path string, body any, out any) error {
	var bodyReader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		bodyReader = bytes.NewReader(b)
	}

	req, err := http.NewRequest(method, c.BaseURL+path, bodyReader)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.AccessToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.AccessToken)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("connection failed – is the API reachable at %s? (%w)", c.BaseURL, err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode >= 400 {
		var apiErr struct {
			Detail string `json:"detail"`
		}
		if json.Unmarshal(respBody, &apiErr) == nil && apiErr.Detail != "" {
			return fmt.Errorf("%s", apiErr.Detail)
		}
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	if out != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, out); err != nil {
			return fmt.Errorf("failed to parse response: %w", err)
		}
	}
	return nil
}

// ── response / request types ─────────────────────────────────────────────────

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
}

type UserResponse struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	Username  string    `json:"username"`
	Role      string    `json:"role"`
	IsActive  bool      `json:"is_active"`
	CreatedAt time.Time `json:"created_at"`
}

type SecretCreateRequest struct {
	Content           string `json:"content"`
	TTLHours          int    `json:"ttl_hours"`
	PasswordProtected bool   `json:"password_protected"`
	AccessPassword    string `json:"access_password,omitempty"`
	MaxViews          int    `json:"max_views"`
	NotifyOnView      bool   `json:"notify_on_view,omitempty"`
	NotifyEmail       string `json:"notify_email,omitempty"`
	WebhookURL        string `json:"webhook_url,omitempty"`
}

type SecretCreateResponse struct {
	SecretID    string    `json:"secret_id"`
	ShareURL    string    `json:"share_url"`
	SignedToken string    `json:"signed_token"`
	ExpiresAt   time.Time `json:"expires_at"`
	QRCode      string    `json:"qr_code,omitempty"`
}

type SecretContent struct {
	Content         string    `json:"content"`
	CreatedAt       time.Time `json:"created_at"`
	ExpiresAt       time.Time `json:"expires_at"`
	ViewsRemaining  *int      `json:"views_remaining"`
	ClientEncrypted bool      `json:"client_encrypted"`
}

type SecretInfo struct {
	Exists            bool       `json:"exists"`
	CreatedAt         *time.Time `json:"created_at"`
	ExpiresAt         *time.Time `json:"expires_at"`
	PasswordProtected bool       `json:"password_protected"`
	Viewed            bool       `json:"viewed"`
	ViewCount         int        `json:"view_count"`
	MaxViews          int        `json:"max_views"`
}

type SecretListItem struct {
	ID                string    `json:"id"`
	CreatedAt         time.Time `json:"created_at"`
	ExpiresAt         time.Time `json:"expires_at"`
	Viewed            bool      `json:"viewed"`
	ViewCount         int       `json:"view_count"`
	MaxViews          int       `json:"max_views"`
	PasswordProtected bool      `json:"password_protected"`
	NotifyOnView      bool      `json:"notify_on_view"`
}

type SecretListResponse struct {
	Items    []SecretListItem `json:"items"`
	Total    int              `json:"total"`
	Page     int              `json:"page"`
	PageSize int              `json:"page_size"`
}

type AuditLogItem struct {
	ID        int            `json:"id"`
	Action    string         `json:"action"`
	ActorID   *string        `json:"actor_id"`
	ActorIP   *string        `json:"actor_ip"`
	SecretID  *string        `json:"secret_id"`
	Metadata  map[string]any `json:"metadata"`
	CreatedAt time.Time      `json:"created_at"`
}

type AuditLogResponse struct {
	Items    []AuditLogItem `json:"items"`
	Total    int            `json:"total"`
	Page     int            `json:"page"`
	PageSize int            `json:"page_size"`
}

type StatsResponse struct {
	TotalSecretsCreated int `json:"total_secrets_created"`
	TotalSecretsViewed  int `json:"total_secrets_viewed"`
	ActiveSecrets       int `json:"active_secrets"`
}

type KeyRotateResponse struct {
	SecretID      string    `json:"secret_id"`
	NewKeyVersion int       `json:"new_key_version"`
	RotatedAt     time.Time `json:"rotated_at"`
}

type UserListResponse struct {
	Items    []UserResponse `json:"items"`
	Total    int            `json:"total"`
	Page     int            `json:"page"`
	PageSize int            `json:"page_size"`
}

// ── auth ─────────────────────────────────────────────────────────────────────

func (c *Client) Register(email, username, password string) (*UserResponse, error) {
	var out UserResponse
	err := c.do("POST", "/api/auth/register", map[string]string{
		"email": email, "username": username, "password": password,
	}, &out)
	return &out, err
}

func (c *Client) Login(email, password string) (*TokenResponse, error) {
	var out TokenResponse
	err := c.do("POST", "/api/auth/login", map[string]string{
		"email": email, "password": password,
	}, &out)
	return &out, err
}

func (c *Client) Logout(refreshToken string) error {
	return c.do("POST", "/api/auth/logout", map[string]string{
		"refresh_token": refreshToken,
	}, nil)
}

func (c *Client) Me() (*UserResponse, error) {
	var out UserResponse
	err := c.do("GET", "/api/auth/me", nil, &out)
	return &out, err
}

// ── secrets ───────────────────────────────────────────────────────────────────

func (c *Client) CreateSecret(req SecretCreateRequest) (*SecretCreateResponse, error) {
	var out SecretCreateResponse
	err := c.do("POST", "/api/secrets", req, &out)
	return &out, err
}

func (c *Client) GetSecret(secretID, password, token string) (*SecretContent, error) {
	path := "/api/secrets/" + secretID
	if token != "" {
		path += "?token=" + url.QueryEscape(token)
	}
	body := map[string]any{}
	if password != "" {
		body["access_password"] = password
	}
	var out SecretContent
	err := c.do("POST", path, body, &out)
	return &out, err
}

func (c *Client) SecretInfo(secretID string) (*SecretInfo, error) {
	var out SecretInfo
	err := c.do("GET", "/api/secrets/"+secretID+"/info", nil, &out)
	return &out, err
}

func (c *Client) ListSecrets(page, pageSize int, viewed, expired *bool) (*SecretListResponse, error) {
	q := fmt.Sprintf("?page=%d&page_size=%d", page, pageSize)
	if viewed != nil {
		q += fmt.Sprintf("&viewed=%v", *viewed)
	}
	if expired != nil {
		q += fmt.Sprintf("&expired=%v", *expired)
	}
	var out SecretListResponse
	err := c.do("GET", "/api/secrets"+q, nil, &out)
	return &out, err
}

func (c *Client) DeleteSecret(secretID string) error {
	return c.do("DELETE", "/api/secrets/"+secretID, nil, nil)
}

func (c *Client) RotateKey(secretID string) (*KeyRotateResponse, error) {
	var out KeyRotateResponse
	err := c.do("POST", "/api/secrets/"+secretID+"/rotate-key", map[string]any{}, &out)
	return &out, err
}

// ── stats ─────────────────────────────────────────────────────────────────────

func (c *Client) Stats() (*StatsResponse, error) {
	var out StatsResponse
	err := c.do("GET", "/api/stats", nil, &out)
	return &out, err
}

func (c *Client) Health() (map[string]string, error) {
	var out map[string]string
	err := c.do("GET", "/health", nil, &out)
	return out, err
}

// ── admin ─────────────────────────────────────────────────────────────────────

func (c *Client) AuditLogs(page, pageSize int, action, actorID, secretID string) (*AuditLogResponse, error) {
	q := fmt.Sprintf("?page=%d&page_size=%d", page, pageSize)
	if action != "" {
		q += "&action=" + url.QueryEscape(action)
	}
	if actorID != "" {
		q += "&actor_id=" + url.QueryEscape(actorID)
	}
	if secretID != "" {
		q += "&secret_id=" + url.QueryEscape(secretID)
	}
	var out AuditLogResponse
	err := c.do("GET", "/api/admin/audit-logs"+q, nil, &out)
	return &out, err
}

func (c *Client) AdminCleanup() (int, error) {
	var out struct {
		DeletedCount int `json:"deleted_count"`
	}
	err := c.do("DELETE", "/api/admin/cleanup", nil, &out)
	return out.DeletedCount, err
}

func (c *Client) ListUsers(page, pageSize int) (*UserListResponse, error) {
	var out UserListResponse
	err := c.do("GET", fmt.Sprintf("/api/admin/users?page=%d&page_size=%d", page, pageSize), nil, &out)
	return &out, err
}

func (c *Client) ChangeRole(userID, role string) error {
	return c.do("PATCH", fmt.Sprintf("/api/admin/users/%s/role?role=%s", userID, url.QueryEscape(role)), nil, nil)
}

func (c *Client) ToggleActivation(userID string) (bool, error) {
	var out struct {
		Active bool `json:"active"`
	}
	err := c.do("PATCH", "/api/admin/users/"+userID+"/switch", nil, &out)
	return out.Active, err
}