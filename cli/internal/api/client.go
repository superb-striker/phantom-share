package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
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
		http:        &http.Client{Timeout: 5 * time.Minute},
	}
}

// internal request helper

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
		return decodeAPIError(resp.StatusCode, respBody)
	}

	if out != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, out); err != nil {
			return fmt.Errorf("failed to parse response: %w", err)
		}
	}
	return nil
}

// APIError retains structured conflict details returned by the backend.
type APIError struct {
	StatusCode     int
	Detail         string
	ErrorCode      string
	CurrentVersion *int
}

func (e *APIError) Error() string {
	if e.ErrorCode != "" && e.CurrentVersion != nil {
		return fmt.Sprintf("%s (current version: %d)", e.ErrorCode, *e.CurrentVersion)
	}
	if e.Detail != "" {
		return e.Detail
	}
	return fmt.Sprintf("HTTP %d", e.StatusCode)
}

func decodeAPIError(statusCode int, body []byte) error {
	var envelope struct {
		Detail json.RawMessage `json:"detail"`
	}
	apiErr := &APIError{StatusCode: statusCode}
	if json.Unmarshal(body, &envelope) == nil && len(envelope.Detail) > 0 {
		if json.Unmarshal(envelope.Detail, &apiErr.Detail) == nil {
			return apiErr
		}
		var detail struct {
			ErrorCode      string `json:"error_code"`
			CurrentVersion *int   `json:"current_version"`
		}
		if json.Unmarshal(envelope.Detail, &detail) == nil {
			apiErr.ErrorCode = detail.ErrorCode
			apiErr.CurrentVersion = detail.CurrentVersion
			if apiErr.ErrorCode != "" {
				return apiErr
			}
		}
		apiErr.Detail = strings.TrimSpace(string(envelope.Detail))
		return apiErr
	}
	apiErr.Detail = strings.TrimSpace(string(body))
	return apiErr
}

// response / request types

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
}

type UserResponse struct {
	ID         string    `json:"id"`
	Email      string    `json:"email"`
	Username   string    `json:"username"`
	Role       string    `json:"role"`
	IsActive   bool      `json:"is_active"`
	IsVerified bool      `json:"is_verified"`
	CreatedAt  time.Time `json:"created_at"`
}

type SecretCreateRequest struct {
	Content            string   `json:"content"`
	TTLHours           int      `json:"ttl_hours"`
	PasswordProtected  bool     `json:"password_protected"`
	AccessPassword     string   `json:"access_password,omitempty"`
	MaxViews           int      `json:"max_views"`
	AllowedEmails      []string `json:"allowed_emails,omitempty"`
	NotifyOnView       bool     `json:"notify_on_view,omitempty"`
	NotifyEmail        string   `json:"notify_email,omitempty"`
	WebhookURL         string   `json:"webhook_url,omitempty"`
	AllowedCIDRs       []string `json:"allowed_cidrs,omitempty"`
	AllowedCountries   []string `json:"allowed_countries,omitempty"`
	LocationPolicyMode string   `json:"location_policy_mode,omitempty"`
	GeoIPFailClosed    bool     `json:"geoip_fail_closed"`
	ClientEncrypted    bool     `json:"client_encrypted,omitempty"`
	ClientNonce        string   `json:"client_nonce,omitempty"`
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
	Version         int       `json:"version"`
}

type SecretInfo struct {
	Exists             bool       `json:"exists"`
	CreatedAt          *time.Time `json:"created_at"`
	ExpiresAt          *time.Time `json:"expires_at"`
	PasswordProtected  bool       `json:"password_protected"`
	Viewed             bool       `json:"viewed"`
	ViewCount          int        `json:"view_count"`
	MaxViews           int        `json:"max_views"`
	CurrentVersion     int        `json:"current_version"`
	PayloadType        string     `json:"payload_type"`
	LocationRestricted bool       `json:"location_restricted"`
	PolicyVersion      int        `json:"policy_version"`
}

type FileCreateRequest struct {
	FilePath           string
	TTLHours           int
	MaxViews           int
	AccessPassword     string
	AllowedEmails      []string
	ChangeNote         string
	AllowedCIDRs       []string
	AllowedCountries   []string
	LocationPolicyMode string
	GeoIPFailClosed    bool
}

type FileCreateResponse struct {
	SecretID    string `json:"secret_id"`
	ShareURL    string `json:"share_url"`
	SignedToken string `json:"signed_token"`
	Version     int    `json:"version"`
	Size        int64  `json:"size"`
}

type SecretUpdateRequest struct {
	Content         string `json:"content"`
	ExpectedVersion int    `json:"expected_version"`
	ChangeNote      string `json:"change_note,omitempty"`
}

type SecretUpdateResponse struct {
	SecretID  string    `json:"secret_id"`
	Version   int       `json:"version"`
	UpdatedAt time.Time `json:"updated_at"`
}

type FileUpdateResponse struct {
	SecretID string `json:"secret_id"`
	Version  int    `json:"version"`
	Size     int64  `json:"size"`
}

type SecretVersionItem struct {
	Version       int       `json:"version"`
	PlaintextSize int64     `json:"plaintext_size"`
	CreatedBy     *string   `json:"created_by"`
	ChangeNote    *string   `json:"change_note"`
	CreatedAt     time.Time `json:"created_at"`
	IsCurrent     bool      `json:"is_current"`
}

type SecretVersionList struct {
	Items          []SecretVersionItem `json:"items"`
	CurrentVersion int                 `json:"current_version"`
}

type LocationPolicyRequest struct {
	AllowedCIDRs       []string `json:"allowed_cidrs"`
	AllowedCountries   []string `json:"allowed_countries"`
	LocationPolicyMode string   `json:"location_policy_mode"`
	GeoIPFailClosed    bool     `json:"geoip_fail_closed"`
}

type LocationPolicyResponse struct {
	SecretID           string   `json:"secret_id"`
	AllowedCIDRs       []string `json:"allowed_cidrs"`
	AllowedCountries   []string `json:"allowed_countries"`
	LocationPolicyMode string   `json:"location_policy_mode"`
	GeoIPFailClosed    bool     `json:"geoip_fail_closed"`
	PolicyVersion      int      `json:"policy_version"`
	SignedToken        string   `json:"signed_token"`
	ShareURL           string   `json:"share_url"`
}

type QuotaResponse struct {
	ActiveSecrets    int   `json:"active_secrets"`
	FileBytes        int64 `json:"file_bytes"`
	MaxActiveSecrets int   `json:"max_active_secrets"`
	MaxFileBytes     int64 `json:"max_file_bytes"`
}

type QuotaUpdateRequest struct {
	MaxActiveSecrets *int   `json:"max_active_secrets,omitempty"`
	MaxFileBytes     *int64 `json:"max_file_bytes,omitempty"`
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
	Severity  string         `json:"severity"` // info | warning | critical
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

// AdminUserResponse mirrors the richer /api/admin/users shape
// (includes updated_at and delete_after, absent from UserResponse).
type AdminUserResponse struct {
	ID          string     `json:"id"`
	Email       string     `json:"email"`
	Username    string     `json:"username"`
	Role        string     `json:"role"`
	IsActive    bool       `json:"is_active"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	DeleteAfter *time.Time `json:"delete_after"`
}

type UserListResponse struct {
	Items    []AdminUserResponse `json:"items"`
	Total    int                 `json:"total"`
	Page     int                 `json:"page"`
	PageSize int                 `json:"page_size"`
}

// auth

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

func (c *Client) Refresh(refreshToken string) (*TokenResponse, error) {
	var out TokenResponse
	err := c.do("POST", "/api/auth/refresh", map[string]string{
		"refresh_token": refreshToken,
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

// secrets

func (c *Client) CreateSecret(req SecretCreateRequest) (*SecretCreateResponse, error) {
	var out SecretCreateResponse
	err := c.do("POST", "/api/secrets", req, &out)
	return &out, err
}

func (c *Client) CreateFileSecret(req FileCreateRequest) (*FileCreateResponse, error) {
	fields := map[string][]string{
		"ttl_hours":            {strconv.Itoa(req.TTLHours)},
		"max_views":            {strconv.Itoa(req.MaxViews)},
		"location_policy_mode": {req.LocationPolicyMode},
		"geoip_fail_closed":    {strconv.FormatBool(req.GeoIPFailClosed)},
		"allowed_email":        req.AllowedEmails,
		"allowed_cidr":         req.AllowedCIDRs,
		"allowed_country":      req.AllowedCountries,
	}
	if req.AccessPassword != "" {
		fields["access_password"] = []string{req.AccessPassword}
	}
	if req.ChangeNote != "" {
		fields["change_note"] = []string{req.ChangeNote}
	}
	var out FileCreateResponse
	err := c.multipartUpload("POST", "/api/secrets/files", req.FilePath, fields, &out)
	return &out, err
}

func (c *Client) GetSecret(secretID, password, token string) (*SecretContent, error) {
	path := "/api/secrets/" + url.PathEscape(secretID)
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
	err := c.do("GET", "/api/secrets/"+url.PathEscape(secretID)+"/info", nil, &out)
	return &out, err
}

func (c *Client) DownloadFile(secretID, password, token string) (*http.Response, error) {
	q := url.Values{}
	if token != "" {
		q.Set("token", token)
	}
	if password != "" {
		q.Set("access_password", password)
	}
	path := "/api/secrets/" + url.PathEscape(secretID) + "/file"
	if encoded := q.Encode(); encoded != "" {
		path += "?" + encoded
	}
	req, err := http.NewRequest("GET", c.BaseURL+path, nil)
	if err != nil {
		return nil, err
	}
	if c.AccessToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.AccessToken)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("connection failed – is the API reachable at %s? (%w)", c.BaseURL, err)
	}
	if resp.StatusCode >= 400 {
		defer resp.Body.Close()
		body, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			return nil, readErr
		}
		return nil, decodeAPIError(resp.StatusCode, body)
	}
	return resp, nil
}

func (c *Client) UpdateSecret(secretID string, req SecretUpdateRequest) (*SecretUpdateResponse, error) {
	var out SecretUpdateResponse
	err := c.do("PUT", "/api/secrets/"+url.PathEscape(secretID), req, &out)
	return &out, err
}

func (c *Client) UpdateFileSecret(secretID, filePath string, expectedVersion int, changeNote string) (*FileUpdateResponse, error) {
	fields := map[string][]string{"expected_version": {strconv.Itoa(expectedVersion)}}
	if changeNote != "" {
		fields["change_note"] = []string{changeNote}
	}
	var out FileUpdateResponse
	err := c.multipartUpload("PUT", "/api/secrets/"+url.PathEscape(secretID)+"/file", filePath, fields, &out)
	return &out, err
}

func (c *Client) SecretVersions(secretID string) (*SecretVersionList, error) {
	var out SecretVersionList
	err := c.do("GET", "/api/secrets/"+url.PathEscape(secretID)+"/versions", nil, &out)
	return &out, err
}

func (c *Client) RestoreSecretVersion(secretID string, version int) (*SecretUpdateResponse, error) {
	var out SecretUpdateResponse
	path := fmt.Sprintf("/api/secrets/%s/versions/%d/restore", url.PathEscape(secretID), version)
	err := c.do("POST", path, map[string]any{}, &out)
	return &out, err
}

func (c *Client) UpdateLocationPolicy(secretID string, req LocationPolicyRequest) (*LocationPolicyResponse, error) {
	var out LocationPolicyResponse
	err := c.do("PUT", "/api/secrets/"+url.PathEscape(secretID)+"/access-policy", req, &out)
	return &out, err
}

func (c *Client) Quota() (*QuotaResponse, error) {
	var out QuotaResponse
	err := c.do("GET", "/api/quota", nil, &out)
	return &out, err
}

func (c *Client) UpdateUserQuota(userID string, req QuotaUpdateRequest) (*QuotaResponse, error) {
	var out QuotaResponse
	err := c.do("PATCH", "/api/admin/users/"+url.PathEscape(userID)+"/quota", req, &out)
	return &out, err
}

func (c *Client) multipartUpload(method, path, filePath string, fields map[string][]string, out any) error {
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("cannot open file %q: %w", filePath, err)
	}
	pipeReader, pipeWriter := io.Pipe()
	writer := multipart.NewWriter(pipeWriter)
	go func() {
		defer file.Close()
		var writeErr error
		for name, values := range fields {
			for _, value := range values {
				if err := writer.WriteField(name, value); err != nil {
					writeErr = err
					break
				}
			}
			if writeErr != nil {
				break
			}
		}
		if writeErr == nil {
			var part io.Writer
			part, writeErr = writer.CreateFormFile("upload", filepath.Base(filePath))
			if writeErr == nil {
				_, writeErr = io.Copy(part, file)
			}
		}
		if closeErr := writer.Close(); writeErr == nil {
			writeErr = closeErr
		}
		pipeWriter.CloseWithError(writeErr)
	}()

	req, err := http.NewRequest(method, c.BaseURL+path, pipeReader)
	if err != nil {
		pipeReader.Close()
		return err
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())
	if c.AccessToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.AccessToken)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("connection failed – is the API reachable at %s? (%w)", c.BaseURL, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode >= 400 {
		return decodeAPIError(resp.StatusCode, body)
	}
	if out != nil && len(body) > 0 {
		if err := json.Unmarshal(body, out); err != nil {
			return fmt.Errorf("failed to parse response: %w", err)
		}
	}
	return nil
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
	return c.do("DELETE", "/api/secrets/"+url.PathEscape(secretID), nil, nil)
}

func (c *Client) RotateKey(secretID string) (*KeyRotateResponse, error) {
	var out KeyRotateResponse
	err := c.do("POST", "/api/secrets/"+url.PathEscape(secretID)+"/rotate-key", map[string]any{}, &out)
	return &out, err
}

// stats

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

// admin

func (c *Client) AuditLogs(page, pageSize int, action, severity, actorID, secretID string) (*AuditLogResponse, error) {
	q := fmt.Sprintf("?page=%d&page_size=%d", page, pageSize)
	if action != "" {
		q += "&action=" + url.QueryEscape(action)
	}
	if severity != "" {
		q += "&severity=" + url.QueryEscape(severity)
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

// CleanupResponse matches the new CleanupResponse schema.
type CleanupResponse struct {
	SecretsDeleted  int       `json:"secrets_deleted"`
	SessionsDeleted int       `json:"sessions_deleted"`
	UsersDeleted    int       `json:"users_deleted"`
	RanAt           time.Time `json:"ran_at"`
}

func (c *Client) AdminCleanup() (*CleanupResponse, error) {
	var out CleanupResponse
	err := c.do("DELETE", "/api/admin/cleanup", nil, &out)
	return &out, err
}

func (c *Client) ListUsers(page, pageSize int) (*UserListResponse, error) {
	var out UserListResponse
	err := c.do("GET", fmt.Sprintf("/api/admin/users?page=%d&page_size=%d", page, pageSize), nil, &out)
	return &out, err
}

func (c *Client) ChangeRole(userID, role string) (*AdminUserResponse, error) {
	var out AdminUserResponse
	err := c.do("PATCH", "/api/admin/users/"+url.PathEscape(userID)+"/role", map[string]string{"role": role}, &out)
	return &out, err
}

// UserStatusResponse mirrors the UserStatusResponse schema from the server.
type UserStatusResponse struct {
	UserID      string     `json:"user_id"`
	IsActive    bool       `json:"is_active"`
	DeleteAfter *time.Time `json:"delete_after"`
}

func (c *Client) ToggleActivation(userID string) (*UserStatusResponse, error) {
	var out UserStatusResponse
	err := c.do("PATCH", "/api/admin/users/"+url.PathEscape(userID)+"/switch", nil, &out)
	return &out, err
}

type SecretView struct {
	ID             int64     `json:"id"`
	ViewerID       *string   `json:"viewer_id"`
	ViewerEmail    *string   `json:"viewer_email"`
	EmailVerified  bool      `json:"email_verified"`
	ViewedAt       time.Time `json:"viewed_at"`
	ContentVersion *int      `json:"content_version"`
}

type SecretViewsResponse struct {
	Items       []SecretView `json:"items"`
	Total       int          `json:"total"`
	Page        int          `json:"page"`
	PageSize    int          `json:"page_size"`
	RetainUntil time.Time    `json:"retain_until"`
}

func (c *Client) SecretViews(secretID string, page, pageSize int) (*SecretViewsResponse, error) {
	var out SecretViewsResponse
	path := fmt.Sprintf(
		"/api/secrets/%s/views?page=%d&page_size=%d",
		url.PathEscape(secretID), page, pageSize,
	)
	err := c.do("GET", path, nil, &out)
	return &out, err
}

func (c *Client) RequestEmailVerification() error {
	return c.do("POST", "/api/auth/verification/request", nil, nil)
}

func (c *Client) ConfirmEmailVerification(code string) error {
	return c.do(
		"POST", "/api/auth/verification/confirm",
		map[string]string{"code": code}, nil,
	)
}
