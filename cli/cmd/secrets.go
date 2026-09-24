package cmd

import (
	"fmt"
	"io"
	"mime"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/superb-striker/phantom-share/phantom/internal/api"
	"github.com/superb-striker/phantom-share/phantom/internal/config"
	"github.com/superb-striker/phantom-share/phantom/internal/output"
)

var shareCmd = &cobra.Command{
	Use:   "share [secret]",
	Short: "Create a new secret and print a shareable link",
	Long: `Encrypt a text secret or virus-scan and encrypt a file, then print a share URL.
Authentication is required. Restricted secrets require recipients to log in and verify their email.`,
	Example: `  phantom share "postgres://user:pass@host/db"
  phantom share "my secret" --expires 12h --max-views 3
  phantom share -f ./secret.env --expires 1h --burn-after-read
  phantom share "classified" --password hunter2 --notify ops@company.com`,
	RunE: func(cmd *cobra.Command, args []string) error {
		filePath, _ := cmd.Flags().GetString("file")
		expires, _ := cmd.Flags().GetString("expires")
		burn, _ := cmd.Flags().GetBool("burn-after-read")
		maxViews, _ := cmd.Flags().GetInt("max-views")
		password, _ := cmd.Flags().GetString("password")
		notify, _ := cmd.Flags().GetString("notify")
		webhook, _ := cmd.Flags().GetString("webhook")
		allowedEmails, _ := cmd.Flags().GetStringArray("allow-email")
		allowedCIDRs, _ := cmd.Flags().GetStringArray("allow-cidr")
		allowedCountries, _ := cmd.Flags().GetStringArray("allow-country")
		locationMode, _ := cmd.Flags().GetString("location-mode")
		geoIPFailClosed, _ := cmd.Flags().GetBool("geoip-fail-closed")
		changeNote, _ := cmd.Flags().GetString("note")
		clientEncrypted, _ := cmd.Flags().GetBool("client-encrypted")
		clientNonce, _ := cmd.Flags().GetString("client-nonce")
		if err := config.RequireAuth(); err != nil {
			return err
		}
		if locationMode != "all" && locationMode != "any" {
			return fmt.Errorf("--location-mode must be all or any")
		}

		if filePath != "" && len(args) > 0 {
			return fmt.Errorf("provide either a secret argument or --file, not both")
		}
		if filePath != "" && (clientEncrypted || clientNonce != "") {
			return fmt.Errorf("--client-encrypted and --client-nonce apply only to text secrets")
		}
		if clientEncrypted && clientNonce == "" {
			return fmt.Errorf("--client-nonce is required with --client-encrypted")
		}
		if !clientEncrypted && clientNonce != "" {
			return fmt.Errorf("--client-encrypted is required with --client-nonce")
		}

		var content string
		if filePath == "" && len(args) > 0 {
			content = strings.Join(args, " ")
		} else if filePath == "" {
			return fmt.Errorf("provide a secret string as an argument or use -f <file>")
		}

		ttlHours, err := parseTTL(expires)
		if err != nil {
			return fmt.Errorf("invalid --expires %q – use e.g. 30m, 1h, 12h, 7d", expires)
		}

		if burn {
			maxViews = 1
		}
		client := newAPIClient()
		if filePath != "" {
			if notify != "" || webhook != "" {
				return fmt.Errorf("file secrets do not support --notify or --webhook")
			}
			resp, err := client.CreateFileSecret(api.FileCreateRequest{
				FilePath: filePath, TTLHours: ttlHours, MaxViews: maxViews,
				AccessPassword: password, AllowedEmails: allowedEmails,
				ChangeNote: changeNote, AllowedCIDRs: allowedCIDRs,
				AllowedCountries: allowedCountries, LocationPolicyMode: locationMode,
				GeoIPFailClosed: geoIPFailClosed,
			})
			if err != nil {
				return err
			}
			output.Header("File secret created")
			output.Field("ID", resp.SecretID)
			output.FieldHighlight("Share URL", resp.ShareURL)
			output.Field("Version", strconv.Itoa(resp.Version))
			output.Field("File size", formatBytes(resp.Size))
			fmt.Println()
			color.New(color.FgHiWhite, color.Bold).Println(resp.ShareURL)
			fmt.Println()
			return nil
		}

		req := api.SecretCreateRequest{
			AllowedEmails:      allowedEmails,
			AllowedCIDRs:       allowedCIDRs,
			AllowedCountries:   allowedCountries,
			LocationPolicyMode: locationMode,
			GeoIPFailClosed:    geoIPFailClosed,
			Content:            content,
			TTLHours:           ttlHours,
			MaxViews:           maxViews,
			PasswordProtected:  password != "",
			AccessPassword:     password,
			NotifyOnView:       notify != "",
			NotifyEmail:        notify,
			WebhookURL:         webhook,
			ClientEncrypted:    clientEncrypted,
			ClientNonce:        clientNonce,
		}

		resp, err := client.CreateSecret(req)
		if err != nil {
			return err
		}

		output.Header("Secret created")
		output.Field("ID", resp.SecretID)
		output.FieldHighlight("Share URL", resp.ShareURL)
		output.Field("Expires at", output.FormatTime(resp.ExpiresAt))
		output.Field("Expires in", output.FormatDuration(resp.ExpiresAt))
		output.Field("Max views", strconv.Itoa(maxViews))
		if len(allowedEmails) > 0 {
			output.Field("Allowed emails", strings.Join(allowedEmails, ", "))
			output.Info("Recipients must log in and verify their email. Max views is shared across all recipients.")
		}
		if len(allowedCIDRs) > 0 {
			output.Field("Allowed CIDRs", strings.Join(allowedCIDRs, ", "))
		}
		if len(allowedCountries) > 0 {
			output.Field("Allowed countries", strings.Join(allowedCountries, ", "))
			output.Field("Location mode", locationMode)
		}
		if password != "" {
			output.Field("Password protected", output.BoolIcon(true))
		}
		if notify != "" {
			output.Field("Notify on view", notify)
		}
		if webhook != "" {
			output.Field("Webhook", webhook)
		}

		// Print URL alone on its own line so it's easy to pipe / copy
		fmt.Println()
		color.New(color.FgHiWhite, color.Bold).Println(resp.ShareURL)
		fmt.Println()
		return nil
	},
}

var getCmd = &cobra.Command{
	Use:   "get <share-url>",
	Short: "Retrieve and burn a secret",
	Long:  `Fetches the secret content and increments the view counter. The secret is burned when max-views is reached.`,
	Example: `  phantom get "https://api.example.com/api/secrets/abc123?token=xyz"
  phantom get <share-url> --password hunter2
  phantom get <share-url> --raw | pbcopy`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		password, _ := cmd.Flags().GetString("password")
		raw, _ := cmd.Flags().GetBool("raw")
		destination, _ := cmd.Flags().GetString("output")

		secretID, token, fileHint := parseShareRef(args[0])
		client := newAPIClient()
		if !fileHint {
			info, err := client.SecretInfo(secretID)
			if err == nil {
				fileHint = info.PayloadType == "file"
			}
		}
		if fileHint {
			return retrieveFile(client, secretID, password, token, destination, raw)
		}
		if destination != "" {
			return fmt.Errorf("--output is only valid for file secrets")
		}
		content, err := client.GetSecret(secretID, password, token)
		if err != nil {
			return err
		}

		if raw {
			fmt.Print(content.Content)
			return nil
		}

		output.Header("Secret retrieved")
		output.SecretBox(content.Content)
		output.Field("Created at", output.FormatTime(content.CreatedAt))
		output.Field("Expires at", output.FormatTime(content.ExpiresAt))
		output.Field("Version", strconv.Itoa(content.Version))
		if content.ViewsRemaining != nil {
			rem := *content.ViewsRemaining
			if rem == 0 {
				output.Field("Views remaining", color.RedString("0 — secret burned 🔥"))
			} else {
				output.Field("Views remaining", strconv.Itoa(rem))
			}
		}
		if content.ClientEncrypted {
			output.Warn("Content is client-encrypted; decrypt locally with your key.")
		}
		fmt.Println()
		return nil
	},
}

var infoCmd = &cobra.Command{
	Use:     "info <share-url>",
	Short:   "Show secret metadata without burning it",
	Example: `  phantom info "https://api.example.com/api/secrets/abc123"`,
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		secretID, _ := parseShareURL(args[0])
		client := newAPIClient()
		info, err := client.SecretInfo(secretID)
		if err != nil {
			return err
		}

		output.Header("Secret info")
		output.Field("ID", secretID)
		output.Field("Status", output.StatusIcon(info.Viewed))
		output.Field("Password protected", output.BoolIcon(info.PasswordProtected))
		output.Field("Views", fmt.Sprintf("%d / %d", info.ViewCount, info.MaxViews))
		output.Field("Payload", info.PayloadType)
		output.Field("Current version", strconv.Itoa(info.CurrentVersion))
		output.Field("Location restricted", output.BoolIcon(info.LocationRestricted))
		output.Field("Policy version", strconv.Itoa(info.PolicyVersion))
		if info.CreatedAt != nil {
			output.Field("Created at", output.FormatTime(*info.CreatedAt))
		}
		if info.ExpiresAt != nil {
			output.Field("Expires at", output.FormatTime(*info.ExpiresAt))
			output.Field("Expires in", output.FormatDuration(*info.ExpiresAt))
		}
		fmt.Println()
		return nil
	},
}

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List your secrets (requires auth)",
	Example: `  phantom list
  phantom list --page 2 --page-size 20
  phantom list --viewed=false
  phantom list --expired`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := config.RequireAuth(); err != nil {
			return err
		}

		page, _ := cmd.Flags().GetInt("page")
		pageSize, _ := cmd.Flags().GetInt("page-size")
		viewedFlag := cmd.Flags().Lookup("viewed")
		expiredFlag := cmd.Flags().Lookup("expired")

		var viewed, expired *bool
		if viewedFlag.Changed {
			v, _ := cmd.Flags().GetBool("viewed")
			viewed = &v
		}
		if expiredFlag.Changed {
			e, _ := cmd.Flags().GetBool("expired")
			expired = &e
		}

		client := newAPIClient()
		resp, err := client.ListSecrets(page, pageSize, viewed, expired)
		if err != nil {
			return err
		}

		output.Header(fmt.Sprintf("Your secrets  (page %d/%d, total %d)",
			resp.Page, (resp.Total+resp.PageSize-1)/resp.PageSize, resp.Total))
		fmt.Println()

		if len(resp.Items) == 0 {
			output.Info("No secrets found.")
			return nil
		}

		t := output.NewTable(os.Stdout, []string{"ID", "STATUS", "VIEWS", "EXPIRES IN", "PWD", "NOTIFY", "CREATED"})
		for _, s := range resp.Items {
			t.Append([]string{
				shortID(s.ID),
				output.StatusIcon(s.Viewed),
				fmt.Sprintf("%d/%d", s.ViewCount, s.MaxViews),
				output.FormatDuration(s.ExpiresAt),
				output.BoolIcon(s.PasswordProtected),
				output.BoolIcon(s.NotifyOnView),
				output.FormatTime(s.CreatedAt),
			})
		}
		t.Render()
		fmt.Println()
		return nil
	},
}

var deleteCmd = &cobra.Command{
	Use:     "delete <share-url>",
	Short:   "Delete a secret before it expires",
	Aliases: []string{"rm"},
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := config.RequireAuth(); err != nil {
			return err
		}
		secretID, _ := parseShareURL(args[0])
		client := newAPIClient()
		if err := client.DeleteSecret(secretID); err != nil {
			return err
		}
		output.Success("Secret %s deleted.", secretID)
		return nil
	},
}

var rotateKeyCmd = &cobra.Command{
	Use:   "rotate-key <share-url-or-id>",
	Short: "Re-encrypt a secret with a new data-encryption key",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := config.RequireAuth(); err != nil {
			return err
		}
		secretID, _ := parseShareURL(args[0])
		client := newAPIClient()
		resp, err := client.RotateKey(secretID)
		if err != nil {
			return err
		}
		output.Header("Encryption key rotated")
		output.Field("Secret ID", resp.SecretID)
		output.Field("New key version", strconv.Itoa(resp.NewKeyVersion))
		output.Field("Rotated at", output.FormatTime(resp.RotatedAt))
		fmt.Println()
		return nil
	},
}

func init() {
	shareCmd.Flags().StringArray("allow-email", nil, "Allowed recipient email (repeat for each recipient; requires login)")
	shareCmd.Flags().StringArray("allow-cidr", nil, "Allowed IPv4/IPv6 network (repeatable)")
	shareCmd.Flags().StringArray("allow-country", nil, "Allowed ISO country code (repeatable)")
	shareCmd.Flags().String("location-mode", "all", "Combine CIDR and country rules: all or any")
	shareCmd.Flags().Bool("geoip-fail-closed", true, "Deny access when country lookup is unavailable")
	// share flags
	shareCmd.Flags().StringP("file", "f", "", "Read secret content from this file")
	shareCmd.Flags().StringP("expires", "e", "24h", "TTL: e.g. 30m, 1h, 12h, 7d (max 168h)")
	shareCmd.Flags().BoolP("burn-after-read", "b", false, "Destroy after first view (sets max-views=1)")
	shareCmd.Flags().IntP("max-views", "m", 1, "Maximum number of times the secret can be viewed")
	shareCmd.Flags().StringP("password", "p", "", "Require this password to retrieve the secret")
	shareCmd.Flags().StringP("notify", "n", "", "Email address to notify when the secret is viewed")
	shareCmd.Flags().StringP("webhook", "w", "", "Webhook URL to POST to on view")
	shareCmd.Flags().String("note", "", "Version note (file secrets)")
	shareCmd.Flags().Bool("client-encrypted", false, "Content is already client-encrypted base64 ciphertext")
	shareCmd.Flags().String("client-nonce", "", "Base64 nonce for client-encrypted content")

	// get flags
	getCmd.Flags().StringP("password", "p", "", "Password if the secret is protected")
	getCmd.Flags().Bool("raw", false, "Print only the secret content (no formatting)")
	getCmd.Flags().StringP("output", "o", "", "Write a file secret to this path (defaults to its original filename)")

	// list flags
	listCmd.Flags().Int("page", 1, "Page number")
	listCmd.Flags().Int("page-size", 20, "Results per page (max 100)")
	listCmd.Flags().Bool("viewed", false, "Filter: only viewed secrets")
	listCmd.Flags().Bool("expired", false, "Filter: only expired secrets")
}

// parseShareURL extracts (secretID, token) from a full share URL or bare UUID.
func parseShareURL(raw string) (secretID, token string) {
	secretID, token, _ = parseShareRef(raw)
	return secretID, token
}

func parseShareRef(raw string) (secretID, token string, isFile bool) {
	parsed, err := url.Parse(raw)
	if err == nil {
		token = parsed.Query().Get("token")
		path := parsed.Path
		if idx := strings.Index(path, "/api/secrets/"); idx != -1 {
			rest := strings.Trim(path[idx+len("/api/secrets/"):], "/")
			parts := strings.Split(rest, "/")
			if len(parts) > 0 {
				if parts[0] == "view" && len(parts) > 1 {
					secretID = parts[1]
					return
				}
				secretID = parts[0]
				isFile = len(parts) > 1 && parts[1] == "file"
				return
			}
		}
	}
	return strings.TrimSpace(raw), "", false
}

func retrieveFile(client *api.Client, secretID, password, token, destination string, raw bool) error {
	resp, err := client.DownloadFile(secretID, password, token)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if raw || destination == "-" {
		_, err = io.Copy(os.Stdout, resp.Body)
		return err
	}

	filename := "download-" + secretID
	if _, params, parseErr := mime.ParseMediaType(resp.Header.Get("Content-Disposition")); parseErr == nil {
		if candidate := filepath.Base(params["filename"]); candidate != "." && candidate != "" {
			filename = candidate
		}
	}
	explicit := destination != ""
	if !explicit {
		destination = filename
	} else if stat, statErr := os.Stat(destination); statErr == nil && stat.IsDir() {
		destination = filepath.Join(destination, filename)
	}
	flags := os.O_CREATE | os.O_WRONLY | os.O_TRUNC
	if !explicit {
		flags = os.O_CREATE | os.O_WRONLY | os.O_EXCL
	}
	file, err := os.OpenFile(destination, flags, 0600)
	if err != nil {
		return fmt.Errorf("cannot create output file %q: %w", destination, err)
	}
	written, copyErr := io.Copy(file, resp.Body)
	closeErr := file.Close()
	if copyErr != nil {
		return fmt.Errorf("download failed: %w", copyErr)
	}
	if closeErr != nil {
		return closeErr
	}
	output.Success("Downloaded %s (%s).", destination, formatBytes(written))
	return nil
}

func formatBytes(size int64) string {
	const unit = int64(1024)
	if size < unit {
		return fmt.Sprintf("%d B", size)
	}
	value := float64(size)
	units := []string{"KiB", "MiB", "GiB", "TiB"}
	for _, suffix := range units {
		value /= 1024
		if value < 1024 || suffix == units[len(units)-1] {
			return fmt.Sprintf("%.1f %s", value, suffix)
		}
	}
	return fmt.Sprintf("%d B", size)
}

// parseTTL converts "30m" → 1, "2h" → 2, "3d" → 72, bare int → hours.
func parseTTL(s string) (int, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	switch {
	case strings.HasSuffix(s, "d"):
		n, err := strconv.Atoi(s[:len(s)-1])
		return n * 24, err
	case strings.HasSuffix(s, "h"):
		return strconv.Atoi(s[:len(s)-1])
	case strings.HasSuffix(s, "m"):
		n, err := strconv.Atoi(s[:len(s)-1])
		if err != nil {
			return 0, err
		}
		d := time.Duration(n) * time.Minute
		hours := int(d.Hours())
		if hours < 1 {
			return 1, nil
		}
		return hours, nil
	default:
		return strconv.Atoi(s)
	}
}
