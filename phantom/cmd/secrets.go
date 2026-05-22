package cmd

import (
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/phantom-share/phantom/internal/api"
	"github.com/phantom-share/phantom/internal/config"
	"github.com/phantom-share/phantom/internal/output"
)

// ── share ─────────────────────────────────────────────────────────────────────

var shareCmd = &cobra.Command{
	Use:   "share [secret]",
	Short: "Create a new secret and print a shareable link",
	Long: `Encrypt a secret and store it server-side. Prints a one-time share URL.
Auth is optional – unauthenticated secrets are still encrypted.`,
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

		// -- resolve content
		var content string
		if filePath != "" {
			data, err := os.ReadFile(filePath)
			if err != nil {
				return fmt.Errorf("cannot read file %q: %w", filePath, err)
			}
			content = string(data)
			output.Info("Read %d bytes from %s", len(data), filePath)
		} else if len(args) > 0 {
			content = strings.Join(args, " ")
		} else {
			return fmt.Errorf("provide a secret string as an argument or use -f <file>")
		}

		ttlHours, err := parseTTL(expires)
		if err != nil {
			return fmt.Errorf("invalid --expires %q – use e.g. 30m, 1h, 12h, 7d", expires)
		}

		if burn {
			maxViews = 1
		}

		req := api.SecretCreateRequest{
			Content:           content,
			TTLHours:          ttlHours,
			MaxViews:          maxViews,
			PasswordProtected: password != "",
			AccessPassword:    password,
			NotifyOnView:      notify != "",
			NotifyEmail:       notify,
			WebhookURL:        webhook,
		}

		client := api.New(config.BaseURL(), config.AccessToken())
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

// ── get ───────────────────────────────────────────────────────────────────────

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

		secretID, token := parseShareURL(args[0])
		client := api.New(config.BaseURL(), config.AccessToken())
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

// ── info ──────────────────────────────────────────────────────────────────────

var infoCmd = &cobra.Command{
	Use:     "info <share-url>",
	Short:   "Show secret metadata without burning it",
	Example: `  phantom info "https://api.example.com/api/secrets/abc123"`,
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		secretID, _ := parseShareURL(args[0])
		client := api.New(config.BaseURL(), config.AccessToken())
		info, err := client.SecretInfo(secretID)
		if err != nil {
			return err
		}

		output.Header("Secret info")
		output.Field("ID", secretID)
		output.Field("Status", output.StatusIcon(info.Viewed))
		output.Field("Password protected", output.BoolIcon(info.PasswordProtected))
		output.Field("Views", fmt.Sprintf("%d / %d", info.ViewCount, info.MaxViews))
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

// ── list ──────────────────────────────────────────────────────────────────────

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

		client := api.New(config.BaseURL(), config.AccessToken())
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
				s.ID[:8] + "…",
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

// ── delete ────────────────────────────────────────────────────────────────────

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
		client := api.New(config.BaseURL(), config.AccessToken())
		if err := client.DeleteSecret(secretID); err != nil {
			return err
		}
		output.Success("Secret %s deleted.", secretID)
		return nil
	},
}

// ── rotate-key ────────────────────────────────────────────────────────────────

var rotateKeyCmd = &cobra.Command{
	Use:   "rotate-key <share-url>",
	Short: "Rotate the server-side encryption key for a secret",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := config.RequireAuth(); err != nil {
			return err
		}
		secretID, _ := parseShareURL(args[0])
		client := api.New(config.BaseURL(), config.AccessToken())
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
	// share flags
	shareCmd.Flags().StringP("file", "f", "", "Read secret content from this file")
	shareCmd.Flags().StringP("expires", "e", "24h", "TTL: e.g. 30m, 1h, 12h, 7d (max 168h)")
	shareCmd.Flags().BoolP("burn-after-read", "b", false, "Destroy after first view (sets max-views=1)")
	shareCmd.Flags().IntP("max-views", "m", 1, "Maximum number of times the secret can be viewed")
	shareCmd.Flags().StringP("password", "p", "", "Require this password to retrieve the secret")
	shareCmd.Flags().StringP("notify", "n", "", "Email address to notify when the secret is viewed")
	shareCmd.Flags().StringP("webhook", "w", "", "Webhook URL to POST to on view")

	// get flags
	getCmd.Flags().StringP("password", "p", "", "Password if the secret is protected")
	getCmd.Flags().Bool("raw", false, "Print only the secret content (no formatting)")

	// list flags
	listCmd.Flags().Int("page", 1, "Page number")
	listCmd.Flags().Int("page-size", 20, "Results per page (max 100)")
	listCmd.Flags().Bool("viewed", false, "Filter: only viewed secrets")
	listCmd.Flags().Bool("expired", false, "Filter: only expired secrets")
}

// ── helpers ───────────────────────────────────────────────────────────────────

// parseShareURL extracts (secretID, token) from a full share URL or bare UUID.
func parseShareURL(raw string) (secretID, token string) {
	if idx := strings.Index(raw, "/api/secrets/"); idx != -1 {
		rest := raw[idx+len("/api/secrets/"):]
		if q := strings.Index(rest, "?"); q != -1 {
			secretID = rest[:q]
			// parse query string
			qs, _ := url.ParseQuery(rest[q+1:])
			token = qs.Get("token")
		} else {
			secretID = rest
		}
		return
	}
	// bare UUID
	return raw, ""
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