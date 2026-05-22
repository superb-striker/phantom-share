package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/phantom-share/phantom/internal/api"
	"github.com/phantom-share/phantom/internal/config"
	"github.com/phantom-share/phantom/internal/output"
)

var auditCmd = &cobra.Command{
	Use:   "audit [share-url]",
	Short: "View audit log events for a secret (or all events for admins)",
	Long: `Fetches audit log entries from the API. When a share URL is given, results
are filtered to that specific secret. Admins can omit the URL to see all events.`,
	Example: `  phantom audit "https://api.example.com/api/secrets/abc123"
  phantom audit --action secret_viewed --page-size 100
  phantom audit --actor-id <user-uuid>`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := config.RequireAuth(); err != nil {
			return err
		}

		page, _ := cmd.Flags().GetInt("page")
		pageSize, _ := cmd.Flags().GetInt("page-size")
		action, _ := cmd.Flags().GetString("action")
		actorID, _ := cmd.Flags().GetString("actor-id")

		// Derive secretID from positional arg (share URL or bare UUID)
		secretID := ""
		if len(args) > 0 {
			secretID, _ = parseShareURL(args[0])
		}

		client := api.New(config.BaseURL(), config.AccessToken())
		resp, err := client.AuditLogs(page, pageSize, action, actorID, secretID)
		if err != nil {
			return err
		}

		title := fmt.Sprintf("Audit log  (page %d, total %d)", resp.Page, resp.Total)
		if secretID != "" {
			title = fmt.Sprintf("Audit log for %s…  (total %d)", secretID[:8], resp.Total)
		}
		output.Header(title)
		fmt.Println()

		if len(resp.Items) == 0 {
			output.Info("No audit events found.")
			return nil
		}

		t := output.NewTable(os.Stdout, []string{"#", "ACTION", "ACTOR", "IP", "SECRET", "TIMESTAMP"})
		for _, item := range resp.Items {
			actorStr := "—"
			if item.ActorID != nil {
				actorStr = (*item.ActorID)[:8] + "…"
			}
			ipStr := "—"
			if item.ActorIP != nil {
				ipStr = *item.ActorIP
			}
			secretStr := "—"
			if item.SecretID != nil {
				s := *item.SecretID
				if len(s) > 8 {
					secretStr = s[:8] + "…"
				} else {
					secretStr = s
				}
			}
			t.Append([]string{
				fmt.Sprintf("%d", item.ID),
				formatAction(item.Action),
				actorStr,
				ipStr,
				secretStr,
				output.FormatTime(item.CreatedAt),
			})
		}
		t.Render()

		// Pagination hint
		if resp.Total > resp.Page*resp.PageSize {
			nextPage := resp.Page + 1
			output.Info("More results available – run with --page %d", nextPage)
		}
		fmt.Println()
		return nil
	},
}

func init() {
	auditCmd.Flags().Int("page", 1, "Page number")
	auditCmd.Flags().Int("page-size", 50, "Results per page (max 200)")
	auditCmd.Flags().String("action", "", "Filter by action (e.g. secret_created, secret_viewed, user_login)")
	auditCmd.Flags().String("actor-id", "", "Filter by actor UUID")
}

// formatAction colour-codes the action string for readability.
func formatAction(action string) string {
	switch action {
	case "secret_created":
		return "\033[32m" + action + "\033[0m"  // green
	case "secret_viewed":
		return "\033[33m" + action + "\033[0m"  // yellow
	case "secret_deleted":
		return "\033[31m" + action + "\033[0m"  // red
	case "key_rotated":
		return "\033[35m" + action + "\033[0m"  // magenta
	case "user_login", "user_registered":
		return "\033[36m" + action + "\033[0m"  // cyan
	case "user_logout":
		return "\033[90m" + action + "\033[0m"  // gray
	default:
		return action
	}
}