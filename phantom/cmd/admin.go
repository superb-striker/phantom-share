package cmd

import (
	"fmt"
	"os"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/phantom-share/phantom/internal/api"
	"github.com/phantom-share/phantom/internal/config"
	"github.com/phantom-share/phantom/internal/output"
)

var adminCmd = &cobra.Command{
	Use:   "admin",
	Short: "Admin-only operations (requires admin role)",
}

// ── admin users ───────────────────────────────────────────────────────────────

var adminUsersCmd = &cobra.Command{
	Use:   "users",
	Short: "List all registered users",
	Example: `  phantom admin users
  phantom admin users --page 2 --page-size 100`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := config.RequireAuth(); err != nil {
			return err
		}
		page, _ := cmd.Flags().GetInt("page")
		pageSize, _ := cmd.Flags().GetInt("page-size")

		client := api.New(config.BaseURL(), config.AccessToken())
		resp, err := client.ListUsers(page, pageSize)
		if err != nil {
			return err
		}

		output.Header(fmt.Sprintf("Users  (page %d, total %d)", resp.Page, resp.Total))
		fmt.Println()

		if len(resp.Items) == 0 {
			output.Info("No users found.")
			return nil
		}

		t := output.NewTable(os.Stdout, []string{"ID", "USERNAME", "EMAIL", "ROLE", "STATUS", "CREATED"})
		for _, u := range resp.Items {
			t.Append([]string{
				u.ID[:8] + "…",
				u.Username,
				u.Email,
				output.RoleColor(u.Role),
				output.ActiveColor(u.IsActive),
				output.FormatTime(u.CreatedAt),
			})
		}
		t.Render()
		fmt.Println()
		return nil
	},
}

// ── admin cleanup ─────────────────────────────────────────────────────────────

var adminCleanupCmd = &cobra.Command{
	Use:   "cleanup",
	Short: "Hard-purge all expired secrets from the database",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := config.RequireAuth(); err != nil {
			return err
		}
		client := api.New(config.BaseURL(), config.AccessToken())
		count, err := client.AdminCleanup()
		if err != nil {
			return err
		}
		output.Success("Purged %d expired secret(s).", count)
		return nil
	},
}

// ── admin role ────────────────────────────────────────────────────────────────

var adminRoleCmd = &cobra.Command{
	Use:   "role <user-id> <role>",
	Short: "Change a user's role  (admin | user | readonly)",
	Example: `  phantom admin role <uuid> admin
  phantom admin role <uuid> readonly`,
	Args: cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := config.RequireAuth(); err != nil {
			return err
		}
		userID, role := args[0], args[1]
		validRoles := map[string]bool{"admin": true, "user": true, "readonly": true}
		if !validRoles[role] {
			return fmt.Errorf("invalid role %q – must be admin, user, or readonly", role)
		}

		client := api.New(config.BaseURL(), config.AccessToken())
		if err := client.ChangeRole(userID, role); err != nil {
			return err
		}
		output.Success("User %s role changed to %s.", userID[:8]+"…", output.RoleColor(role))
		return nil
	},
}

// ── admin toggle ──────────────────────────────────────────────────────────────

var adminToggleCmd = &cobra.Command{
	Use:   "toggle <user-id>",
	Short: "Toggle a user's active/inactive status",
	Example: `  phantom admin toggle <uuid>`,
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := config.RequireAuth(); err != nil {
			return err
		}
		userID := args[0]
		client := api.New(config.BaseURL(), config.AccessToken())
		active, err := client.ToggleActivation(userID)
		if err != nil {
			return err
		}
		if active {
			output.Success("User %s is now %s.", userID[:8]+"…", color.GreenString("active"))
		} else {
			output.Warn("User %s is now %s.", userID[:8]+"…", color.RedString("inactive"))
		}
		return nil
	},
}

func init() {
	adminUsersCmd.Flags().Int("page", 1, "Page number")
	adminUsersCmd.Flags().Int("page-size", 50, "Results per page (max 200)")

	adminCmd.AddCommand(adminUsersCmd, adminCleanupCmd, adminRoleCmd, adminToggleCmd)
}