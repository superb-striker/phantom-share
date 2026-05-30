package cmd

import (
	"fmt"
	"os"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/superb-striker/phantom-share/phantom/internal/api"
	"github.com/superb-striker/phantom-share/phantom/internal/config"
	"github.com/superb-striker/phantom-share/phantom/internal/output"
)

var adminCmd = &cobra.Command{
	Use:   "admin",
	Short: "Admin-only operations (requires admin role)",
}


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

		t := output.NewTable(os.Stdout, []string{"ID", "USERNAME", "EMAIL", "ROLE", "STATUS", "DELETE AFTER", "CREATED"})
		for _, u := range resp.Items {
			deleteAfter := "—"
			if u.DeleteAfter != nil {
				deleteAfter = output.FormatTime(*u.DeleteAfter)
			}
			t.Append([]string{
				u.ID[:8] + "…",
				u.Username,
				u.Email,
				output.RoleColor(u.Role),
				output.ActiveColor(u.IsActive),
				deleteAfter,
				output.FormatTime(u.CreatedAt),
			})
		}
		t.Render()
		fmt.Println()
		return nil
	},
}

var adminCleanupCmd = &cobra.Command{
	Use:   "cleanup",
	Short: "Hard-purge all expired secrets from the database",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := config.RequireAuth(); err != nil {
			return err
		}
		client := api.New(config.BaseURL(), config.AccessToken())
		result, err := client.AdminCleanup()
		if err != nil {
			return err
		}
		output.Success("Cleanup complete.")
		output.Field("Secrets deleted", fmt.Sprintf("%d", result.SecretsDeleted))
		output.Field("Sessions deleted", fmt.Sprintf("%d", result.SessionsDeleted))
		output.Field("Users deleted", fmt.Sprintf("%d", result.UsersDeleted))
		output.Field("Ran at", output.FormatTime(result.RanAt))
		fmt.Println()
		return nil
	},
}

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
		updated, err := client.ChangeRole(userID, role)
		if err != nil {
			return err
		}
		output.Success("Role updated.")
		output.Field("User", updated.Username+" ("+updated.Email+")")
		output.Field("New role", output.RoleColor(updated.Role))
		fmt.Println()
		return nil
	},
}

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
		result, err := client.ToggleActivation(userID)
		if err != nil {
			return err
		}
		if result.IsActive {
			output.Success("User %s is now %s.", userID[:8]+"…", color.GreenString("active"))
		} else {
			output.Warn("User %s is now %s.", userID[:8]+"…", color.RedString("inactive"))
			if result.DeleteAfter != nil {
				output.Field("Scheduled deletion", output.FormatTime(*result.DeleteAfter))
			}
		}
		return nil
	},
}

func init() {
	adminUsersCmd.Flags().Int("page", 1, "Page number")
	adminUsersCmd.Flags().Int("page-size", 50, "Results per page (max 200)")

	adminCmd.AddCommand(adminUsersCmd, adminCleanupCmd, adminRoleCmd, adminToggleCmd)
}