package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/superb-striker/phantom-share/phantom/internal/api"
	"github.com/superb-striker/phantom-share/phantom/internal/config"
	"github.com/superb-striker/phantom-share/phantom/internal/output"
)

var quotaCmd = &cobra.Command{
	Use:   "quota",
	Short: "Show your secret and file-storage usage",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := config.RequireAuth(); err != nil {
			return err
		}
		client := newAPIClient()
		quota, err := client.Quota()
		if err != nil {
			return err
		}
		output.Header("Your quota")
		printQuota(quota)
		return nil
	},
}

var adminQuotaCmd = &cobra.Command{
	Use:   "quota <user-id>",
	Short: "Override a user's active-secret or file-storage limits",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := config.RequireAuth(); err != nil {
			return err
		}
		var req api.QuotaUpdateRequest
		if cmd.Flags().Changed("max-secrets") {
			value, _ := cmd.Flags().GetInt("max-secrets")
			if value < 1 {
				return fmt.Errorf("--max-secrets must be at least 1")
			}
			req.MaxActiveSecrets = &value
		}
		if cmd.Flags().Changed("max-file-bytes") {
			value, _ := cmd.Flags().GetInt64("max-file-bytes")
			if value < 1 {
				return fmt.Errorf("--max-file-bytes must be at least 1")
			}
			req.MaxFileBytes = &value
		}
		if req.MaxActiveSecrets == nil && req.MaxFileBytes == nil {
			return fmt.Errorf("set --max-secrets, --max-file-bytes, or both")
		}
		client := newAPIClient()
		quota, err := client.UpdateUserQuota(args[0], req)
		if err != nil {
			return err
		}
		output.Success("Quota updated for %s.", args[0])
		printQuota(quota)
		return nil
	},
}

func printQuota(quota *api.QuotaResponse) {
	output.Field("Active secrets", fmt.Sprintf("%d / %d", quota.ActiveSecrets, quota.MaxActiveSecrets))
	output.Field("File storage", fmt.Sprintf("%s / %s", formatBytes(quota.FileBytes), formatBytes(quota.MaxFileBytes)))
}

func init() {
	adminQuotaCmd.Flags().Int("max-secrets", 0, "Maximum active secrets")
	adminQuotaCmd.Flags().Int64("max-file-bytes", 0, "Maximum stored file bytes")
	adminCmd.AddCommand(adminQuotaCmd)
	rootCmd.AddCommand(quotaCmd)
}
