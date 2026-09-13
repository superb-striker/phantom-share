package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/superb-striker/phantom-share/phantom/internal/api"
	"github.com/superb-striker/phantom-share/phantom/internal/config"
	"github.com/superb-striker/phantom-share/phantom/internal/output"
)

var viewsCmd = &cobra.Command{
	Use:   "views <share-url-or-id>",
	Short: "Show who retrieved your secret and when, including after it burns",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := config.RequireAuth(); err != nil {
			return err
		}
		secretID, _ := parseShareURL(args[0])
		page, _ := cmd.Flags().GetInt("page")
		pageSize, _ := cmd.Flags().GetInt("page-size")
		client := api.New(config.BaseURL(), config.AccessToken())
		resp, err := client.SecretViews(secretID, page, pageSize)
		if err != nil {
			return err
		}

		output.Header(fmt.Sprintf("Secret views (page %d, total %d)", resp.Page, resp.Total))
		output.Field("History retained until", resp.RetainUntil.UTC().Format(time.RFC3339))
		if len(resp.Items) == 0 {
			output.Info("No views on this page.")
			return nil
		}

		table := output.NewTable(os.Stdout, []string{"EMAIL", "VERIFIED", "VIEWED AT (UTC)"})
		for _, view := range resp.Items {
			email := "anonymous"
			if view.ViewerEmail != nil {
				email = *view.ViewerEmail
			}
			table.Append([]string{
				email,
				output.BoolIcon(view.EmailVerified),
				view.ViewedAt.UTC().Format(time.RFC3339Nano),
			})
		}
		table.Render()
		if resp.Total > resp.Page*resp.PageSize {
			output.Info("More results: use --page %d", resp.Page+1)
		}
		return nil
	},
}

func init() {
	viewsCmd.Flags().Int("page", 1, "Page number")
	viewsCmd.Flags().Int("page-size", 20, "Results per page (max 100)")
	rootCmd.AddCommand(viewsCmd)
}
