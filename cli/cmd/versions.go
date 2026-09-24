package cmd

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/superb-striker/phantom-share/phantom/internal/api"
	"github.com/superb-striker/phantom-share/phantom/internal/config"
	"github.com/superb-striker/phantom-share/phantom/internal/output"
)

var updateCmd = &cobra.Command{
	Use:   "update <share-url-or-id> [content]",
	Short: "Append a new text or file version",
	Args:  cobra.RangeArgs(1, 2),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := config.RequireAuth(); err != nil {
			return err
		}
		expectedVersion, _ := cmd.Flags().GetInt("expected-version")
		if expectedVersion < 1 {
			return fmt.Errorf("--expected-version must be at least 1")
		}
		note, _ := cmd.Flags().GetString("note")
		filePath, _ := cmd.Flags().GetString("file")
		contentFile, _ := cmd.Flags().GetString("content-file")
		if filePath != "" && (contentFile != "" || len(args) == 2) {
			return fmt.Errorf("--file cannot be combined with text content or --content-file")
		}
		if contentFile != "" && len(args) == 2 {
			return fmt.Errorf("provide text as an argument or --content-file, not both")
		}

		secretID, _ := parseShareURL(args[0])
		client := newAPIClient()
		if filePath != "" {
			resp, err := client.UpdateFileSecret(secretID, filePath, expectedVersion, note)
			if err != nil {
				return err
			}
			output.Success("File secret updated to version %d (%s).", resp.Version, formatBytes(resp.Size))
			return nil
		}

		var content string
		if contentFile != "" {
			data, err := os.ReadFile(contentFile)
			if err != nil {
				return fmt.Errorf("cannot read content file %q: %w", contentFile, err)
			}
			content = string(data)
		} else if len(args) == 2 {
			content = args[1]
		} else {
			return fmt.Errorf("provide new text content, --content-file, or --file")
		}
		resp, err := client.UpdateSecret(secretID, api.SecretUpdateRequest{
			Content: content, ExpectedVersion: expectedVersion, ChangeNote: note,
		})
		if err != nil {
			return err
		}
		output.Success("Text secret updated to version %d.", resp.Version)
		output.Field("Updated at", output.FormatTime(resp.UpdatedAt))
		return nil
	},
}

var versionsCmd = &cobra.Command{
	Use:   "versions <share-url-or-id>",
	Short: "List a secret's version history",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := config.RequireAuth(); err != nil {
			return err
		}
		secretID, _ := parseShareURL(args[0])
		client := newAPIClient()
		resp, err := client.SecretVersions(secretID)
		if err != nil {
			return err
		}
		output.Header(fmt.Sprintf("Secret versions (current: %d)", resp.CurrentVersion))
		table := output.NewTable(os.Stdout, []string{"VERSION", "CURRENT", "SIZE", "NOTE", "CREATED"})
		for _, version := range resp.Items {
			note := "—"
			if version.ChangeNote != nil && strings.TrimSpace(*version.ChangeNote) != "" {
				note = *version.ChangeNote
			}
			table.Append([]string{
				strconv.Itoa(version.Version), output.BoolIcon(version.IsCurrent),
				formatBytes(version.PlaintextSize), note, output.FormatTime(version.CreatedAt),
			})
		}
		table.Render()
		return nil
	},
}

var restoreCmd = &cobra.Command{
	Use:   "restore <share-url-or-id> <version>",
	Short: "Restore a text version as a new current version",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := config.RequireAuth(); err != nil {
			return err
		}
		version, err := strconv.Atoi(args[1])
		if err != nil || version < 1 {
			return fmt.Errorf("version must be a positive integer")
		}
		secretID, _ := parseShareURL(args[0])
		client := newAPIClient()
		resp, err := client.RestoreSecretVersion(secretID, version)
		if err != nil {
			return err
		}
		output.Success("Version %d restored as new version %d.", version, resp.Version)
		return nil
	},
}

func init() {
	updateCmd.Flags().Int("expected-version", 0, "Current version required for conflict-safe update")
	updateCmd.Flags().StringP("file", "f", "", "Upload this file as the next file version")
	updateCmd.Flags().String("content-file", "", "Read the next text version from this file")
	updateCmd.Flags().String("note", "", "Describe this version")
	rootCmd.AddCommand(updateCmd, versionsCmd, restoreCmd, rotateKeyCmd)
}
