package cmd

import (
	"fmt"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/phantom-share/phantom/internal/api"
	"github.com/phantom-share/phantom/internal/config"
	"github.com/phantom-share/phantom/internal/output"
)

// ── stats ─────────────────────────────────────────────────────────────────────

var statsCmd = &cobra.Command{
	Use:   "stats",
	Short: "Show service-wide secret statistics",
	RunE: func(cmd *cobra.Command, args []string) error {
		client := api.New(config.BaseURL(), config.AccessToken())
		s, err := client.Stats()
		if err != nil {
			return err
		}

		output.Header("Service statistics")
		output.Field("Active secrets", color.GreenString("%d", s.ActiveSecrets))
		output.Field("Total created", fmt.Sprintf("%d", s.TotalSecretsCreated))
		output.Field("Total viewed", fmt.Sprintf("%d", s.TotalSecretsViewed))
		if s.TotalSecretsCreated > 0 {
			pct := float64(s.TotalSecretsViewed) / float64(s.TotalSecretsCreated) * 100
			output.Field("View rate", fmt.Sprintf("%.1f%%", pct))
		}
		fmt.Println()
		return nil
	},
}

// ── health ────────────────────────────────────────────────────────────────────

var healthCmd = &cobra.Command{
	Use:   "health",
	Short: "Check API and database health",
	RunE: func(cmd *cobra.Command, args []string) error {
		client := api.New(config.BaseURL(), "")
		result, err := client.Health()
		if err != nil {
			output.Error("API unreachable: %v", err)
			return err
		}

		output.Header("Health check  →  " + config.BaseURL())
		for k, v := range result {
			if v == "ok" {
				output.Field(k, color.GreenString("✓ "+v))
			} else {
				output.Field(k, color.RedString("✗ "+v))
			}
		}
		fmt.Println()
		return nil
	},
}

// ── version ───────────────────────────────────────────────────────────────────

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print phantom CLI version",
	Run: func(cmd *cobra.Command, args []string) {
		output.Banner()
		output.Field("CLI version", "1.0.0")
		output.Field("API URL", config.BaseURL())
		if u := config.Username(); u != "" {
			output.Field("Logged in as", u)
		}
		fmt.Println()
	},
}