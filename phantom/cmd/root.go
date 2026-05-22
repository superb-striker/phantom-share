package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/phantom-share/phantom/internal/config"
	"github.com/phantom-share/phantom/internal/output"
)

var rootCmd = &cobra.Command{
	Use:   "phantom",
	Short: "Phantom – secure, burn-after-reading secret sharing",
	Long:  `Phantom is a CLI for creating and retrieving time-limited, encrypted secrets.`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		return config.Init()
	},
	SilenceUsage:  true,
	SilenceErrors: true,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		output.Error("%v", err)
		os.Exit(1)
	}
}

func init() {
	// --url flag overrides base_url for any command
	rootCmd.PersistentFlags().String("url", "", "Override API base URL (or set PHANTOM_BASE_URL)")

	cobra.OnInitialize(func() {
		if u, _ := rootCmd.Flags().GetString("url"); u != "" {
			fmt.Println(u) // viper picks it up via flag binding in Init
		}
	})

	rootCmd.AddCommand(
		authCmd,
		shareCmd,
		getCmd,
		infoCmd,
		listCmd,
		deleteCmd,
		pingCmd,
		auditCmd,
		statsCmd,
		healthCmd,
		rotateKeyCmd,
		adminCmd,
		configCmd,
		versionCmd,
	)
}