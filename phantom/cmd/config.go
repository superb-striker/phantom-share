package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/phantom-share/phantom/internal/config"
	"github.com/phantom-share/phantom/internal/output"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage local CLI configuration (~/.phantom/config.yaml)",
}

var configShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Print current configuration",
	RunE: func(cmd *cobra.Command, args []string) error {
		output.Header("Configuration  (~/.phantom/config.yaml)")
		output.Field("API URL", config.BaseURL())
		if u := config.Username(); u != "" {
			output.Field("Logged in as", u+" ("+config.Email()+")")
		} else {
			output.Field("Auth", "not logged in")
		}
		// SMTP
		if h := viper.GetString("smtp.host"); h != "" {
			output.Field("SMTP host", h+":"+viper.GetString("smtp.port"))
			output.Field("SMTP user", viper.GetString("smtp.user"))
		} else {
			output.Field("SMTP", "not configured")
		}
		fmt.Println()
		return nil
	},
}

var configSetURLCmd = &cobra.Command{
	Use:   "set-url <url>",
	Short: "Set the API base URL",
	Example: `  phantom config set-url https://phantom.mycompany.com
  phantom config set-url http://localhost:8000`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		viper.Set(config.KeyBaseURL, args[0])
		if err := config.Save(); err != nil {
			return err
		}
		output.Success("API URL set to %s", args[0])
		return nil
	},
}

var configSetSMTPCmd = &cobra.Command{
	Use:   "set-smtp",
	Short: "Configure SMTP settings for phantom ping",
	Example: `  phantom config set-smtp --host smtp.gmail.com --port 587 --user me@gmail.com --password secret --from me@gmail.com`,
	RunE: func(cmd *cobra.Command, args []string) error {
		host, _ := cmd.Flags().GetString("host")
		port, _ := cmd.Flags().GetString("port")
		user, _ := cmd.Flags().GetString("user")
		pass, _ := cmd.Flags().GetString("password")
		from, _ := cmd.Flags().GetString("from")

		if host != "" {
			viper.Set("smtp.host", host)
		}
		if port != "" {
			viper.Set("smtp.port", port)
		}
		if user != "" {
			viper.Set("smtp.user", user)
		}
		if pass != "" {
			viper.Set("smtp.password", pass)
		}
		if from != "" {
			viper.Set("smtp.from", from)
		}

		if err := config.Save(); err != nil {
			return err
		}
		output.Success("SMTP settings saved.")
		output.Field("Host", viper.GetString("smtp.host")+":"+viper.GetString("smtp.port"))
		output.Field("User", viper.GetString("smtp.user"))
		output.Field("From", viper.GetString("smtp.from"))
		fmt.Println()
		return nil
	},
}

func init() {
	configSetSMTPCmd.Flags().String("host", "", "SMTP host (e.g. smtp.gmail.com)")
	configSetSMTPCmd.Flags().String("port", "587", "SMTP port")
	configSetSMTPCmd.Flags().String("user", "", "SMTP username")
	configSetSMTPCmd.Flags().String("password", "", "SMTP password")
	configSetSMTPCmd.Flags().String("from", "", "Default sender address")

	configCmd.AddCommand(configShowCmd, configSetURLCmd, configSetSMTPCmd)
}