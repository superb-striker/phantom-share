package cmd

import (
	"github.com/spf13/cobra"

	"github.com/superb-striker/phantom-share/phantom/internal/config"
	"github.com/superb-striker/phantom-share/phantom/internal/output"
)

var requestVerificationCmd = &cobra.Command{
	Use:   "request-verification",
	Short: "Send a verification code to your account email",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := config.RequireAuth(); err != nil {
			return err
		}
		client := newAPIClient()
		if err := client.RequestEmailVerification(); err != nil {
			return err
		}
		output.Success("Verification requested. Check your email, then run 'phantom auth verify-email'.")
		return nil
	},
}

var verifyEmailCmd = &cobra.Command{
	Use:   "verify-email",
	Short: "Verify your account using the code from your email",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := config.RequireAuth(); err != nil {
			return err
		}
		code := promptSecret("Verification code")
		client := newAPIClient()
		if err := client.ConfirmEmailVerification(code); err != nil {
			return err
		}
		output.Success("Email verified. You can now retrieve secrets shared with your email.")
		return nil
	},
}

func init() {
	authCmd.AddCommand(requestVerificationCmd, verifyEmailCmd)
}
