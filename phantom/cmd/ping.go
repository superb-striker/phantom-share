package cmd

import (
	"fmt"
	"net/smtp"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/superb-striker/phantom-share/phantom/internal/config"
	"github.com/superb-striker/phantom-share/phantom/internal/output"
)

var pingCmd = &cobra.Command{
	Use:   "ping <share-url>",
	Short: "Email a share link to a recipient",
	Long: `Send the share URL to someone over email.
Requires SMTP settings in ~/.phantom/config.yaml or via PHANTOM_SMTP_* env vars.`,
	Example: `  phantom ping "https://..." --to alice@example.com
  phantom ping "https://..." --to alice@example.com --from me@example.com --subject "Your credentials"
  phantom ping "https://..." --to alice@example.com --message "Here's the DB password we discussed"
  phantom ping "https://..." --to alice@example.com --password "hunter2"`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		shareURL := args[0]

		to, _ := cmd.Flags().GetString("to")
		from, _ := cmd.Flags().GetString("from")
		subject, _ := cmd.Flags().GetString("subject")
		message, _ := cmd.Flags().GetString("message")
		password, _ := cmd.Flags().GetString("password")

		if to == "" {
			return fmt.Errorf("--to is required")
		}

		// SMTP config: flags > viper (config.yaml / PHANTOM_SMTP_* env)
		smtpHost := stringOr(viper.GetString("smtp.host"), "localhost")
		smtpPort := stringOr(viper.GetString("smtp.port"), "587")
		smtpUser := viper.GetString("smtp.user")
		smtpPass := viper.GetString("smtp.password")

		if from == "" {
			from = viper.GetString("smtp.from")
			if from == "" {
				from = smtpUser
			}
		}
		if from == "" {
			return fmt.Errorf("sender address not set – use --from or set smtp.from in config")
		}

		sender := config.Username()
		if sender == "" {
			sender = from
		}

		viewURL := strings.Replace(shareURL, "/api/secrets/", "/api/secrets/view/", 1)

		body := buildPingEmail(from, to, subject, viewURL, message, sender, password)

		addr := smtpHost + ":" + smtpPort
		var auth smtp.Auth
		if smtpUser != "" && smtpPass != "" {
			auth = smtp.PlainAuth("", smtpUser, smtpPass, smtpHost)
		}

		if err := smtp.SendMail(addr, auth, from, []string{to}, []byte(body)); err != nil {
			return fmt.Errorf("failed to send email: %w", err)
		}

		output.Header("Ping sent")
		output.Field("To", to)
		output.Field("From", from)
		output.Field("Subject", subject)
		output.Field("Share URL", viewURL)
		fmt.Println()
		output.Success("Email delivered via %s", addr)
		if password != "" {
			fmt.Println()
			output.Field("🔒 Password", password)
			fmt.Println("  The recipient will be prompted on the page — send them this separately.")
		}
		fmt.Println()
		return nil
	},
}

func init() {
	pingCmd.Flags().StringP("to", "t", "", "Recipient email address (required)")
	pingCmd.Flags().String("from", "", "Sender address (falls back to smtp.from in config)")
	pingCmd.Flags().StringP("subject", "s", "Someone shared a secret with you", "Email subject line")
	pingCmd.Flags().StringP("message", "m", "", "Optional personal message to include in the email body")
	pingCmd.Flags().StringP("password", "p", "", "Access password for the secret (recipient will be prompted on the page)")
	pingCmd.MarkFlagRequired("to")
}

func buildPingEmail(from, to, subject, shareURL, message, sender, password string) string {
	var sb strings.Builder
	sb.WriteString("From: "); sb.WriteString(from); sb.WriteString("\r\n")
	sb.WriteString("To: "); sb.WriteString(to); sb.WriteString("\r\n")
	sb.WriteString("Subject: "); sb.WriteString(subject); sb.WriteString("\r\n")
	sb.WriteString("MIME-Version: 1.0\r\n")
	sb.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	sb.WriteString("\r\n")

	if message != "" {
		sb.WriteString(message); sb.WriteString("\r\n\r\n")
	}

	sb.WriteString("A secret has been shared with you via Phantom:\r\n\r\n")
	sb.WriteString("  "); sb.WriteString(shareURL); sb.WriteString("\r\n\r\n")
	sb.WriteString("⚠  This link is one-time use and will expire. Open it once to reveal the secret.\r\n")
	sb.WriteString("   Once viewed, the secret is permanently destroyed.\r\n\r\n")

	if password != "" {
		sb.WriteString("🔒 This secret is password-protected.\r\n")
		sb.WriteString("   You will be prompted to enter a password when you open the link.\r\n\r\n")
	}

	if sender != "" && sender != from {
		sb.WriteString("Sent by: "); sb.WriteString(sender); sb.WriteString("\r\n\r\n")
	}

	sb.WriteString("─────────────────────────────────────────\r\n")
	sb.WriteString("Powered by Phantom – secure secret sharing\r\n")
	return sb.String()
}

func stringOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}