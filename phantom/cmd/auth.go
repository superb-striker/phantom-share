package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/superb-striker/phantom-share/phantom/internal/api"
	"github.com/superb-striker/phantom-share/phantom/internal/config"
	"github.com/superb-striker/phantom-share/phantom/internal/output"
)

var authCmd = &cobra.Command{
	Use:   "auth",
	Short: "Authenticate with the Phantom API",
}

var authLoginCmd = &cobra.Command{
	Use:   "login",
	Short: "Log in and save credentials to ~/.phantom/config.yaml",
	Example: `  phantom auth login
  PHANTOM_BASE_URL=https://myserver.com phantom auth login`,
	RunE: func(cmd *cobra.Command, args []string) error {
		
		if config.AccessToken() != "" {
			return fmt.Errorf("already logged in as %s – run 'phantom auth logout' first", config.Username())
		}

		output.Header("Log in to Phantom")

		email := prompt("Email")
		password := promptPassword("Password")
		if email == "" || password == "" {
			return fmt.Errorf("email and password are required")
		}

		client := api.New(config.BaseURL(), "")
		tokens, err := client.Login(email, password)
		if err != nil {
			return err
		}

		client.AccessToken = tokens.AccessToken
		user, err := client.Me()
		if err != nil {
			return err
		}

		if err := config.SetCredentials(tokens.AccessToken, tokens.RefreshToken, user.Username, user.Email); err != nil {
			return fmt.Errorf("failed to save credentials: %w", err)
		}

		fmt.Println()
		output.Success("Logged in as %s (%s)", user.Username, user.Email)
		output.Field("Role", output.RoleColor(user.Role))
		output.Field("Session expires in", fmt.Sprintf("%ds", tokens.ExpiresIn))
		fmt.Println()
		return nil
	},
}

var authRegisterCmd = &cobra.Command{
	Use:   "register",
	Short: "Create a new Phantom account",
	RunE: func(cmd *cobra.Command, args []string) error {

		if config.AccessToken() != "" {
			return fmt.Errorf("already logged in as %s – run 'phantom auth logout' first", config.Username())
		}

		output.Header("Create a Phantom account")

		email := prompt("Email")
		username := prompt("Username")
		password := promptPassword("Password")
		confirm := promptPassword("Confirm password")

		if password != confirm {
			return fmt.Errorf("passwords do not match")
		}

		client := api.New(config.BaseURL(), "")
		user, err := client.Register(email, username, password)
		if err != nil {
			return err
		}

		fmt.Println()
		output.Success("Account created! Welcome, %s", user.Username)
		output.Info("Run 'phantom auth login' to authenticate.")
		fmt.Println()
		return nil
	},
}

var authLogoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Revoke the current session and clear saved credentials",
	RunE: func(cmd *cobra.Command, args []string) error {
		if config.AccessToken() == "" {
			output.Warn("Already logged out.")
			return nil
		}

		client := api.New(config.BaseURL(), config.AccessToken())
		if rt := config.RefreshToken(); rt != "" {
			if err := client.Logout(rt); err != nil {
				output.Warn("Server-side logout failed (%v); clearing local credentials anyway.", err)
			}
		}

		username := config.Username()
		if err := config.ClearCredentials(); err != nil {
			return err
		}

		output.Success("Logged out %s. Credentials cleared.", username)
		return nil
	},
}

var authWhoamiCmd = &cobra.Command{
	Use:     "whoami",
	Short:   "Show the currently authenticated user",
	Aliases: []string{"me"},
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := config.RequireAuth(); err != nil {
			return err
		}

		client := api.New(config.BaseURL(), config.AccessToken())
		user, err := client.Me()
		if err != nil {
			return err
		}

		output.Header("Current user")
		output.Field("Username", user.Username)
		output.Field("Email", user.Email)
		output.Field("Role", output.RoleColor(user.Role))
		output.Field("Active", output.BoolIcon(user.IsActive))
		output.Field("Member since", output.FormatTime(user.CreatedAt))
		fmt.Println()
		return nil
	},
}

func init() {
	authCmd.AddCommand(authLoginCmd, authRegisterCmd, authLogoutCmd, authWhoamiCmd)
}


// TODO: Fix the Ctrl+C bug which breaks the prompt
func prompt(label string) string {
	fmt.Printf("  %s: ", label)
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	return strings.TrimSpace(scanner.Text())
}

func promptPassword(label string) string {
	fmt.Printf("  %s: ", label)
	pw, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		// fallback for non-tty environments
		scanner := bufio.NewScanner(os.Stdin)
		scanner.Scan()
		return strings.TrimSpace(scanner.Text())
	}
	return string(pw)
}