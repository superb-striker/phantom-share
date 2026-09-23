package cmd

import (
	"fmt"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/superb-striker/phantom-share/phantom/internal/api"
	"github.com/superb-striker/phantom-share/phantom/internal/config"
	"github.com/superb-striker/phantom-share/phantom/internal/output"
)

var policyCmd = &cobra.Command{
	Use:   "policy <share-url-or-id>",
	Short: "Replace a secret's CIDR and country access policy",
	Long:  "Replace the location policy and issue a new share URL. Existing signed URLs stop working.",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := config.RequireAuth(); err != nil {
			return err
		}
		cidrs, _ := cmd.Flags().GetStringArray("allow-cidr")
		countries, _ := cmd.Flags().GetStringArray("allow-country")
		mode, _ := cmd.Flags().GetString("location-mode")
		if mode != "all" && mode != "any" {
			return fmt.Errorf("--location-mode must be all or any")
		}
		failClosed, _ := cmd.Flags().GetBool("geoip-fail-closed")
		secretID, _ := parseShareURL(args[0])
		client := newAPIClient()
		resp, err := client.UpdateLocationPolicy(secretID, api.LocationPolicyRequest{
			AllowedCIDRs: cidrs, AllowedCountries: countries,
			LocationPolicyMode: mode, GeoIPFailClosed: failClosed,
		})
		if err != nil {
			return err
		}
		output.Header("Access policy updated")
		output.Field("Allowed CIDRs", displayList(resp.AllowedCIDRs))
		output.Field("Allowed countries", displayList(resp.AllowedCountries))
		output.Field("Location mode", resp.LocationPolicyMode)
		output.Field("GeoIP fail closed", output.BoolIcon(resp.GeoIPFailClosed))
		output.Field("Policy version", fmt.Sprintf("%d", resp.PolicyVersion))
		output.FieldHighlight("New share URL", resp.ShareURL)
		fmt.Println()
		color.New(color.FgHiWhite, color.Bold).Println(resp.ShareURL)
		return nil
	},
}

func displayList(values []string) string {
	if len(values) == 0 {
		return "none"
	}
	return strings.Join(values, ", ")
}

func init() {
	policyCmd.Flags().StringArray("allow-cidr", nil, "Allowed IPv4/IPv6 network (repeatable)")
	policyCmd.Flags().StringArray("allow-country", nil, "Allowed ISO country code (repeatable)")
	policyCmd.Flags().String("location-mode", "all", "Combine CIDR and country rules: all or any")
	policyCmd.Flags().Bool("geoip-fail-closed", true, "Deny access when country lookup is unavailable")
	rootCmd.AddCommand(policyCmd)
}
