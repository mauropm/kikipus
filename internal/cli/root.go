package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	version = "0.1.0"
	rootCmd = &cobra.Command{
		Use:   "kikipus",
		Short: "Kikipus - Know what lives inside your cloud",
		Long: `K I K I P U S
"Know what lives inside your cloud."

Kikipus is a read-only GCP reconnaissance, inventory, security,
cost-analysis, and infrastructure-health tool.`,
		Version: version,
		RunE:    runRoot,
	}
)

// Execute runs the root command.
func Execute() error {
	return rootCmd.Execute()
}

func runRoot(cmd *cobra.Command, args []string) error {
	// Show Kikipus banner
	fmt.Print(`
K I K I P U S
"Know what lives inside your cloud."

● READ ONLY

Use 'kikipus scan' to scan your GCP environment.
Use 'kikipus --help' to see all available commands.
`)
	return nil
}

func init() {
	rootCmd.Flags().BoolP("json", "j", false, "Output in JSON format")
	rootCmd.Flags().BoolP("csv", "", false, "Output in CSV format")
	rootCmd.Flags().BoolP("markdown", "m", false, "Output in Markdown format")
	rootCmd.Flags().StringP("project", "p", "", "Specific GCP project to scan")
	rootCmd.Flags().StringP("organization", "o", "", "Organization ID to scan")
	rootCmd.Flags().StringP("folder", "f", "", "Folder ID to scan")
	rootCmd.Flags().StringP("config", "c", "", "Path to config file")
	rootCmd.Flags().BoolP("verbose", "v", false, "Verbose output")
	rootCmd.Flags().BoolP("quiet", "q", false, "Quiet mode")
	rootCmd.Flags().BoolP("no-cache", "", false, "Disable caching")
	rootCmd.Flags().BoolP("read-only", "", true, "Read-only mode (default)")
}