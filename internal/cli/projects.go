package cli

import (
	"github.com/spf13/cobra"
)

func init() {
	cmd := &cobra.Command{
		Use:   "projects",
		Short: "List discovered projects",
		RunE:  runProjects,
	}

	cmd.Flags().BoolP("json", "j", false, "Output in JSON format")

	rootCmd.AddCommand(cmd)
}

func runProjects(cmd *cobra.Command, args []string) error {
	// To be implemented
	return nil
}