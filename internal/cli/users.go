package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/mauropm/kikipus/internal/app"
	"github.com/mauropm/kikipus/internal/config"
	"github.com/mauropm/kikipus/internal/gcp"
)

func init() {
	usersCmd := &cobra.Command{
		Use:   "users",
		Short: "List users and service accounts",
		Long: `List all users and service accounts across projects.

Examples:
  kikipus users
  kikipus users --json`,
		RunE: runUsers,
	}

	usersCmd.Flags().BoolP("json", "j", false, "Output in JSON format")

	rootCmd.AddCommand(usersCmd)
}

func runUsers(cmd *cobra.Command, args []string) error {
	cfg := &config.Config{}

	a, err := app.New(cfg)
	if err != nil {
		return fmt.Errorf("creating application: %w", err)
	}
	defer a.Close()

	ctx := context.Background()

	// Get projects
	projects, err := a.GetProjects(ctx)
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "✕ Unable to discover projects: %v\n", err)
		return err
	}

	jsonOutput, _ := cmd.Flags().GetBool("json")

	if jsonOutput {
		return outputUsersJSON(projects)
	}

	// Print table header
	fmt.Println("USERS AND SERVICE ACCOUNTS")
	fmt.Println("=========================")
	fmt.Println()
	fmt.Printf("%-30s %-15s %-10s %s\n", "Principal", "Type", "Risk", "Projects")
	fmt.Println(string(make([]byte, 80)))

	// For each project, show IAM bindings
	for _, project := range projects {
		fmt.Printf("\nProject: %s\n", project.ID)
		fmt.Println("---")

		// Scan project to get IAM bindings
		result, err := a.Scan(ctx)
		if err != nil {
			fmt.Printf("  Warning: unable to scan project: %v\n", err)
			continue
		}

		for _, projResult := range result.Projects {
			if projResult.ProjectID != project.ID {
				continue
			}

			for _, binding := range projResult.IAMBindings {
				for _, member := range binding.Members {
					principalType := getPrincipalType(member)
					risk := binding.RiskLevel
					fmt.Printf("  %-28s %-15s %-10s\n", member, principalType, risk)
				}
			}
		}
	}

	return nil
}

func outputUsersJSON(projects []*gcp.ProjectInfo) error {
	output := struct {
		Projects []string `json:"projects"`
	}{
		Projects: make([]string, len(projects)),
	}

	for i, p := range projects {
		output.Projects[i] = p.ID
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(output)
}

func getPrincipalType(member string) string {
	switch {
	case member == "allUsers":
		return "AllUsers"
	case member == "allAuthenticatedUsers":
		return "AllAuthenticated"
	case member[:5] == "user:":
		return "User"
	case member[:13] == "serviceAccount:":
		return "ServiceAccount"
	case member[:6] == "group:":
		return "Group"
	case member[:7] == "domain:":
		return "Domain"
	default:
		return "Unknown"
	}
}