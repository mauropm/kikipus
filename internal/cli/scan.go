package cli

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/mauropm/kikipus/internal/app"
	"github.com/mauropm/kikipus/internal/config"
	"github.com/mauropm/kikipus/internal/analysis"
)

func init() {
	scanCmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan GCP environment",
		Long: `Scan the GCP environment and collect resource information.

Examples:
  kikipus scan
  kikipus scan --project my-project
  kikipus scan --organization 123456789`,
		RunE: runScan,
	}

	scanCmd.Flags().StringP("project", "p", "", "Specific project to scan")
	scanCmd.Flags().StringP("organization", "o", "", "Organization ID")
	scanCmd.Flags().StringP("folder", "f", "", "Folder ID")
	scanCmd.Flags().BoolP("json", "j", false, "Output in JSON format")

	rootCmd.AddCommand(scanCmd)
}

func runScan(cmd *cobra.Command, args []string) error {
	cfg := &config.Config{}
	
	project, _ := cmd.Flags().GetString("project")
	if project != "" {
		cfg.Project = project
	}

	organization, _ := cmd.Flags().GetString("organization")
	if organization != "" {
		cfg.Organization = organization
	}

	folder, _ := cmd.Flags().GetString("folder")
	if folder != "" {
		cfg.Folder = folder
	}

	a, err := app.New(cfg)
	if err != nil {
		return fmt.Errorf("creating application: %w", err)
	}
	defer a.Close()

	ctx := context.Background()

	// Check authentication
	projects, err := a.GetProjects(ctx)
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "✕ GCP authentication unavailable\n\n")
		fmt.Fprintf(cmd.ErrOrStderr(), "Run:\n    gcloud auth login\n\n")
		return err
	}

	fmt.Fprintf(cmd.ErrOrStderr(), "● READ ONLY\n\n")
	fmt.Fprintf(cmd.ErrOrStderr(), "Discovered %d project(s).\n\n", len(projects))

	// Run scan
	result, err := a.Scan(ctx)
	if err != nil {
		return fmt.Errorf("scanning: %w", err)
	}

	// Print summary
	printScanSummary(result)

	return nil
}

func printScanSummary(result *analysis.ScanResult) {
	fmt.Println("SCAN SUMMARY")
	fmt.Println("============")
	fmt.Printf("Projects scanned: %d\n", result.ProjectCount)
	fmt.Printf("Findings: %d\n", len(result.Findings))
	fmt.Printf("Skipped resources: %d\n", len(result.SkippedResources))
	fmt.Println()

	// Print findings by severity
	critical := 0
	high := 0
	medium := 0
	low := 0
	info := 0

	for _, f := range result.Findings {
		switch f.Severity {
		case "CRITICAL":
			critical++
		case "HIGH":
			high++
		case "MEDIUM":
			medium++
		case "LOW":
			low++
		default:
			info++
		}
	}

	fmt.Println("FINDINGS BY SEVERITY")
	fmt.Println("===================")
	fmt.Printf("🔴 Critical: %d\n", critical)
	fmt.Printf("🟠 High:     %d\n", high)
	fmt.Printf("🟡 Medium:   %d\n", medium)
	fmt.Printf("🔵 Low:      %d\n", low)
	fmt.Printf("ℹ️  Info:      %d\n", info)
	fmt.Println()

	// Print top findings
	if len(result.Findings) > 0 {
		fmt.Println("TOP FINDINGS")
		fmt.Println("============")
		for i, f := range result.Findings {
			if i >= 10 {
				break
			}
			fmt.Printf("%d. [%s] %s\n", i+1, f.Severity, f.Title)
			fmt.Printf("   Project: %s\n", f.ProjectID)
			fmt.Printf("   Category: %s\n", f.Category)
			fmt.Println()
		}
	}

	// Print scan coverage
	fmt.Println("SCAN COVERAGE")
	fmt.Println("=============")
	fmt.Printf("Projects fully scanned: %d\n", len(result.Projects))
	fmt.Printf("Projects skipped: %d\n", len(result.SkippedResources))
}