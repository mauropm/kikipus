package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/mauropm/kikipus/internal/app"
	"github.com/mauropm/kikipus/internal/config"
	"github.com/mauropm/kikipus/internal/analysis"
)

func init() {
	securityCmd := &cobra.Command{
		Use:   "security",
		Short: "Show security findings",
		Long: `Show security findings from the last scan.

Examples:
  kikipus security
  kikipus security --json
  kikipus security --severity high`,
		RunE: runSecurity,
	}

	securityCmd.Flags().BoolP("json", "j", false, "Output in JSON format")
	securityCmd.Flags().StringP("severity", "s", "", "Filter by severity (critical, high, medium, low)")

	rootCmd.AddCommand(securityCmd)
}

func runSecurity(cmd *cobra.Command, args []string) error {
	cfg := &config.Config{}

	a, err := app.New(cfg)
	if err != nil {
		return fmt.Errorf("creating application: %w", err)
	}
	defer a.Close()

	ctx := context.Background()

	// Run scan first
	_, err = a.Scan(ctx)
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Warning: scan incomplete: %v\n", err)
	}

	// Get findings
	findings := a.GetFindings()

	// Filter by severity if specified
	severity, _ := cmd.Flags().GetString("severity")
	if severity != "" {
		findings = filterBySeverity(findings, severity)
	}

	jsonOutput, _ := cmd.Flags().GetBool("json")

	if jsonOutput {
		return outputFindingsJSON(findings)
	}

	// Print findings
	printFindings(findings)

	return nil
}

func filterBySeverity(findings []*analysis.Finding, severity string) []*analysis.Finding {
	var filtered []*analysis.Finding
	for _, f := range findings {
		if f.Severity == severity {
			filtered = append(filtered, f)
		}
	}
	return filtered
}

func outputFindingsJSON(findings []*analysis.Finding) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(findings)
}

func printFindings(findings []*analysis.Finding) {
	if len(findings) == 0 {
		fmt.Println("No security findings.")
		return
	}

	fmt.Println("SECURITY FINDINGS")
	fmt.Println("==================")
	fmt.Println()

	// Group by severity
	critical := filterBySeverity(findings, "CRITICAL")
	high := filterBySeverity(findings, "HIGH")
	medium := filterBySeverity(findings, "MEDIUM")
	low := filterBySeverity(findings, "LOW")

	printFindingsBySeverity("🔴 CRITICAL", critical)
	printFindingsBySeverity("🟠 HIGH", high)
	printFindingsBySeverity("🟡 MEDIUM", medium)
	printFindingsBySeverity("🔵 LOW", low)
}

func printFindingsBySeverity(header string, findings []*analysis.Finding) {
	if len(findings) == 0 {
		return
	}

	fmt.Printf("%s (%d)\n", header, len(findings))
	fmt.Println("---")

	for _, f := range findings {
		fmt.Printf("  %s\n", f.Title)
		fmt.Printf("    ID: %s\n", f.ID)
		fmt.Printf("    Project: %s\n", f.ProjectID)
		fmt.Printf("    Category: %s\n", f.Category)
		fmt.Printf("    Resource: %s\n", f.Resource)
		fmt.Printf("    Description: %s\n", f.Description)
		fmt.Printf("    Impact: %s\n", f.Impact)
		fmt.Printf("    Remediation: %s\n", f.Remediation)
		fmt.Printf("    Confidence: %s\n", f.Confidence)
		fmt.Println()
	}
}