package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/mauropm/kikipus/internal/app"
	"github.com/mauropm/kikipus/internal/config"
	"github.com/mauropm/kikipus/internal/cost"
)

func init() {
	costsCmd := &cobra.Command{
		Use:   "costs",
		Short: "Show cost analysis",
		Long: `Show cost analysis and potential waste.

Examples:
  kikipus costs
  kikipus costs --json`,
		RunE: runCosts,
	}

	costsCmd.Flags().BoolP("json", "j", false, "Output in JSON format")

	rootCmd.AddCommand(costsCmd)
}

func runCosts(cmd *cobra.Command, args []string) error {
	cfg := &config.Config{}

	a, err := app.New(cfg)
	if err != nil {
		return fmt.Errorf("creating application: %w", err)
	}
	defer a.Close()

	ctx := context.Background()

	// Check authentication
	_, err = a.GetProjects(ctx)
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "✕ GCP authentication unavailable\n\n")
		fmt.Fprintf(cmd.ErrOrStderr(), "Run:\n    gcloud auth login\n\n")
		return err
	}

	// Run scan
	result, err := a.Scan(ctx)
	if err != nil {
		return fmt.Errorf("scanning: %w", err)
	}

	// Perform cost analysis
	analyzer := cost.NewAnalyzer()
	costAnalysis := analyzer.Analyze(result.Projects)

	// Detect waste and orphans
	waste := analyzer.DetectWaste(result.Projects)
	orphans := analyzer.DetectOrphans(result.Projects)
	expensive := analyzer.DetectExpensive(result.Projects)

	jsonOutput, _ := cmd.Flags().GetBool("json")

	if jsonOutput {
		return outputCostsJSON(costAnalysis, waste, orphans, expensive)
	}

	// Print cost analysis
	printCostAnalysis(costAnalysis)

	// Print waste items
	printWasteItems(waste)

	// Print orphan resources
	printOrphanResources(orphans)

	// Print expensive resources
	printExpensiveResources(expensive)

	return nil
}

func outputCostsJSON(costAnalysis *cost.CostAnalysis, waste []*cost.WasteItem, orphans []*cost.OrphanResource, expensive []*cost.ExpensiveResource) error {
	output := struct {
		CostAnalysis   *cost.CostAnalysis       `json:"cost_analysis"`
		WasteItems     []*cost.WasteItem        `json:"waste_items"`
		OrphanResources []*cost.OrphanResource  `json:"orphan_resources"`
		ExpensiveResources []*cost.ExpensiveResource `json:"expensive_resources"`
	}{
		CostAnalysis:       costAnalysis,
		WasteItems:         waste,
		OrphanResources:    orphans,
		ExpensiveResources: expensive,
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(output)
}

func printCostAnalysis(ca *cost.CostAnalysis) {
	fmt.Println("COST ANALYSIS")
	fmt.Println("=============")
	fmt.Printf("Current month:      $%.2f\n", ca.TotalCost)
	fmt.Printf("Previous month:     $%.2f\n", ca.PreviousCost)
	fmt.Printf("Change:             $%.2f (%.1f%%)\n", ca.CostChange, ca.CostChangePct)
	fmt.Printf("Estimated waste:    $%.2f/month\n", ca.WasteEstimate)
	fmt.Printf("Potential savings:  $%.2f/month\n", ca.PotentialSavings)
	fmt.Println()

	// Service breakdown
	fmt.Println("TOP SERVICES")
	fmt.Println("============")
	for i, sc := range ca.ServiceBreakdown {
		if i >= 5 {
			break
		}
		fmt.Printf("%d. %-20s $%.2f (%.1f%%)\n", i+1, sc.Service, sc.CostUSD, sc.PctOfTotal)
	}
	fmt.Println()

	// Project breakdown
	fmt.Println("TOP PROJECTS")
	fmt.Println("=============")
	for i, pc := range ca.ProjectCosts {
		if i >= 5 {
			break
		}
		fmt.Printf("%d. %-30s $%.2f\n", i+1, pc.ProjectID, pc.TotalCost)
	}
	fmt.Println()
}

func printWasteItems(waste []*cost.WasteItem) {
	if len(waste) == 0 {
		return
	}

	fmt.Println("POTENTIAL WASTE")
	fmt.Println("===============")
	for _, w := range waste {
		fmt.Printf("🟠 %s\n", w.Reason)
		fmt.Printf("   Project: %s\n", w.ProjectID)
		fmt.Printf("   Resource: %s\n", w.Resource)
		fmt.Printf("   Estimated cost: $%.2f/month\n", w.EstimatedMonthlyCost)
		fmt.Printf("   Confidence: %s\n", w.Confidence)
		fmt.Println()
	}
}

func printOrphanResources(orphans []*cost.OrphanResource) {
	if len(orphans) == 0 {
		return
	}

	fmt.Println("ORPHAN RESOURCES")
	fmt.Println("================")
	for _, o := range orphans {
		fmt.Printf("🔴 %s\n", o.Resource)
		fmt.Printf("   Type: %s\n", o.ResourceType)
		fmt.Printf("   Project: %s\n", o.ProjectID)
		fmt.Printf("   Zone: %s\n", o.Zone)
		fmt.Printf("   Estimated cost: $%.2f/month\n", o.CostUSD)
		fmt.Printf("   Confidence: %s\n", o.Confidence)
		fmt.Println()
	}
}

func printExpensiveResources(expensive []*cost.ExpensiveResource) {
	if len(expensive) == 0 {
		return
	}

	fmt.Println("EXPENSIVE RESOURCES")
	fmt.Println("===================")
	for _, e := range expensive {
		status := "🟠"
		if e.Idle {
			status = "🔴"
		}
		fmt.Printf("%s %s\n", status, e.Resource)
		fmt.Printf("   Type: %s\n", e.ResourceType)
		fmt.Printf("   Project: %s\n", e.ProjectID)
		fmt.Printf("   Monthly cost: $%.2f\n", e.CostUSD)
		fmt.Printf("   Idle: %v\n", e.Idle)
		fmt.Println()
	}
}
