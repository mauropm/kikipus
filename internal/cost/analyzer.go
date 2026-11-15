package cost

import (
	"fmt"
	"time"

	"github.com/mauropm/kikipus/internal/analysis"
)

// CostRecord represents a single cost entry.
type CostRecord struct {
	ProjectID     string
	Service       string
	SKU           string
	Description   string
	CostUSD       float64
	Currency      string
	BillingAccount string
	UsageAmount   float64
	UsageUnit     string
	StartTime     time.Time
	EndTime       time.Time
	Labels        map[string]string
}

// ProjectCost represents aggregated cost for a project.
type ProjectCost struct {
	ProjectID       string
	ProjectName     string
	TotalCost       float64
	PreviousCost    float64
	CostChange      float64
	CostChangePct   float64
	ServiceCosts    []*ServiceCost
	ResourceCosts   []*ResourceCost
	Trend           []MonthlyCost
}

// ServiceCost represents cost for a specific service.
type ServiceCost struct {
	Service     string
	Description string
	CostUSD     float64
	PctOfTotal  float64
}

// ResourceCost represents cost for a specific resource.
type ResourceCost struct {
	Resource    string
	ResourceType string
	ProjectID   string
	CostUSD     float64
	Status      string
	Idle        bool
}

// MonthlyCost represents cost for a specific month.
type MonthlyCost struct {
	Month    string
	CostUSD  float64
}

// CostAnalysis holds the results of cost analysis.
type CostAnalysis struct {
	TotalCost          float64
	PreviousCost       float64
	CostChange         float64
	CostChangePct      float64
	ProjectCosts       []*ProjectCost
	ServiceBreakdown   []*ServiceCost
	PotentialSavings   float64
	WasteEstimate      float64
	Trend              []MonthlyCost
}

// OrphanResource represents a potentially orphaned resource.
type OrphanResource struct {
	Resource    string
	ResourceType string
	ProjectID   string
	Zone        string
	CostUSD     float64
	Age         time.Duration
	LastUsed    time.Time
	Confidence  string
	Recommendation string
}

// ExpensiveResource represents a high-cost resource.
type ExpensiveResource struct {
	Resource    string
	ResourceType string
	ProjectID   string
	CostUSD     float64
	Status      string
	Utilization float64
	Idle        bool
	Recommendation string
}

// WasteItem represents a potential waste item.
type WasteItem struct {
	Resource    string
	ResourceType string
	ProjectID   string
	EstimatedMonthlyCost float64
	Status      string
	Reason      string
	Confidence  string
}

// Analyzer performs cost analysis.
type Analyzer struct{}

// NewAnalyzer creates a new cost analyzer.
func NewAnalyzer() *Analyzer {
	return &Analyzer{}
}

// Analyze performs comprehensive cost analysis on scan results.
func (a *Analyzer) Analyze(results []*analysis.ProjectScanResult) *CostAnalysis {
	analysis := &CostAnalysis{
		ProjectCosts:     []*ProjectCost{},
		ServiceBreakdown: []*ServiceCost{},
		Trend:            []MonthlyCost{},
	}

	for _, result := range results {
		projectCost := a.analyzeProjectCost(result)
		analysis.ProjectCosts = append(analysis.ProjectCosts, projectCost)
		analysis.TotalCost += projectCost.TotalCost
	}

	// Aggregate service costs
	analysis.ServiceBreakdown = a.aggregateServiceCosts(results)

	// Calculate total cost change
	if len(analysis.ProjectCosts) > 0 {
		for _, pc := range analysis.ProjectCosts {
			analysis.PreviousCost += pc.PreviousCost
		}
		analysis.CostChange = analysis.TotalCost - analysis.PreviousCost
		if analysis.PreviousCost > 0 {
			analysis.CostChangePct = (analysis.CostChange / analysis.PreviousCost) * 100
		}
	}

	// Detect waste and savings
	analysis.WasteEstimate = a.estimateWaste(results)
	analysis.PotentialSavings = analysis.WasteEstimate * 0.8 // Conservative estimate

	return analysis
}

// analyzeProjectCost analyzes cost for a single project.
func (a *Analyzer) analyzeProjectCost(result *analysis.ProjectScanResult) *ProjectCost {
	pc := &ProjectCost{
		ProjectID:   result.ProjectID,
		ProjectName: result.ProjectName,
		ServiceCosts: []*ServiceCost{},
		ResourceCosts: []*ResourceCost{},
	}

	// Estimate costs based on resources
	vmCost := a.estimateVMCost(result.ComputeResources)
	gkeCost := a.estimateGKECost(result.GKEClusters)
	sqlCost := a.estimateSQLCost(result.SQLInstances)
	storageCost := a.estimateStorageCost(result.StorageBuckets)

	pc.TotalCost = vmCost + gkeCost + sqlCost + storageCost

	// Service breakdown
	if vmCost > 0 {
		pc.ServiceCosts = append(pc.ServiceCosts, &ServiceCost{
			Service:    "Compute Engine",
			CostUSD:    vmCost,
			PctOfTotal: (vmCost / pc.TotalCost) * 100,
		})
	}

	if gkeCost > 0 {
		pc.ServiceCosts = append(pc.ServiceCosts, &ServiceCost{
			Service:    "GKE",
			CostUSD:    gkeCost,
			PctOfTotal: (gkeCost / pc.TotalCost) * 100,
		})
	}

	if sqlCost > 0 {
		pc.ServiceCosts = append(pc.ServiceCosts, &ServiceCost{
			Service:    "Cloud SQL",
			CostUSD:    sqlCost,
			PctOfTotal: (sqlCost / pc.TotalCost) * 100,
		})
	}

	if storageCost > 0 {
		pc.ServiceCosts = append(pc.ServiceCosts, &ServiceCost{
			Service:    "Cloud Storage",
			CostUSD:    storageCost,
			PctOfTotal: (storageCost / pc.TotalCost) * 100,
		})
	}

	// Resource costs
	for _, vm := range result.ComputeResources {
		vmCost := a.estimateSingleVMCost(vm)
		pc.ResourceCosts = append(pc.ResourceCosts, &ResourceCost{
			Resource:    vm.Name,
			ResourceType: "VM",
			ProjectID:   result.ProjectID,
			CostUSD:     vmCost,
			Status:      vm.Status,
			Idle:        vm.Status == "TERMINATED" && len(vm.Disks) > 0,
		})
	}

	return pc
}

// estimateVMCost estimates total VM cost for a project.
func (a *Analyzer) estimateVMCost(resources []*analysis.ComputeResource) float64 {
	total := 0.0
	for _, vm := range resources {
		total += a.estimateSingleVMCost(vm)
	}
	return total
}

// estimateSingleVMCost estimates cost for a single VM.
func (a *Analyzer) estimateSingleVMCost(vm *analysis.ComputeResource) float64 {
	// Simple estimation based on machine type
	// These are rough estimates - actual pricing varies by region
	machinePrices := map[string]float64{
		"e2-micro":     6.07,
		"e2-small":     12.14,
		"e2-medium":    24.27,
		"n1-standard-1": 34.73,
		"n1-standard-2": 69.46,
		"n1-standard-4": 138.92,
		"n1-standard-8": 277.84,
		"n2-standard-2": 70.08,
		"n2-standard-4": 140.16,
		"n2-standard-8": 280.32,
	}

	// Extract machine type from URL if needed
	machineType := vm.MachineType
	if price, ok := machinePrices[machineType]; ok {
		if vm.Status == "RUNNING" {
			return price
		} else if vm.Status == "TERMINATED" {
			// Stopped VMs still incur disk costs
			diskCost := 0.0
			for _, disk := range vm.Disks {
				diskCost += float64(disk.SizeGb) * 0.04 // $0.04/GB/month for SSD
			}
			return diskCost
		}
	}

	// Default estimate for unknown machine types
	if vm.Status == "RUNNING" {
		return 50.0 // Conservative estimate
	}

	// Disk cost for stopped VMs
	diskCost := 0.0
	for _, disk := range vm.Disks {
		diskCost += float64(disk.SizeGb) * 0.04
	}
	return diskCost
}

// estimateGKECost estimates GKE cluster cost.
func (a *Analyzer) estimateGKECost(clusters []*analysis.GKECluster) float64 {
	total := 0.0
	for _, cluster := range clusters {
		// GKE management fee: $0.10/hour per cluster = ~$73/month
		total += 73.0

		// Node costs (estimated)
		nodeCost := float64(cluster.NodeCount) * 35.0 // Average node cost
		total += nodeCost
	}
	return total
}

// estimateSQLCost estimates Cloud SQL cost.
func (a *Analyzer) estimateSQLCost(instances []*analysis.SQLInstance) float64 {
	total := 0.0
	for _, instance := range instances {
		// Base cost estimate based on tier
		tierCosts := map[string]float64{
			"db-f1-micro": 10.0,
			"db-g1-small": 25.0,
			"db-n1-standard-1": 50.0,
			"db-n1-standard-2": 100.0,
			"db-n1-standard-4": 200.0,
		}

		if cost, ok := tierCosts[instance.Tier]; ok {
			total += cost
		} else {
			total += 50.0 // Default estimate
		}

		// Storage cost
		total += float64(instance.StorageGb) * 0.17 // $0.17/GB/month
	}
	return total
}

// estimateStorageCost estimates Cloud Storage cost.
func (a *Analyzer) estimateStorageCost(buckets []*analysis.StorageBucket) float64 {
	total := 0.0
	for _, bucket := range buckets {
		// Estimate based on size (if available) or use default
		if bucket.Size > 0 {
			sizeGB := float64(bucket.Size) / 1024 / 1024 / 1024 // Convert bytes to GB
			switch bucket.Class {
			case "STANDARD":
				total += sizeGB * 0.020 // $0.020/GB/month
			case "NEARLINE":
				total += sizeGB * 0.010
			case "COLDLINE":
				total += sizeGB * 0.004
			case "ARCHIVE":
				total += sizeGB * 0.0012
			default:
				total += sizeGB * 0.020
			}
		} else {
			// Default estimate for buckets without size info
			total += 5.0
		}
	}
	return total
}

// aggregateServiceCosts aggregates costs across all projects.
func (a *Analyzer) aggregateServiceCosts(results []*analysis.ProjectScanResult) []*ServiceCost {
	serviceMap := make(map[string]*ServiceCost)
	totalCost := 0.0

	for _, result := range results {
		pc := a.analyzeProjectCost(result)
		totalCost += pc.TotalCost

		for _, sc := range pc.ServiceCosts {
			if existing, ok := serviceMap[sc.Service]; ok {
				existing.CostUSD += sc.CostUSD
			} else {
				serviceMap[sc.Service] = &ServiceCost{
					Service:     sc.Service,
					Description: sc.Service,
					CostUSD:     sc.CostUSD,
				}
			}
		}
	}

	// Calculate percentages
	var services []*ServiceCost
	for _, sc := range serviceMap {
		if totalCost > 0 {
			sc.PctOfTotal = (sc.CostUSD / totalCost) * 100
		}
		services = append(services, sc)
	}

	// Sort by cost (descending)
	for i := 0; i < len(services); i++ {
		for j := i + 1; j < len(services); j++ {
			if services[i].CostUSD < services[j].CostUSD {
				services[i], services[j] = services[j], services[i]
			}
		}
	}

	return services
}

// DetectOrphans finds potentially orphaned resources.
func (a *Analyzer) DetectOrphans(results []*analysis.ProjectScanResult) []*OrphanResource {
	var orphans []*OrphanResource

	for _, result := range results {
		// Find unattached disks
		orphans = append(orphans, a.findUnattachedDisks(result)...)

		// Find stopped VMs
		orphans = append(orphans, a.findStoppedVMs(result)...)

		// Find unused external IPs
		orphans = append(orphans, a.findUnusedExternalIPs(result)...)
	}

	return orphans
}

// findUnattachedDisks finds disks not attached to any VM.
func (a *Analyzer) findUnattachedDisks(result *analysis.ProjectScanResult) []*OrphanResource {
	// In production, this would compare all disks against attached disks
	// For now, return empty
	return nil
}

// findStoppedVMs finds VMs that have been stopped for a long time.
func (a *Analyzer) findStoppedVMs(result *analysis.ProjectScanResult) []*OrphanResource {
	var orphans []*OrphanResource

	for _, vm := range result.ComputeResources {
		if vm.Status == "TERMINATED" || vm.Status == "STOPPING" {
			orphans = append(orphans, &OrphanResource{
				Resource:     vm.Name,
				ResourceType: "VM",
				ProjectID:    result.ProjectID,
				Zone:         vm.Zone,
				CostUSD:      a.estimateSingleVMCost(vm),
				Age:          vm.Uptime,
				Confidence:   "MEDIUM",
				Recommendation: "Review if VM is still needed. Delete if abandoned.",
			})
		}
	}

	return orphans
}

// findUnusedExternalIPs finds external IPs not in use.
func (a *Analyzer) findUnusedExternalIPs(result *analysis.ProjectScanResult) []*OrphanResource {
	// In production, this would compare allocated vs used IPs
	// For now, return empty
	return nil
}

// DetectExpensive finds expensive resources that may be underutilized.
func (a *Analyzer) DetectExpensive(results []*analysis.ProjectScanResult) []*ExpensiveResource {
	var expensive []*ExpensiveResource

	for _, result := range results {
		for _, vm := range result.ComputeResources {
			cost := a.estimateSingleVMCost(vm)
			if cost > 100.0 { // Threshold for "expensive"
				expensive = append(expensive, &ExpensiveResource{
					Resource:     vm.Name,
					ResourceType: "VM",
					ProjectID:    result.ProjectID,
					CostUSD:      cost,
					Status:       vm.Status,
					Idle:         vm.Status == "TERMINATED",
					Recommendation: "Review if resource size is appropriate. Consider downsizing.",
				})
			}
		}

		for _, sql := range result.SQLInstances {
			cost := 0.0
			tierCosts := map[string]float64{
				"db-n1-standard-4": 200.0,
				"db-n1-standard-2": 100.0,
			}
			if c, ok := tierCosts[sql.Tier]; ok {
				cost = c
			}

			if cost > 100.0 {
				expensive = append(expensive, &ExpensiveResource{
					Resource:     sql.Name,
					ResourceType: "Cloud SQL",
					ProjectID:    result.ProjectID,
					CostUSD:      cost,
					Recommendation: "Review if instance size is appropriate. Consider downsizing.",
				})
			}
		}
	}

	return expensive
}

// DetectWaste finds potential waste items.
func (a *Analyzer) DetectWaste(results []*analysis.ProjectScanResult) []*WasteItem {
	var waste []*WasteItem

	for _, result := range results {
		// Stopped VMs with disks
		for _, vm := range result.ComputeResources {
			if (vm.Status == "TERMINATED" || vm.Status == "STOPPING") && len(vm.Disks) > 0 {
				diskCost := 0.0
				for _, disk := range vm.Disks {
					diskCost += float64(disk.SizeGb) * 0.04
				}
				waste = append(waste, &WasteItem{
					Resource:             vm.Name,
					ResourceType:         "VM",
					ProjectID:            result.ProjectID,
					EstimatedMonthlyCost: diskCost,
					Status:               vm.Status,
					Reason:               "Stopped VM with attached disks",
					Confidence:           "HIGH",
				})
			}
		}

		// Idle GKE clusters
		for _, cluster := range result.GKEClusters {
			if result.Activity != nil && result.Activity.GKEWorkloads == 0 {
				waste = append(waste, &WasteItem{
					Resource:             cluster.Name,
					ResourceType:         "GKE",
					ProjectID:            result.ProjectID,
					EstimatedMonthlyCost: 73.0 + float64(cluster.NodeCount)*35.0,
					Status:               "IDLE",
					Reason:               "GKE cluster with no workloads",
					Confidence:           "MEDIUM",
				})
			}
		}
	}

	return waste
}

// estimateWaste estimates total potential waste.
func (a *Analyzer) estimateWaste(results []*analysis.ProjectScanResult) float64 {
	wasteItems := a.DetectWaste(results)
	total := 0.0
	for _, item := range wasteItems {
		total += item.EstimatedMonthlyCost
	}
	return total
}

// GenerateFindings generates cost-related findings from analysis.
func (a *Analyzer) GenerateFindings(costAnalysis *CostAnalysis) []*analysis.Finding {
	var findings []*analysis.Finding

	// Cost trend findings
	if costAnalysis.CostChangePct > 20.0 {
		findings = append(findings, &analysis.Finding{
			ID:          "COST-003",
			Severity:    "MEDIUM",
			Category:    "COST",
			Title:       "Significant cost increase detected",
			Description: fmt.Sprintf("Costs increased by %.1f%% compared to previous period", costAnalysis.CostChangePct),
			Evidence:    []string{fmt.Sprintf("Current: $%.2f", costAnalysis.TotalCost), fmt.Sprintf("Previous: $%.2f", costAnalysis.PreviousCost)},
			Impact:      "Budget overrun potential",
			Remediation: "Review cost drivers and optimize resource usage.",
			Confidence:  "HIGH",
		})
	}

	// Waste findings
	wasteItems := a.DetectWaste(nil) // Would pass results in production
	for _, item := range wasteItems {
		findings = append(findings, &analysis.Finding{
			ID:          "COST-002",
			Severity:    "LOW",
			Category:    "COST",
			Title:       fmt.Sprintf("Potential waste: %s", item.Reason),
			Description: fmt.Sprintf("Resource %s may be wasting $%.2f/month", item.Resource, item.EstimatedMonthlyCost),
			Evidence:    []string{item.Resource, item.Reason},
			Impact:      "Unnecessary cost accumulation",
			Remediation: item.Reason,
			Confidence:  item.Confidence,
		})
	}

	return findings
}
