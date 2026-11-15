package cost

import (
	"testing"

	"github.com/mauropm/kikipus/internal/analysis"
)

func TestAnalyzer_Analyze(t *testing.T) {
	analyzer := NewAnalyzer()

	results := []*analysis.ProjectScanResult{
		{
			ProjectID:   "project-1",
			ProjectName: "Project 1",
			ComputeResources: []*analysis.ComputeResource{
				{
					Name:        "vm-1",
					Status:      "RUNNING",
					MachineType: "n1-standard-2",
					Disks: []*analysis.DiskInfo{
						{DiskName: "disk-1", SizeGb: 100},
					},
				},
				{
					Name:        "vm-2",
					Status:      "TERMINATED",
					MachineType: "n1-standard-4",
					Disks: []*analysis.DiskInfo{
						{DiskName: "disk-2", SizeGb: 200},
					},
				},
			},
			GKEClusters: []*analysis.GKECluster{
				{
					Name:      "cluster-1",
					Location:  "us-central1-a",
					Version:   "1.28.3",
					NodeCount: 3,
				},
			},
			SQLInstances: []*analysis.SQLInstance{
				{
					Name:      "sql-1",
					Database:  "MYSQL_8_0",
					Tier:      "db-n1-standard-2",
					StorageGb: 50,
				},
			},
			StorageBuckets: []*analysis.StorageBucket{
				{
					Name:   "bucket-1",
					Class:  "STANDARD",
					Size:   100 * 1024 * 1024 * 1024, // 100 GB
				},
			},
		},
	}

	costAnalysis := analyzer.Analyze(results)

	if costAnalysis.TotalCost <= 0 {
		t.Errorf("expected total cost > 0, got %.2f", costAnalysis.TotalCost)
	}

	if len(costAnalysis.ProjectCosts) != 1 {
		t.Errorf("expected 1 project cost, got %d", len(costAnalysis.ProjectCosts))
	}

	if len(costAnalysis.ServiceBreakdown) == 0 {
		t.Error("expected service breakdown to be populated")
	}
}

func TestAnalyzer_estimateVMCost(t *testing.T) {
	analyzer := NewAnalyzer()

	tests := []struct {
		name     string
		vms      []*analysis.ComputeResource
		minCost  float64
		maxCost  float64
	}{
		{
			name: "Running VM",
			vms: []*analysis.ComputeResource{
				{
					Name:        "vm-1",
					Status:      "RUNNING",
					MachineType: "n1-standard-2",
				},
			},
			minCost: 60.0,
			maxCost: 80.0,
		},
		{
			name: "Stopped VM with disk",
			vms: []*analysis.ComputeResource{
				{
					Name:        "vm-2",
					Status:      "TERMINATED",
					MachineType: "n1-standard-4",
					Disks: []*analysis.DiskInfo{
						{DiskName: "disk-1", SizeGb: 100},
					},
				},
			},
			minCost: 3.0,
			maxCost: 5.0,
		},
		{
			name: "Mixed VMs",
			vms: []*analysis.ComputeResource{
				{
					Name:        "vm-1",
					Status:      "RUNNING",
					MachineType: "e2-medium",
				},
				{
					Name:        "vm-2",
					Status:      "TERMINATED",
					MachineType: "n1-standard-2",
					Disks: []*analysis.DiskInfo{
						{DiskName: "disk-1", SizeGb: 50},
					},
				},
			},
			minCost: 20.0,
			maxCost: 30.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cost := analyzer.estimateVMCost(tt.vms)
			if cost < tt.minCost || cost > tt.maxCost {
				t.Errorf("cost %.2f outside expected range [%.2f, %.2f]", cost, tt.minCost, tt.maxCost)
			}
		})
	}
}

func TestAnalyzer_estimateGKECost(t *testing.T) {
	analyzer := NewAnalyzer()

	tests := []struct {
		name     string
		clusters []*analysis.GKECluster
		minCost  float64
		maxCost  float64
	}{
		{
			name: "Single cluster",
			clusters: []*analysis.GKECluster{
				{Name: "cluster-1", NodeCount: 3},
			},
			minCost: 170.0,
			maxCost: 180.0,
		},
		{
			name: "Multiple clusters",
			clusters: []*analysis.GKECluster{
				{Name: "cluster-1", NodeCount: 2},
				{Name: "cluster-2", NodeCount: 4},
			},
			minCost: 280.0,
			maxCost: 400.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cost := analyzer.estimateGKECost(tt.clusters)
			if cost < tt.minCost || cost > tt.maxCost {
				t.Errorf("cost %.2f outside expected range [%.2f, %.2f]", cost, tt.minCost, tt.maxCost)
			}
		})
	}
}

func TestAnalyzer_estimateSQLCost(t *testing.T) {
	analyzer := NewAnalyzer()

	tests := []struct {
		name      string
		instances []*analysis.SQLInstance
		minCost   float64
		maxCost   float64
	}{
		{
			name: "Standard instance",
			instances: []*analysis.SQLInstance{
				{Name: "sql-1", Tier: "db-n1-standard-2", StorageGb: 50},
			},
			minCost: 100.0,
			maxCost: 120.0,
		},
		{
			name: "Multiple instances",
			instances: []*analysis.SQLInstance{
				{Name: "sql-1", Tier: "db-n1-standard-1", StorageGb: 20},
				{Name: "sql-2", Tier: "db-n1-standard-4", StorageGb: 100},
			},
			minCost: 250.0,
			maxCost: 300.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cost := analyzer.estimateSQLCost(tt.instances)
			if cost < tt.minCost || cost > tt.maxCost {
				t.Errorf("cost %.2f outside expected range [%.2f, %.2f]", cost, tt.minCost, tt.maxCost)
			}
		})
	}
}

func TestAnalyzer_estimateStorageCost(t *testing.T) {
	analyzer := NewAnalyzer()

	tests := []struct {
		name     string
		buckets  []*analysis.StorageBucket
		minCost  float64
		maxCost  float64
	}{
		{
			name: "Standard bucket",
			buckets: []*analysis.StorageBucket{
				{Name: "bucket-1", Class: "STANDARD", Size: 100 * 1024 * 1024 * 1024}, // 100 GB
			},
			minCost: 1.0,
			maxCost: 3.0,
		},
		{
			name: "Multiple buckets",
			buckets: []*analysis.StorageBucket{
				{Name: "bucket-1", Class: "STANDARD", Size: 500 * 1024 * 1024 * 1024}, // 500 GB
				{Name: "bucket-2", Class: "NEARLINE", Size: 200 * 1024 * 1024 * 1024}, // 200 GB
			},
			minCost: 10.0,
			maxCost: 15.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cost := analyzer.estimateStorageCost(tt.buckets)
			if cost < tt.minCost || cost > tt.maxCost {
				t.Errorf("cost %.2f outside expected range [%.2f, %.2f]", cost, tt.minCost, tt.maxCost)
			}
		})
	}
}

func TestAnalyzer_DetectOrphans(t *testing.T) {
	analyzer := NewAnalyzer()

	results := []*analysis.ProjectScanResult{
		{
			ProjectID: "project-1",
			ComputeResources: []*analysis.ComputeResource{
				{
					Name:   "stopped-vm",
					Status: "TERMINATED",
					Zone:   "us-central1-a",
					Disks: []*analysis.DiskInfo{
						{DiskName: "disk-1", SizeGb: 100},
					},
				},
			},
		},
	}

	orphans := analyzer.DetectOrphans(results)

	if len(orphans) < 1 {
		t.Errorf("expected at least 1 orphan, got %d", len(orphans))
	}

	// Check that stopped VM is detected as orphan
	found := false
	for _, o := range orphans {
		if o.Resource == "stopped-vm" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected stopped-vm to be detected as orphan")
	}
}

func TestAnalyzer_DetectExpensive(t *testing.T) {
	analyzer := NewAnalyzer()

	results := []*analysis.ProjectScanResult{
		{
			ProjectID: "project-1",
			ComputeResources: []*analysis.ComputeResource{
				{
					Name:        "expensive-vm",
					Status:      "RUNNING",
					MachineType: "n1-standard-8",
				},
				{
					Name:        "cheap-vm",
					Status:      "RUNNING",
					MachineType: "e2-micro",
				},
			},
			SQLInstances: []*analysis.SQLInstance{
				{
					Name: "expensive-sql",
					Tier: "db-n1-standard-4",
				},
			},
		},
	}

	expensive := analyzer.DetectExpensive(results)

	if len(expensive) < 2 {
		t.Errorf("expected at least 2 expensive resources, got %d", len(expensive))
	}

	// Check that expensive VM is detected
	foundVM := false
	foundSQL := false
	for _, e := range expensive {
		if e.Resource == "expensive-vm" {
			foundVM = true
		}
		if e.Resource == "expensive-sql" {
			foundSQL = true
		}
	}
	if !foundVM {
		t.Error("expected expensive-vm to be detected")
	}
	if !foundSQL {
		t.Error("expected expensive-sql to be detected")
	}
}

func TestAnalyzer_DetectWaste(t *testing.T) {
	analyzer := NewAnalyzer()

	results := []*analysis.ProjectScanResult{
		{
			ProjectID: "project-1",
			ComputeResources: []*analysis.ComputeResource{
				{
					Name:   "stopped-vm-with-disks",
					Status: "TERMINATED",
					Disks: []*analysis.DiskInfo{
						{DiskName: "disk-1", SizeGb: 100},
						{DiskName: "disk-2", SizeGb: 50},
					},
				},
			},
			GKEClusters: []*analysis.GKECluster{
				{
					Name:      "idle-cluster",
					NodeCount: 3,
				},
			},
			Activity: &analysis.ActivitySignals{
				RunningVMs:     0,
				GKEWorkloads:   0,
				CloudSQLActive: 0,
				StorageBuckets: 0,
			},
		},
	}

	waste := analyzer.DetectWaste(results)

	if len(waste) < 1 {
		t.Errorf("expected at least 1 waste item, got %d", len(waste))
	}

	// Check that stopped VM with disks is detected
	found := false
	for _, w := range waste {
		if w.Resource == "stopped-vm-with-disks" {
			found = true
			if w.EstimatedMonthlyCost <= 0 {
				t.Error("expected positive cost for stopped VM with disks")
			}
			break
		}
	}
	if !found {
		t.Error("expected stopped-vm-with-disks to be detected as waste")
	}
}

func TestAnalyzer_GenerateFindings(t *testing.T) {
	analyzer := NewAnalyzer()

	costAnalysis := &CostAnalysis{
		TotalCost:       1000.0,
		PreviousCost:    800.0,
		CostChangePct:   25.0,
		ProjectCosts:    []*ProjectCost{},
		ServiceBreakdown: []*ServiceCost{},
	}

	findings := analyzer.GenerateFindings(costAnalysis)

	if len(findings) < 1 {
		t.Errorf("expected at least 1 finding, got %d", len(findings))
	}

	// Check that cost increase finding is generated
	found := false
	for _, f := range findings {
		if f.ID == "COST-003" {
			found = true
			if f.Severity != "MEDIUM" {
				t.Errorf("expected MEDIUM severity, got %s", f.Severity)
			}
			break
		}
	}
	if !found {
		t.Error("expected COST-003 finding for cost increase")
	}
}

func TestAnalyzer_aggregateServiceCosts(t *testing.T) {
	analyzer := NewAnalyzer()

	results := []*analysis.ProjectScanResult{
		{
			ProjectID: "project-1",
			ComputeResources: []*analysis.ComputeResource{
				{Name: "vm-1", Status: "RUNNING", MachineType: "n1-standard-2"},
			},
			GKEClusters: []*analysis.GKECluster{
				{Name: "cluster-1", NodeCount: 2},
			},
		},
		{
			ProjectID: "project-2",
			ComputeResources: []*analysis.ComputeResource{
				{Name: "vm-2", Status: "RUNNING", MachineType: "e2-medium"},
			},
			SQLInstances: []*analysis.SQLInstance{
				{Name: "sql-1", Tier: "db-n1-standard-2", StorageGb: 50},
			},
		},
	}

	services := analyzer.aggregateServiceCosts(results)

	if len(services) < 3 {
		t.Errorf("expected at least 3 services, got %d", len(services))
	}

	// Check that services are sorted by cost (descending)
	for i := 0; i < len(services)-1; i++ {
		if services[i].CostUSD < services[i+1].CostUSD {
			t.Error("expected services to be sorted by cost descending")
			break
		}
	}
}
