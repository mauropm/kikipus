package security

import (
	"testing"

	"github.com/mauropm/kikipus/internal/analysis"
)

func TestExposureAnalyzer_Analyze(t *testing.T) {
	analyzer := NewExposureAnalyzer()

	// Test with a project that has exposed resources
	project := &analysis.ProjectScanResult{
		ProjectID: "test-project",
		ComputeResources: []*analysis.ComputeResource{
			{
				Name:       "vm-with-external-ip",
				Status:     "RUNNING",
				ExternalIP: "34.123.45.67",
				InternalIP: "10.128.0.2",
			},
			{
				Name:       "vm-without-external-ip",
				Status:     "RUNNING",
				ExternalIP: "",
				InternalIP: "10.128.0.3",
			},
		},
		StorageBuckets: []*analysis.StorageBucket{
			{Name: "public-bucket", Public: true},
			{Name: "private-bucket", Public: false},
		},
		SQLInstances: []*analysis.SQLInstance{
			{Name: "public-sql", PublicIP: true},
			{Name: "private-sql", PublicIP: false},
		},
		GKEClusters: []*analysis.GKECluster{
			{Name: "test-cluster", Location: "us-central1-a", Version: "1.28.3-gke.1011000"},
		},
	}

	findings := analyzer.Analyze(project)

	// Should have findings for:
	// - External IPs (NET-007)
	// - Public bucket (STORAGE-001)
	// - Public SQL (SQL-001)
	// - GKE endpoint (GKE-001)
	if len(findings) < 3 {
		t.Errorf("expected at least 3 findings, got %d", len(findings))
		for i, f := range findings {
			t.Logf("Finding %d: %s - %s", i+1, f.ID, f.Title)
		}
	}

	// Verify specific findings
	var hasExternalIPs, hasPublicBucket, hasPublicSQL bool
	for _, f := range findings {
		switch f.ID {
		case "NET-007":
			hasExternalIPs = true
		case "STORAGE-001":
			hasPublicBucket = true
		case "SQL-001":
			hasPublicSQL = true
		}
	}

	if !hasExternalIPs {
		t.Error("expected NET-007 finding for external IPs")
	}
	if !hasPublicBucket {
		t.Error("expected STORAGE-001 finding for public bucket")
	}
	if !hasPublicSQL {
		t.Error("expected SQL-001 finding for public SQL")
	}
}

func TestExposureAnalyzer_checkExternalIPs(t *testing.T) {
	analyzer := NewExposureAnalyzer()

	tests := []struct {
		name     string
		vms      []*analysis.ComputeResource
		expected int
	}{
		{
			name: "VMs with external IPs",
			vms: []*analysis.ComputeResource{
				{Name: "vm-1", ExternalIP: "34.123.45.67"},
				{Name: "vm-2", ExternalIP: "34.123.45.68"},
			},
			expected: 1,
		},
		{
			name: "VMs without external IPs",
			vms: []*analysis.ComputeResource{
				{Name: "vm-1", ExternalIP: ""},
				{Name: "vm-2", ExternalIP: ""},
			},
			expected: 0,
		},
		{
			name: "Mixed VMs",
			vms: []*analysis.ComputeResource{
				{Name: "vm-1", ExternalIP: "34.123.45.67"},
				{Name: "vm-2", ExternalIP: ""},
			},
			expected: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			project := &analysis.ProjectScanResult{
				ProjectID:      "test-project",
				ComputeResources: tt.vms,
			}

			findings := analyzer.checkExternalIPs(project)
			if len(findings) != tt.expected {
				t.Errorf("expected %d findings, got %d", tt.expected, len(findings))
			}
		})
	}
}

func TestExposureAnalyzer_checkPublicStorage(t *testing.T) {
	analyzer := NewExposureAnalyzer()

	tests := []struct {
		name     string
		buckets  []*analysis.StorageBucket
		expected int
	}{
		{
			name: "Public bucket",
			buckets: []*analysis.StorageBucket{
				{Name: "public-bucket", Public: true},
			},
			expected: 1,
		},
		{
			name: "Private buckets",
			buckets: []*analysis.StorageBucket{
				{Name: "private-bucket-1", Public: false},
				{Name: "private-bucket-2", Public: false},
			},
			expected: 0,
		},
		{
			name: "Mixed buckets",
			buckets: []*analysis.StorageBucket{
				{Name: "public-bucket", Public: true},
				{Name: "private-bucket", Public: false},
			},
			expected: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			project := &analysis.ProjectScanResult{
				ProjectID:      "test-project",
				StorageBuckets: tt.buckets,
			}

			findings := analyzer.checkPublicStorage(project)
			if len(findings) != tt.expected {
				t.Errorf("expected %d findings, got %d", tt.expected, len(findings))
			}
		})
	}
}

func TestExposureAnalyzer_checkPublicSQL(t *testing.T) {
	analyzer := NewExposureAnalyzer()

	tests := []struct {
		name     string
		instances []*analysis.SQLInstance
		expected int
	}{
		{
			name: "Public SQL instance",
			instances: []*analysis.SQLInstance{
				{Name: "public-sql", PublicIP: true},
			},
			expected: 1,
		},
		{
			name: "Private SQL instances",
			instances: []*analysis.SQLInstance{
				{Name: "private-sql-1", PublicIP: false},
				{Name: "private-sql-2", PublicIP: false},
			},
			expected: 0,
		},
		{
			name: "Mixed SQL instances",
			instances: []*analysis.SQLInstance{
				{Name: "public-sql", PublicIP: true},
				{Name: "private-sql", PublicIP: false},
			},
			expected: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			project := &analysis.ProjectScanResult{
				ProjectID:    "test-project",
				SQLInstances: tt.instances,
			}

			findings := analyzer.checkPublicSQL(project)
			if len(findings) != tt.expected {
				t.Errorf("expected %d findings, got %d", tt.expected, len(findings))
			}
		})
	}
}

func TestExposureAnalyzer_AnalyzeAll(t *testing.T) {
	analyzer := NewExposureAnalyzer()

	results := []*analysis.ProjectScanResult{
		{
			ProjectID: "project-1",
			ComputeResources: []*analysis.ComputeResource{
				{Name: "vm-1", ExternalIP: "34.123.45.67"},
			},
			StorageBuckets: []*analysis.StorageBucket{
				{Name: "public-bucket", Public: true},
			},
		},
		{
			ProjectID: "project-2",
			ComputeResources: []*analysis.ComputeResource{
				{Name: "vm-2", ExternalIP: ""},
			},
		},
	}

	findings := analyzer.AnalyzeAll(results)

	if len(findings) < 1 {
		t.Errorf("expected at least 1 finding, got %d", len(findings))
	}
}
