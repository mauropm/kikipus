package analysis

import (
	"testing"
)

func TestEngine_Analyze(t *testing.T) {
	engine := NewEngine()
	result := &ScanResult{
		ProjectCount: 3,
		Projects: []*ProjectScanResult{
			{
				ProjectID: "project-1",
				Activity: &ActivitySignals{
					RunningVMs:     5,
					GKEWorkloads:   2,
					CloudSQLActive: 1,
					StorageBuckets: 10,
				},
			},
			{
				ProjectID: "project-2",
				Activity: &ActivitySignals{
					RunningVMs:     0,
					GKEWorkloads:   0,
					CloudSQLActive: 0,
					StorageBuckets: 3,
				},
			},
		},
	}

	engine.Analyze(result)

	// Engine.Analyze is a placeholder for now, but should not panic
	if result.ProjectCount != 3 {
		t.Errorf("expected project count 3, got %d", result.ProjectCount)
	}
}

func TestScanResultFields(t *testing.T) {
	result := &ScanResult{
		Scope:     "test-scope",
		Projects:  []*ProjectScanResult{},
		Findings:  []*Finding{},
		Coverage:  &CoverageInfo{},
		SkippedResources: []string{},
	}

	if result.Scope != "test-scope" {
		t.Errorf("expected scope 'test-scope', got '%s'", result.Scope)
	}

	if result.Projects == nil {
		t.Error("expected Projects to be initialized")
	}

	if result.Findings == nil {
		t.Error("expected Findings to be initialized")
	}
}

func TestProjectScanResultFields(t *testing.T) {
	result := &ProjectScanResult{
		ProjectID:       "test-project",
		ProjectNum:      "123456789012",
		ProjectName:     "Test Project",
		State:           "ACTIVE",
		Labels:          map[string]string{"env": "test"},
		ComputeResources: []*ComputeResource{},
		GKEClusters:     []*GKECluster{},
		SQLInstances:    []*SQLInstance{},
		StorageBuckets:  []*StorageBucket{},
		Network:         &NetworkInfo{},
		Activity:        &ActivitySignals{},
	}

	if result.ProjectID != "test-project" {
		t.Errorf("expected project ID 'test-project', got '%s'", result.ProjectID)
	}

	if len(result.ComputeResources) != 0 {
		t.Errorf("expected empty compute resources, got %d", len(result.ComputeResources))
	}

	if result.Network == nil {
		t.Error("expected Network to be initialized")
	}
}

func TestFindingFields(t *testing.T) {
	finding := &Finding{
		ID:        "IAM-001",
		Severity:  "HIGH",
		Category:  "IAM",
		ProjectID: "test-project",
		Resource:  "roles/owner",
		Title:     "Owner role assigned to human user",
		Evidence:  []string{"user:admin@example.com"},
		Confidence: "HIGH",
	}

	if finding.ID != "IAM-001" {
		t.Errorf("expected finding ID 'IAM-001', got '%s'", finding.ID)
	}

	if finding.Severity != "HIGH" {
		t.Errorf("expected severity 'HIGH', got '%s'", finding.Severity)
	}

	if finding.Category != "IAM" {
		t.Errorf("expected category 'IAM', got '%s'", finding.Category)
	}
}
