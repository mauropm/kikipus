package security

import (
	"testing"

	"github.com/mauropm/kikipus/internal/analysis"
)

func TestEngine_Run(t *testing.T) {
	engine := NewEngine()

	// Test with a project that has IAM issues
	result := &analysis.ScanResult{
		Projects: []*analysis.ProjectScanResult{
			{
				ProjectID: "test-project",
				IAMBindings: []*analysis.IAMBinding{
					{
						Role:    "roles/owner",
						Members: []string{"user:admin@example.com"},
					},
					{
						Role:    "roles/editor",
						Members: []string{"user:developer@example.com"},
					},
				},
				Network: &analysis.NetworkInfo{
					Firewall: []*analysis.FirewallRule{
						{
							Name:         "allow-ssh",
							Dir:          "INGRESS",
							SourceRanges: []string{"0.0.0.0/0"},
							Allowed: []*analysis.AllowedRule{
								{
									IPProtocol: "tcp",
									Ports:      []string{"22"},
								},
							},
						},
					},
				},
				StorageBuckets: []*analysis.StorageBucket{
					{
						Name:   "public-bucket",
						Public: true,
					},
				},
				Activity: &analysis.ActivitySignals{
					RunningVMs:     0,
					GKEWorkloads:   0,
					CloudSQLActive: 0,
					StorageBuckets: 0,
				},
			},
		},
	}

	findings := engine.Run(result)

	// Should have findings for:
	// - IAM-001 (owner role)
	// - IAM-002 (editor role)
	// - NET-001 (SSH public)
	// - STORAGE-001 (public bucket)
	// - HYGIENE-001 (dormant project)
	if len(findings) < 5 {
		t.Errorf("expected at least 5 findings, got %d", len(findings))
	}

	// Check specific findings
	var hasOwnerFinding, hasEditorFinding, hasSSHFinding, hasPublicBucket, hasDormant bool
	for _, f := range findings {
		switch f.ID {
		case "IAM-001":
			hasOwnerFinding = true
		case "IAM-002":
			hasEditorFinding = true
		case "NET-001":
			hasSSHFinding = true
		case "STORAGE-001":
			hasPublicBucket = true
		case "HYGIENE-001":
			hasDormant = true
		}
	}

	if !hasOwnerFinding {
		t.Error("expected IAM-001 finding for owner role")
	}
	if !hasEditorFinding {
		t.Error("expected IAM-002 finding for editor role")
	}
	if !hasSSHFinding {
		t.Error("expected NET-001 finding for SSH public access")
	}
	if !hasPublicBucket {
		t.Error("expected STORAGE-001 finding for public bucket")
	}
	if !hasDormant {
		t.Error("expected HYGIENE-001 finding for dormant project")
	}
}

func TestCheckOwnerRole(t *testing.T) {
	project := &analysis.ProjectScanResult{
		ProjectID: "test-project",
		IAMBindings: []*analysis.IAMBinding{
			{
				Role:    "roles/owner",
				Members: []string{"user:admin@example.com"},
			},
			{
				Role:    "roles/owner",
				Members: []string{"serviceAccount:sa@test-project.iam.gserviceaccount.com"},
			},
		},
	}

	findings := checkOwnerRole(project)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	if findings[0].Severity != "HIGH" {
		t.Errorf("expected HIGH severity, got %s", findings[0].Severity)
	}
}

func TestCheckEditorRole(t *testing.T) {
	project := &analysis.ProjectScanResult{
		ProjectID: "test-project",
		IAMBindings: []*analysis.IAMBinding{
			{
				Role:    "roles/editor",
				Members: []string{"user:developer@example.com"},
			},
		},
	}

	findings := checkEditorRole(project)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	if findings[0].Severity != "MEDIUM" {
		t.Errorf("expected MEDIUM severity, got %s", findings[0].Severity)
	}
}

func TestCheckSSHPublicAccess(t *testing.T) {
	tests := []struct {
		name     string
		rules    []*analysis.FirewallRule
		expected int
	}{
		{
			name: "SSH from 0.0.0.0/0",
			rules: []*analysis.FirewallRule{
				{
					Name:         "allow-ssh",
					Dir:          "INGRESS",
					SourceRanges: []string{"0.0.0.0/0"},
					Allowed: []*analysis.AllowedRule{
						{IPProtocol: "tcp", Ports: []string{"22"}},
					},
				},
			},
			expected: 1,
		},
		{
			name: "SSH from specific range",
			rules: []*analysis.FirewallRule{
				{
					Name:         "allow-ssh",
					Dir:          "INGRESS",
					SourceRanges: []string{"10.0.0.0/8"},
					Allowed: []*analysis.AllowedRule{
						{IPProtocol: "tcp", Ports: []string{"22"}},
					},
				},
			},
			expected: 0,
		},
		{
			name: "Egress SSH rule",
			rules: []*analysis.FirewallRule{
				{
					Name:         "allow-ssh-out",
					Dir:          "EGRESS",
					SourceRanges: []string{"0.0.0.0/0"},
					Allowed: []*analysis.AllowedRule{
						{IPProtocol: "tcp", Ports: []string{"22"}},
					},
				},
			},
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			project := &analysis.ProjectScanResult{
				ProjectID: "test-project",
				Network: &analysis.NetworkInfo{
					Firewall: tt.rules,
				},
			}

			findings := checkSSHPublicAccess(project)
			if len(findings) != tt.expected {
				t.Errorf("expected %d findings, got %d", tt.expected, len(findings))
			}
		})
	}
}

func TestCheckPublicBuckets(t *testing.T) {
	project := &analysis.ProjectScanResult{
		ProjectID: "test-project",
		StorageBuckets: []*analysis.StorageBucket{
			{Name: "public-bucket", Public: true},
			{Name: "private-bucket", Public: false},
		},
	}

	findings := checkPublicBuckets(project)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	if findings[0].Resource != "public-bucket" {
		t.Errorf("expected resource 'public-bucket', got '%s'", findings[0].Resource)
	}
}

func TestCheckDormantProjects(t *testing.T) {
	tests := []struct {
		name     string
		activity *analysis.ActivitySignals
		expected int
	}{
		{
			name: "All zero activity",
			activity: &analysis.ActivitySignals{
				RunningVMs:     0,
				GKEWorkloads:   0,
				CloudSQLActive: 0,
				StorageBuckets: 0,
			},
			expected: 1,
		},
		{
			name: "Some activity",
			activity: &analysis.ActivitySignals{
				RunningVMs:     1,
				GKEWorkloads:   0,
				CloudSQLActive: 0,
				StorageBuckets: 0,
			},
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			project := &analysis.ProjectScanResult{
				ProjectID: "test-project",
				Activity:  tt.activity,
			}

			findings := checkDormantProjects(project)
			if len(findings) != tt.expected {
				t.Errorf("expected %d findings, got %d", tt.expected, len(findings))
			}
		})
	}
}

func TestEngine_GetRuleIDs(t *testing.T) {
	engine := NewEngine()
	ids := engine.GetRuleIDs()

	if len(ids) != 12 {
		t.Errorf("expected 12 rule IDs, got %d", len(ids))
	}

	// Check specific rule IDs
	expectedRules := []string{
		"IAM-001", "IAM-002", "IAM-003", "IAM-004", "IAM-005",
		"NET-001", "NET-002", "NET-003",
		"STORAGE-001",
		"COST-001", "COST-002",
		"HYGIENE-001",
	}

	for _, expected := range expectedRules {
		found := false
		for _, id := range ids {
			if id == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected rule ID %s not found", expected)
		}
	}
}

func TestEngine_AddRule(t *testing.T) {
	engine := NewEngine()

	customRule := Rule{
		ID:       "CUSTOM-001",
		Name:     "Custom Rule",
		Severity: "LOW",
		Category: "CUSTOM",
		Check:    func(*analysis.ProjectScanResult) []*analysis.Finding { return nil },
	}

	engine.AddRule(customRule)

	ids := engine.GetRuleIDs()
	found := false
	for _, id := range ids {
		if id == "CUSTOM-001" {
			found = true
			break
		}
	}

	if !found {
		t.Error("expected custom rule to be added")
	}
}
