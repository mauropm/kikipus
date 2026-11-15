package gcp

import (
	"context"
	"testing"
	"time"

	"github.com/mauropm/kikipus/internal/analysis"
)

func TestMockProvider_DiscoverOrgAndProjects(t *testing.T) {
	provider := NewMockProvider().
		WithProject(&ProjectInfo{
			ID:        "test-project-1",
			Number:    "123456789012",
			Name:      "Test Project 1",
			State:     "ACTIVE",
			Labels:    map[string]string{"env": "test"},
		}).
		WithProject(&ProjectInfo{
			ID:        "test-project-2",
			Number:    "123456789013",
			Name:      "Test Project 2",
			State:     "ACTIVE",
		})

	overview, projects, err := provider.DiscoverOrgAndProjects(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if overview == nil {
		t.Fatal("expected overview, got nil")
	}

	if len(projects) != 2 {
		t.Fatalf("expected 2 projects, got %d", len(projects))
	}

	if projects[0].ID != "test-project-1" {
		t.Errorf("expected project ID 'test-project-1', got '%s'", projects[0].ID)
	}
}

func TestMockProvider_ScanProject(t *testing.T) {
	provider := NewMockProvider().
		WithProject(&ProjectInfo{
			ID:        "test-project",
			Number:    "123456789012",
			Name:      "Test Project",
			State:     "ACTIVE",
		}).
		WithResources("test-project", []*analysis.ComputeResource{
			{
				Project:     "test-project",
				Zone:        "us-central1-a",
				Name:        "test-vm-1",
				Status:      "RUNNING",
				MachineType: "n1-standard-2",
				ExternalIP:  "34.123.45.67",
				InternalIP:  "10.128.0.2",
			},
			{
				Project:     "test-project",
				Zone:        "us-central1-b",
				Name:        "test-vm-2",
				Status:      "TERMINATED",
				MachineType: "n1-standard-4",
			},
		}).
		WithClusters("test-project", []*analysis.GKECluster{
			{
				Name:        "test-cluster",
				Location:    "us-central1-a",
				Version:     "1.28.3-gke.1011000",
				NodeCount:   3,
				Autoscaling: true,
			},
		}).
		WithBuckets("test-project", []*analysis.StorageBucket{
			{
				Name:       "test-bucket-1",
				Location:   "US",
				Class:      "STANDARD",
				Public:     false,
				Versioning: true,
			},
		})

	project := provider.Projects[0]
	result, err := provider.ScanProject(context.Background(), project)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.ProjectID != "test-project" {
		t.Errorf("expected project ID 'test-project', got '%s'", result.ProjectID)
	}

	if len(result.ComputeResources) != 2 {
		t.Fatalf("expected 2 compute resources, got %d", len(result.ComputeResources))
	}

	if len(result.GKEClusters) != 1 {
		t.Fatalf("expected 1 GKE cluster, got %d", len(result.GKEClusters))
	}

	if len(result.StorageBuckets) != 1 {
		t.Fatalf("expected 1 storage bucket, got %d", len(result.StorageBuckets))
	}

	if result.Activity.RunningVMs != 1 {
		t.Errorf("expected 1 running VM, got %d", result.Activity.RunningVMs)
	}

	if result.Activity.GKEWorkloads != 1 {
		t.Errorf("expected 1 GKE workload, got %d", result.Activity.GKEWorkloads)
	}
}

func TestMockProvider_WithError(t *testing.T) {
	provider := NewMockProvider().WithError(context.DeadlineExceeded)

	_, _, err := provider.DiscoverOrgAndProjects(context.Background())
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if err != context.DeadlineExceeded {
		t.Errorf("expected DeadlineExceeded, got %v", err)
	}
}

func TestHelperFunctions(t *testing.T) {
	t.Run("countRunningVMs", func(t *testing.T) {
		resources := []*analysis.ComputeResource{
			{Status: "RUNNING"},
			{Status: "TERMINATED"},
			{Status: "RUNNING"},
			{Status: "STOPPING"},
		}

		count := countRunningVMs(resources)
		if count != 2 {
			t.Errorf("expected 2 running VMs, got %d", count)
		}
	})

	t.Run("getZoneFromURL", func(t *testing.T) {
		url := "https://www.googleapis.com/compute/v1/projects/test-project/zones/us-central1-a"
		zone := getZoneFromURL(url)
		if zone != "us-central1-a" {
			t.Errorf("expected zone 'us-central1-a', got '%s'", zone)
		}
	})

	t.Run("getMachineTypeFromURL", func(t *testing.T) {
		url := "https://www.googleapis.com/compute/v1/projects/test-project/zones/us-central1-a/machineTypes/n1-standard-2"
		mt := getMachineTypeFromURL(url)
		if mt != "n1-standard-2" {
			t.Errorf("expected machine type 'n1-standard-2', got '%s'", mt)
		}
	})

	t.Run("getRegionFromURL", func(t *testing.T) {
		url := "https://www.googleapis.com/compute/v1/projects/test-project/regions/us-central1"
		region := getRegionFromURL(url)
		if region != "us-central1" {
			t.Errorf("expected region 'us-central1', got '%s'", region)
		}
	})

	t.Run("calculateUptime", func(t *testing.T) {
		// Running instance with recent creation
		creation := time.Now().Add(-24 * time.Hour).Format(time.RFC3339)
		uptime := calculateUptime(creation, "RUNNING")
		if uptime < 23*time.Hour {
			t.Errorf("expected uptime >= 23h, got %v", uptime)
		}

		// Stopped instance should have 0 uptime
		uptime = calculateUptime(creation, "TERMINATED")
		if uptime != 0 {
			t.Errorf("expected 0 uptime for stopped instance, got %v", uptime)
		}
	})
}

func TestCalculateIAMRisk(t *testing.T) {
	tests := []struct {
		name     string
		role     string
		members  []string
		expected string
	}{
		{
			name:     "Owner with human user",
			role:     "roles/owner",
			members:  []string{"user:admin@example.com"},
			expected: "HIGH",
		},
		{
			name:     "Editor with service account",
			role:     "roles/editor",
			members:  []string{"serviceAccount:deploy@test-project.iam.gserviceaccount.com"},
			expected: "MEDIUM",
		},
		{
			name:     "Viewer role",
			role:     "roles/viewer",
			members:  []string{"user:viewer@example.com"},
			expected: "LOW",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			binding := &analysis.IAMBinding{
				Role:    tt.role,
				Members: tt.members,
			}
			risk := CalculateIAMRisk(binding)
			if risk != tt.expected {
				t.Errorf("expected risk '%s', got '%s'", tt.expected, risk)
			}
		})
	}
}
