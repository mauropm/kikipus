package gcp

import (
	"context"
	"github.com/mauropm/kikipus/internal/analysis"
)

// MockProvider is a mock GCP provider for testing.
type MockProvider struct {
	Account    string
	ProjectID  string
	OrgID      string
	Projects   []*ProjectInfo
	Resources  map[string][]*analysis.ComputeResource
	Clusters   map[string][]*analysis.GKECluster
	SQL        map[string][]*analysis.SQLInstance
	Buckets    map[string][]*analysis.StorageBucket
	Network    map[string]*analysis.NetworkInfo
	IAM        map[string][]*analysis.IAMBinding
	Error      error
}

// NewMockProvider creates a new mock provider.
func NewMockProvider() *MockProvider {
	return &MockProvider{
		Resources: make(map[string][]*analysis.ComputeResource),
		Clusters:  make(map[string][]*analysis.GKECluster),
		SQL:       make(map[string][]*analysis.SQLInstance),
		Buckets:   make(map[string][]*analysis.StorageBucket),
		Network:   make(map[string]*analysis.NetworkInfo),
		IAM:       make(map[string][]*analysis.IAMBinding),
	}
}

// DiscoverOrgAndProjects returns mock organization and project data.
func (m *MockProvider) DiscoverOrgAndProjects(ctx context.Context) (*OrganizationOverview, []*ProjectInfo, error) {
	if m.Error != nil {
		return nil, nil, m.Error
	}

	overview := &OrganizationOverview{
		Organization: &OrganizationDetails{
			Name:        "organizations/" + m.OrgID,
			DisplayName: "Test Organization",
		},
		Projects: m.Projects,
	}

	return overview, m.Projects, nil
}

// GetActiveAccountAndProject returns mock account and project.
func (m *MockProvider) GetActiveAccountAndProject(ctx context.Context) (string, string, error) {
	if m.Error != nil {
		return "", "", m.Error
	}
	return m.Account, m.ProjectID, nil
}

// ScanProject returns mock scan results for a project.
func (m *MockProvider) ScanProject(ctx context.Context, project *ProjectInfo) (*analysis.ProjectScanResult, error) {
	if m.Error != nil {
		return nil, m.Error
	}

	result := &analysis.ProjectScanResult{
		ProjectID:       project.ID,
		ProjectNum:      project.Number,
		ProjectName:     project.Name,
		State:           project.State,
		Labels:          project.Labels,
		ComputeResources: m.Resources[project.ID],
		GKEClusters:     m.Clusters[project.ID],
		SQLInstances:    m.SQL[project.ID],
		StorageBuckets:  m.Buckets[project.ID],
		Network:         m.Network[project.ID],
		IAMBindings:     m.IAM[project.ID],
		Activity: &analysis.ActivitySignals{
			RunningVMs:     countRunningVMs(m.Resources[project.ID]),
			GKEWorkloads:   len(m.Clusters[project.ID]),
			CloudSQLActive: len(m.SQL[project.ID]),
			StorageBuckets: len(m.Buckets[project.ID]),
		},
	}

	return result, nil
}

// countRunningVMs counts the number of running VMs in a list of resources.
func countRunningVMs(resources []*analysis.ComputeResource) int {
	count := 0
	for _, r := range resources {
		if r.Status == "RUNNING" {
			count++
		}
	}
	return count
}

// WithError sets an error to be returned by all methods.
func (m *MockProvider) WithError(err error) *MockProvider {
	m.Error = err
	return m
}

// WithProject adds a project to the mock provider.
func (m *MockProvider) WithProject(p *ProjectInfo) *MockProvider {
	m.Projects = append(m.Projects, p)
	return m
}

// WithResources adds resources for a project.
func (m *MockProvider) WithResources(projectID string, resources []*analysis.ComputeResource) *MockProvider {
	m.Resources[projectID] = resources
	return m
}

// WithClusters adds GKE clusters for a project.
func (m *MockProvider) WithClusters(projectID string, clusters []*analysis.GKECluster) *MockProvider {
	m.Clusters[projectID] = clusters
	return m
}

// WithSQL adds Cloud SQL instances for a project.
func (m *MockProvider) WithSQL(projectID string, instances []*analysis.SQLInstance) *MockProvider {
	m.SQL[projectID] = instances
	return m
}

// WithBuckets adds storage buckets for a project.
func (m *MockProvider) WithBuckets(projectID string, buckets []*analysis.StorageBucket) *MockProvider {
	m.Buckets[projectID] = buckets
	return m
}

// WithNetwork adds network info for a project.
func (m *MockProvider) WithNetwork(projectID string, network *analysis.NetworkInfo) *MockProvider {
	m.Network[projectID] = network
	return m
}

// WithIAM adds IAM bindings for a project.
func (m *MockProvider) WithIAM(projectID string, bindings []*analysis.IAMBinding) *MockProvider {
	m.IAM[projectID] = bindings
	return m
}
