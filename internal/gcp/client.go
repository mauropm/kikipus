package gcp

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"google.golang.org/api/option"

	"google.golang.org/api/cloudresourcemanager/v3"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/iam/v1"
	"google.golang.org/api/storage/v1"
	"google.golang.org/api/monitoring/v3"
	"google.golang.org/api/logging/v2"
	"google.golang.org/api/container/v1"
	"google.golang.org/api/sqladmin/v1"
	"google.golang.org/api/run/v2"

	"github.com/mauropm/kikipus/internal/analysis"
)

// Provider is the GCP API client provider.
// It abstracts access to various Google Cloud APIs using the user's
// existing gcloud authentication configuration.
type Provider struct {
	// Resource Manager client for organization/project discovery
	ResourceManager *cloudresourcemanager.Service

	// Compute client for VM and resource inventory
	Compute *compute.Service

	// IAM client for identity and access analysis
	IAM *iam.Service

	// Storage client for bucket inventory
	Storage *storage.Service

	// Monitoring client for metric collection
	Monitoring *monitoring.Service

	// Logging client for log inspection
	Logging *logging.Service

	// Container client for GKE inventory
	Container *container.Service

	// SQL client for Cloud SQL inventory
	SQL *sqladmin.Service

	// Cloud Run client
	CloudRun *run.Service

	// Active context
	ProjectID string
	Account   string
	OrgID     string
}

// NewProvider creates a new GCP provider using the user's existing
// gcloud authentication configuration.
// It uses Application Default Credentials from the user's gcloud config.
func NewProvider() (*Provider, error) {
	opts := option.WithScopes(
		"https://www.googleapis.com/auth/cloud-platform.read-only",
		"https://www.googleapis.com/auth/cloud-platform",
		"https://www.googleapis.com/auth/resourcemanager",
		"https://www.googleapis.com/auth/compute",
		"https://www.googleapis.com/auth/iam",
		"https://www.googleapis.com/auth/monitoring.read",
		"https://www.googleapis.com/auth/logging.read",
		"https://www.googleapis.com/auth/container",
		"https://www.googleapis.com/auth/sqlservice.admin",
		"https://www.googleapis.com/auth/cloud-run",
	)

	rm, err := cloudresourcemanager.NewService(context.Background(), opts)
	if err != nil {
		return nil, fmt.Errorf("creating resource manager: %w", err)
	}

	computeSvc, err := compute.NewService(context.Background(), opts)
	if err != nil {
		return nil, fmt.Errorf("creating compute service: %w", err)
	}

	iamSvc, err := iam.NewService(context.Background(), opts)
	if err != nil {
		return nil, fmt.Errorf("creating IAM service: %w", err)
	}

	storageSvc, err := storage.NewService(context.Background(), opts)
	if err != nil {
		return nil, fmt.Errorf("creating storage service: %w", err)
	}

	monitoringSvc, err := monitoring.NewService(context.Background(), opts)
	if err != nil {
		return nil, fmt.Errorf("creating monitoring service: %w", err)
	}

	loggingSvc, err := logging.NewService(context.Background(), opts)
	if err != nil {
		return nil, fmt.Errorf("creating logging service: %w", err)
	}

	containerSvc, err := container.NewService(context.Background(), opts)
	if err != nil {
		return nil, fmt.Errorf("creating container service: %w", err)
	}

	sqlSvc, err := sqladmin.NewService(context.Background(), opts)
	if err != nil {
		return nil, fmt.Errorf("creating SQL admin service: %w", err)
	}

	cloudRunSvc, err := run.NewService(context.Background(), opts)
	if err != nil {
		return nil, fmt.Errorf("creating Cloud Run service: %w", err)
	}

	account, project := detectGCPContext()
	orgID := discoverOrganization(rm)

	return &Provider{
		ResourceManager: rm,
		Compute:         computeSvc,
		IAM:             iamSvc,
		Storage:         storageSvc,
		Monitoring:      monitoringSvc,
		Logging:         loggingSvc,
		Container:       containerSvc,
		SQL:             sqlSvc,
		CloudRun:        cloudRunSvc,
		ProjectID:       project,
		Account:         account,
		OrgID:           orgID,
	}, nil
}

// detectGCPContext reads the user's gcloud configuration to determine
// the active account and project.
func detectGCPContext() (string, string) {
	account := ""
	project := ""

	// Try to read from gcloud config
	configPath := filepath.Join(os.Getenv("HOME"), ".config", "gcloud", "configuration", "config_default")

	data, err := os.ReadFile(configPath)
	if err != nil {
		return account, project
	}

	// Parse config file for active project and account
	content := string(data)
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "project=") {
			project = strings.TrimPrefix(line, "project=")
		}
		if strings.HasPrefix(line, "account=") {
			account = strings.TrimPrefix(line, "account=")
		}
	}

	if project == "" {
		// Fall back to gcloud CLI
		project = gcloudCLI("config", "get-value", "project")
	}

	if account == "" {
		// Fall back to gcloud CLI
		account = gcloudCLI("auth", "print-identity-token")
	}

	return account, project
}

// gcloudCLI runs a gcloud command and returns stdout.
func gcloudCLI(cmd string, args ...string) string {
	ctx := context.Background()
	out, err := runGcloudCommand(ctx, cmd, args...)
	if err != nil || len(out) == 0 {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// runGcloudCommand executes a gcloud command using exec.CommandContext.
func runGcloudCommand(ctx context.Context, cmd string, args ...string) ([]byte, error) {
	cmdCtx := exec.CommandContext(ctx, "gcloud", args...)
	out, err := cmdCtx.Output()
	if err != nil {
		return nil, err
	}
	return out, nil
}

// discoverOrganization tries to find the organization ID from the project's parent.
func discoverOrganization(rm *cloudresourcemanager.Service) string {
	if rm == nil {
		return ""
	}

	proj, err := rm.Projects.Get("").Do()
	if err != nil {
		return ""
	}

	if proj.Parent != "" {
		if strings.HasPrefix(proj.Parent, "organizations/") {
			return strings.TrimPrefix(proj.Parent, "organizations/")
		}
		if strings.HasPrefix(proj.Parent, "folders/") {
			return ""
		}
	}

	return ""
}

// ProjectInfo represents a Google Cloud project with its basic metadata.
type ProjectInfo struct {
	ID        string
	Number    string
	Name      string
	State     string
	CreateTime time.Time
	Labels    map[string]string
	Parent    string
}

// FolderInfo represents a GCP folder.
type FolderInfo struct {
	ID        string
	Number    string
	Title     string
	Parent    string
	CreateTime time.Time
}

// ScanResult holds the results of a project scan.
type ScanResult struct {
	StartTime time.Time
	EndTime   time.Time
	Scope     string
}

// ProjectScanResult holds scan results for a single project.
type ProjectScanResult struct {
	ProjectID       string
	ProjectNum      string
	ProjectName     string
	State           string
	Labels          map[string]string
	BillingAccount  string
	IAMBindings     []*IAMBinding
	ComputeResources []*ComputeResource
	GKEClusters     []*GKECluster
	SQLInstances    []*SQLInstance
	StorageBuckets  []*StorageBucket
	Network         *NetworkInfo
	Activity        *ActivitySignals
}

// IAMBinding represents an IAM binding with risk assessment.
type IAMBinding struct {
	Role       string
	Members    []string
	Project    string
	RiskLevel  string // LOW, MEDIUM, HIGH, CRITICAL
}

// ComputeResource represents a Compute Engine VM or resource.
type ComputeResource struct {
	Project       string
	Zone          string
	Name          string
	Status        string
	MachineType   string
	CPU           float32
	Memory        float32
	ExternalIP    string
	InternalIP    string
	Disks         []*DiskInfo
	Labels        map[string]string
	Uptime        time.Duration
	CPUUtilization float32
	MemoryUtilization float32
}

// DiskInfo represents a persistent disk.
type DiskInfo struct {
	DiskName string
	SizeGb   int64
	Mode     string // READ_WRITE, READ_ONLY
}

// GKECluster represents a GKE cluster.
type GKECluster struct {
	Name      string
	Location  string
	Version   string
	NodeCount int
	Autoscaling bool
}

// SQLInstance represents a Cloud SQL instance.
type SQLInstance struct {
	Name      string
	Database  string
	Version   string
	Tier      string
	StorageGb int64
	PublicIP  bool
	Replicas  int
}

// StorageBucket represents a Cloud Storage bucket.
type StorageBucket struct {
	Name   string
	Location string
	Class   string
	Size   int64
	Labels   map[string]string
	Public   bool
	Versioning bool
}

// NetworkInfo represents network inventory for a project.
type NetworkInfo struct {
	VPC       string
	Subnets  []*SubnetInfo
	Routes   []*RouteInfo
	Firewall []*FirewallRule
	NAT      *NATInfo
}

// SubnetInfo represents a VPC subnet.
type SubnetInfo struct {
	Name      string
	CIDR     string
	Region   string
	PrimaryIPRange string
	SecondaryIPRange string
}

// RouteInfo represents a route.
type RouteInfo struct {
	Name      string
	DestRange string
	NextHop   string
}

// FirewallRule represents a firewall rule.
type FirewallRule struct {
	Name     string
	Dir      string // INGRESS, EGRESS
	Priority int
	SourceRanges []string
	TargetTags []string
	Allowed  []*AllowedRule
}

// AllowedRule represents allowed traffic in a firewall rule.
type AllowedRule struct {
	IPProtocol string
	Ports      []string
	SourceRanges []string
}

// NATInfo represents Cloud NAT.
type NATInfo struct {
	Name      string
	Region    string
	SourceSubnets []string
}

// ActivitySignals represents activity detection signals for a project.
type ActivitySignals struct {
	RunningVMs       int
	GKEWorkloads     int
	CloudRunTasks    int
	CloudFunctions   int
	CloudSQLActive   int
	BigQueryTables   int
	StorageBuckets   int
	PubSubSubs       int
	LoadBalancers    int
	LastAPIActivity  time.Time
	Deprecated       bool
}

// OrganizationOverview represents the organization hierarchy.
type OrganizationOverview struct {
	Organization *OrganizationDetails
	Folders      []*FolderDetails
	Projects     []*ProjectInfo
}

// OrganizationDetails represents an organization.
type OrganizationDetails struct {
	Name     string
	DisplayName string
	Folders    []string
}

// FolderDetails represents a folder in the organization.
type FolderDetails struct {
	Name      string
	DisplayName string
	Parent    string
	Projects  []*ProjectInfo
}

// DiscoverOrgAndProjects discovers the organization hierarchy and lists all projects.
func (p *Provider) DiscoverOrgAndProjects(ctx context.Context) (*OrganizationOverview, []*ProjectInfo, error) {
	var overview *OrganizationOverview
	var projects []*ProjectInfo

	// Try to get projects
	call := p.ResourceManager.Projects.List()
	if p.OrgID != "" {
		call.Parent("organizations/" + p.OrgID)
	}

	resp, err := call.Do()
	if err != nil {
		return nil, nil, fmt.Errorf("listing projects: %w", err)
	}

	for _, p := range resp.Projects {
		projects = append(projects, &ProjectInfo{
			ID:        p.ProjectId,
			Number:    p.Name,
			Name:      p.DisplayName,
			State:     p.State,
			Labels:    p.Labels,
			Parent:    p.Parent,
		})
	}

	if p.OrgID != "" {
		overview = &OrganizationOverview{
			Organization: &OrganizationDetails{
				Name:     "organizations/" + p.OrgID,
				DisplayName: p.OrgID,
			},
		}
	}

	return overview, projects, nil
}

// GetActiveAccountAndProject returns the active account and project.
func (p *Provider) GetActiveAccountAndProject(ctx context.Context) (string, string, error) {
	if p.Account == "" {
		return "", "", fmt.Errorf("not authenticated")
	}
	return p.Account, p.ProjectID, nil
}

// ScanProject performs a read-only scan of a single project.
func (p *Provider) ScanProject(ctx context.Context, project *ProjectInfo) (*analysis.ProjectScanResult, error) {
	result := &analysis.ProjectScanResult{
		ProjectID:   project.ID,
		ProjectNum:  project.Number,
		ProjectName: project.Name,
		State:       project.State,
	}

	// IAM analysis
	iamBindings, err := p.getProjectIAM(ctx, project.ID)
	if err != nil {
		// Log but don't fail
		result.IAMBindings = []*analysis.IAMBinding{}
	} else {
		result.IAMBindings = iamBindings
	}

	// Compute resources
	computeResources, err := p.getComputeResources(ctx, project.ID)
	if err != nil {
		result.ComputeResources = []*analysis.ComputeResource{}
	} else {
		result.ComputeResources = computeResources
	}

	// GKE clusters
	gkeClusters, err := p.getGKEClusters(ctx, project.ID)
	if err != nil {
		result.GKEClusters = []*analysis.GKECluster{}
	} else {
		result.GKEClusters = gkeClusters
	}

	// Cloud SQL instances
	sqlInstances, err := p.getSQLInstances(ctx, project.ID)
	if err != nil {
		result.SQLInstances = []*analysis.SQLInstance{}
	} else {
		result.SQLInstances = sqlInstances
	}

	// Storage buckets
	buckets, err := p.getStorageBuckets(ctx, project.ID)
	if err != nil {
		result.StorageBuckets = []*analysis.StorageBucket{}
	} else {
		result.StorageBuckets = buckets
	}

	// Network inventory
	network, err := p.getNetworkInventory(ctx, project.ID)
	if err != nil {
		result.Network = &analysis.NetworkInfo{}
	} else {
		result.Network = network
	}

	// Activity signals
	result.Activity = &analysis.ActivitySignals{
		RunningVMs:     len(filterRunningVMs(computeResources)),
		GKEWorkloads:   len(gkeClusters),
		CloudSQLActive: len(sqlInstances),
		StorageBuckets: len(buckets),
	}

	return result, nil
}

// getProjectIAM retrieves IAM bindings for a project.
func (p *Provider) getProjectIAM(ctx context.Context, projectID string) ([]*analysis.IAMBinding, error) {
	// Use Resource Manager's GetIamPolicy since IAM API is for service accounts
	policy, err := p.ResourceManager.Projects.GetIamPolicy(projectID, &cloudresourcemanager.GetIamPolicyRequest{}).Do()
	if err != nil {
		return nil, fmt.Errorf("getting IAM policy for project %s: %w", projectID, err)
	}

	var bindings []*analysis.IAMBinding
	for _, binding := range policy.Bindings {
		bindings = append(bindings, &analysis.IAMBinding{
			Role:       binding.Role,
			Members:    binding.Members,
			Project:    projectID,
			RiskLevel:  calculateIAMRisk(binding.Role, binding.Members),
		})
	}

	return bindings, nil
}

// calculateIAMRisk calculates the risk level for an IAM binding.
func calculateIAMRisk(role string, members []string) string {
	highPrivRoles := []string{"roles/owner", "roles/editor", "roles/admin"}
	for _, hr := range highPrivRoles {
		if role == hr {
			for _, m := range members {
				if strings.Contains(m, "@") && !strings.Contains(m, "iam.gserviceaccount.com") {
					return "HIGH"
				}
			}
			return "MEDIUM"
		}
	}
	return "LOW"
}

// getComputeResources lists VM instances and other compute resources.
func (p *Provider) getComputeResources(ctx context.Context, projectID string) ([]*analysis.ComputeResource, error) {
	var resources []*analysis.ComputeResource

	// Use aggregated list to get instances across all zones
	call := p.Compute.Instances.AggregatedList(projectID)
	err := call.Pages(ctx, func(page *compute.InstanceAggregatedList) error {
		for _, zoneScopedList := range page.Items {
			if zoneScopedList.Instances == nil || len(zoneScopedList.Instances) == 0 {
				continue
			}
			for _, instance := range zoneScopedList.Instances {
				resources = append(resources, &analysis.ComputeResource{
					Project:     projectID,
					Zone:        getZoneFromURL(instance.Zone),
					Name:        instance.Name,
					Status:      instance.Status,
					MachineType: getMachineTypeFromURL(instance.MachineType),
					ExternalIP:  getExternalIP(instance),
					InternalIP:  getInternalIP(instance),
					Disks:       extractAnalysisDisks(instance),
					Labels:      instance.Labels,
					Uptime:      calculateUptime(instance.CreationTimestamp, instance.Status),
				})
			}
		}
		return nil
	})

	if err != nil {
		return resources, fmt.Errorf("listing compute instances for project %s: %w", projectID, err)
	}

	return resources, nil
}

// getZoneFromURL extracts the zone from a full URL.
func getZoneFromURL(url string) string {
	parts := strings.Split(url, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return ""
}

// getMachineTypeFromURL extracts the machine type from a full URL.
func getMachineTypeFromURL(url string) string {
	parts := strings.Split(url, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return ""
}

// getExternalIP extracts the external IP from an instance.
func getExternalIP(instance *compute.Instance) string {
	for _, nic := range instance.NetworkInterfaces {
		for _, ac := range nic.AccessConfigs {
			if ac.NatIP != "" {
				return ac.NatIP
			}
		}
	}
	return ""
}

// getInternalIP extracts the internal IP from an instance.
func getInternalIP(instance *compute.Instance) string {
	for _, nic := range instance.NetworkInterfaces {
		if nic.NetworkIP != "" {
			return nic.NetworkIP
		}
	}
	return ""
}

// extractAnalysisDisks extracts disk information from an instance.
func extractAnalysisDisks(instance *compute.Instance) []*analysis.DiskInfo {
	var disks []*analysis.DiskInfo
	for _, disk := range instance.Disks {
		disks = append(disks, &analysis.DiskInfo{
			DiskName: disk.DeviceName,
			SizeGb:   disk.DiskSizeGb,
			Mode:     disk.Mode,
		})
	}
	return disks
}

// calculateUptime calculates the uptime of an instance.
func calculateUptime(creationTimestamp, status string) time.Duration {
	if status != "RUNNING" {
		return 0
	}

	creationTime, err := time.Parse(time.RFC3339, creationTimestamp)
	if err != nil {
		return 0
	}

	return time.Since(creationTime)
}

// getGKEClusters lists GKE clusters for a project.
func (p *Provider) getGKEClusters(ctx context.Context, projectID string) ([]*analysis.GKECluster, error) {
	var clusters []*analysis.GKECluster

	call := p.Container.Projects.Locations.Clusters.List("projects/" + projectID + "/locations/-")
	resp, err := call.Do()
	if err != nil {
		return clusters, fmt.Errorf("listing GKE clusters for project %s: %w", projectID, err)
	}

	for _, cluster := range resp.Clusters {
		gkeCluster := &analysis.GKECluster{
			Name:      cluster.Name,
			Location:  cluster.Location,
			Version:   cluster.CurrentMasterVersion,
			NodeCount: len(cluster.NodePools),
			Autoscaling: false,
		}

		// Check if any node pool has autoscaling enabled
		for _, pool := range cluster.NodePools {
			if pool.Autoscaling != nil && pool.Autoscaling.Enabled {
				gkeCluster.Autoscaling = true
				break
			}
		}

		clusters = append(clusters, gkeCluster)
	}

	return clusters, nil
}

// getSQLInstances lists Cloud SQL instances for a project.
func (p *Provider) getSQLInstances(ctx context.Context, projectID string) ([]*analysis.SQLInstance, error) {
	var instances []*analysis.SQLInstance

	call := p.SQL.Instances.List(projectID)
	resp, err := call.Do()
	if err != nil {
		return instances, fmt.Errorf("listing SQL instances for project %s: %w", projectID, err)
	}

	for _, instance := range resp.Items {
		sqlInst := &analysis.SQLInstance{
			Name:      instance.Name,
			Database:  instance.DatabaseVersion,
			Version:   instance.DatabaseVersion,
			Tier:      instance.Settings.Tier,
			StorageGb: instance.Settings.DataDiskSizeGb,
			PublicIP:  hasPublicIP(instance),
			Replicas:  len(instance.ReplicaNames),
		}

		instances = append(instances, sqlInst)
	}

	return instances, nil
}

// hasPublicIP checks if a Cloud SQL instance has a public IP.
func hasPublicIP(instance *sqladmin.DatabaseInstance) bool {
	if instance.Settings == nil || instance.Settings.IpConfiguration == nil {
		return false
	}
	return instance.Settings.IpConfiguration.RequireSsl
}

// getStorageBuckets lists Cloud Storage buckets for a project.
func (p *Provider) getStorageBuckets(ctx context.Context, projectID string) ([]*analysis.StorageBucket, error) {
	var buckets []*analysis.StorageBucket

	call := p.Storage.Buckets.List(projectID)
	err := call.Pages(ctx, func(page *storage.Buckets) error {
		for _, bucket := range page.Items {
			bucket := &analysis.StorageBucket{
				Name:       bucket.Name,
				Location:   bucket.Location,
				Class:      bucket.StorageClass,
				Size:       0, // Would need to make additional API call
				Labels:     bucket.Labels,
				Public:     isPublicBucket(bucket),
				Versioning: bucket.Versioning != nil && bucket.Versioning.Enabled,
			}

			buckets = append(buckets, bucket)
		}
		return nil
	})

	if err != nil {
		return buckets, fmt.Errorf("listing storage buckets for project %s: %w", projectID, err)
	}

	return buckets, nil
}

// isPublicBucket checks if a bucket has public access.
func isPublicBucket(bucket *storage.Bucket) bool {
	// Check for public ACLs
	for _, acl := range bucket.Acl {
		if acl.Entity == "allUsers" || acl.Entity == "allAuthenticatedUsers" {
			return true
		}
	}

	// Check for public default object ACLs
	for _, acl := range bucket.DefaultObjectAcl {
		if acl.Entity == "allUsers" || acl.Entity == "allAuthenticatedUsers" {
			return true
		}
	}

	return false
}

// getNetworkInventory lists network resources for a project.
func (p *Provider) getNetworkInventory(ctx context.Context, projectID string) (*analysis.NetworkInfo, error) {
	network := &analysis.NetworkInfo{}

	// Get networks
	networksCall := p.Compute.Networks.List(projectID)
	networksResp, err := networksCall.Do()
	if err != nil {
		return network, fmt.Errorf("listing networks for project %s: %w", projectID, err)
	}

	for _, net := range networksResp.Items {
		if network.VPC == "" {
			network.VPC = net.Name
		}

		// Get subnets for this network (networks are global, subnets are regional)
		subnetsCall := p.Compute.Subnetworks.List(projectID, "")
		subnetsResp, err := subnetsCall.Do()
		if err == nil {
			for _, subnet := range subnetsResp.Items {
				if subnet.Network == net.SelfLink {
					network.Subnets = append(network.Subnets, &analysis.SubnetInfo{
						Name:             subnet.Name,
						CIDR:             subnet.IpCidrRange,
						Region:           getRegionFromURL(subnet.Region),
						PrimaryIPRange:   subnet.IpCidrRange,
						SecondaryIPRange: "", // Would need additional API call
					})
				}
			}
		}
	}

	// Get firewall rules
	firewallCall := p.Compute.Firewalls.List(projectID)
	firewallResp, err := firewallCall.Do()
	if err == nil {
		for _, rule := range firewallResp.Items {
			allowedRules := []*analysis.AllowedRule{}
			for _, allowed := range rule.Allowed {
				allowedRules = append(allowedRules, &analysis.AllowedRule{
					IPProtocol:   allowed.IPProtocol,
					Ports:        allowed.Ports,
					SourceRanges: rule.SourceRanges,
				})
			}

			network.Firewall = append(network.Firewall, &analysis.FirewallRule{
				Name:         rule.Name,
				Dir:          rule.Direction,
				Priority:     int(rule.Priority),
				SourceRanges: rule.SourceRanges,
				TargetTags:   rule.TargetTags,
				Allowed:      allowedRules,
			})
		}
	}

	// Get routes
	routesCall := p.Compute.Routes.List(projectID)
	routesResp, err := routesCall.Do()
	if err == nil {
		for _, route := range routesResp.Items {
			network.Routes = append(network.Routes, &analysis.RouteInfo{
				Name:      route.Name,
				DestRange: route.DestRange,
				NextHop:   route.NextHopInstance,
			})
		}
	}

	return network, nil
}

// getRegionFromURL extracts the region from a full URL.
func getRegionFromURL(url string) string {
	parts := strings.Split(url, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return ""
}

// filterRunningVMs filters compute resources to only include running VMs.
func filterRunningVMs(resources []*analysis.ComputeResource) []*analysis.ComputeResource {
	var running []*analysis.ComputeResource
	for _, r := range resources {
		if r.Status == "RUNNING" {
			running = append(running, r)
		}
	}
	return running
}

// CalculateIAMRisk calculates the risk level for an IAM binding.
func CalculateIAMRisk(binding *analysis.IAMBinding) string {
	return calculateIAMRisk(binding.Role, binding.Members)
}
