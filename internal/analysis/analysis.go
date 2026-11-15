package analysis

import (
	"time"
)

// ScanResult holds the results of a full scan.
type ScanResult struct {
	StartTime time.Time
	EndTime   time.Time
	Scope     string
	ProjectCount int
	Projects   []*ProjectScanResult
	Findings   []*Finding
	Coverage   *CoverageInfo
	SkippedResources []string
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
	RiskScore      float32
	HealthScore    float32
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

// CoverageInfo reports scan coverage percentages.
type CoverageInfo struct {
	IAM       int
	Compute   int
	Billing   int
	GKE       int
	Storage   int
	Network   int
}

// ProjectHealth gives each project a health overview.
type ProjectHealth struct {
	ProjectID string
	HealthScore float32
	Security  float32
	Cost      float32
	Activity  float32
	Hygiene   float32
}

// Finding is a security/infrastructure finding.
type Finding struct {
	ID        string
	Severity  string // INFO, LOW, MEDIUM, HIGH, CRITICAL
	Category  string // IAM, NETWORK, STORAGE, COMPUTE, DATABASE, GKE, SECRETS, LOGGING, COST, HYGIENE, ACTIVITY
	ProjectID string
	Resource  string
	Title     string
	Description string
	Evidence  []string
	Impact    string
	Remediation string
	Confidence string // HIGH, MEDIUM, LOW
}

// Engine is the analysis engine.
type Engine struct{}

// NewEngine creates a new analysis engine.
func NewEngine() *Engine {
	return &Engine{}
}

// Analyze processes scan results and generates analysis.
func (e *Engine) Analyze(sr *ScanResult) {
	// To be implemented in later phases
	_ = sr
}