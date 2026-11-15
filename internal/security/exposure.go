package security

import (
	"fmt"
	"strings"

	"github.com/mauropm/kikipus/internal/analysis"
)

// ExposureAnalyzer detects publicly exposed resources.
type ExposureAnalyzer struct{}

// NewExposureAnalyzer creates a new exposure analyzer.
func NewExposureAnalyzer() *ExposureAnalyzer {
	return &ExposureAnalyzer{}
}

// Analyze analyzes a project scan result for public exposure.
func (e *ExposureAnalyzer) Analyze(project *analysis.ProjectScanResult) []*analysis.Finding {
	var findings []*analysis.Finding

	// Check for VMs with external IPs
	findings = append(findings, e.checkExternalIPs(project)...)

	// Check for public storage buckets
	findings = append(findings, e.checkPublicStorage(project)...)

	// Check for GKE public endpoints
	findings = append(findings, e.checkGKEEndpoints(project)...)

	// Check for public Cloud SQL instances
	findings = append(findings, e.checkPublicSQL(project)...)

	return findings
}

// checkExternalIPs checks for VMs with external IPs.
func (e *ExposureAnalyzer) checkExternalIPs(project *analysis.ProjectScanResult) []*analysis.Finding {
	var findings []*analysis.Finding

	var vmsWithExternalIPs []string
	for _, vm := range project.ComputeResources {
		if vm.ExternalIP != "" {
			vmsWithExternalIPs = append(vmsWithExternalIPs, fmt.Sprintf("%s (%s)", vm.Name, vm.ExternalIP))
		}
	}

	if len(vmsWithExternalIPs) > 0 {
		findings = append(findings, &analysis.Finding{
			ID:          "NET-007",
			Severity:    "MEDIUM",
			Category:    "NETWORK",
			ProjectID:   project.ProjectID,
			Resource:    "compute-instances",
			Title:       fmt.Sprintf("%d VM(s) with external IP addresses", len(vmsWithExternalIPs)),
			Description: fmt.Sprintf("Project %s has %d VM(s) with external IP addresses", project.ProjectID, len(vmsWithExternalIPs)),
			Evidence:    vmsWithExternalIPs,
			Impact:      "VMs with external IPs are directly accessible from the Internet",
			Remediation: "Use internal IPs where possible. Consider using a bastion host or IAP for access.",
			Confidence:  "HIGH",
		})
	}

	return findings
}

// checkPublicStorage checks for publicly accessible storage buckets.
func (e *ExposureAnalyzer) checkPublicStorage(project *analysis.ProjectScanResult) []*analysis.Finding {
	var findings []*analysis.Finding

	for _, bucket := range project.StorageBuckets {
		if bucket.Public {
			findings = append(findings, &analysis.Finding{
				ID:          "STORAGE-001",
				Severity:    "HIGH",
				Category:    "STORAGE",
				ProjectID:   project.ProjectID,
				Resource:    bucket.Name,
				Title:       fmt.Sprintf("Publicly accessible storage bucket: %s", bucket.Name),
				Description: fmt.Sprintf("Storage bucket '%s' is publicly accessible", bucket.Name),
				Evidence:    []string{bucket.Name, "public access enabled"},
				Impact:      "Bucket contents are accessible to anyone on the Internet",
				Remediation: "Review if public access is necessary. Remove public access if not required.",
				Confidence:  "HIGH",
			})
		}
	}

	return findings
}

// checkGKEEndpoints checks for GKE clusters with public endpoints.
func (e *ExposureAnalyzer) checkGKEEndpoints(project *analysis.ProjectScanResult) []*analysis.Finding {
	var findings []*analysis.Finding

	for _, cluster := range project.GKEClusters {
		// Check if cluster has a public endpoint
		// This would require additional API data in production
		if strings.Contains(cluster.Location, "us") || strings.Contains(cluster.Location, "europe") || strings.Contains(cluster.Location, "asia") {
			// Placeholder - in production, check actual endpoint configuration
			findings = append(findings, &analysis.Finding{
				ID:          "GKE-001",
				Severity:    "MEDIUM",
				Category:    "GKE",
				ProjectID:   project.ProjectID,
				Resource:    cluster.Name,
				Title:       fmt.Sprintf("GKE cluster with potential public endpoint: %s", cluster.Name),
				Description: fmt.Sprintf("GKE cluster '%s' in %s may have a public endpoint", cluster.Name, cluster.Location),
				Evidence:    []string{cluster.Name, cluster.Location, cluster.Version},
				Impact:      "GKE control plane may be accessible from the Internet",
				Remediation: "Use private clusters where possible. Restrict authorized networks.",
				Confidence:  "LOW",
			})
		}
	}

	return findings
}

// checkPublicSQL checks for Cloud SQL instances with public IPs.
func (e *ExposureAnalyzer) checkPublicSQL(project *analysis.ProjectScanResult) []*analysis.Finding {
	var findings []*analysis.Finding

	for _, instance := range project.SQLInstances {
		if instance.PublicIP {
			findings = append(findings, &analysis.Finding{
				ID:          "SQL-001",
				Severity:    "HIGH",
				Category:    "DATABASE",
				ProjectID:   project.ProjectID,
				Resource:    instance.Name,
				Title:       fmt.Sprintf("Cloud SQL instance with public IP: %s", instance.Name),
				Description: fmt.Sprintf("Cloud SQL instance '%s' has a public IP address", instance.Name),
				Evidence:    []string{instance.Name, instance.Database, "public IP enabled"},
				Impact:      "Database is accessible from the Internet",
				Remediation: "Use private IP or Cloud SQL proxy. Restrict authorized networks.",
				Confidence:  "HIGH",
			})
		}
	}

	return findings
}

// AnalyzeAll analyzes all projects for public exposure.
func (e *ExposureAnalyzer) AnalyzeAll(results []*analysis.ProjectScanResult) []*analysis.Finding {
	var findings []*analysis.Finding

	for _, result := range results {
		projectFindings := e.Analyze(result)
		findings = append(findings, projectFindings...)
	}

	return findings
}
