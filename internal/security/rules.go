package security

import (
	"fmt"
	"strings"

	"github.com/mauropm/kikipus/internal/analysis"
	"github.com/mauropm/kikipus/internal/security/firewall"
)

// Rule represents a security rule.
type Rule struct {
	ID          string
	Name        string
	Description string
	Severity    string
	Category    string
	Check       func(*analysis.ProjectScanResult) []*analysis.Finding
}

// Engine is the security rules engine.
type Engine struct {
	rules       []Rule
	fwAnalyzer  *firewall.Analyzer
	expAnalyzer *ExposureAnalyzer
}

// NewEngine creates a new security rules engine.
func NewEngine() *Engine {
	e := &Engine{
		fwAnalyzer:  firewall.NewAnalyzer(),
		expAnalyzer: NewExposureAnalyzer(),
	}
	e.registerRules()
	return e
}

// registerRules registers all built-in security rules.
func (e *Engine) registerRules() {
	// IAM Rules
	e.rules = append(e.rules, Rule{
		ID:          "IAM-001",
		Name:        "Owner role assigned to human user",
		Description: "Human user has project-level Owner role",
		Severity:    "HIGH",
		Category:    "IAM",
		Check:       checkOwnerRole,
	})

	e.rules = append(e.rules, Rule{
		ID:          "IAM-002",
		Name:        "Editor role assigned to human user",
		Description: "Human user has project-level Editor role",
		Severity:    "MEDIUM",
		Category:    "IAM",
		Check:       checkEditorRole,
	})

	e.rules = append(e.rules, Rule{
		ID:          "IAM-003",
		Name:        "Service account with broad administrative role",
		Description: "Service account has broad administrative permissions",
		Severity:    "MEDIUM",
		Category:    "IAM",
		Check:       checkServiceAccountRoles,
	})

	e.rules = append(e.rules, Rule{
		ID:          "IAM-004",
		Name:        "External principal with privileged access",
		Description: "External principal has privileged access to project",
		Severity:    "HIGH",
		Category:    "IAM",
		Check:       checkExternalPrincipals,
	})

	e.rules = append(e.rules, Rule{
		ID:          "IAM-005",
		Name:        "Old service account key",
		Description: "Service account has old keys that should be rotated",
		Severity:    "MEDIUM",
		Category:    "IAM",
		Check:       checkOldServiceAccountKeys,
	})

	// Network Rules
	e.rules = append(e.rules, Rule{
		ID:          "NET-001",
		Name:        "SSH exposed to the public Internet",
		Description: "Firewall rule allows SSH (port 22) from 0.0.0.0/0",
		Severity:    "HIGH",
		Category:    "NETWORK",
		Check:       checkSSHPublicAccess,
	})

	e.rules = append(e.rules, Rule{
		ID:          "NET-002",
		Name:        "RDP exposed to the public Internet",
		Description: "Firewall rule allows RDP (port 3389) from 0.0.0.0/0",
		Severity:    "HIGH",
		Category:    "NETWORK",
		Check:       checkRDPPublicAccess,
	})

	e.rules = append(e.rules, Rule{
		ID:          "NET-003",
		Name:        "Broad unrestricted ingress rule",
		Description: "Firewall rule allows all traffic from 0.0.0.0/0",
		Severity:    "HIGH",
		Category:    "NETWORK",
		Check:       checkBroadIngress,
	})

	// Storage Rules
	e.rules = append(e.rules, Rule{
		ID:          "STORAGE-001",
		Name:        "Publicly accessible bucket",
		Description: "Cloud Storage bucket has public access",
		Severity:    "MEDIUM",
		Category:    "STORAGE",
		Check:       checkPublicBuckets,
	})

	// Cost Rules
	e.rules = append(e.rules, Rule{
		ID:          "COST-001",
		Name:        "Potentially idle expensive resource",
		Description: "Resource appears expensive but unused",
		Severity:    "LOW",
		Category:    "COST",
		Check:       checkIdleResources,
	})

	e.rules = append(e.rules, Rule{
		ID:          "COST-002",
		Name:        "Unattached disk",
		Description: "Persistent disk is not attached to any instance",
		Severity:    "LOW",
		Category:    "COST",
		Check:       checkUnattachedDisks,
	})

	// Hygiene Rules
	e.rules = append(e.rules, Rule{
		ID:          "HYGIENE-001",
		Name:        "Potentially dormant project",
		Description: "Project shows minimal or no activity",
		Severity:    "LOW",
		Category:    "HYGIENE",
		Check:       checkDormantProjects,
	})
}

// Run runs all security rules against a scan result.
func (e *Engine) Run(result *analysis.ScanResult) []*analysis.Finding {
	var findings []*analysis.Finding

	// Run rules-based checks
	for _, project := range result.Projects {
		for _, rule := range e.rules {
			ruleFindings := rule.Check(project)
			for _, f := range ruleFindings {
				// Set default values if not set by the rule
				if f.ID == "" {
					f.ID = rule.ID
				}
				if f.Severity == "" {
					f.Severity = rule.Severity
				}
				if f.Category == "" {
					f.Category = rule.Category
				}
				findings = append(findings, f)
			}
		}

		// Run specialized analyzers
		findings = append(findings, e.fwAnalyzer.Analyze(project.ProjectID, project.Network.Firewall)...)
		findings = append(findings, e.expAnalyzer.Analyze(project)...)
	}

	return findings
}

// checkOwnerRole checks for owner role assigned to human users.
func checkOwnerRole(project *analysis.ProjectScanResult) []*analysis.Finding {
	var findings []*analysis.Finding

	for _, binding := range project.IAMBindings {
		if binding.Role != "roles/owner" {
			continue
		}

		for _, member := range binding.Members {
			if strings.HasPrefix(member, "user:") {
				findings = append(findings, &analysis.Finding{
					ID:          "IAM-001",
					Severity:    "HIGH",
					Category:    "IAM",
					ProjectID:   project.ProjectID,
					Resource:    member,
					Title:       "Owner role assigned to human user",
					Description: fmt.Sprintf("Human user %s has Owner role on project %s", extractEmail(member), project.ProjectID),
					Evidence:    []string{member, "roles/owner"},
					Impact:      "Owner role provides full control over the project including billing and IAM",
					Remediation: "Review if Owner role is necessary. Consider using Editor or more specific roles.",
					Confidence:  "HIGH",
				})
			}
		}
	}

	return findings
}

// checkEditorRole checks for editor role assigned to human users.
func checkEditorRole(project *analysis.ProjectScanResult) []*analysis.Finding {
	var findings []*analysis.Finding

	for _, binding := range project.IAMBindings {
		if binding.Role != "roles/editor" {
			continue
		}

		for _, member := range binding.Members {
			if strings.HasPrefix(member, "user:") {
				findings = append(findings, &analysis.Finding{
					ID:          "IAM-002",
					Severity:    "MEDIUM",
					Category:    "IAM",
					ProjectID:   project.ProjectID,
					Resource:    member,
					Title:       "Editor role assigned to human user",
					Description: fmt.Sprintf("Human user %s has Editor role on project %s", extractEmail(member), project.ProjectID),
					Evidence:    []string{member, "roles/editor"},
					Impact:      "Editor role allows modification of most resources",
					Remediation: "Review if Editor role is necessary. Consider using more specific roles.",
					Confidence:  "MEDIUM",
				})
			}
		}
	}

	return findings
}

// checkServiceAccountRoles checks for service accounts with broad roles.
func checkServiceAccountRoles(project *analysis.ProjectScanResult) []*analysis.Finding {
	var findings []*analysis.Finding

	broadRoles := []string{"roles/owner", "roles/editor", "roles/admin"}

	for _, binding := range project.IAMBindings {
		isBroad := false
		for _, broadRole := range broadRoles {
			if binding.Role == broadRole {
				isBroad = true
				break
			}
		}

		if !isBroad {
			continue
		}

		for _, member := range binding.Members {
			if strings.HasPrefix(member, "serviceAccount:") {
				findings = append(findings, &analysis.Finding{
					ID:          "IAM-003",
					Severity:    "MEDIUM",
					Category:    "IAM",
					ProjectID:   project.ProjectID,
					Resource:    member,
					Title:       "Service account with broad administrative role",
					Description: fmt.Sprintf("Service account %s has %s role", extractEmail(member), binding.Role),
					Evidence:    []string{member, binding.Role},
					Impact:      "Service accounts with broad roles can be exploited for privilege escalation",
					Remediation: "Review service account permissions. Use least privilege principle.",
					Confidence:  "MEDIUM",
				})
			}
		}
	}

	return findings
}

// checkExternalPrincipals checks for external principals with access.
func checkExternalPrincipals(project *analysis.ProjectScanResult) []*analysis.Finding {
	var findings []*analysis.Finding

	for _, binding := range project.IAMBindings {
		for _, member := range binding.Members {
			email := extractEmail(member)
			if email == "" {
				continue
			}

			if isExternalDomain(email) {
				findings = append(findings, &analysis.Finding{
					ID:          "IAM-004",
					Severity:    "HIGH",
					Category:    "IAM",
					ProjectID:   project.ProjectID,
					Resource:    member,
					Title:       "External principal with access",
					Description: fmt.Sprintf("External principal %s has role %s", email, binding.Role),
					Evidence:    []string{member, binding.Role},
					Impact:      "External entities have access to project resources",
					Remediation: "Verify external access is intentional and necessary. Consider using VPC Service Controls.",
					Confidence:  "MEDIUM",
				})
			}
		}
	}

	return findings
}

// checkOldServiceAccountKeys checks for old service account keys.
func checkOldServiceAccountKeys(project *analysis.ProjectScanResult) []*analysis.Finding {
	// This would require the IAM provider to get key information
	// For now, return empty findings
	return nil
}

// checkSSHPublicAccess checks for SSH exposed to public internet.
func checkSSHPublicAccess(project *analysis.ProjectScanResult) []*analysis.Finding {
	var findings []*analysis.Finding

	if project.Network == nil {
		return findings
	}

	for _, rule := range project.Network.Firewall {
		if rule.Dir != "INGRESS" {
			continue
		}

		for _, allowed := range rule.Allowed {
			if allowed.IPProtocol == "tcp" {
				for _, port := range allowed.Ports {
					if port == "22" || port == "22-22" {
						for _, source := range rule.SourceRanges {
							if source == "0.0.0.0/0" || source == "::/0" {
								findings = append(findings, &analysis.Finding{
									ID:          "NET-001",
									Severity:    "HIGH",
									Category:    "NETWORK",
									ProjectID:   project.ProjectID,
									Resource:    rule.Name,
									Title:       "SSH exposed to the public Internet",
									Description: fmt.Sprintf("Firewall rule %s allows SSH from %s", rule.Name, source),
									Evidence:    []string{rule.Name, source, "tcp:22"},
									Impact:      "SSH is accessible from any IP address on the Internet",
									Remediation: "Restrict source IP ranges or use IAP for SSH access.",
									Confidence:  "HIGH",
								})
							}
						}
					}
				}
			}
		}
	}

	return findings
}

// checkRDPPublicAccess checks for RDP exposed to public internet.
func checkRDPPublicAccess(project *analysis.ProjectScanResult) []*analysis.Finding {
	var findings []*analysis.Finding

	if project.Network == nil {
		return findings
	}

	for _, rule := range project.Network.Firewall {
		if rule.Dir != "INGRESS" {
			continue
		}

		for _, allowed := range rule.Allowed {
			if allowed.IPProtocol == "tcp" {
				for _, port := range allowed.Ports {
					if port == "3389" || port == "3389-3389" {
						for _, source := range rule.SourceRanges {
							if source == "0.0.0.0/0" || source == "::/0" {
								findings = append(findings, &analysis.Finding{
									ID:          "NET-002",
									Severity:    "HIGH",
									Category:    "NETWORK",
									ProjectID:   project.ProjectID,
									Resource:    rule.Name,
									Title:       "RDP exposed to the public Internet",
									Description: fmt.Sprintf("Firewall rule %s allows RDP from %s", rule.Name, source),
									Evidence:    []string{rule.Name, source, "tcp:3389"},
									Impact:      "RDP is accessible from any IP address on the Internet",
									Remediation: "Restrict source IP ranges or use IAP for RDP access.",
									Confidence:  "HIGH",
								})
							}
						}
					}
				}
			}
		}
	}

	return findings
}

// checkBroadIngress checks for broad unrestricted ingress.
func checkBroadIngress(project *analysis.ProjectScanResult) []*analysis.Finding {
	var findings []*analysis.Finding

	if project.Network == nil {
		return findings
	}

	for _, rule := range project.Network.Firewall {
		if rule.Dir != "INGRESS" {
			continue
		}

		isBroad := false
		for _, allowed := range rule.Allowed {
			if allowed.IPProtocol == "all" || allowed.IPProtocol == "" {
				for _, source := range rule.SourceRanges {
					if source == "0.0.0.0/0" || source == "::/0" {
						isBroad = true
						break
					}
				}
			}
		}

		if isBroad {
			findings = append(findings, &analysis.Finding{
				ID:          "NET-003",
				Severity:    "HIGH",
				Category:    "NETWORK",
				ProjectID:   project.ProjectID,
				Resource:    rule.Name,
				Title:       "Broad unrestricted ingress rule",
				Description: fmt.Sprintf("Firewall rule %s allows all traffic from 0.0.0.0/0", rule.Name),
				Evidence:    []string{rule.Name, "0.0.0.0/0", "all"},
				Impact:      "All traffic is allowed from any source",
				Remediation: "Restrict traffic to specific protocols, ports, and source ranges.",
				Confidence:  "HIGH",
			})
		}
	}

	return findings
}

// checkPublicBuckets checks for publicly accessible storage buckets.
func checkPublicBuckets(project *analysis.ProjectScanResult) []*analysis.Finding {
	var findings []*analysis.Finding

	for _, bucket := range project.StorageBuckets {
		if bucket.Public {
			findings = append(findings, &analysis.Finding{
				ID:          "STORAGE-001",
				Severity:    "MEDIUM",
				Category:    "STORAGE",
				ProjectID:   project.ProjectID,
				Resource:    bucket.Name,
				Title:       "Publicly accessible storage bucket",
				Description: fmt.Sprintf("Bucket %s has public access enabled", bucket.Name),
				Evidence:    []string{bucket.Name, "public: true"},
				Impact:      "Bucket contents are accessible to anyone on the Internet",
				Remediation: "Review if public access is necessary. Remove if not required.",
				Confidence:  "HIGH",
			})
		}
	}

	return findings
}

// checkIdleResources checks for potentially idle expensive resources.
func checkIdleResources(project *analysis.ProjectScanResult) []*analysis.Finding {
	var findings []*analysis.Finding

	for _, vm := range project.ComputeResources {
		if vm.Status == "TERMINATED" || vm.Status == "STOPPING" {
			if len(vm.Disks) > 0 {
				findings = append(findings, &analysis.Finding{
					ID:          "COST-001",
					Severity:    "LOW",
					Category:    "COST",
					ProjectID:   project.ProjectID,
					Resource:    vm.Name,
					Title:       "Stopped VM with attached disks",
					Description: fmt.Sprintf("VM %s is stopped but has %d attached disk(s)", vm.Name, len(vm.Disks)),
					Evidence:    []string{vm.Name, vm.Status, fmt.Sprintf("disks: %d", len(vm.Disks))},
					Impact:      "Disks continue to incur costs even when VM is stopped",
					Remediation: "Consider deleting disks if no longer needed, or starting the VM if still required.",
					Confidence:  "MEDIUM",
				})
			}
		}
	}

	return findings
}

// checkUnattachedDisks checks for unattached persistent disks.
func checkUnattachedDisks(project *analysis.ProjectScanResult) []*analysis.Finding {
	// This would require comparing disks across all instances
	// For now, return empty findings
	return nil
}

// checkDormantProjects checks for potentially dormant projects.
func checkDormantProjects(project *analysis.ProjectScanResult) []*analysis.Finding {
	var findings []*analysis.Finding

	if project.Activity == nil {
		return findings
	}

	activity := project.Activity

	if activity.RunningVMs == 0 &&
		activity.GKEWorkloads == 0 &&
		activity.CloudSQLActive == 0 &&
		activity.StorageBuckets == 0 {

		findings = append(findings, &analysis.Finding{
			ID:          "HYGIENE-001",
			Severity:    "LOW",
			Category:    "HYGIENE",
			ProjectID:   project.ProjectID,
			Resource:    project.ProjectID,
			Title:       "Potentially dormant project",
			Description: fmt.Sprintf("Project %s shows no significant activity in available signals", project.ProjectID),
			Evidence: []string{
				"Running VMs: 0",
				"GKE clusters: 0",
				"Cloud SQL instances: 0",
				"Storage buckets: 0",
			},
			Impact:      "Project may be incurring costs without providing value",
			Remediation: "Review project usage and consider decommissioning if no longer needed.",
			Confidence:  "LOW",
		})
	}

	return findings
}

// Helper functions
func extractEmail(member string) string {
	if strings.HasPrefix(member, "user:") {
		return strings.TrimPrefix(member, "user:")
	}
	if strings.HasPrefix(member, "serviceAccount:") {
		return strings.TrimPrefix(member, "serviceAccount:")
	}
	if strings.HasPrefix(member, "group:") {
		return strings.TrimPrefix(member, "group:")
	}
	return member
}

func isExternalDomain(email string) bool {
	if email == "" {
		return false
	}

	internalDomains := []string{
		"@google.com",
		"@g.co",
		"@abc.xyz",
	}

	for _, domain := range internalDomains {
		if strings.HasSuffix(email, domain) {
			return false
		}
	}

	return true
}

// GetRuleIDs returns all registered rule IDs.
func (e *Engine) GetRuleIDs() []string {
	var ids []string
	for _, rule := range e.rules {
		ids = append(ids, rule.ID)
	}
	return ids
}

// GetRuleByID returns a rule by its ID.
func (e *Engine) GetRuleByID(id string) *Rule {
	for _, rule := range e.rules {
		if rule.ID == id {
			return &rule
		}
	}
	return nil
}

// AddRule adds a custom rule to the engine.
func (e *Engine) AddRule(rule Rule) {
	e.rules = append(e.rules, rule)
}
