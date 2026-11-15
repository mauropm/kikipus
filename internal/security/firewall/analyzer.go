package firewall

import (
	"fmt"
	"strings"

	"github.com/mauropm/kikipus/internal/analysis"
)

// Analyzer performs firewall rule analysis.
type Analyzer struct{}

// NewAnalyzer creates a new firewall analyzer.
func NewAnalyzer() *Analyzer {
	return &Analyzer{}
}

// Analyze analyzes firewall rules and returns findings.
func (a *Analyzer) Analyze(projectID string, rules []*analysis.FirewallRule) []*analysis.Finding {
	var findings []*analysis.Finding

	for _, rule := range rules {
		findings = append(findings, a.analyzeRule(projectID, rule)...)
	}

	return findings
}

// analyzeRule analyzes a single firewall rule.
func (a *Analyzer) analyzeRule(projectID string, rule *analysis.FirewallRule) []*analysis.Finding {
	var findings []*analysis.Finding

	if rule.Dir != "INGRESS" {
		return findings
	}

	// Check for public internet access
	publicSources := a.getPublicSources(rule.SourceRanges)
	if len(publicSources) == 0 {
		return findings
	}

	// Check for SSH exposure
	if a.hasPort(rule, "tcp", []string{"22", "22-22"}) {
		findings = append(findings, &analysis.Finding{
			ID:          "NET-001",
			Severity:    "HIGH",
			Category:    "NETWORK",
			ProjectID:   projectID,
			Resource:    rule.Name,
			Title:       "SSH exposed to the public Internet",
			Description: fmt.Sprintf("Firewall rule '%s' allows SSH (tcp:22) from %s", rule.Name, strings.Join(publicSources, ", ")),
			Evidence:    []string{rule.Name, "tcp:22", strings.Join(publicSources, ", ")},
			Impact:      "SSH access is available from any IP address on the Internet",
			Remediation: "Restrict source IP ranges to known trusted networks. Consider using Identity-Aware Proxy (IAP) for SSH access.",
			Confidence:  "HIGH",
		})
	}

	// Check for RDP exposure
	if a.hasPort(rule, "tcp", []string{"3389", "3389-3389"}) {
		findings = append(findings, &analysis.Finding{
			ID:          "NET-002",
			Severity:    "HIGH",
			Category:    "NETWORK",
			ProjectID:   projectID,
			Resource:    rule.Name,
			Title:       "RDP exposed to the public Internet",
			Description: fmt.Sprintf("Firewall rule '%s' allows RDP (tcp:3389) from %s", rule.Name, strings.Join(publicSources, ", ")),
			Evidence:    []string{rule.Name, "tcp:3389", strings.Join(publicSources, ", ")},
			Impact:      "RDP access is available from any IP address on the Internet",
			Remediation: "Restrict source IP ranges to known trusted networks. Consider using Identity-Aware Proxy (IAP) for RDP access.",
			Confidence:  "HIGH",
		})
	}

	// Check for broad ingress (all protocols, all ports)
	if a.isBroadIngress(rule) {
		findings = append(findings, &analysis.Finding{
			ID:          "NET-003",
			Severity:    "HIGH",
			Category:    "NETWORK",
			ProjectID:   projectID,
			Resource:    rule.Name,
			Title:       "Broad unrestricted ingress rule",
			Description: fmt.Sprintf("Firewall rule '%s' allows all traffic from %s", rule.Name, strings.Join(publicSources, ", ")),
			Evidence:    []string{rule.Name, "all protocols", strings.Join(publicSources, ", ")},
			Impact:      "All network traffic is allowed from public Internet sources",
			Remediation: "Restrict to specific protocols, ports, and source ranges required for the application.",
			Confidence:  "HIGH",
		})
	}

	// Check for database port exposure
	dbPorts := map[string][]string{
		"MySQL":      {"3306", "3306-3306"},
		"PostgreSQL": {"5432", "5432-5432"},
		"MongoDB":    {"27017", "27017-27017"},
		"Redis":      {"6379", "6379-6379"},
		"Elasticsearch": {"9200", "9200-9200", "9300", "9300-9300"},
	}

	for dbName, ports := range dbPorts {
		if a.hasPort(rule, "tcp", ports) {
			findings = append(findings, &analysis.Finding{
				ID:          "NET-004",
				Severity:    "CRITICAL",
				Category:    "NETWORK",
				ProjectID:   projectID,
				Resource:    rule.Name,
				Title:       fmt.Sprintf("%s exposed to the public Internet", dbName),
				Description: fmt.Sprintf("Firewall rule '%s' allows %s (tcp:%s) from %s", rule.Name, dbName, strings.Join(ports, ","), strings.Join(publicSources, ", ")),
				Evidence:    []string{rule.Name, fmt.Sprintf("tcp:%s", strings.Join(ports, ",")), strings.Join(publicSources, ", ")},
				Impact:      fmt.Sprintf("%s database is accessible from any IP address on the Internet", dbName),
				Remediation: "Restrict source IP ranges to application servers only. Use VPC peering or private service access.",
				Confidence:  "HIGH",
			})
		}
	}

	// Check for administrative port exposure
	adminPorts := map[string][]string{
		"HTTP":     {"80", "80-80"},
		"HTTPS":    {"443", "443-443"},
		"FTP":      {"21", "21-21"},
		"Telnet":   {"23", "23-23"},
		"SMB/CIFS": {"445", "445-445"},
	}

	for svcName, ports := range adminPorts {
		if a.hasPort(rule, "tcp", ports) {
			findings = append(findings, &analysis.Finding{
				ID:          "NET-005",
				Severity:    "MEDIUM",
				Category:    "NETWORK",
				ProjectID:   projectID,
				Resource:    rule.Name,
				Title:       fmt.Sprintf("%s exposed to the public Internet", svcName),
				Description: fmt.Sprintf("Firewall rule '%s' allows %s (tcp:%s) from %s", rule.Name, svcName, strings.Join(ports, ","), strings.Join(publicSources, ", ")),
				Evidence:    []string{rule.Name, fmt.Sprintf("tcp:%s", strings.Join(ports, ",")), strings.Join(publicSources, ", ")},
				Impact:      fmt.Sprintf("%s service is accessible from any IP address on the Internet", svcName),
				Remediation: "Review if public access is necessary. Restrict to specific source ranges if possible.",
				Confidence:  "MEDIUM",
			})
		}
	}

	// Check for default-allow rules
	if strings.HasPrefix(rule.Name, "default-allow-") {
		findings = append(findings, &analysis.Finding{
			ID:          "NET-006",
			Severity:    "MEDIUM",
			Category:    "NETWORK",
			ProjectID:   projectID,
			Resource:    rule.Name,
			Title:       "Default allow firewall rule",
			Description: fmt.Sprintf("Default firewall rule '%s' allows traffic", rule.Name),
			Evidence:    []string{rule.Name, "default rule"},
			Impact:      "Default rules may allow more access than intended",
			Remediation: "Review default rules and replace with specific rules if needed.",
			Confidence:  "LOW",
		})
	}

	return findings
}

// getPublicSources returns source ranges that include public internet.
func (a *Analyzer) getPublicSources(ranges []string) []string {
	var public []string
	for _, r := range ranges {
		if r == "0.0.0.0/0" || r == "::/0" {
			public = append(public, r)
		}
	}
	return public
}

// hasPort checks if a rule allows specific ports.
func (a *Analyzer) hasPort(rule *analysis.FirewallRule, protocol string, ports []string) bool {
	for _, allowed := range rule.Allowed {
		if allowed.IPProtocol != protocol && allowed.IPProtocol != "all" {
			continue
		}

		for _, rulePort := range allowed.Ports {
			for _, checkPort := range ports {
				if rulePort == checkPort {
					return true
				}
				// Handle port ranges like "22-22"
				if strings.Contains(rulePort, "-") {
					parts := strings.Split(rulePort, "-")
					if len(parts) == 2 && parts[0] == checkPort {
						return true
					}
				}
			}
		}
	}
	return false
}

// isBroadIngress checks if a rule allows all traffic from public sources.
func (a *Analyzer) isBroadIngress(rule *analysis.FirewallRule) bool {
	for _, allowed := range rule.Allowed {
		if allowed.IPProtocol == "all" || allowed.IPProtocol == "" {
			publicSources := a.getPublicSources(rule.SourceRanges)
			if len(publicSources) > 0 {
				return true
			}
		}
	}
	return false
}

// AnalyzeAll analyzes all firewall rules across projects.
func (a *Analyzer) AnalyzeAll(results []*analysis.ProjectScanResult) []*analysis.Finding {
	var findings []*analysis.Finding

	for _, result := range results {
		if result.Network == nil || len(result.Network.Firewall) == 0 {
			continue
		}

		projectFindings := a.Analyze(result.ProjectID, result.Network.Firewall)
		findings = append(findings, projectFindings...)
	}

	return findings
}
