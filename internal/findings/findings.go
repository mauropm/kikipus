package findings

import (
	"github.com/mauropm/kikipus/internal/analysis"
	"github.com/mauropm/kikipus/internal/security"
)

// Finding is a security/infrastructure finding with severity, category, and evidence.
type Finding struct {
	ID          string
	Severity    string
	Category    string
	ProjectID   string
	Resource    string
	Title       string
	Description string
	Evidence    []string
	Impact      string
	Remediation string
	Confidence  string
}

// Engine is the finding generation engine.
type Engine struct {
	securityEngine *security.Engine
	findings       []*analysis.Finding
}

// NewEngine creates a new findings engine.
func NewEngine() *Engine {
	return &Engine{
		securityEngine: security.NewEngine(),
	}
}

// Generate populates findings from a scan result.
func (e *Engine) Generate(sr *analysis.ScanResult) {
	if sr == nil {
		return
	}

	// Run security rules against the scan result
	e.findings = e.securityEngine.Run(sr)

	// Update the scan result with findings
	sr.Findings = e.findings
}

// GetFindings returns all generated findings.
func (e *Engine) GetFindings() []*analysis.Finding {
	return e.findings
}

// GetFindingsBySeverity returns findings filtered by severity.
func (e *Engine) GetFindingsBySeverity(severity string) []*analysis.Finding {
	var filtered []*analysis.Finding
	for _, f := range e.findings {
		if f.Severity == severity {
			filtered = append(filtered, f)
		}
	}
	return filtered
}

// GetFindingsByCategory returns findings filtered by category.
func (e *Engine) GetFindingsByCategory(category string) []*analysis.Finding {
	var filtered []*analysis.Finding
	for _, f := range e.findings {
		if f.Category == category {
			filtered = append(filtered, f)
		}
	}
	return filtered
}

// GetFindingsByProject returns findings filtered by project ID.
func (e *Engine) GetFindingsByProject(projectID string) []*analysis.Finding {
	var filtered []*analysis.Finding
	for _, f := range e.findings {
		if f.ProjectID == projectID {
			filtered = append(filtered, f)
		}
	}
	return filtered
}

// GetCriticalFindings returns all critical severity findings.
func (e *Engine) GetCriticalFindings() []*analysis.Finding {
	return e.GetFindingsBySeverity("CRITICAL")
}

// GetHighFindings returns all high severity findings.
func (e *Engine) GetHighFindings() []*analysis.Finding {
	return e.GetFindingsBySeverity("HIGH")
}

// GetMediumFindings returns all medium severity findings.
func (e *Engine) GetMediumFindings() []*analysis.Finding {
	return e.GetFindingsBySeverity("MEDIUM")
}

// GetLowFindings returns all low severity findings.
func (e *Engine) GetLowFindings() []*analysis.Finding {
	return e.GetFindingsBySeverity("LOW")
}
