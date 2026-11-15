package reports

import (
	"github.com/mauropm/kikipus/internal/analysis"
	"github.com/mauropm/kikipus/internal/findings"
	"time"
)

// Engine is the reporting engine.
type Engine struct {
	reports []*Report
	format  string
}

// Report is a generated report in a specific format.
type Report struct {
	Title       string
	Content     string
	Format      string
	GeneratedAt time.Time
}

// NewEngine creates a new reports engine.
func NewEngine() *Engine {
	return &Engine{}
}

// GenerateMarkdown generates a markdown report.
func (e *Engine) GenerateMarkdown(sr *analysis.ScanResult, fs []*findings.Finding) (*Report, error) {
	// To be implemented
	return &Report{
		Title:       "Kikipus Scan Report",
		Format:      "markdown",
		GeneratedAt: time.Now(),
	}, nil
}

// GenerateJSON generates a JSON report.
func (e *Engine) GenerateJSON(sr *analysis.ScanResult, fs []*findings.Finding) (*Report, error) {
	// To be implemented
	return &Report{
		Title:       "Kikipus Scan Report",
		Format:      "json",
		GeneratedAt: time.Now(),
	}, nil
}

// GenerateCSV generates a CSV report.
func (e *Engine) GenerateCSV(sr *analysis.ScanResult, fs []*findings.Finding) (*Report, error) {
	// To be implemented
	return &Report{
		Title:       "Kikipus Scan Report",
		Format:      "csv",
		GeneratedAt: time.Now(),
	}, nil
}

// GenerateTerminal generates a terminal-ready report.
func (e *Engine) GenerateTerminal(sr *analysis.ScanResult, fs []*findings.Finding) string {
	// To be implemented
	return ""
}