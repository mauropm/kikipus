package storage

import "github.com/mauropm/kikipus/internal/analysis"

// Facade provides optional local snapshot storage for Kikipus.
// It uses SQLite to store normalized metadata locally.
type Facade struct {
	dbPath string
	enabled bool
}

// NewFacade creates a new storage facade.
// If enabled is false, all operations are no-ops.
func NewFacade(opts ...func(*Facade)) *Facade {
	f := &Facade{
		enabled: true,
	}

	for _, opt := range opts {
		opt(f)
	}

	return f
}

// SaveScan stores a scan result locally.
func (f *Facade) SaveScan(projectID string, sr *analysis.ProjectScanResult) {
	if !f.enabled {
		return
	}
	// To be implemented - SQLite persistence
	_ = projectID
	_ = sr
}

// Close closes the storage facade.
func (f *Facade) Close() {
	// To be implemented
	_ = f
}

// SaveFinding stores a finding locally.
func (f *Facade) SaveFinding(finding *analysis.Finding) {
	if !f.enabled {
		return
	}
	// To be implemented
	_ = finding
}

// ListFindings lists stored findings.
func (f *Facade) ListFindings() []*analysis.Finding {
	if !f.enabled {
		return nil
	}
	return nil
}