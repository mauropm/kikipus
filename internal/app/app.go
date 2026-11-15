package app

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/mauropm/kikipus/internal/config"
	"github.com/mauropm/kikipus/internal/gcp"
	"github.com/mauropm/kikipus/internal/findings"
	"github.com/mauropm/kikipus/internal/analysis"
	"github.com/mauropm/kikipus/internal/storage"
	"github.com/mauropm/kikipus/internal/reports"
)

type Application struct {
	cfg          *config.Config
	cloud        *gcp.Provider
	findings     *findings.Engine
	analysis     *analysis.Engine
	storage     *storage.Facade
	reports      *reports.Engine
}

func New(cfg *config.Config) (*Application, error) {
	// Detect GCP context - this may fail if not authenticated
	provider, _ := gcp.NewProvider()

	// Initialize findings engine
	findingsEngine := findings.NewEngine()

	// Initialize analysis engine
	analysisEngine := analysis.NewEngine()

	// Initialize storage
	st := storage.NewFacade()

	// Initialize reports engine
	rep := reports.NewEngine()

	return &Application{
		cfg:      cfg,
		cloud:    provider,
		findings: findingsEngine,
		analysis: analysisEngine,
		storage:  st,
		reports:  rep,
	}, nil
}

func (a *Application) Close() {
	if a.storage != nil {
		a.storage.Close()
	}
}

func (a *Application) Run() error {
	ctx := context.Background()

	// Show GCP context
	if err := a.showGCPContext(ctx); err != nil {
		return fmt.Errorf("showing GCP context: %w", err)
	}

	// If not authenticated, stop here
	if a.cloud == nil {
		fmt.Fprintf(os.Stderr, "\n● READ ONLY\n\n")
		fmt.Fprintf(os.Stderr, "Authentication required to scan GCP resources.\n")
		fmt.Fprintf(os.Stderr, "Run: gcloud auth login\n\n")
		return nil
	}

	// Discover organization and projects
	_, projects, err := a.cloud.DiscoverOrgAndProjects(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: unable to discover organization/projects: %v\n", err)
		fmt.Fprintf(os.Stderr, "\n● READ ONLY\n\n")
		fmt.Fprintf(os.Stderr, "Unable to discover GCP resources.\n")
		fmt.Fprintf(os.Stderr, "Verify your gcloud configuration: gcloud config list\n\n")
		return nil
	}

	fmt.Fprintf(os.Stderr, "\n● READ ONLY\n\n")
	fmt.Fprintf(os.Stderr, "Discovered %d project(s).\n\n", len(projects))

	// Scan projects
	scanCtx, cancel := context.WithTimeout(ctx, 300*time.Second)
	defer cancel()

	scanResult, err := a.runScan(scanCtx, projects)
	if err != nil {
		return fmt.Errorf("running scan: %w", err)
	}

	// Enrich with analysis
	a.analysis.Analyze(scanResult)

	// Generate findings
	a.findings.Generate(scanResult)

	return nil
}

// Scan performs a scan and returns the result.
func (a *Application) Scan(ctx context.Context) (*analysis.ScanResult, error) {
	if a.cloud == nil {
		return nil, fmt.Errorf("not authenticated")
	}

	_, projects, err := a.cloud.DiscoverOrgAndProjects(ctx)
	if err != nil {
		return nil, fmt.Errorf("discovering projects: %w", err)
	}

	scanCtx, cancel := context.WithTimeout(ctx, 300*time.Second)
	defer cancel()

	result, err := a.runScan(scanCtx, projects)
	if err != nil {
		return nil, err
	}

	a.analysis.Analyze(result)
	a.findings.Generate(result)

	return result, nil
}

// GetFindings returns all findings from the last scan.
func (a *Application) GetFindings() []*analysis.Finding {
	return a.findings.GetFindings()
}

// GetProjects returns all discovered projects.
func (a *Application) GetProjects(ctx context.Context) ([]*gcp.ProjectInfo, error) {
	if a.cloud == nil {
		return nil, fmt.Errorf("not authenticated")
	}

	_, projects, err := a.cloud.DiscoverOrgAndProjects(ctx)
	return projects, err
}

func (a *Application) showGCPContext(ctx context.Context) error {
	if a.cloud == nil {
		fmt.Fprintf(os.Stderr, "✕ GCP authentication unavailable\n\n")
		fmt.Fprintf(os.Stderr, "Run:\n    gcloud auth login\n\n")
		return nil
	}

	account, project, err := a.cloud.GetActiveAccountAndProject(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "✕ GCP authentication unavailable\n\n")
		fmt.Fprintf(os.Stderr, "Run:\n    gcloud auth login\n\n")
		return nil
	}

	fmt.Fprintf(os.Stderr, "GCP CONTEXT\n\n")
	fmt.Fprintf(os.Stderr, "Account:\n    %s\n\n", account)
	fmt.Fprintf(os.Stderr, "Active project:\n    %s\n\n", project)
	return nil
}

func (a *Application) runScan(ctx context.Context, projects []*gcp.ProjectInfo) (*analysis.ScanResult, error) {
	result := &analysis.ScanResult{
		StartTime: time.Now(),
		Scope:     a.cfg.Project,
	}

	// If specific project requested, filter
	var projectsToScan []*gcp.ProjectInfo
	if a.cfg.Project != "" {
		for _, p := range projects {
			if p.ID == a.cfg.Project || p.Number == a.cfg.Project {
				projectsToScan = append(projectsToScan, p)
			}
		}
	} else {
		projectsToScan = projects
	}

	result.ProjectCount = len(projectsToScan)

	// Scan each project (with context cancellation support)
	for _, project := range projectsToScan {
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		default:
		}

		projResult, err := a.cloud.ScanProject(ctx, project)
		if err != nil {
			// Log but don't fail
			result.SkippedResources = append(result.SkippedResources, fmt.Sprintf("project %s: %v", project.ID, err))
			continue
		}

		result.Projects = append(result.Projects, projResult)
		a.storage.SaveScan(project.ID, projResult)
	}

	result.EndTime = time.Now()
	return result, nil
}