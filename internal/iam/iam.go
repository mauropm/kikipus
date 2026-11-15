package iam

import (
	"context"
	"fmt"
	"strings"
	"time"

	"google.golang.org/api/cloudresourcemanager/v3"
	"google.golang.org/api/iam/v1"
	"google.golang.org/api/option"

	"github.com/mauropm/kikipus/internal/analysis"
)

// Provider handles IAM-specific operations.
type Provider struct {
	IAM           *iam.Service
	ResourceManager *cloudresourcemanager.Service
}

// NewProvider creates a new IAM provider.
func NewProvider() (*Provider, error) {
	opts := option.WithScopes(
		"https://www.googleapis.com/auth/cloud-platform.read-only",
		"https://www.googleapis.com/auth/iam.readonly",
		"https://www.googleapis.com/auth/resourcemanager",
	)

	iamSvc, err := iam.NewService(context.Background(), opts)
	if err != nil {
		return nil, fmt.Errorf("creating IAM service: %w", err)
	}

	rm, err := cloudresourcemanager.NewService(context.Background(), opts)
	if err != nil {
		return nil, fmt.Errorf("creating resource manager: %w", err)
	}

	return &Provider{
		IAM:           iamSvc,
		ResourceManager: rm,
	}, nil
}

// Principal represents an IAM principal (user, group, service account, etc.)
type Principal struct {
	Name        string
	Type        PrincipalType
	Email       string
	Project     string
	Roles       []string
	LastActive  time.Time
	Created     time.Time
	Disabled    bool
	Keys        []ServiceAccountKey
}

// PrincipalType represents the type of IAM principal.
type PrincipalType string

const (
	UserType         PrincipalType = "User"
	GroupType        PrincipalType = "Group"
	ServiceAcct      PrincipalType = "ServiceAccount"
	ExternalUser     PrincipalType = "ExternalUser"
	GoogleGroup      PrincipalType = "GoogleGroup"
	DomainType       PrincipalType = "Domain"
	AllUsersType     PrincipalType = "AllUsers"
	AllAuthenticated PrincipalType = "AllAuthenticatedUsers"
	DeletedType      PrincipalType = "Deleted"
)

// ServiceAccountKey represents a service account key.
type ServiceAccountKey struct {
	Name           string
	Algorithm      string
	ValidAfter     time.Time
	ValidBefore    time.Time
	Origin         string // GOOGLE_PROVIDED or USER_PROVIDED
	KeyType        string // SYSTEM_MANAGED or USER_MANAGED
	IsExpired      bool
	IsExpiringSoon bool
}

// ServiceAccount represents a GCP service account.
type ServiceAccount struct {
	Name        string
	Email       string
	Project     string
	DisplayName string
	Description string
	Disabled    bool
	Created     time.Time
	Keys        []ServiceAccountKey
	Roles       []string
}

// GetProjectIAMPolicy retrieves the IAM policy for a project.
func (p *Provider) GetProjectIAMPolicy(ctx context.Context, projectID string) (*cloudresourcemanager.Policy, error) {
	policy, err := p.ResourceManager.Projects.GetIamPolicy(projectID, &cloudresourcemanager.GetIamPolicyRequest{
		Options: &cloudresourcemanager.GetPolicyOptions{
			RequestedPolicyVersion: 3,
		},
	}).Do()
	if err != nil {
		return nil, fmt.Errorf("getting IAM policy for project %s: %w", projectID, err)
	}

	return policy, nil
}

// ListServiceAccounts lists all service accounts in a project.
func (p *Provider) ListServiceAccounts(ctx context.Context, projectID string) ([]*ServiceAccount, error) {
	var accounts []*ServiceAccount

	parent := "projects/" + projectID
	call := p.IAM.Projects.ServiceAccounts.List(parent)
	err := call.Pages(ctx, func(page *iam.ListServiceAccountsResponse) error {
		for _, sa := range page.Accounts {
			saKeys, err := p.ListServiceAccountKeys(ctx, sa.Name)
			if err != nil {
				// Log but don't fail
				saKeys = []ServiceAccountKey{}
			}

			account := &ServiceAccount{
				Name:        sa.Name,
				Email:       sa.Email,
				Project:     projectID,
				DisplayName: sa.DisplayName,
				Description: sa.Description,
				Disabled:    sa.Disabled,
				Created:     parseTimestamp(sa.UniqueId), // UniqueId is actually the ID, not timestamp
				Keys:        saKeys,
			}

			accounts = append(accounts, account)
		}
		return nil
	})

	if err != nil {
		return accounts, fmt.Errorf("listing service accounts for project %s: %w", projectID, err)
	}

	return accounts, nil
}

// ListServiceAccountKeys lists keys for a service account.
func (p *Provider) ListServiceAccountKeys(ctx context.Context, saName string) ([]ServiceAccountKey, error) {
	var keys []ServiceAccountKey

	call := p.IAM.Projects.ServiceAccounts.Keys.List(saName)
	keyList, err := call.Do()
	if err != nil {
		return keys, fmt.Errorf("listing keys for service account %s: %w", saName, err)
	}

	for _, key := range keyList.Keys {
		if key.KeyOrigin != "USER_PROVIDED" {
			// Skip system-managed keys by default
			continue
		}

		validAfter, _ := time.Parse(time.RFC3339, key.ValidAfterTime)
		validBefore, _ := time.Parse(time.RFC3339, key.ValidBeforeTime)

		saKey := ServiceAccountKey{
			Name:           key.Name,
			Algorithm:      key.KeyAlgorithm,
			ValidAfter:     validAfter,
			ValidBefore:    validBefore,
			Origin:         key.KeyOrigin,
			KeyType:        key.KeyType,
			IsExpired:      key.ValidBeforeTime != "" && time.Now().After(validBefore),
			IsExpiringSoon: key.ValidBeforeTime != "" && time.Until(validBefore) < 30*24*time.Hour,
		}

		keys = append(keys, saKey)
	}

	return keys, nil
}

// AnalyzeIAMPolicy analyzes an IAM policy and returns findings.
func (p *Provider) AnalyzeIAMPolicy(ctx context.Context, projectID string) ([]*analysis.Finding, error) {
	policy, err := p.GetProjectIAMPolicy(ctx, projectID)
	if err != nil {
		return nil, err
	}

	var findings []*analysis.Finding

	for _, binding := range policy.Bindings {
		for _, member := range binding.Members {
			finding := p.evaluateMember(projectID, binding.Role, member)
			if finding != nil {
				findings = append(findings, finding)
			}
		}
	}

	return findings, nil
}

// evaluateMember evaluates a single IAM member for potential security issues.
func (p *Provider) evaluateMember(projectID, role, member string) *analysis.Finding {
	// Check for allUsers/allAuthenticatedUsers
	if member == "allUsers" || member == "allAuthenticatedUsers" {
		return &analysis.Finding{
			ID:         fmt.Sprintf("IAM-OPEN-%s", role),
			Severity:   "HIGH",
			Category:   "IAM",
			ProjectID:  projectID,
			Resource:   role,
			Title:      fmt.Sprintf("Public access via role %s", role),
			Description: fmt.Sprintf("The role %s is granted to %s, which provides public access.", role, member),
			Evidence:   []string{member},
			Impact:     "Public access to project resources",
			Remediation: "Remove public access. Use specific principals instead.",
			Confidence: "HIGH",
		}
	}

	// Check for external users
	if strings.HasPrefix(member, "user:") && isExternalDomain(member) {
		return &analysis.Finding{
			ID:         "IAM-EXTERNAL-USER",
			Severity:   "MEDIUM",
			Category:   "IAM",
			ProjectID:  projectID,
			Resource:   role,
			Title:      "External user access",
			Description: fmt.Sprintf("External user has role %s", role),
			Evidence:   []string{member},
			Impact:     "External entity has access to project resources",
			Remediation: "Verify external user access is intentional and necessary.",
			Confidence: "MEDIUM",
		}
	}

	// Check for owner/editor roles with human users
	if (role == "roles/owner" || role == "roles/editor") && strings.HasPrefix(member, "user:") {
		return &analysis.Finding{
			ID:         "IAM-BROAD-ACCESS",
			Severity:   "HIGH",
			Category:   "IAM",
			ProjectID:  projectID,
			Resource:   role,
			Title:      fmt.Sprintf("Broad access: %s with %s", extractEmail(member), role),
			Description: fmt.Sprintf("Human user has %s role, which provides broad access to project resources.", role),
			Evidence:   []string{member, role},
			Impact:     "Broad access may lead to accidental or malicious changes",
			Remediation: "Consider using more specific roles instead of owner/editor.",
			Confidence: "HIGH",
		}
	}

	return nil
}

// isExternalDomain checks if a user email is from an external domain.
func isExternalDomain(member string) bool {
	email := extractEmail(member)
	if email == "" {
		return false
	}

	// Check for common Google domains
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

// extractEmail extracts the email from an IAM member string.
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
	return ""
}

// parseTimestamp attempts to parse a timestamp string.
func parseTimestamp(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}
	}
	return t
}
