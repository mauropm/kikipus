package firewall

import (
	"testing"

	"github.com/mauropm/kikipus/internal/analysis"
)

func TestAnalyzer_Analyze(t *testing.T) {
	analyzer := NewAnalyzer()

	tests := []struct {
		name     string
		rules    []*analysis.FirewallRule
		expected int
	}{
		{
			name: "SSH from 0.0.0.0/0",
			rules: []*analysis.FirewallRule{
				{
					Name:         "allow-ssh",
					Dir:          "INGRESS",
					SourceRanges: []string{"0.0.0.0/0"},
					Allowed: []*analysis.AllowedRule{
						{IPProtocol: "tcp", Ports: []string{"22"}},
					},
				},
			},
			expected: 1,
		},
		{
			name: "RDP from 0.0.0.0/0",
			rules: []*analysis.FirewallRule{
				{
					Name:         "allow-rdp",
					Dir:          "INGRESS",
					SourceRanges: []string{"0.0.0.0/0"},
					Allowed: []*analysis.AllowedRule{
						{IPProtocol: "tcp", Ports: []string{"3389"}},
					},
				},
			},
			expected: 1,
		},
		{
			name: "All traffic from 0.0.0.0/0",
			rules: []*analysis.FirewallRule{
				{
					Name:         "allow-all",
					Dir:          "INGRESS",
					SourceRanges: []string{"0.0.0.0/0"},
					Allowed: []*analysis.AllowedRule{
						{IPProtocol: "all"},
					},
				},
			},
			expected: 1,
		},
		{
			name: "MySQL from 0.0.0.0/0",
			rules: []*analysis.FirewallRule{
				{
					Name:         "allow-mysql",
					Dir:          "INGRESS",
					SourceRanges: []string{"0.0.0.0/0"},
					Allowed: []*analysis.AllowedRule{
						{IPProtocol: "tcp", Ports: []string{"3306"}},
					},
				},
			},
			expected: 1,
		},
		{
			name: "Restricted SSH",
			rules: []*analysis.FirewallRule{
				{
					Name:         "allow-ssh-restricted",
					Dir:          "INGRESS",
					SourceRanges: []string{"10.0.0.0/8"},
					Allowed: []*analysis.AllowedRule{
						{IPProtocol: "tcp", Ports: []string{"22"}},
					},
				},
			},
			expected: 0,
		},
		{
			name: "Egress rule",
			rules: []*analysis.FirewallRule{
				{
					Name:         "allow-ssh-out",
					Dir:          "EGRESS",
					SourceRanges: []string{"0.0.0.0/0"},
					Allowed: []*analysis.AllowedRule{
						{IPProtocol: "tcp", Ports: []string{"22"}},
					},
				},
			},
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := analyzer.Analyze("test-project", tt.rules)
			if len(findings) != tt.expected {
				t.Errorf("expected %d findings, got %d", tt.expected, len(findings))
				for i, f := range findings {
					t.Logf("Finding %d: %s - %s", i+1, f.ID, f.Title)
				}
			}
		})
	}
}

func TestAnalyzer_getPublicSources(t *testing.T) {
	analyzer := NewAnalyzer()

	tests := []struct {
		name     string
		ranges   []string
		expected int
	}{
		{
			name:     "Public range",
			ranges:   []string{"0.0.0.0/0"},
			expected: 1,
		},
		{
			name:     "IPv6 public range",
			ranges:   []string{"::/0"},
			expected: 1,
		},
		{
			name:     "Private range",
			ranges:   []string{"10.0.0.0/8"},
			expected: 0,
		},
		{
			name:     "Mixed ranges",
			ranges:   []string{"0.0.0.0/0", "10.0.0.0/8"},
			expected: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			public := analyzer.getPublicSources(tt.ranges)
			if len(public) != tt.expected {
				t.Errorf("expected %d public sources, got %d", tt.expected, len(public))
			}
		})
	}
}

func TestAnalyzer_hasPort(t *testing.T) {
	analyzer := NewAnalyzer()

	tests := []struct {
		name     string
		rule     *analysis.FirewallRule
		protocol string
		ports    []string
		expected bool
	}{
		{
			name: "Port matches",
			rule: &analysis.FirewallRule{
				Allowed: []*analysis.AllowedRule{
					{IPProtocol: "tcp", Ports: []string{"22"}},
				},
			},
			protocol: "tcp",
			ports:    []string{"22"},
			expected: true,
		},
		{
			name: "Port range matches",
			rule: &analysis.FirewallRule{
				Allowed: []*analysis.AllowedRule{
					{IPProtocol: "tcp", Ports: []string{"22-22"}},
				},
			},
			protocol: "tcp",
			ports:    []string{"22"},
			expected: true,
		},
		{
			name: "All protocol matches",
			rule: &analysis.FirewallRule{
				Allowed: []*analysis.AllowedRule{
					{IPProtocol: "all"},
				},
			},
			protocol: "tcp",
			ports:    []string{"22"},
			expected: false, // all protocol doesn't have ports
		},
		{
			name: "Port doesn't match",
			rule: &analysis.FirewallRule{
				Allowed: []*analysis.AllowedRule{
					{IPProtocol: "tcp", Ports: []string{"80"}},
				},
			},
			protocol: "tcp",
			ports:    []string{"22"},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := analyzer.hasPort(tt.rule, tt.protocol, tt.ports)
			if got != tt.expected {
				t.Errorf("hasPort() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestAnalyzer_isBroadIngress(t *testing.T) {
	analyzer := NewAnalyzer()

	tests := []struct {
		name     string
		rule     *analysis.FirewallRule
		expected bool
	}{
		{
			name: "Broad ingress",
			rule: &analysis.FirewallRule{
				Dir:          "INGRESS",
				SourceRanges: []string{"0.0.0.0/0"},
				Allowed: []*analysis.AllowedRule{
					{IPProtocol: "all"},
				},
			},
			expected: true,
		},
		{
			name: "Specific protocol",
			rule: &analysis.FirewallRule{
				Dir:          "INGRESS",
				SourceRanges: []string{"0.0.0.0/0"},
				Allowed: []*analysis.AllowedRule{
					{IPProtocol: "tcp", Ports: []string{"80"}},
				},
			},
			expected: false,
		},
		{
			name: "Restricted source",
			rule: &analysis.FirewallRule{
				Dir:          "INGRESS",
				SourceRanges: []string{"10.0.0.0/8"},
				Allowed: []*analysis.AllowedRule{
					{IPProtocol: "all"},
				},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := analyzer.isBroadIngress(tt.rule)
			if got != tt.expected {
				t.Errorf("isBroadIngress() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestAnalyzer_AnalyzeAll(t *testing.T) {
	analyzer := NewAnalyzer()

	results := []*analysis.ProjectScanResult{
		{
			ProjectID: "project-1",
			Network: &analysis.NetworkInfo{
				Firewall: []*analysis.FirewallRule{
					{
						Name:         "allow-ssh",
						Dir:          "INGRESS",
						SourceRanges: []string{"0.0.0.0/0"},
						Allowed: []*analysis.AllowedRule{
							{IPProtocol: "tcp", Ports: []string{"22"}},
						},
					},
				},
			},
		},
		{
			ProjectID: "project-2",
			Network:   &analysis.NetworkInfo{},
		},
	}

	findings := analyzer.AnalyzeAll(results)

	if len(findings) < 1 {
		t.Errorf("expected at least 1 finding, got %d", len(findings))
	}
}
