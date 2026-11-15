package iam

import (
	"testing"
)

func TestExtractEmail(t *testing.T) {
	tests := []struct {
		name   string
		member string
		want   string
	}{
		{"user", "user:admin@example.com", "admin@example.com"},
		{"service account", "serviceAccount:sa@project.iam.gserviceaccount.com", "sa@project.iam.gserviceaccount.com"},
		{"group", "group:team@example.com", "team@example.com"},
		{"allUsers", "allUsers", ""},
		{"allAuthenticatedUsers", "allAuthenticatedUsers", ""},
		{"unknown", "unknown:format", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractEmail(tt.member)
			if got != tt.want {
				t.Errorf("extractEmail(%q) = %q, want %q", tt.member, got, tt.want)
			}
		})
	}
}

func TestIsExternalDomain(t *testing.T) {
	tests := []struct {
		name  string
		email string
		want  bool
	}{
		{"google internal", "user@google.com", false},
		{"google short domain", "user@g.co", false},
		{"abc.xyz", "user@abc.xyz", false},
		{"empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isExternalDomain(tt.email)
			if got != tt.want {
				t.Errorf("isExternalDomain(%q) = %v, want %v", tt.email, got, tt.want)
			}
		})
	}
}

func TestParseTimestamp(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantZero bool
	}{
		{"valid RFC3339", "2024-01-01T00:00:00Z", false},
		{"invalid format", "not-a-date", true},
		{"empty", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseTimestamp(tt.input)
			if tt.wantZero && !got.IsZero() {
				t.Errorf("parseTimestamp(%q) = %v, want zero time", tt.input, got)
			}
			if !tt.wantZero && got.IsZero() {
				t.Errorf("parseTimestamp(%q) = zero time, want valid time", tt.input)
			}
		})
	}
}
