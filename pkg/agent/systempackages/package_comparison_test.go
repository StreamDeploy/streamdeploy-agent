package systempackages

import (
	"fmt"
	"testing"
)

// Test package comparison logic with "any" version handling
func TestPackageComparisonWithAnyVersion(t *testing.T) {
	tests := []struct {
		name            string
		currentState    []string
		desiredState    []string
		expectedDestroy []string
		expectedCreate  []string
		description     string
	}{
		{
			name:            "any_vs_specific_version",
			currentState:    []string{"nginx=1.2.3", "curl=7.68.0"},
			desiredState:    []string{"nginx=any", "curl"},
			expectedDestroy: []string{},
			expectedCreate:  []string{},
			description:     "Desired state has 'any' version, current state has specific version - should be considered the same",
		},
		{
			name:            "specific_vs_any_version",
			currentState:    []string{"nginx=any", "curl"},
			desiredState:    []string{"nginx=1.2.3", "curl"},
			expectedDestroy: []string{"nginx"},
			expectedCreate:  []string{"nginx=1.2.3"},
			description:     "Desired state has specific version, current state has 'any' version - should destroy 'any' and create specific",
		},
		{
			name:            "different_specific_versions",
			currentState:    []string{"nginx=1.2.3", "curl=7.68.0"},
			desiredState:    []string{"nginx=1.2.4", "curl=7.68.0"},
			expectedDestroy: []string{"nginx=1.2.3"},
			expectedCreate:  []string{"nginx=1.2.4"},
			description:     "Both have specific versions that differ - should destroy old and create new",
		},
		{
			name:            "both_any_versions",
			currentState:    []string{"nginx=any", "curl=any"},
			desiredState:    []string{"nginx=any", "curl=any"},
			expectedDestroy: []string{},
			expectedCreate:  []string{},
			description:     "Both have 'any' version - should be considered the same",
		},
		{
			name:            "mixed_scenarios",
			currentState:    []string{"nginx=1.2.3", "curl=any", "apache=2.4.0"},
			desiredState:    []string{"nginx=any", "curl=7.68.0", "apache=2.4.1"},
			expectedDestroy: []string{"curl", "apache=2.4.0"},
			expectedCreate:  []string{"curl=7.68.0", "apache=2.4.1"},
			description:     "Mixed scenarios with different version requirements",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			toDestroy, toCreate := CompareStates(tt.currentState, tt.desiredState)

			// Check destroy list
			if len(toDestroy) != len(tt.expectedDestroy) {
				t.Errorf("Expected %d packages to destroy, got %d", len(tt.expectedDestroy), len(toDestroy))
				t.Errorf("Expected: %v", tt.expectedDestroy)
				t.Errorf("Got: %v", toDestroy)
			} else {
				for i, expected := range tt.expectedDestroy {
					if i >= len(toDestroy) || toDestroy[i] != expected {
						t.Errorf("Expected destroy[%d] = %s, got %s", i, expected, toDestroy[i])
					}
				}
			}

			// Check create list
			if len(toCreate) != len(tt.expectedCreate) {
				t.Errorf("Expected %d packages to create, got %d", len(tt.expectedCreate), len(toCreate))
				t.Errorf("Expected: %v", tt.expectedCreate)
				t.Errorf("Got: %v", toCreate)
			} else {
				for i, expected := range tt.expectedCreate {
					if i >= len(toCreate) || toCreate[i] != expected {
						t.Errorf("Expected create[%d] = %s, got %s", i, expected, toCreate[i])
					}
				}
			}

			t.Logf("✓ %s", tt.description)
		})
	}
}

// Test parsePackageString function with "any" version
func TestParsePackageStringWithAnyVersion(t *testing.T) {
	tests := []struct {
		input              string
		expectedName       string
		expectedVersion    string
		expectedHasVersion bool
	}{
		{"nginx=any", "nginx", "any", false},
		{"nginx=1.2.3", "nginx", "1.2.3", true},
		{"nginx", "nginx", "", false},
		{"curl=7.68.0", "curl", "7.68.0", true},
		{"apache==2.4.0", "apache", "2.4.0", true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := parsePackageString(tt.input)

			if result.Name != tt.expectedName {
				t.Errorf("Expected name %s, got %s", tt.expectedName, result.Name)
			}
			if result.Version != tt.expectedVersion {
				t.Errorf("Expected version %s, got %s", tt.expectedVersion, result.Version)
			}
			if result.HasVersion != tt.expectedHasVersion {
				t.Errorf("Expected HasVersion %v, got %v", tt.expectedHasVersion, result.HasVersion)
			}
		})
	}
}

// Helper function to run the comparison (same logic as in manager.go)
func CompareStates(currentState, desiredState []string) ([]string, []string) {
	// Parse both states
	currentParsed := make(map[string]PackageInfo)
	for _, pkg := range currentState {
		info := parsePackageString(pkg)
		currentParsed[info.Name] = info
	}

	desiredParsed := make(map[string]PackageInfo)
	for _, pkg := range desiredState {
		info := parsePackageString(pkg)
		desiredParsed[info.Name] = info
	}

	var toDestroy, toCreate []string

	// Find packages to destroy (in current but not in desired)
	for name := range currentParsed {
		if _, exists := desiredParsed[name]; !exists {
			toDestroy = append(toDestroy, name)
		}
	}

	// Find packages to create or handle version mismatches
	for name, desiredInfo := range desiredParsed {
		if currentInfo, exists := currentParsed[name]; exists {
			// Package exists, check if version needs change
			if desiredInfo.HasVersion && desiredInfo.Version != "any" {
				// Desired state has a specific version requirement (not "any")
				if currentInfo.HasVersion && currentInfo.Version != desiredInfo.Version {
					// Version mismatch - destroy current version and create desired version
					toDestroy = append(toDestroy, fmt.Sprintf("%s=%s", name, currentInfo.Version))
					toCreate = append(toCreate, fmt.Sprintf("%s=%s", name, desiredInfo.Version))
				} else if !currentInfo.HasVersion || currentInfo.Version == "any" {
					// Current package has no version or "any" version but desired state requires specific version
					// Destroy the unversioned/any package and create the versioned one
					if currentInfo.HasVersion && currentInfo.Version == "any" {
						toDestroy = append(toDestroy, fmt.Sprintf("%s=any", name))
					} else {
						toDestroy = append(toDestroy, name)
					}
					toCreate = append(toCreate, fmt.Sprintf("%s=%s", name, desiredInfo.Version))
				}
				// If both have versions and they match, no action needed
			} else {
				// Desired state has no version or version="any" (any version acceptable)
				// No action needed - current version (whether specific or "any") is acceptable
			}
		} else {
			// Package doesn't exist - needs creation
			if desiredInfo.HasVersion && desiredInfo.Version != "any" {
				toCreate = append(toCreate, fmt.Sprintf("%s=%s", name, desiredInfo.Version))
			} else {
				toCreate = append(toCreate, name)
			}
		}
	}

	return toDestroy, toCreate
}
