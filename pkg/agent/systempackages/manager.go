package systempackages

import (
	"fmt"
	"sync"

	"github.com/StreamDeploy/streamdeploy-agent/pkg/core/types"
)

// Manager implements the SystemPackageManager interface
type Manager struct {
	logger         types.Logger
	packageManager *types.PackageManagerConfig
	mutex          sync.Mutex // Protects package operations from concurrent access
}

// NewManager creates a new system package manager
func NewManager(logger types.Logger, packageManager *types.PackageManagerConfig) *Manager {
	manager := &Manager{
		logger:         logger,
		packageManager: packageManager,
	}

	// Detect and populate package manager if not provided
	if manager.packageManager == nil {
		manager.packageManager = manager.detectPackageManager()
	}

	return manager
}

// DetectCurrentState detects the current state of system packages
// Runs the command defined in packageManager and sends it through a parser
func (m *Manager) DetectCurrentState(desiredState *types.StateConfig) []string {
	if desiredState == nil || len(desiredState.Packages) == 0 {
		return []string{}
	}

	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.logger.Info("Detecting current system package state")

	// Get system state by running the check command
	systemPackages, err := m.getSystemPackages()
	if err != nil {
		m.logger.Errorf("Failed to get system packages: %v", err)
		return []string{}
	}

	// Parse desired state
	desiredPackages := m.parseDesiredState(desiredState.Packages)

	// Compare and build current state
	currentState := m.buildCurrentState(systemPackages, desiredPackages)

	m.logger.Infof("Detected %d packages in current state", len(currentState))
	return currentState
}

// CompareStates compares current state with desired state and returns what needs to be destroyed and created
func (m *Manager) CompareStates(currentState, desiredState []string) ([]string, []string) {
	// Parse both states
	currentParsed := make(map[string]PackageInfo)
	for _, pkg := range currentState {
		info := parsePackageString(pkg)
		currentParsed[info.Name] = info
	}

	desiredParsed := make(map[string]PackageInfo)
	for _, pkg := range desiredState {
		info := parsePackageString(pkg)
		// Keep HasVersion as false when no version specified - any version is acceptable
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

// Update updates existing system packages to new versions
func (m *Manager) Update(packages []string) error {
	if len(packages) == 0 {
		return nil
	}

	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.logger.Info("Updating system packages")

	// Use bulk install for updates
	if err := m.installPackages(packages); err != nil {
		m.logger.Errorf("Failed to update packages %v: %v", packages, err)
		return fmt.Errorf("failed to update packages %v: %w", packages, err)
	}

	m.logger.Info("Successfully updated system packages")
	return nil
}

// Destroy removes system packages that are no longer needed
func (m *Manager) Destroy(packages []string) error {
	if len(packages) == 0 {
		return nil
	}

	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.logger.Info("Destroying system packages")

	// Use bulk remove for destruction
	if err := m.removePackages(packages); err != nil {
		m.logger.Errorf("Failed to destroy packages %v: %v", packages, err)
		return fmt.Errorf("failed to destroy packages %v: %w", packages, err)
	}

	m.logger.Info("Successfully destroyed system packages")
	return nil
}

// Create installs new system packages
func (m *Manager) Create(packages []string) error {
	if len(packages) == 0 {
		return nil
	}

	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.logger.Info("Creating system packages")

	// Use bulk install for creation
	if err := m.installPackages(packages); err != nil {
		m.logger.Errorf("Failed to create packages %v: %v", packages, err)
		return fmt.Errorf("failed to create packages %v: %w", packages, err)
	}

	m.logger.Info("Successfully created system packages")
	return nil
}

// StateConsolidation performs a complete state consolidation process:
// 1. Calls CompareStates to determine what needs to be done
// 2. Applies Delete or Install operations
// 3. Reports errors if failed
// 4. Returns the updated current state based on what succeeded
func (m *Manager) StateConsolidation(currentState, desiredState []string) ([]string, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.logger.Info("Starting state consolidation for system packages")
	m.logger.Infof("Current state: %d packages, Desired state: %d packages", len(currentState), len(desiredState))

	// Step 1: Compare states to determine what needs to be done
	toDestroy, toCreate := m.CompareStates(currentState, desiredState)
	m.logger.Infof("State comparison: %d to destroy, %d to create", len(toDestroy), len(toCreate))

	// Step 2: Apply changes if needed
	if len(toDestroy) > 0 || len(toCreate) > 0 {
		m.logger.Info("Applying package changes")

		// Apply changes in the correct order: destroy first, then create
		if err := m.ApplyChanges(toDestroy, toCreate); err != nil {
			m.logger.Errorf("Failed to apply package changes: %v", err)
			// Return updated current state even if changes failed, as some operations might have succeeded
			updatedState := m.updateCurrentStateAfterChanges(currentState, toDestroy, toCreate)
			return updatedState, err
		}

		m.logger.Info("Package changes applied successfully")
	} else {
		m.logger.Info("No package changes needed")
	}

	// Step 3: Return updated current state based on what succeeded
	updatedCurrentState := m.updateCurrentStateAfterChanges(currentState, toDestroy, toCreate)
	m.logger.Infof("State consolidation completed. Final state: %d packages", len(updatedCurrentState))

	return updatedCurrentState, nil
}
