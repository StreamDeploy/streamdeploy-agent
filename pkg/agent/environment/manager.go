package environment

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/StreamDeploy/streamdeploy-agent/pkg/core/types"
)

// Manager implements system-wide environment variable management
type Manager struct {
	logger types.Logger
}

// NewManager creates a new environment manager
func NewManager(logger types.Logger) *Manager {
	return &Manager{
		logger: logger,
	}
}

// DetectCurrentState detects the current state of environment variables based on desired state
// For env vars, find if the env vars declared in desired state exist.
// If they don't exist, don't add them to currentState
func (m *Manager) DetectCurrentState(desiredState *types.StateConfig) map[string]string {
	if desiredState == nil {
		return map[string]string{}
	}

	currentEnv := make(map[string]string)

	// Get current system environment
	systemEnv, err := m.GetCurrentSystemEnvironment()
	if err != nil {
		// If we can't get system environment, return empty map
		return currentEnv
	}

	// Check each desired environment variable
	for key, expectedValue := range desiredState.Env {
		if actualValue, exists := systemEnv[key]; exists && actualValue == expectedValue {
			currentEnv[key] = actualValue
		}
	}

	return currentEnv
}

// CompareStates compares current state with desired state and returns what needs to be destroyed and created
// For environment variables, we only track what's in desired state (like package managers)
func (m *Manager) CompareStates(currentState, desiredState map[string]string) (map[string]string, map[string]string) {
	var toDestroy, toCreate map[string]string

	// Find variables to destroy (in current but not in desired)
	for key, currentValue := range currentState {
		if _, exists := desiredState[key]; !exists {
			// Variable exists in current but not in desired - needs to be destroyed
			if toDestroy == nil {
				toDestroy = make(map[string]string)
			}
			toDestroy[key] = currentValue
		}
	}

	// Find variables to create or update (in desired)
	for key, desiredValue := range desiredState {
		if currentValue, exists := currentState[key]; !exists || currentValue != desiredValue {
			// Variable doesn't exist or has different value - needs to be created/updated
			if toCreate == nil {
				toCreate = make(map[string]string)
			}
			toCreate[key] = desiredValue
		}
	}

	return toDestroy, toCreate
}

// Destroy removes environment variables that are no longer needed
func (m *Manager) Destroy(variables map[string]string) error {
	if len(variables) == 0 {
		return nil
	}

	m.logger.Infof("Destroying %d environment variable(s)", len(variables))

	// Get current environment variables
	currentEnv, err := m.GetCurrentSystemEnvironment()
	if err != nil {
		m.logger.Errorf("Failed to get current environment: %v", err)
		// Continue anyway as we still want to try removing the variables
	}

	// Calculate remaining variables after removal
	remainingVars := make(map[string]string)
	for key, value := range currentEnv {
		if _, shouldDelete := variables[key]; !shouldDelete {
			remainingVars[key] = value
		}
	}

	m.logger.Infof("After removal, %d variable(s) will remain", len(remainingVars))

	// If no variables remain, remove all files completely
	if len(remainingVars) == 0 {
		return m.RemoveSystemEnvironment()
	}

	// Otherwise, update all files with remaining variables
	// Update /etc/environment
	if err := m.updateEtcEnvironment(remainingVars); err != nil {
		m.logger.Errorf("Failed to update /etc/environment: %v", err)
		return fmt.Errorf("failed to update /etc/environment: %w", err)
	}

	// Update /etc/profile.d/
	if err := m.updateProfileD(remainingVars); err != nil {
		m.logger.Errorf("Failed to update profile.d: %v", err)
		return fmt.Errorf("failed to update profile.d: %w", err)
	}

	// Update systemd environment
	if err := m.updateSystemdEnvironment(remainingVars); err != nil {
		m.logger.Errorf("Failed to update systemd environment: %v", err)
		// Don't return error as this is not critical
	}

	m.logger.Info("Successfully destroyed environment variables")
	return nil
}

// Create sets new environment variables
func (m *Manager) Create(variables map[string]string) error {
	if len(variables) == 0 {
		return nil
	}

	m.logger.Info("Creating environment variables")

	// Update /etc/environment for system-wide variables
	if err := m.updateEtcEnvironment(variables); err != nil {
		m.logger.Errorf("Failed to update /etc/environment: %v", err)
		return fmt.Errorf("failed to update /etc/environment: %w", err)
	}

	// Update /etc/profile.d/ for shell sessions
	if err := m.updateProfileD(variables); err != nil {
		m.logger.Errorf("Failed to update profile.d: %v", err)
		return fmt.Errorf("failed to update profile.d: %w", err)
	}

	// Update systemd environment for services
	if err := m.updateSystemdEnvironment(variables); err != nil {
		m.logger.Errorf("Failed to update systemd environment: %v", err)
		// Don't return error as this is not critical
	}

	m.logger.Info("Successfully created environment variables")
	return nil
}

// Update modifies existing environment variables
func (m *Manager) Update(variables map[string]string) error {
	if len(variables) == 0 {
		return nil
	}

	m.logger.Info("Updating environment variables")

	// Update /etc/environment for system-wide variables
	if err := m.updateEtcEnvironment(variables); err != nil {
		m.logger.Errorf("Failed to update /etc/environment: %v", err)
		return fmt.Errorf("failed to update /etc/environment: %w", err)
	}

	// Update /etc/profile.d/ for shell sessions
	if err := m.updateProfileD(variables); err != nil {
		m.logger.Errorf("Failed to update profile.d: %v", err)
		return fmt.Errorf("failed to update profile.d: %w", err)
	}

	// Update systemd environment for services
	if err := m.updateSystemdEnvironment(variables); err != nil {
		m.logger.Errorf("Failed to update systemd environment: %v", err)
		// Don't return error as this is not critical
	}

	m.logger.Info("Successfully updated environment variables")
	return nil
}

// SyncSystemEnvironment synchronizes system-wide environment variables
func (m *Manager) SyncSystemEnvironment(envVars map[string]string) (map[string]string, bool, error) {
	m.logger.Info("Synchronizing system-wide environment variables")

	// Check if changes are needed by comparing with current state
	currentEnv, err := m.GetCurrentSystemEnvironment()
	if err != nil {
		m.logger.Errorf("Failed to get current environment: %v", err)
		// Continue with sync even if we can't get current state
	}

	// If desired state is empty but current state has variables, we need to remove them
	if len(envVars) == 0 {
		if len(currentEnv) > 0 {
			m.logger.Info("Desired state is empty, removing all environment variables")
			if err := m.RemoveSystemEnvironment(); err != nil {
				m.logger.Errorf("Failed to remove environment variables: %v", err)
				return envVars, true, err
			}
			m.logger.Info("All environment variables removed successfully")
			return envVars, true, nil
		}
		m.logger.Info("No environment variables to sync - desired and current states are both empty")
		return envVars, false, nil
	}

	changesMade := false
	// Check if any values changed or if variables need to be added/removed
	if len(currentEnv) != len(envVars) {
		changesMade = true
	} else {
		for key, desiredValue := range envVars {
			if currentValue, exists := currentEnv[key]; !exists || currentValue != desiredValue {
				changesMade = true
				break
			}
		}
	}

	// Update /etc/environment for system-wide variables
	if err := m.updateEtcEnvironment(envVars); err != nil {
		m.logger.Errorf("Failed to update /etc/environment: %v", err)
		return envVars, changesMade, err
	}

	// Update /etc/profile.d/ for shell sessions
	if err := m.updateProfileD(envVars); err != nil {
		m.logger.Errorf("Failed to update profile.d: %v", err)
		return envVars, changesMade, err
	}

	// Update systemd environment for services
	if err := m.updateSystemdEnvironment(envVars); err != nil {
		m.logger.Errorf("Failed to update systemd environment: %v", err)
		// Don't return error as this is not critical
	}

	if changesMade {
		m.logger.Info("System environment variables synchronized successfully with changes")
	} else {
		m.logger.Info("System environment variables synchronized successfully - no changes needed")
	}
	return envVars, changesMade, nil
}

// GetCurrentSystemEnvironment retrieves current system environment variables
func (m *Manager) GetCurrentSystemEnvironment() (map[string]string, error) {
	envVars := make(map[string]string)

	// Read from /etc/environment
	if data, err := os.ReadFile("/etc/environment"); err == nil {
		lines := strings.Split(string(data), "\n")
		inStreamDeploySection := false

		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "# StreamDeploy Agent Environment Variables" {
				inStreamDeploySection = true
				continue
			}

			if inStreamDeploySection && strings.Contains(line, "=") && !strings.HasPrefix(line, "#") {
				parts := strings.SplitN(line, "=", 2)
				if len(parts) == 2 {
					envVars[parts[0]] = parts[1]
				}
			}
		}
	}

	return envVars, nil
}

// StateConsolidation performs a complete state consolidation process:
// 1. Calls CompareStates to determine what needs to be done
// 2. Applies Destroy and Create operations
// 3. Reports errors if failed
// 4. Returns the updated current state based on what succeeded
func (m *Manager) StateConsolidation(currentState, desiredState map[string]string) (map[string]string, error) {
	m.logger.Info("Environment variable state consolidation started")
	m.logger.Debugf("Current state: %d variables, Desired state: %d variables", len(currentState), len(desiredState))

	// Step 1: Compare states to determine what needs to be done
	toDestroy, toCreate := m.CompareStates(currentState, desiredState)
	m.logger.Debugf("State comparison: %d to destroy, %d to create", len(toDestroy), len(toCreate))

	// Step 2: Apply changes if needed
	if len(toDestroy) > 0 || len(toCreate) > 0 {
		m.logger.Info("Applying environment variable changes")

		// Apply changes in the correct order: destroy first, then create
		if len(toDestroy) > 0 {
			if err := m.Destroy(toDestroy); err != nil {
				m.logger.Errorf("Environment variable destroy operation failed: %v", err)
				// Return updated current state even if changes failed
				updatedState := m.updateCurrentStateAfterChanges(currentState, toDestroy, toCreate)
				return updatedState, err
			}
		}

		if len(toCreate) > 0 {
			if err := m.Create(toCreate); err != nil {
				m.logger.Errorf("Environment variable create operation failed: %v", err)
				// Return updated current state even if changes failed
				updatedState := m.updateCurrentStateAfterChanges(currentState, toDestroy, toCreate)
				return updatedState, err
			}
		}

		m.logger.Info("Environment variable changes applied successfully")
	} else {
		m.logger.Debug("No environment variable changes needed")
	}

	// Step 3: Return updated current state based on what succeeded
	updatedCurrentState := m.updateCurrentStateAfterChanges(currentState, toDestroy, toCreate)
	m.logger.Debugf("State consolidation completed. Final state: %d variables", len(updatedCurrentState))

	return updatedCurrentState, nil
}

// updateCurrentStateAfterChanges updates the current state based on successful operations
func (m *Manager) updateCurrentStateAfterChanges(currentState, destroyed, created map[string]string) map[string]string {
	// Create a copy of current state
	result := make(map[string]string)
	for key, value := range currentState {
		result[key] = value
	}

	// Remove destroyed variables
	for key := range destroyed {
		delete(result, key)
	}

	// Add created variables
	for key, value := range created {
		result[key] = value
	}

	return result
}

// RemoveSystemEnvironment removes StreamDeploy environment variables from the system
func (m *Manager) RemoveSystemEnvironment() error {
	m.logger.Info("Removing StreamDeploy environment variables from system")

	// Remove from /etc/environment
	if err := m.removeFromEtcEnvironment(); err != nil {
		m.logger.Errorf("Failed to remove from /etc/environment: %v", err)
	}

	// Remove profile.d script
	profileFile := "/etc/profile.d/streamdeploy.sh"
	if err := os.Remove(profileFile); err != nil {
		if !os.IsNotExist(err) {
			m.logger.Errorf("Failed to remove profile script: %v", err)
		}
	} else {
		m.logger.Infof("Removed profile script: %s", profileFile)
	}

	// Remove systemd environment file
	systemdEnvFile := "/etc/systemd/system.conf.d/streamdeploy-env.conf"
	systemdFileRemoved := false
	if err := os.Remove(systemdEnvFile); err != nil {
		if !os.IsNotExist(err) {
			m.logger.Errorf("Failed to remove systemd environment file: %v", err)
		}
	} else {
		m.logger.Infof("Removed systemd environment file: %s", systemdEnvFile)
		systemdFileRemoved = true
	}

	// Reload systemd configuration if we removed the systemd file
	if systemdFileRemoved {
		if cmd := exec.Command("systemctl", "daemon-reload"); cmd.Run() != nil {
			m.logger.Error("Failed to reload systemd configuration after cleanup")
		} else {
			m.logger.Info("Systemd configuration reloaded successfully")
		}
	}

	m.logger.Info("StreamDeploy environment variables removed from system")
	return nil
}
