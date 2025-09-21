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

// CompareStates compares current state with desired state and returns what needs to be destroyed, created, or updated
func (m *Manager) CompareStates(currentState, desiredState map[string]string) (map[string]string, map[string]string, map[string]string) {
	var toDestroy, toCreate, toUpdate map[string]string

	// Find variables to destroy (in current but not in desired)
	for key, currentValue := range currentState {
		if desiredValue, exists := desiredState[key]; !exists {
			// Variable exists in current but not in desired - needs to be destroyed
			if toDestroy == nil {
				toDestroy = make(map[string]string)
			}
			toDestroy[key] = currentValue
		} else if currentValue != desiredValue {
			// Variable exists in both but values differ - needs to be updated
			if toUpdate == nil {
				toUpdate = make(map[string]string)
			}
			toUpdate[key] = desiredValue
		}
	}

	// Find variables to create (in desired but not in current)
	for key, desiredValue := range desiredState {
		if _, exists := currentState[key]; !exists {
			// Variable exists in desired but not in current - needs to be created
			if toCreate == nil {
				toCreate = make(map[string]string)
			}
			toCreate[key] = desiredValue
		}
	}

	return toDestroy, toCreate, toUpdate
}

// Destroy removes environment variables that are no longer needed
func (m *Manager) Destroy(variables map[string]string) error {
	if len(variables) == 0 {
		return nil
	}

	m.logger.Info("Destroying environment variables")

	// Remove from /etc/environment
	if err := m.removeFromEtcEnvironment(); err != nil {
		m.logger.Errorf("Failed to remove from /etc/environment: %v", err)
		return fmt.Errorf("failed to remove from /etc/environment: %w", err)
	}

	// Remove profile.d script
	profileFile := "/etc/profile.d/streamdeploy.sh"
	if err := os.Remove(profileFile); err != nil && !os.IsNotExist(err) {
		m.logger.Errorf("Failed to remove profile script: %v", err)
		return fmt.Errorf("failed to remove profile script: %w", err)
	} else {
		m.logger.Infof("Removed profile script: %s", profileFile)
	}

	// Remove systemd environment file
	systemdEnvFile := "/etc/systemd/system.conf.d/streamdeploy-env.conf"
	if err := os.Remove(systemdEnvFile); err != nil && !os.IsNotExist(err) {
		m.logger.Errorf("Failed to remove systemd environment file: %v", err)
		return fmt.Errorf("failed to remove systemd environment file: %w", err)
	} else {
		m.logger.Infof("Removed systemd environment file: %s", systemdEnvFile)

		// Reload systemd configuration
		if cmd := exec.Command("systemctl", "daemon-reload"); cmd.Run() != nil {
			m.logger.Error("Failed to reload systemd configuration after cleanup")
		}
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
func (m *Manager) SyncSystemEnvironment(envVars map[string]string) error {
	if len(envVars) == 0 {
		m.logger.Info("No environment variables to sync")
		return nil
	}

	m.logger.Info("Synchronizing system-wide environment variables")

	// Update /etc/environment for system-wide variables
	if err := m.updateEtcEnvironment(envVars); err != nil {
		m.logger.Errorf("Failed to update /etc/environment: %v", err)
		return err
	}

	// Update /etc/profile.d/ for shell sessions
	if err := m.updateProfileD(envVars); err != nil {
		m.logger.Errorf("Failed to update profile.d: %v", err)
		return err
	}

	// Update systemd environment for services
	if err := m.updateSystemdEnvironment(envVars); err != nil {
		m.logger.Errorf("Failed to update systemd environment: %v", err)
		// Don't return error as this is not critical
	}

	m.logger.Info("System environment variables synchronized successfully")
	return nil
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

// RemoveSystemEnvironment removes StreamDeploy environment variables from the system
func (m *Manager) RemoveSystemEnvironment() error {
	m.logger.Info("Removing StreamDeploy environment variables from system")

	// Remove from /etc/environment
	if err := m.removeFromEtcEnvironment(); err != nil {
		m.logger.Errorf("Failed to remove from /etc/environment: %v", err)
	}

	// Remove profile.d script
	profileFile := "/etc/profile.d/streamdeploy.sh"
	if err := os.Remove(profileFile); err != nil && !os.IsNotExist(err) {
		m.logger.Errorf("Failed to remove profile script: %v", err)
	} else {
		m.logger.Infof("Removed profile script: %s", profileFile)
	}

	// Remove systemd environment file
	systemdEnvFile := "/etc/systemd/system.conf.d/streamdeploy-env.conf"
	if err := os.Remove(systemdEnvFile); err != nil && !os.IsNotExist(err) {
		m.logger.Errorf("Failed to remove systemd environment file: %v", err)
	} else {
		m.logger.Infof("Removed systemd environment file: %s", systemdEnvFile)

		// Reload systemd configuration
		if cmd := exec.Command("systemctl", "daemon-reload"); cmd.Run() != nil {
			m.logger.Error("Failed to reload systemd configuration after cleanup")
		}
	}

	return nil
}
