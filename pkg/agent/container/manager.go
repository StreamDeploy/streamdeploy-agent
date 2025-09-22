package container

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/StreamDeploy/streamdeploy-agent/pkg/core/types"
)

// Manager implements the ContainerManager interface using Docker CLI
type Manager struct {
	logger types.Logger
}

// NewManager creates a new container manager
func NewManager(logger types.Logger) *Manager {
	return &Manager{
		logger: logger,
	}
}

// DetectCurrentState detects the current state of containers
// Gets all containers (desired + extra) and performs health checks
// If health check fails, adds "failed" to the HealthPath
func (m *Manager) DetectCurrentState(desiredState *types.StateConfig) []types.ContainerConfig {
	var currentContainers []types.ContainerConfig

	// First, use Docker command to list all running containers
	runningContainers, err := m.GetRunningContainers()
	if err != nil {
		m.logger.Errorf("Failed to get running containers: %v", err)
		return currentContainers
	}

	// Create a map of desired containers by name for quick lookup
	var desiredContainerMap map[string]types.ContainerConfig
	if desiredState != nil {
		desiredContainerMap = make(map[string]types.ContainerConfig)
		for _, container := range desiredState.Containers {
			desiredContainerMap[container.Name] = container
		}
	}

	// For each running container, add it to current state with health check
	for _, runningContainer := range runningContainers {
		var containerConfig types.ContainerConfig

		if desiredContainerMap != nil {
			if desiredContainer, exists := desiredContainerMap[runningContainer.Name]; exists {
				// Container exists in desired state, use desired config as base
				containerConfig = desiredContainer
			} else {
				// Container not in desired state, use running state as base
				containerConfig = runningContainer
			}
		} else {
			// No desired state, use running state as base
			containerConfig = runningContainer
		}

		// Perform health check if container has health path and ports
		if containerConfig.HealthPath != "" && len(containerConfig.Ports) > 0 {
			// Use the first port for health check (could be enhanced to support multiple)
			port := containerConfig.Ports[0].ContainerPort
			containerInfo := &types.ContainerInfo{
				Name:       containerConfig.Name,
				Port:       port,
				HealthPath: containerConfig.HealthPath,
			}

			// Perform health check
			healthCheckPassed := m.PerformHealthCheck(containerInfo)
			if !healthCheckPassed {
				// Add "failed" to the health path to indicate health check failure
				containerConfig.HealthPath = containerConfig.HealthPath + " failed"
			}
		}

		currentContainers = append(currentContainers, containerConfig)
	}

	return currentContainers
}

// CompareStates compares current and desired states
// Compares every single field in ContainerConfig and returns lists to destroy and create
// For containers, update is done by destroy + create
func (m *Manager) CompareStates(currentState, desiredState []types.ContainerConfig) ([]types.ContainerConfig, []types.ContainerConfig) {
	// Create maps for easier lookup
	currentMap := make(map[string]types.ContainerConfig)
	desiredMap := make(map[string]types.ContainerConfig)

	for _, config := range currentState {
		currentMap[config.Name] = config
	}

	for _, config := range desiredState {
		desiredMap[config.Name] = config
	}

	var toDestroy, toCreate []types.ContainerConfig

	// Process all current containers
	for name, currentConfig := range currentMap {
		if desiredConfig, exists := desiredMap[name]; exists {
			// Container exists in both current and desired states
			// Compare every field to determine if recreation is needed
			if !m.configsEqual(currentConfig, desiredConfig) {
				// Configuration differs - destroy current and create desired
				toDestroy = append(toDestroy, currentConfig)
				toCreate = append(toCreate, desiredConfig)
				m.logger.Debugf("Container %s needs recreation due to configuration differences", name)
			} else {
				m.logger.Debugf("Container %s configuration matches, no action needed", name)
			}
		} else {
			// Container exists in current but not in desired - destroy it
			toDestroy = append(toDestroy, currentConfig)
			m.logger.Debugf("Container %s no longer needed, marked for destruction", name)
		}
	}

	// Process desired containers that don't exist in current state
	for name, desiredConfig := range desiredMap {
		if _, exists := currentMap[name]; !exists {
			// Container exists in desired but not in current - create it
			toCreate = append(toCreate, desiredConfig)
			m.logger.Debugf("Container %s needs to be created", name)
		}
	}

	return toDestroy, toCreate
}

// Destroy removes containers that are no longer needed
func (m *Manager) Destroy(containers []types.ContainerConfig) error {
	for _, config := range containers {
		m.logger.Infof("Destroying container: %s", config.Name)

		// Stop container if running
		if m.IsContainerRunning(config.Name) {
			if err := m.StopContainer(config.Name); err != nil {
				m.logger.Errorf("Failed to stop container %s: %v", config.Name, err)
				return fmt.Errorf("failed to stop container %s: %w", config.Name, err)
			}
		}

		// Remove container
		if err := m.removeContainer(config.Name); err != nil {
			m.logger.Errorf("Failed to remove container %s: %v", config.Name, err)
			return fmt.Errorf("failed to remove container %s: %w", config.Name, err)
		}

		m.logger.Infof("Successfully destroyed container: %s", config.Name)
	}

	return nil
}

// Create starts new containers
func (m *Manager) Create(containers []types.ContainerConfig) error {
	for _, config := range containers {
		m.logger.Infof("Creating container: %s", config.Name)

		if err := m.StartContainer(&config); err != nil {
			m.logger.Errorf("Failed to create container %s: %v", config.Name, err)
			return fmt.Errorf("failed to create container %s: %w", config.Name, err)
		}

		m.logger.Infof("Successfully created container: %s", config.Name)
	}

	return nil
}

// Update recreates containers with updated configuration
func (m *Manager) Update(containers []types.ContainerConfig) error {
	for _, config := range containers {
		m.logger.Infof("Updating container: %s", config.Name)

		// Stop and remove existing container
		if m.IsContainerRunning(config.Name) {
			if err := m.StopContainer(config.Name); err != nil {
				m.logger.Errorf("Failed to stop container %s: %v", config.Name, err)
			}
		}

		if m.containerExists(config.Name) {
			if err := m.removeContainer(config.Name); err != nil {
				m.logger.Errorf("Failed to remove container %s: %v", config.Name, err)
			}
		}

		// Start container with new configuration
		if err := m.StartContainer(&config); err != nil {
			m.logger.Errorf("Failed to update container %s: %v", config.Name, err)
			return fmt.Errorf("failed to update container %s: %w", config.Name, err)
		}

		m.logger.Infof("Successfully updated container: %s", config.Name)
	}

	return nil
}

// IsContainerRunning checks if a container is currently running
func (m *Manager) IsContainerRunning(name string) bool {
	cmd := exec.Command("docker", "ps", "--filter", fmt.Sprintf("name=%s", name), "--format", "{{.Names}}")
	output, err := cmd.Output()
	if err != nil {
		m.logger.Errorf("Failed to check container status: %v", err)
		return false
	}

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	for _, line := range lines {
		if strings.TrimSpace(line) == name {
			return true
		}
	}
	return false
}

// PerformHealthCheck performs a health check on a container
func (m *Manager) PerformHealthCheck(container *types.ContainerInfo) bool {
	if container == nil {
		return false
	}

	// First check if container is running
	if !m.IsContainerRunning(container.Name) {
		m.logger.Errorf("Container %s is not running", container.Name)
		return false
	}

	// If health path is specified, perform HTTP health check
	if container.HealthPath != "" && container.Port > 0 {
		// Use curl to perform health check
		url := fmt.Sprintf("http://localhost:%d%s", container.Port, container.HealthPath)
		cmd := exec.Command("curl", "-f", "-s", "--max-time", "5", url)

		err := cmd.Run()
		if err != nil {
			m.logger.Errorf("Health check failed for container %s at %s: %v", container.Name, url, err)
			return false
		}

		m.logger.Debugf("Health check passed for container %s at %s", container.Name, url)
		return true
	}

	// If no health path specified, just check if container is running
	m.logger.Debugf("Container %s is running (no health path specified)", container.Name)
	return true
}

// EnsureContainersRunning ensures all specified containers are running
func (m *Manager) EnsureContainersRunning(configs []types.ContainerConfig) error {
	for _, config := range configs {
		if err := m.StartContainer(&config); err != nil {
			m.logger.Errorf("Failed to ensure container %s is running: %v", config.Name, err)
			return err
		}
	}
	return nil
}

// StateConsolidation performs a complete state consolidation process:
// 1. Calls CompareStates to determine what needs to be done
// 2. Applies Destroy and Create operations (no update for containers)
// 3. Reports errors if failed
// 4. Returns the updated current state based on what succeeded
func (m *Manager) StateConsolidation(currentState, desiredState []types.ContainerConfig) ([]types.ContainerConfig, error) {
	m.logger.Info("Container state consolidation started")
	m.logger.Debugf("Current state: %d containers, Desired state: %d containers", len(currentState), len(desiredState))

	// Step 1: Compare states to determine what needs to be done
	toDestroy, toCreate := m.CompareStates(currentState, desiredState)
	m.logger.Debugf("State comparison: %d to destroy, %d to create", len(toDestroy), len(toCreate))

	// Step 2: Apply changes if needed
	if len(toDestroy) > 0 || len(toCreate) > 0 {
		m.logger.Info("Applying container changes")

		// Apply changes in the correct order: destroy first, then create
		if len(toDestroy) > 0 {
			if err := m.Destroy(toDestroy); err != nil {
				m.logger.Errorf("Container destroy operation failed: %v", err)
				// Return updated current state even if changes failed
				updatedState := m.updateCurrentStateAfterChanges(currentState, toDestroy, toCreate)
				return updatedState, err
			}
		}

		if len(toCreate) > 0 {
			if err := m.Create(toCreate); err != nil {
				m.logger.Errorf("Container create operation failed: %v", err)
				// Return updated current state even if changes failed
				updatedState := m.updateCurrentStateAfterChanges(currentState, toDestroy, toCreate)
				return updatedState, err
			}
		}

		m.logger.Info("Container changes applied successfully")
	} else {
		m.logger.Debug("No container changes needed")
	}

	// Step 3: Return updated current state based on what succeeded
	updatedCurrentState := m.updateCurrentStateAfterChanges(currentState, toDestroy, toCreate)
	m.logger.Debugf("State consolidation completed. Final state: %d containers", len(updatedCurrentState))

	return updatedCurrentState, nil
}

// updateCurrentStateAfterChanges updates the current state based on successful operations
func (m *Manager) updateCurrentStateAfterChanges(currentState, destroyed, created []types.ContainerConfig) []types.ContainerConfig {
	// Create a map of current containers by name
	currentMap := make(map[string]types.ContainerConfig)
	for _, container := range currentState {
		currentMap[container.Name] = container
	}

	// Remove destroyed containers
	for _, container := range destroyed {
		delete(currentMap, container.Name)
	}

	// Add created containers
	for _, container := range created {
		currentMap[container.Name] = container
	}

	// Convert back to slice
	var result []types.ContainerConfig
	for _, container := range currentMap {
		result = append(result, container)
	}

	return result
}
