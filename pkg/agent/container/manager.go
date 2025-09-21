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
// For Docker containers, list all running containers and for those that exist in desired state,
// add the extra fields from desired state. For containers not in desired state, include them as-is.
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

	// For each running container, add it to current state
	for _, runningContainer := range runningContainers {
		if desiredContainerMap != nil {
			if desiredContainer, exists := desiredContainerMap[runningContainer.Name]; exists {
				// Container exists in desired state, add it with all fields from desired state
				currentContainers = append(currentContainers, types.ContainerConfig{
					Name:       desiredContainer.Name,
					Image:      desiredContainer.Image,
					Port:       desiredContainer.Port,
					HealthPath: desiredContainer.HealthPath,
					Env:        desiredContainer.Env,
				})
			} else {
				// Container not in desired state, add it as-is from running state
				currentContainers = append(currentContainers, runningContainer)
			}
		} else {
			// No desired state, add all running containers as-is
			currentContainers = append(currentContainers, runningContainer)
		}
	}

	return currentContainers
}

// CompareStates compares current state with desired state and returns what needs to be destroyed, created, or updated
func (m *Manager) CompareStates(currentState, desiredState []types.ContainerConfig) ([]types.ContainerConfig, []types.ContainerConfig, []types.ContainerConfig) {
	// Create maps for easier lookup
	currentMap := make(map[string]types.ContainerConfig)
	desiredMap := make(map[string]types.ContainerConfig)

	for _, config := range currentState {
		currentMap[config.Name] = config
	}

	for _, config := range desiredState {
		desiredMap[config.Name] = config
	}

	var toDestroy, toCreate, toUpdate []types.ContainerConfig

	// Find containers to destroy (in current but not in desired)
	for name, currentConfig := range currentMap {
		if _, exists := desiredMap[name]; !exists {
			toDestroy = append(toDestroy, currentConfig)
		}
	}

	// Find containers to create or update (in desired)
	for name, desiredConfig := range desiredMap {
		if currentConfig, exists := currentMap[name]; exists {
			// Container exists, check if it needs updating
			if !m.configsEqual(currentConfig, desiredConfig) {
				toUpdate = append(toUpdate, desiredConfig)
			}
		} else {
			// Container doesn't exist, needs to be created
			toCreate = append(toCreate, desiredConfig)
		}
	}

	return toDestroy, toCreate, toUpdate
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

// StartContainer starts a container with the given configuration
func (m *Manager) StartContainer(config *types.ContainerConfig) error {
	if config == nil {
		return fmt.Errorf("container config is nil")
	}

	m.logger.Infof("Starting container: %s", config.Name)

	// Check if container already exists
	if m.containerExists(config.Name) {
		// If it exists but not running, start it
		if !m.IsContainerRunning(config.Name) {
			cmd := exec.Command("docker", "start", config.Name)
			if err := cmd.Run(); err != nil {
				return fmt.Errorf("failed to start existing container %s: %w", config.Name, err)
			}
			m.logger.Infof("Started existing container: %s", config.Name)
			return nil
		}
		m.logger.Infof("Container %s is already running", config.Name)
		return nil
	}

	// Build docker run command
	args := []string{"run", "-d", "--name", config.Name}

	// Add port mapping if specified
	if config.Port > 0 {
		args = append(args, "-p", fmt.Sprintf("%d:%d", config.Port, config.Port))
	}

	// Add environment variables
	for key, value := range config.Env {
		args = append(args, "-e", fmt.Sprintf("%s=%s", key, value))
	}

	// Add restart policy
	args = append(args, "--restart", "unless-stopped")

	// Add image
	args = append(args, config.Image)

	// Execute docker run command
	cmd := exec.Command("docker", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to start container %s: %w, output: %s", config.Name, err, string(output))
	}

	m.logger.Infof("Successfully started container: %s", config.Name)
	return nil
}

// StopContainer stops a running container
func (m *Manager) StopContainer(name string) error {
	if !m.IsContainerRunning(name) {
		m.logger.Infof("Container %s is not running", name)
		return nil
	}

	m.logger.Infof("Stopping container: %s", name)

	cmd := exec.Command("docker", "stop", name)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to stop container %s: %w, output: %s", name, err, string(output))
	}

	m.logger.Infof("Successfully stopped container: %s", name)
	return nil
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
		return m.performHTTPHealthCheck(container)
	}

	// If no health path specified, just check if container is running
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

// SyncContainers synchronizes containers based on new and old configurations
func (m *Manager) SyncContainers(newConfigs, oldConfigs []types.ContainerConfig) (bool, error) {
	// Check if there are any actual changes needed
	hasChanges := false

	// Create maps for easier lookup
	newConfigMap := make(map[string]types.ContainerConfig)
	oldConfigMap := make(map[string]types.ContainerConfig)

	for _, config := range newConfigs {
		newConfigMap[config.Name] = config
	}

	for _, config := range oldConfigs {
		oldConfigMap[config.Name] = config
	}

	// Check for containers to remove
	for name := range oldConfigMap {
		if _, exists := newConfigMap[name]; !exists {
			hasChanges = true
			break
		}
	}

	// Check for containers to add or update
	if !hasChanges {
		for name, newConfig := range newConfigMap {
			oldConfig, exists := oldConfigMap[name]
			if !exists || !m.configsEqual(oldConfig, newConfig) {
				hasChanges = true
				break
			}
		}
	}

	// If no changes needed, return early
	if !hasChanges {
		return false, nil
	}

	m.logger.Info("Synchronizing containers")

	// Stop and remove containers that are no longer needed
	for name := range oldConfigMap {
		if _, exists := newConfigMap[name]; !exists {
			m.logger.Infof("Removing container: %s", name)
			if err := m.StopContainer(name); err != nil {
				m.logger.Errorf("Failed to stop container %s: %v", name, err)
			}
			if err := m.removeContainer(name); err != nil {
				m.logger.Errorf("Failed to remove container %s: %v", name, err)
			}
		}
	}

	// Start or update containers
	for name, newConfig := range newConfigMap {
		oldConfig, exists := oldConfigMap[name]

		if !exists {
			// New container, start it
			m.logger.Infof("Starting new container: %s", name)
			if err := m.StartContainer(&newConfig); err != nil {
				return true, fmt.Errorf("failed to start new container %s: %w", name, err)
			}
		} else if !m.configsEqual(oldConfig, newConfig) {
			// Configuration changed, recreate container
			m.logger.Infof("Recreating container with updated config: %s", name)
			if err := m.StopContainer(name); err != nil {
				m.logger.Errorf("Failed to stop container %s: %v", name, err)
			}
			if err := m.removeContainer(name); err != nil {
				m.logger.Errorf("Failed to remove container %s: %v", name, err)
			}
			if err := m.StartContainer(&newConfig); err != nil {
				return true, fmt.Errorf("failed to recreate container %s: %w", name, err)
			}
		} else {
			// Configuration unchanged, ensure it's running
			if err := m.StartContainer(&newConfig); err != nil {
				return true, fmt.Errorf("failed to ensure container %s is running: %w", name, err)
			}
		}
	}

	m.logger.Info("Container synchronization completed")
	return true, nil
}

// CheckContainerDrift checks if containers are in the desired state without logging synchronization messages
func (m *Manager) CheckContainerDrift(configs []types.ContainerConfig) (bool, []types.ContainerConfig) {
	var driftedContainers []types.ContainerConfig

	for _, config := range configs {
		// Check if container is running
		if !m.IsContainerRunning(config.Name) {
			driftedContainers = append(driftedContainers, config)
			continue
		}

		// If health path is provided, perform health check
		if config.HealthPath != "" && config.Port > 0 {
			containerInfo := &types.ContainerInfo{
				Name:       config.Name,
				Image:      config.Image,
				Port:       config.Port,
				HealthPath: config.HealthPath,
				Running:    true,
			}

			if !m.PerformHealthCheck(containerInfo) {
				driftedContainers = append(driftedContainers, config)
			}
		}
	}

	return len(driftedContainers) > 0, driftedContainers
}

// GetCurrentContainerState returns the current container state merged with desired state
func (m *Manager) GetCurrentContainerState(desiredState *types.StateConfig) []types.ContainerConfig {
	return m.DetectCurrentState(desiredState)
}
