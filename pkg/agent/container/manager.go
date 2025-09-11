package container

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strconv"
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

// SyncContainers synchronizes containers based on new and old configurations
func (m *Manager) SyncContainers(newConfigs, oldConfigs []types.ContainerConfig) error {
	m.logger.Info("Synchronizing containers")

	// Create maps for easier lookup
	newConfigMap := make(map[string]types.ContainerConfig)
	oldConfigMap := make(map[string]types.ContainerConfig)

	for _, config := range newConfigs {
		newConfigMap[config.Name] = config
	}

	for _, config := range oldConfigs {
		oldConfigMap[config.Name] = config
	}

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
				return fmt.Errorf("failed to start new container %s: %w", name, err)
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
				return fmt.Errorf("failed to recreate container %s: %w", name, err)
			}
		} else {
			// Configuration unchanged, ensure it's running
			if err := m.StartContainer(&newConfig); err != nil {
				return fmt.Errorf("failed to ensure container %s is running: %w", name, err)
			}
		}
	}

	m.logger.Info("Container synchronization completed")
	return nil
}

// GetContainerInfo retrieves information about a container
func (m *Manager) GetContainerInfo(name string) (*types.ContainerInfo, error) {
	// Get container details using docker inspect
	cmd := exec.Command("docker", "inspect", name)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to inspect container %s: %w", name, err)
	}

	// Parse JSON output
	var inspectData []map[string]interface{}
	if err := json.Unmarshal(output, &inspectData); err != nil {
		return nil, fmt.Errorf("failed to parse container inspect data: %w", err)
	}

	if len(inspectData) == 0 {
		return nil, fmt.Errorf("no container data found for %s", name)
	}

	containerData := inspectData[0]

	// Extract relevant information
	info := &types.ContainerInfo{
		Name:    name,
		Running: m.IsContainerRunning(name),
		Healthy: true, // Will be updated by health check
	}

	// Extract image
	if config, ok := containerData["Config"].(map[string]interface{}); ok {
		if image, ok := config["Image"].(string); ok {
			info.Image = image
		}
	}

	// Extract port information
	if networkSettings, ok := containerData["NetworkSettings"].(map[string]interface{}); ok {
		if ports, ok := networkSettings["Ports"].(map[string]interface{}); ok {
			for portKey := range ports {
				if strings.Contains(portKey, "/tcp") {
					portStr := strings.Split(portKey, "/")[0]
					if port, err := strconv.Atoi(portStr); err == nil {
						info.Port = port
						break
					}
				}
			}
		}
	}

	return info, nil
}

// ListContainers lists all containers managed by this agent
func (m *Manager) ListContainers() ([]*types.ContainerInfo, error) {
	cmd := exec.Command("docker", "ps", "-a", "--format", "{{.Names}}")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to list containers: %w", err)
	}

	var containers []*types.ContainerInfo
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")

	for _, line := range lines {
		name := strings.TrimSpace(line)
		if name == "" {
			continue
		}

		info, err := m.GetContainerInfo(name)
		if err != nil {
			m.logger.Errorf("Failed to get info for container %s: %v", name, err)
			continue
		}

		containers = append(containers, info)
	}

	return containers, nil
}

// containerExists checks if a container exists (running or stopped)
func (m *Manager) containerExists(name string) bool {
	cmd := exec.Command("docker", "ps", "-a", "--filter", fmt.Sprintf("name=%s", name), "--format", "{{.Names}}")
	output, err := cmd.Output()
	if err != nil {
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

// removeContainer removes a container
func (m *Manager) removeContainer(name string) error {
	cmd := exec.Command("docker", "rm", name)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to remove container %s: %w, output: %s", name, err, string(output))
	}
	return nil
}

// performHTTPHealthCheck performs an HTTP health check
func (m *Manager) performHTTPHealthCheck(container *types.ContainerInfo) bool {
	// Use curl to perform health check
	url := fmt.Sprintf("http://localhost:%d%s", container.Port, container.HealthPath)
	cmd := exec.Command("curl", "-f", "-s", "--max-time", "5", url)

	err := cmd.Run()
	if err != nil {
		m.logger.Errorf("Health check failed for container %s at %s: %v", container.Name, url, err)
		return false
	}

	return true
}

// configsEqual compares two container configurations for equality
func (m *Manager) configsEqual(a, b types.ContainerConfig) bool {
	if a.Name != b.Name || a.Image != b.Image || a.Port != b.Port || a.HealthPath != b.HealthPath {
		return false
	}

	if len(a.Env) != len(b.Env) {
		return false
	}

	for key, value := range a.Env {
		if b.Env[key] != value {
			return false
		}
	}

	return true
}

// PullImage pulls a Docker image
func (m *Manager) PullImage(image string) error {
	m.logger.Infof("Pulling Docker image: %s", image)

	cmd := exec.Command("docker", "pull", image)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to pull image %s: %w, output: %s", image, err, string(output))
	}

	m.logger.Infof("Successfully pulled image: %s", image)
	return nil
}

// GetContainerLogs retrieves logs from a container
func (m *Manager) GetContainerLogs(name string, lines int) (string, error) {
	args := []string{"logs"}
	if lines > 0 {
		args = append(args, "--tail", strconv.Itoa(lines))
	}
	args = append(args, name)

	cmd := exec.Command("docker", args...)
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to get logs for container %s: %w", name, err)
	}

	return string(output), nil
}
