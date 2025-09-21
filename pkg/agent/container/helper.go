package container

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"github.com/StreamDeploy/streamdeploy-agent/pkg/core/types"
)

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

// GetRunningContainers returns all currently running containers as ContainerConfig
func (m *Manager) GetRunningContainers() ([]types.ContainerConfig, error) {
	// Use docker ps with custom format to get container information
	cmd := exec.Command("docker", "ps", "--format", "{{.Names}}|{{.Image}}|{{.Ports}}|{{.Status}}")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get running containers: %w", err)
	}

	var containers []types.ContainerConfig
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Parse the formatted output: name|image|ports|status
		parts := strings.Split(line, "|")
		if len(parts) < 4 {
			m.logger.Errorf("Invalid container line format: %s", line)
			continue
		}

		name := strings.TrimSpace(parts[0])
		image := strings.TrimSpace(parts[1])
		ports := strings.TrimSpace(parts[2])
		status := strings.TrimSpace(parts[3])

		// Skip if container is not running
		if !strings.Contains(strings.ToLower(status), "up") {
			continue
		}

		// Extract port from ports string (format: "0.0.0.0:8080->8080/tcp")
		port := 0
		if ports != "" && ports != "<none>" {
			// Look for pattern like "0.0.0.0:8080->8080/tcp" or "8080/tcp"
			portParts := strings.Split(ports, "->")
			if len(portParts) > 1 {
				// Format: "0.0.0.0:8080->8080/tcp"
				rightPart := strings.TrimSpace(portParts[1])
				if strings.Contains(rightPart, "/tcp") {
					portStr := strings.Split(rightPart, "/")[0]
					if p, err := strconv.Atoi(portStr); err == nil {
						port = p
					}
				}
			} else if strings.Contains(ports, "/tcp") {
				// Format: "8080/tcp"
				portStr := strings.Split(ports, "/")[0]
				if p, err := strconv.Atoi(portStr); err == nil {
					port = p
				}
			}
		}

		// Create ContainerConfig
		container := types.ContainerConfig{
			Name:       name,
			Image:      image,
			Port:       port,
			HealthPath: "",                  // Will be determined later if needed
			Env:        map[string]string{}, // Environment variables not easily available from docker ps
		}

		containers = append(containers, container)
	}

	return containers, nil
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
