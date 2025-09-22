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

// getExistingContainerConfig retrieves the configuration of an existing container
func (m *Manager) getExistingContainerConfig(name string) (*types.ContainerConfig, error) {
	// Get container details using docker inspect
	cmd := exec.Command("docker", "inspect", name)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to inspect container %s: %w", name, err)
	}

	// Parse JSON output
	var inspectData []map[string]interface{}
	if err := json.Unmarshal(output, &inspectData); err != nil {
		return nil, fmt.Errorf("failed to parse container inspect data for %s: %w", name, err)
	}

	if len(inspectData) == 0 {
		return nil, fmt.Errorf("no container data found for %s", name)
	}

	containerData := inspectData[0]
	config := &types.ContainerConfig{
		Name: name,
		// Initialize maps
		Env:     map[string]string{},
		Labels:  map[string]string{},
		Sysctls: map[string]string{},
	}

	// Extract image
	if configData, ok := containerData["Config"].(map[string]interface{}); ok {
		if image, ok := configData["Image"].(string); ok {
			config.Image = image
		}

		// Extract environment variables
		if envArray, ok := configData["Env"].([]interface{}); ok {
			for _, envVar := range envArray {
				if envStr, ok := envVar.(string); ok {
					parts := strings.SplitN(envStr, "=", 2)
					if len(parts) == 2 {
						config.Env[parts[0]] = parts[1]
					}
				}
			}
		}

		// Extract working directory
		if workingDir, ok := configData["WorkingDir"].(string); ok {
			config.WorkingDir = workingDir
		}

		// Extract user
		if user, ok := configData["User"].(string); ok {
			config.User = user
		}

		// Extract hostname
		if hostname, ok := configData["Hostname"].(string); ok {
			config.Hostname = hostname
		}
	}

	// Extract port mappings
	if networkSettings, ok := containerData["NetworkSettings"].(map[string]interface{}); ok {
		if ports, ok := networkSettings["Ports"].(map[string]interface{}); ok {
			for portKey, portBindings := range ports {
				if strings.Contains(portKey, "/tcp") {
					containerPortStr := strings.Split(portKey, "/")[0]
					if containerPort, err := strconv.Atoi(containerPortStr); err == nil {
						// Get host port from bindings
						hostPort := 0
						if bindings, ok := portBindings.([]interface{}); ok && len(bindings) > 0 {
							if binding, ok := bindings[0].(map[string]interface{}); ok {
								if hostPortStr, ok := binding["HostPort"].(string); ok {
									if hp, err := strconv.Atoi(hostPortStr); err == nil {
										hostPort = hp
									}
								}
							}
						}

						protocol := "tcp"
						if strings.Contains(portKey, "/udp") {
							protocol = "udp"
						}

						config.Ports = append(config.Ports, types.PortMapping{
							HostPort:      hostPort,
							ContainerPort: containerPort,
							Protocol:      protocol,
						})
					}
				}
			}
		}
	}

	// Extract labels
	if configData, ok := containerData["Config"].(map[string]interface{}); ok {
		if labels, ok := configData["Labels"].(map[string]interface{}); ok {
			for key, value := range labels {
				if valueStr, ok := value.(string); ok {
					config.Labels[key] = valueStr
				}
			}
		}
	}

	return config, nil
}

// StartContainer starts a container with the given configuration
func (m *Manager) StartContainer(config *types.ContainerConfig) error {
	if config == nil {
		return fmt.Errorf("container config is nil")
	}

	m.logger.Infof("Starting container: %s", config.Name)

	// Check if container already exists
	if m.containerExists(config.Name) {
		// Get the existing container's configuration
		existingConfig, err := m.getExistingContainerConfig(config.Name)
		if err != nil {
			m.logger.Errorf("Failed to get existing container config for %s: %v", config.Name, err)
			// If we can't get the config, remove the container and recreate it
			m.logger.Infof("Removing container %s due to config retrieval failure", config.Name)
			if err := m.removeContainer(config.Name); err != nil {
				m.logger.Errorf("Failed to remove container %s: %v", config.Name, err)
			}
		} else {
			// Compare configurations
			if m.configsEqual(*existingConfig, *config) {
				// Configurations match, just start if not running
				if !m.IsContainerRunning(config.Name) {
					cmd := exec.Command("docker", "start", config.Name)
					if err := cmd.Run(); err != nil {
						return fmt.Errorf("failed to start existing container %s: %w", config.Name, err)
					}
					m.logger.Infof("Started existing container: %s", config.Name)
					return nil
				}
				m.logger.Infof("Container %s is already running with matching configuration", config.Name)
				return nil
			} else {
				// Configurations differ, need to recreate container
				m.logger.Infof("Container %s exists but has different configuration, recreating...", config.Name)
				if err := m.StopContainer(config.Name); err != nil {
					m.logger.Errorf("Failed to stop container %s: %v", config.Name, err)
				}
				if err := m.removeContainer(config.Name); err != nil {
					m.logger.Errorf("Failed to remove container %s: %v", config.Name, err)
				}
			}
		}
	}

	// Build docker run command
	args := []string{"run", "-d", "--name", config.Name}

	// Add port mappings (multiple port support)
	for _, port := range config.Ports {
		if port.Protocol != "" && port.Protocol != "tcp" {
			args = append(args, "-p", fmt.Sprintf("%d:%d/%s", port.HostPort, port.ContainerPort, port.Protocol))
		} else {
			args = append(args, "-p", fmt.Sprintf("%d:%d", port.HostPort, port.ContainerPort))
		}
	}

	// Add environment variables
	for key, value := range config.Env {
		args = append(args, "-e", fmt.Sprintf("%s=%s", key, value))
	}

	// Add environment file if specified
	if config.EnvFile != "" {
		args = append(args, "--env-file", config.EnvFile)
	}

	// Add volume mounts
	for _, volume := range config.Volumes {
		volumeArg := fmt.Sprintf("%s:%s", volume.Source, volume.Destination)
		if volume.Mode != "" {
			volumeArg += fmt.Sprintf(":%s", volume.Mode)
		}
		args = append(args, "-v", volumeArg)
	}

	// Add working directory
	if config.WorkingDir != "" {
		args = append(args, "-w", config.WorkingDir)
	}

	// Add user
	if config.User != "" {
		args = append(args, "-u", config.User)
	}

	// Add hostname
	if config.Hostname != "" {
		args = append(args, "-h", config.Hostname)
	}

	// Add network mode
	if config.Network != "" {
		args = append(args, "--network", config.Network)
	}

	// Add restart policy
	restartPolicy := "unless-stopped" // default
	if config.Restart != "" {
		restartPolicy = config.Restart
	}
	args = append(args, "--restart", restartPolicy)

	// Add resource limits
	if config.Resources != nil {
		if config.Resources.Memory != "" {
			args = append(args, "--memory", config.Resources.Memory)
		}
		if config.Resources.CPUs != "" {
			args = append(args, "--cpus", config.Resources.CPUs)
		}
		if config.Resources.MemorySwap != "" {
			args = append(args, "--memory-swap", config.Resources.MemorySwap)
		}
		if config.Resources.ShmSize != "" {
			args = append(args, "--shm-size", config.Resources.ShmSize)
		}
	}

	// Add labels
	for key, value := range config.Labels {
		args = append(args, "-l", fmt.Sprintf("%s=%s", key, value))
	}

	// Add runtime
	if config.Runtime != "" {
		args = append(args, "--runtime", config.Runtime)
	}

	// Add IPC mode
	if config.IPC != "" {
		args = append(args, "--ipc", config.IPC)
	}

	// Add ulimits
	for _, ulimit := range config.Ulimits {
		args = append(args, "--ulimit", fmt.Sprintf("%s=%d:%d", ulimit.Name, ulimit.Soft, ulimit.Hard))
	}

	// Add device mappings
	for _, device := range config.Devices {
		deviceArg := fmt.Sprintf("%s:%s", device.PathOnHost, device.PathInContainer)
		if device.Permissions != "" {
			deviceArg += fmt.Sprintf(":%s", device.Permissions)
		}
		args = append(args, "--device", deviceArg)
	}

	// Add sysctls
	for key, value := range config.Sysctls {
		args = append(args, "--sysctl", fmt.Sprintf("%s=%s", key, value))
	}

	// Add entrypoint if specified
	if len(config.Entrypoint) > 0 {
		args = append(args, "--entrypoint")
		args = append(args, config.Entrypoint...)
	}

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

// configsEqual compares two container configurations for equality
// Compares every field in ContainerConfig
func (m *Manager) configsEqual(a, b types.ContainerConfig) bool {
	// Compare Name field
	if a.Name != b.Name {
		m.logger.Debugf("Container name differs: current='%s', desired='%s'", a.Name, b.Name)
		return false
	}

	// Compare Image field
	if a.Image != b.Image {
		m.logger.Debugf("Container %s image differs: current='%s', desired='%s'", a.Name, a.Image, b.Image)
		return false
	}

	// Compare Ports field (multiple port support)
	if !m.portMappingsEqual(a.Ports, b.Ports) {
		m.logger.Debugf("Container %s ports differ", a.Name)
		return false
	}

	// Compare HealthPath field
	if a.HealthPath != b.HealthPath {
		m.logger.Debugf("Container %s health path differs: current='%s', desired='%s'", a.Name, a.HealthPath, b.HealthPath)
		return false
	}

	// Compare Env field (map[string]string)
	if !m.envMapsEqual(a.Env, b.Env) {
		m.logger.Debugf("Container %s env vars differ", a.Name)
		return false
	}

	// Compare EnvFile field
	if a.EnvFile != b.EnvFile {
		m.logger.Debugf("Container %s env file differs: current='%s', desired='%s'", a.Name, a.EnvFile, b.EnvFile)
		return false
	}

	// Compare Volumes field
	if !m.volumeMountsEqual(a.Volumes, b.Volumes) {
		m.logger.Debugf("Container %s volumes differ", a.Name)
		return false
	}

	// Compare WorkingDir field
	if a.WorkingDir != b.WorkingDir {
		m.logger.Debugf("Container %s working dir differs: current='%s', desired='%s'", a.Name, a.WorkingDir, b.WorkingDir)
		return false
	}

	// Compare User field
	if a.User != b.User {
		m.logger.Debugf("Container %s user differs: current='%s', desired='%s'", a.Name, a.User, b.User)
		return false
	}

	// Compare Entrypoint field
	if !m.stringSlicesEqual(a.Entrypoint, b.Entrypoint) {
		m.logger.Debugf("Container %s entrypoint differs", a.Name)
		return false
	}

	// Compare Hostname field
	if a.Hostname != b.Hostname {
		m.logger.Debugf("Container %s hostname differs: current='%s', desired='%s'", a.Name, a.Hostname, b.Hostname)
		return false
	}

	// Compare Network field
	if a.Network != b.Network {
		m.logger.Debugf("Container %s network differs: current='%s', desired='%s'", a.Name, a.Network, b.Network)
		return false
	}

	// Compare Restart field
	if a.Restart != b.Restart {
		m.logger.Debugf("Container %s restart policy differs: current='%s', desired='%s'", a.Name, a.Restart, b.Restart)
		return false
	}

	// Compare Resources field
	if !m.resourceLimitsEqual(a.Resources, b.Resources) {
		m.logger.Debugf("Container %s resources differ", a.Name)
		return false
	}

	// Compare Labels field
	if !m.envMapsEqual(a.Labels, b.Labels) {
		m.logger.Debugf("Container %s labels differ", a.Name)
		return false
	}

	// Compare Runtime field
	if a.Runtime != b.Runtime {
		m.logger.Debugf("Container %s runtime differs: current='%s', desired='%s'", a.Name, a.Runtime, b.Runtime)
		return false
	}

	// Compare IPC field
	if a.IPC != b.IPC {
		m.logger.Debugf("Container %s IPC differs: current='%s', desired='%s'", a.Name, a.IPC, b.IPC)
		return false
	}

	// Compare Ulimits field
	if !m.ulimitsEqual(a.Ulimits, b.Ulimits) {
		m.logger.Debugf("Container %s ulimits differ", a.Name)
		return false
	}

	// Compare Devices field
	if !m.devicesEqual(a.Devices, b.Devices) {
		m.logger.Debugf("Container %s devices differ", a.Name)
		return false
	}

	// Compare Sysctls field
	if !m.envMapsEqual(a.Sysctls, b.Sysctls) {
		m.logger.Debugf("Container %s sysctls differ", a.Name)
		return false
	}

	m.logger.Debugf("Container %s configuration matches exactly", a.Name)
	return true
}

// Helper methods for comparing complex fields

func (m *Manager) portMappingsEqual(a, b []types.PortMapping) bool {
	if len(a) != len(b) {
		return false
	}
	for i, portA := range a {
		portB := b[i]
		if portA.HostPort != portB.HostPort || portA.ContainerPort != portB.ContainerPort || portA.Protocol != portB.Protocol {
			return false
		}
	}
	return true
}

func (m *Manager) envMapsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for key, value := range a {
		if b[key] != value {
			return false
		}
	}
	for key := range b {
		if _, exists := a[key]; !exists {
			return false
		}
	}
	return true
}

func (m *Manager) volumeMountsEqual(a, b []types.VolumeMount) bool {
	if len(a) != len(b) {
		return false
	}
	for i, volA := range a {
		volB := b[i]
		if volA.Source != volB.Source || volA.Destination != volB.Destination || volA.Mode != volB.Mode {
			return false
		}
	}
	return true
}

func (m *Manager) stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i, strA := range a {
		if strA != b[i] {
			return false
		}
	}
	return true
}

func (m *Manager) resourceLimitsEqual(a, b *types.ResourceLimit) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return a.Memory == b.Memory && a.CPUs == b.CPUs && a.MemorySwap == b.MemorySwap && a.ShmSize == b.ShmSize
}

func (m *Manager) ulimitsEqual(a, b []types.Ulimit) bool {
	if len(a) != len(b) {
		return false
	}
	for i, ulimitA := range a {
		ulimitB := b[i]
		if ulimitA.Name != ulimitB.Name || ulimitA.Soft != ulimitB.Soft || ulimitA.Hard != ulimitB.Hard {
			return false
		}
	}
	return true
}

func (m *Manager) devicesEqual(a, b []types.Device) bool {
	if len(a) != len(b) {
		return false
	}
	for i, deviceA := range a {
		deviceB := b[i]
		if deviceA.PathOnHost != deviceB.PathOnHost || deviceA.PathInContainer != deviceB.PathInContainer || deviceA.Permissions != deviceB.Permissions {
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

		// Create ContainerConfig with new structure
		container := types.ContainerConfig{
			Name:       name,
			Image:      image,
			Ports:      []types.PortMapping{}, // Will be populated below if port found
			HealthPath: "",                    // Will be determined later if needed
			Env:        map[string]string{},   // Environment variables not easily available from docker ps
		}

		// Add port mapping if found
		if port > 0 {
			container.Ports = append(container.Ports, types.PortMapping{
				HostPort:      port,
				ContainerPort: port,
				Protocol:      "tcp",
			})
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
		Name: name,
		// Port and HealthPath will be set if needed for health checks
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
