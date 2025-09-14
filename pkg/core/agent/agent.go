package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/StreamDeploy/streamdeploy-agent/pkg/core/config"
	"github.com/StreamDeploy/streamdeploy-agent/pkg/core/types"
	"github.com/StreamDeploy/streamdeploy-agent/pkg/core/utils"
)

type CoreAgent struct {
	configManager      types.ConfigManager
	logger             types.Logger
	httpClient         types.HTTPClient
	mqttClient         types.MQTTClient
	metricsCollector   types.MetricsCollector
	containerManager   types.ContainerManager
	certificateManager types.CertificateManager
	environmentManager types.EnvironmentManager
	packageManager     types.PackageManager

	// Control channels
	ctx     context.Context
	cancel  context.CancelFunc
	running bool

	// Timing
	heartbeatInterval        time.Duration
	updateInterval           time.Duration
	certificateCheckInterval time.Duration

	// Update lock to prevent API calls during agent updates
	updateLock sync.RWMutex
	isUpdating bool

	// Status update lock to prevent concurrent status updates
	statusUpdateLock sync.Mutex

	// Self-healing lock to prevent status updates during system state corrections
	selfHealingLock sync.RWMutex
	isSelfHealing   bool
}

// NewCoreAgent creates a new core agent instance
func NewCoreAgent(deviceConfigPath string) (*CoreAgent, error) {
	configManager, err := config.NewManager(deviceConfigPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create config manager: %w", err)
	}

	logger := utils.NewLogger("AGENT")

	ctx, cancel := context.WithCancel(context.Background())

	agent := &CoreAgent{
		configManager: configManager,
		logger:        logger,
		ctx:           ctx,
		cancel:        cancel,
		running:       false,
	}

	// Parse timing intervals
	agent.heartbeatInterval = configManager.GetHeartbeatFrequency()
	agent.updateInterval = configManager.GetUpdateFrequency()
	agent.certificateCheckInterval = 24 * time.Hour // Check certificates daily

	logger.Info("Core agent initialized successfully")

	return agent, nil
}

// SetHTTPClient sets the HTTP client implementation
func (a *CoreAgent) SetHTTPClient(client types.HTTPClient) {
	a.httpClient = client
}

// SetMQTTClient sets the MQTT client implementation
func (a *CoreAgent) SetMQTTClient(client types.MQTTClient) {
	a.mqttClient = client
}

// SetMetricsCollector sets the metrics collector implementation
func (a *CoreAgent) SetMetricsCollector(collector types.MetricsCollector) {
	a.metricsCollector = collector
}

// SetContainerManager sets the container manager implementation
func (a *CoreAgent) SetContainerManager(manager types.ContainerManager) {
	a.containerManager = manager
}

// SetCertificateManager sets the certificate manager implementation
func (a *CoreAgent) SetCertificateManager(manager types.CertificateManager) {
	a.certificateManager = manager
}

// SetEnvironmentManager sets the environment manager implementation
func (a *CoreAgent) SetEnvironmentManager(manager types.EnvironmentManager) {
	a.environmentManager = manager
}

// SetPackageManager sets the package manager implementation
func (a *CoreAgent) SetPackageManager(manager types.PackageManager) {
	a.packageManager = manager
}

// Start starts the core agent
func (a *CoreAgent) Start() error {
	if a.running {
		a.logger.Info("Agent is already running")
		return nil
	}

	a.logger.Info("Starting StreamDeploy core agent")
	a.running = true

	// Set up config change callback
	a.configManager.SetConfigChangeCallback(a.handleConfigChange)

	// Start config monitoring
	if err := a.configManager.StartMonitoring(); err != nil {
		a.logger.Errorf("Failed to start config monitoring: %v", err)
	}

	// Start worker goroutines
	go a.heartbeatLoop()
	go a.updateLoop()
	go a.certificateCheckLoop()
	go a.agentUpdateLoop()

	a.logger.Info("Core agent started successfully")
	return nil
}

// Stop stops the core agent
func (a *CoreAgent) Stop() {
	if !a.running {
		return
	}

	a.logger.Info("Stopping StreamDeploy core agent")
	a.running = false

	// Cancel context to stop goroutines
	a.cancel()

	// Stop config monitoring
	a.configManager.StopMonitoring()

	a.logger.Info("Core agent stopped")
}

// IsRunning returns whether the agent is running
func (a *CoreAgent) IsRunning() bool {
	return a.running
}

// SetUpdating sets the update lock to prevent API calls during agent updates
func (a *CoreAgent) SetUpdating(updating bool) {
	a.updateLock.Lock()
	defer a.updateLock.Unlock()
	a.isUpdating = updating
	if updating {
		a.logger.Info("Agent update started - API calls will be suspended")
	} else {
		a.logger.Info("Agent update completed - API calls resumed")
	}
}

// IsUpdating returns whether the agent is currently updating
func (a *CoreAgent) IsUpdating() bool {
	a.updateLock.RLock()
	defer a.updateLock.RUnlock()
	return a.isUpdating
}

// SetSelfHealing sets the self-healing lock to prevent API calls during system state corrections
func (a *CoreAgent) SetSelfHealing(healing bool) {
	a.selfHealingLock.Lock()
	defer a.selfHealingLock.Unlock()
	a.isSelfHealing = healing
	if healing {
		a.logger.Info("Self-healing started - API calls will be suspended")
	} else {
		a.logger.Info("Self-healing completed - API calls resumed")
	}
}

// IsSelfHealing returns whether the agent is currently performing self-healing
func (a *CoreAgent) IsSelfHealing() bool {
	a.selfHealingLock.RLock()
	defer a.selfHealingLock.RUnlock()
	return a.isSelfHealing
}

// CheckForAgentUpdate checks if the agent binary itself needs updating
func (a *CoreAgent) CheckForAgentUpdate() error {
	// This method can be called to check if the agent needs to update itself
	// For now, we'll implement a simple check that can be extended
	// In a real implementation, this would check for new agent versions

	// Set updating flag to prevent API calls during self-update
	a.SetUpdating(true)
	defer a.SetUpdating(false)

	a.logger.Info("Checking for agent self-update...")

	// TODO: Implement actual agent update logic here
	// This could involve:
	// 1. Checking for new agent versions from the API
	// 2. Downloading new agent binary
	// 3. Replacing current binary
	// 4. Restarting the agent service

	a.logger.Info("Agent self-update check completed")
	return nil
}

// heartbeatLoop runs the heartbeat loop
func (a *CoreAgent) heartbeatLoop() {
	a.logger.Infof("Heartbeat loop started with interval: %v", a.heartbeatInterval)

	ticker := time.NewTicker(a.heartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-a.ctx.Done():
			a.logger.Info("Heartbeat loop stopped")
			return
		case <-ticker.C:
			// Skip heartbeat if agent is updating (but allow during self-healing)
			if a.IsUpdating() {
				a.logger.Info("Skipping heartbeat - agent is updating")
				continue
			}
			if err := a.sendHeartbeat(); err != nil {
				a.logger.Errorf("Heartbeat failed: %v", err)
			}
		}
	}
}

// updateLoop runs the update loop
func (a *CoreAgent) updateLoop() {
	a.logger.Infof("Update loop started with interval: %v", a.updateInterval)

	ticker := time.NewTicker(a.updateInterval)
	defer ticker.Stop()

	for {
		select {
		case <-a.ctx.Done():
			a.logger.Info("Update loop stopped")
			return
		case <-ticker.C:
			// Skip update check if agent is updating or self-healing
			if a.IsUpdating() {
				a.logger.Info("Skipping update check - agent is updating")
				continue
			}
			if a.IsSelfHealing() {
				a.logger.Info("Skipping update check - agent is self-healing")
				continue
			}
			if err := a.performUpdateCheck(); err != nil {
				a.logger.Errorf("Update check failed: %v", err)
			}
		}
	}
}

// agentUpdateLoop runs the agent self-update check loop
func (a *CoreAgent) agentUpdateLoop() {
	// Check for agent updates every hour
	agentUpdateInterval := 1 * time.Hour
	a.logger.Infof("Agent update loop started with interval: %v", agentUpdateInterval)

	ticker := time.NewTicker(agentUpdateInterval)
	defer ticker.Stop()

	for {
		select {
		case <-a.ctx.Done():
			a.logger.Info("Agent update loop stopped")
			return
		case <-ticker.C:
			// Only check for agent updates if not already updating
			if !a.IsUpdating() {
				if err := a.CheckForAgentUpdate(); err != nil {
					a.logger.Errorf("Agent update check failed: %v", err)
				}
			} else {
				a.logger.Info("Skipping agent update check - already updating")
			}
		}
	}
}

// certificateCheckLoop runs the certificate check loop
func (a *CoreAgent) certificateCheckLoop() {
	if a.certificateManager == nil {
		a.logger.Info("Certificate manager not configured, skipping certificate checks")
		return
	}

	a.logger.Infof("Certificate check loop started with interval: %v", a.certificateCheckInterval)

	ticker := time.NewTicker(a.certificateCheckInterval)
	defer ticker.Stop()

	// Perform initial certificate check
	if err := a.performCertificateCheck(); err != nil {
		a.logger.Errorf("Initial certificate check failed: %v", err)
	}

	for {
		select {
		case <-a.ctx.Done():
			a.logger.Info("Certificate check loop stopped")
			return
		case <-ticker.C:
			if err := a.performCertificateCheck(); err != nil {
				a.logger.Errorf("Certificate check failed: %v", err)
			}
		}
	}
}

// sendHeartbeat sends a heartbeat message
func (a *CoreAgent) sendHeartbeat() error {
	stateConfig := a.configManager.GetStateConfig()
	if stateConfig == nil {
		return fmt.Errorf("state config is nil")
	}

	// Collect metrics if collector is available
	var metrics map[string]interface{}
	if a.metricsCollector != nil {
		systemMetrics, err := a.metricsCollector.CollectSystemMetrics()
		if err != nil {
			a.logger.Errorf("Failed to collect system metrics: %v", err)
			metrics = make(map[string]interface{})
		} else {
			metrics = map[string]interface{}{
				"cpu_pct":  systemMetrics.CPUPercent,
				"mem_pct":  systemMetrics.MemPercent,
				"disk_pct": systemMetrics.DiskPercent,
				"swap_pct": systemMetrics.SwapPercent,
			}

			// Add custom metrics
			customMetrics, err := a.metricsCollector.CollectCustomMetrics(stateConfig.CustomMetrics)
			if err != nil {
				a.logger.Errorf("Failed to collect custom metrics: %v", err)
			} else {
				for k, v := range customMetrics {
					metrics[k] = v
				}
			}
		}
	} else {
		metrics = make(map[string]interface{})
	}

	// Check container health
	containersHealthy := true
	if a.containerManager != nil {
		stateConfig := a.configManager.GetStateConfig()
		if stateConfig != nil && len(stateConfig.Containers) > 0 {
			// Ensure containers are running
			if err := a.containerManager.EnsureContainersRunning(stateConfig.Containers); err != nil {
				a.logger.Errorf("Failed to ensure containers are running: %v", err)
				containersHealthy = false
			}

			// Perform health checks
			for _, containerConfig := range stateConfig.Containers {
				containerInfo := &types.ContainerInfo{
					Name:       containerConfig.Name,
					Image:      containerConfig.Image,
					Port:       containerConfig.Port,
					HealthPath: containerConfig.HealthPath,
					Running:    a.containerManager.IsContainerRunning(containerConfig.Name),
				}

				if !a.containerManager.PerformHealthCheck(containerInfo) {
					containersHealthy = false
					a.logger.Errorf("Health check failed for container: %s", containerConfig.Name)
				}
			}
		}
	}

	// Determine system status
	status := "normal"
	if a.metricsCollector != nil {
		cpuPct, _ := metrics["cpu_pct"].(float64)
		memPct, _ := metrics["mem_pct"].(float64)
		diskPct, _ := metrics["disk_pct"].(float64)
		status = a.metricsCollector.DetermineSystemStatus(cpuPct, memPct, diskPct, containersHealthy)
	}

	// Build heartbeat payload
	heartbeat := &types.HeartbeatPayload{
		Status:       status,
		AgentSetting: stateConfig.AgentSetting,
		Metrics:      metrics,
	}

	// Send heartbeat based on mode
	mode := a.configManager.GetMode()
	deviceID := a.configManager.GetDeviceID()

	switch mode {
	case "http", "https":
		if a.httpClient == nil {
			return fmt.Errorf("HTTP client not configured")
		}
		response, err := a.httpClient.SendHeartbeat(heartbeat, deviceID)
		if err != nil {
			return fmt.Errorf("failed to send HTTP heartbeat: %w", err)
		}
		if response.StatusCode >= 200 && response.StatusCode < 300 {
			a.logger.Info("Heartbeat sent successfully")
		} else {
			return fmt.Errorf("heartbeat failed with status: %d", response.StatusCode)
		}

	case "mqtt":
		if a.mqttClient == nil {
			return fmt.Errorf("MQTT client not configured")
		}
		if !a.mqttClient.IsConnected() {
			if err := a.mqttClient.Connect(); err != nil {
				return fmt.Errorf("failed to connect to MQTT: %w", err)
			}
		}
		if err := a.mqttClient.PublishHeartbeat(heartbeat); err != nil {
			return fmt.Errorf("failed to publish MQTT heartbeat: %w", err)
		}
		a.logger.Info("Heartbeat published successfully")

	default:
		return fmt.Errorf("unsupported mode: %s", mode)
	}

	return nil
}

// performUpdateCheck performs an update check
func (a *CoreAgent) performUpdateCheck() error {
	// Lock to prevent concurrent status updates
	a.statusUpdateLock.Lock()
	defer a.statusUpdateLock.Unlock()

	stateConfig := a.configManager.GetStateConfig()
	if stateConfig == nil {
		return fmt.Errorf("state config is nil")
	}

	// Build status update payload
	statusUpdate := &types.StatusUpdatePayload{
		UpdateType:   "update_check",
		CurrentState: *stateConfig,
	}

	// Send status update based on mode
	mode := a.configManager.GetMode()
	deviceID := a.configManager.GetDeviceID()

	var apiCallSuccessful bool
	var apiError error

	switch mode {
	case "http", "https":
		if a.httpClient == nil {
			apiError = fmt.Errorf("HTTP client not configured")
			break
		}
		response, err := a.httpClient.SendStatusUpdate(statusUpdate, deviceID)
		if err != nil {
			apiError = fmt.Errorf("failed to send HTTP status update: %w", err)
			break
		}
		if response.StatusCode >= 200 && response.StatusCode < 300 {
			a.logger.Info("Status update sent successfully")
			apiCallSuccessful = true

			// Parse response for new state
			if len(response.Body) > 0 {
				if err := a.handleStatusUpdateResponse(response.Body); err != nil {
					a.logger.Errorf("Failed to handle status update response: %v", err)
				}
			}
		} else {
			apiError = fmt.Errorf("status update failed with status: %d", response.StatusCode)
		}

	case "mqtt":
		if a.mqttClient == nil {
			apiError = fmt.Errorf("MQTT client not configured")
			break
		}
		if !a.mqttClient.IsConnected() {
			if err := a.mqttClient.Connect(); err != nil {
				apiError = fmt.Errorf("failed to connect to MQTT: %w", err)
				break
			}
		}
		if err := a.mqttClient.PublishStatusUpdate(statusUpdate); err != nil {
			apiError = fmt.Errorf("failed to publish MQTT status update: %w", err)
			break
		}
		a.logger.Info("Status update published successfully")
		apiCallSuccessful = true

	default:
		apiError = fmt.Errorf("unsupported mode: %s", mode)
	}

	// If API call failed, still perform local state check
	if !apiCallSuccessful {
		a.logger.Infof("API call failed (%v), performing local state check", apiError)
		if err := a.performLocalStateCheck(); err != nil {
			a.logger.Errorf("Local state check failed: %v", err)
			// Return the original API error, not the local state check error
			return apiError
		}
		a.logger.Info("Local state check completed successfully")
	}

	return apiError
}

// performLocalStateCheck performs a local state check when API calls fail
func (a *CoreAgent) performLocalStateCheck() error {
	a.logger.Info("Performing local state check...")

	// Get current state from config manager (in-memory state)
	currentState := a.configManager.GetStateConfig()
	if currentState == nil {
		return fmt.Errorf("current state config is nil")
	}

	// Check if actual system state matches the in-memory state
	// and make corrections if needed
	if err := a.verifyAndCorrectSystemState(currentState); err != nil {
		return fmt.Errorf("failed to verify and correct system state: %w", err)
	}

	a.logger.Info("Local state check completed successfully")
	return nil
}

// verifyAndCorrectSystemState verifies that the actual system state matches the in-memory state
func (a *CoreAgent) verifyAndCorrectSystemState(state *types.StateConfig) error {
	// Set self-healing flag to prevent API calls during system corrections
	a.SetSelfHealing(true)
	defer a.SetSelfHealing(false)

	a.logger.Info("Verifying system state against in-memory configuration...")

	// Verify containers
	if err := a.verifyContainers(state); err != nil {
		a.logger.Errorf("Container verification failed: %v", err)
		// Continue with other verifications
	}

	// Verify packages
	if err := a.verifyPackages(state); err != nil {
		a.logger.Errorf("Package verification failed: %v", err)
		// Continue with other verifications
	}

	// Verify environment variables
	if err := a.verifyEnvironmentVariables(state); err != nil {
		a.logger.Errorf("Environment variable verification failed: %v", err)
		// Continue with other verifications
	}

	return nil
}

// verifyContainers checks if containers in the state are actually running
func (a *CoreAgent) verifyContainers(state *types.StateConfig) error {
	if a.containerManager == nil {
		a.logger.Info("Container manager not available, skipping container verification")
		return nil
	}

	if len(state.Containers) == 0 {
		a.logger.Info("No containers configured, skipping container verification")
		return nil
	}

	a.logger.Info("Verifying container state...")

	// Check each container in the state
	for _, containerConfig := range state.Containers {
		containerName := containerConfig.Name

		// Check if container is running
		if !a.containerManager.IsContainerRunning(containerName) {
			a.logger.Infof("Container %s is not running, attempting to start it...", containerName)

			// Try to start the container
			if err := a.containerManager.EnsureContainersRunning([]types.ContainerConfig{containerConfig}); err != nil {
				a.logger.Errorf("Failed to start container %s: %v", containerName, err)
				continue
			}

			a.logger.Infof("Container %s started successfully", containerName)
		} else {
			a.logger.Infof("Container %s is running", containerName)

			// Perform health check
			containerInfo := &types.ContainerInfo{
				Name:       containerConfig.Name,
				Image:      containerConfig.Image,
				Port:       containerConfig.Port,
				HealthPath: containerConfig.HealthPath,
				Running:    true,
			}

			if !a.containerManager.PerformHealthCheck(containerInfo) {
				a.logger.Infof("Health check failed for container %s", containerName)
				// Could restart the container here if needed
			}
		}
	}

	return nil
}

// verifyPackages checks if packages in the state are actually installed
func (a *CoreAgent) verifyPackages(state *types.StateConfig) error {
	if a.packageManager == nil {
		a.logger.Info("Package manager not available, skipping package verification")
		return nil
	}

	if len(state.Packages) == 0 && len(state.CustomPackages) == 0 {
		a.logger.Info("No packages configured, skipping package verification")
		return nil
	}

	a.logger.Info("Verifying package state...")

	// Ensure all packages are installed
	if len(state.Packages) > 0 {
		a.logger.Info("Ensuring system packages are installed...")
		if err := a.packageManager.EnsurePackagesInstalled(state.Packages); err != nil {
			a.logger.Errorf("Failed to ensure packages are installed: %v", err)
		} else {
			a.logger.Info("System packages verified successfully")
		}
	}

	// Ensure all custom packages are installed
	if len(state.CustomPackages) > 0 {
		a.logger.Info("Ensuring custom packages are installed...")
		if err := a.packageManager.EnsureCustomPackagesInstalled(state.CustomPackages); err != nil {
			a.logger.Errorf("Failed to ensure custom packages are installed: %v", err)
		} else {
			a.logger.Info("Custom packages verified successfully")
		}
	}

	return nil
}

// verifyEnvironmentVariables checks if environment variables in the state are actually set
func (a *CoreAgent) verifyEnvironmentVariables(state *types.StateConfig) error {
	if a.environmentManager == nil {
		a.logger.Info("Environment manager not available, skipping environment variable verification")
		return nil
	}

	if len(state.Env) == 0 {
		a.logger.Info("No environment variables configured, skipping environment variable verification")
		return nil
	}

	a.logger.Info("Verifying environment variable state...")

	// Get current system environment
	currentEnv, err := a.environmentManager.GetCurrentSystemEnvironment()
	if err != nil {
		return fmt.Errorf("failed to get current system environment: %w", err)
	}

	// Check if environment variables match
	needsUpdate := false
	for key, expectedValue := range state.Env {
		if currentValue, exists := currentEnv[key]; !exists || currentValue != expectedValue {
			a.logger.Infof("Environment variable %s mismatch (expected: %s, current: %s)",
				key, expectedValue, currentValue)
			needsUpdate = true
		}
	}

	// If there are mismatches, sync the environment
	if needsUpdate {
		a.logger.Info("Environment variables need updating, syncing...")
		if err := a.environmentManager.SyncSystemEnvironment(state.Env); err != nil {
			return fmt.Errorf("failed to sync environment variables: %w", err)
		}
		a.logger.Info("Environment variables synced successfully")
	} else {
		a.logger.Info("Environment variables are correctly set")
	}

	return nil
}

// handleStatusUpdateResponse handles the response from a status update
func (a *CoreAgent) handleStatusUpdateResponse(responseBody []byte) error {
	var response map[string]interface{}
	if err := json.Unmarshal(responseBody, &response); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	newStateData, exists := response["new_state"]
	if !exists {
		return nil // No new state
	}

	// Convert to JSON and back to StateConfig
	newStateJSON, err := json.Marshal(newStateData)
	if err != nil {
		return fmt.Errorf("failed to marshal new state: %w", err)
	}

	var newState types.StateConfig
	if err := json.Unmarshal(newStateJSON, &newState); err != nil {
		return fmt.Errorf("failed to unmarshal new state: %w", err)
	}

	// Compare with current state
	currentState := a.configManager.GetStateConfig()
	if !stateConfigsEqual(currentState, &newState) {
		a.logger.Info("Received new state configuration")

		// Set self-healing flag to prevent API calls during state synchronization
		a.SetSelfHealing(true)
		defer a.SetSelfHealing(false)

		// Sync containers if container manager is available
		if a.containerManager != nil {
			oldContainers := []types.ContainerConfig{}
			if currentState != nil {
				oldContainers = currentState.Containers
			}

			if err := a.containerManager.SyncContainers(newState.Containers, oldContainers); err != nil {
				a.logger.Errorf("Failed to sync containers: %v", err)
			} else {
				a.logger.Info("Containers synchronized successfully")
			}
		}

		// Sync system environment variables if environment manager is available
		if a.environmentManager != nil {
			oldEnv := make(map[string]string)
			if currentState != nil {
				oldEnv = currentState.Env
			}

			// Check if environment variables have changed
			if !envMapsEqual(oldEnv, newState.Env) {
				if err := a.syncEnvironmentVariables(oldEnv, newState.Env); err != nil {
					a.logger.Errorf("Failed to sync system environment variables: %v", err)
				} else {
					a.logger.Info("System environment variables synchronized successfully")
				}
			}
		}

		// Sync system packages if package manager is available
		if a.packageManager != nil {
			oldPackages := []string{}
			if currentState != nil {
				oldPackages = currentState.Packages
			}

			if err := a.packageManager.SyncPackages(newState.Packages, oldPackages); err != nil {
				a.logger.Errorf("Failed to sync system packages: %v", err)
			} else {
				a.logger.Info("System packages synchronized successfully")
			}

			// Sync custom packages
			oldCustomPackages := make(map[string]types.CustomPackage)
			if currentState != nil {
				oldCustomPackages = currentState.CustomPackages
			}

			if err := a.packageManager.SyncCustomPackages(newState.CustomPackages, oldCustomPackages); err != nil {
				a.logger.Errorf("Failed to sync custom packages: %v", err)
			} else {
				a.logger.Info("Custom packages synchronized successfully")
			}
		}

		if err := a.configManager.UpdateStateConfig(&newState); err != nil {
			return fmt.Errorf("failed to update state config: %w", err)
		}

		a.logger.Info("State configuration updated")
	}

	return nil
}

// performCertificateCheck checks certificate expiration and renews if necessary
func (a *CoreAgent) performCertificateCheck() error {
	a.logger.Info("Performing certificate expiration check")

	// Check if certificate is expiring within 30 days
	if !a.certificateManager.IsCertificateExpiringSoon(30) {
		a.logger.Info("Certificate is not expiring soon")
		return nil
	}

	a.logger.Info("Certificate is expiring soon, initiating renewal")

	// Get device configuration for renewal endpoint
	deviceConfig := a.configManager.GetDeviceConfig()
	if deviceConfig == nil {
		return fmt.Errorf("device config is nil")
	}

	deviceID := a.configManager.GetDeviceID()
	enrollEndpoint := deviceConfig.HTTPSMTLSEndpoint

	// Renew the certificate
	if err := a.certificateManager.RenewCertificate(deviceID, enrollEndpoint); err != nil {
		return fmt.Errorf("failed to renew certificate: %w", err)
	}

	// Update HTTP client with new certificates if available
	if a.httpClient != nil {
		caCertPath := a.certificateManager.GetCACertificatePath()
		certPath := a.certificateManager.GetCertificatePath()
		keyPath := a.certificateManager.GetPrivateKeyPath()

		// Check if the HTTP client supports certificate updates
		if updater, ok := a.httpClient.(interface {
			UpdateCertificates(caCertPath, certPath, keyPath string) error
		}); ok {
			if err := updater.UpdateCertificates(caCertPath, certPath, keyPath); err != nil {
				a.logger.Errorf("Failed to update HTTP client certificates: %v", err)
			} else {
				a.logger.Info("HTTP client certificates updated successfully")
			}
		}
	}

	a.logger.Info("Certificate renewal completed successfully")
	return nil
}

// handleConfigChange handles configuration file changes
func (a *CoreAgent) handleConfigChange(filePath string) {
	a.logger.Infof("Configuration changed: %s", filePath)

	// Check if this is an error case
	isError := strings.HasSuffix(filePath, ":error")
	if isError {
		// Remove the error suffix to get the actual file path
		filePath = strings.TrimSuffix(filePath, ":error")
	}

	// Determine which config file changed
	if strings.HasSuffix(filePath, "agent.json") {
		a.handleDeviceConfigChange(isError)
	} else if strings.HasSuffix(filePath, "state.json") {
		a.handleStateConfigChange(isError)
	}

	a.logger.Info("Configuration reloaded successfully")
}

// handleDeviceConfigChange handles device configuration changes
func (a *CoreAgent) handleDeviceConfigChange(isError bool) {
	if isError {
		a.logger.Errorf("Failed to parse agent.json, resetting with default configuration from memory...")
		// Reset agent.json with default configuration
		if err := a.resetAgentConfigToDefault(); err != nil {
			a.logger.Errorf("Failed to reset agent.json: %v", err)
		} else {
			a.logger.Info("agent.json reset to default configuration successfully")
		}
		return
	}

	a.logger.Info("Device configuration changed, updating timing intervals...")

	// Update timing intervals
	oldUpdateInterval := a.updateInterval
	a.heartbeatInterval = a.configManager.GetHeartbeatFrequency()
	a.updateInterval = a.configManager.GetUpdateFrequency()

	// Restart file monitoring if update frequency changed
	if oldUpdateInterval != a.updateInterval {
		a.logger.Infof("Update frequency changed from %v to %v, restarting file monitoring", oldUpdateInterval, a.updateInterval)
		a.configManager.RestartMonitoring()
	}

	a.logger.Info("Device configuration updated successfully")
}

// handleStateConfigChange handles state configuration changes
func (a *CoreAgent) handleStateConfigChange(isError bool) {
	if isError {
		a.logger.Errorf("Failed to parse state.json, saving memory state back to file...")
		// Save current in-memory state back to state.json
		if err := a.configManager.SaveStateConfig(); err != nil {
			a.logger.Errorf("Failed to save state config back to file: %v", err)
		} else {
			a.logger.Info("Memory state saved back to state.json successfully")
		}
		return
	}

	// Check if agent is currently updating
	if a.IsUpdating() {
		a.logger.Info("Agent is currently updating, waiting for update to complete before applying file changes...")
		// Wait for update to complete
		go a.waitForUpdateAndApplyStateChange()
		return
	}

	a.logger.Info("State configuration changed, applying changes...")

	// Get the new state configuration (already loaded by the config manager)
	newState := a.configManager.GetStateConfig()
	if newState == nil {
		a.logger.Errorf("Failed to get new state configuration")
		return
	}

	// Apply the changes using the same logic as API responses
	// We pass nil as oldState since we want to apply all changes
	if err := a.applyStateChanges(nil, newState); err != nil {
		a.logger.Errorf("Failed to apply state changes: %v", err)
		return
	}

	a.logger.Info("State changes applied successfully")
}

// resetAgentConfigToDefault resets agent.json with the current device configuration from memory
func (a *CoreAgent) resetAgentConfigToDefault() error {
	// Get the current device configuration from memory
	deviceConfig := a.configManager.GetDeviceConfig()
	if deviceConfig == nil {
		return fmt.Errorf("no device configuration available in memory")
	}

	// Get the device config path
	deviceConfigPath := a.configManager.GetDeviceConfigPath()
	if deviceConfigPath == "" {
		return fmt.Errorf("device config path not available")
	}

	// Write the current device config back to the file
	data, err := json.MarshalIndent(deviceConfig, "", "    ")
	if err != nil {
		return fmt.Errorf("failed to marshal device config: %w", err)
	}

	if err := os.WriteFile(deviceConfigPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write device config file: %w", err)
	}

	a.logger.Info("agent.json reset with current device configuration from memory")
	return nil
}

// waitForUpdateAndApplyStateChange waits for update to complete and then applies state change
func (a *CoreAgent) waitForUpdateAndApplyStateChange() {
	a.logger.Info("Waiting for update to complete...")

	// Poll until update is complete
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	timeout := time.After(5 * time.Minute) // 5 minute timeout

	for {
		select {
		case <-ticker.C:
			if !a.IsUpdating() {
				a.logger.Info("Update completed, applying state change...")
				// Apply the state change now that update is complete
				a.handleStateConfigChange(false)
				return
			}
		case <-timeout:
			a.logger.Errorf("Timeout waiting for update to complete, applying state change anyway...")
			a.handleStateConfigChange(false)
			return
		}
	}
}

// applyStateChanges applies state changes from old state to new state
func (a *CoreAgent) applyStateChanges(oldState, newState *types.StateConfig) error {
	// Set self-healing flag to prevent API calls during state changes
	a.SetSelfHealing(true)
	defer a.SetSelfHealing(false)

	// Sync containers if container manager is available
	if a.containerManager != nil {
		oldContainers := []types.ContainerConfig{}
		if oldState != nil {
			oldContainers = oldState.Containers
		}

		if err := a.containerManager.SyncContainers(newState.Containers, oldContainers); err != nil {
			a.logger.Errorf("Failed to sync containers: %v", err)
		} else {
			a.logger.Info("Containers synchronized successfully")
		}
	}

	// Sync system environment variables if environment manager is available
	if a.environmentManager != nil {
		oldEnv := make(map[string]string)
		if oldState != nil {
			oldEnv = oldState.Env
		}

		// Check if environment variables have changed
		if !envMapsEqual(oldEnv, newState.Env) {
			if err := a.syncEnvironmentVariables(oldEnv, newState.Env); err != nil {
				a.logger.Errorf("Failed to sync system environment variables: %v", err)
			} else {
				a.logger.Info("System environment variables synchronized successfully")
			}
		}
	}

	// Sync system packages if package manager is available
	if a.packageManager != nil {
		oldPackages := []string{}
		if oldState != nil {
			oldPackages = oldState.Packages
		}

		if err := a.packageManager.SyncPackages(newState.Packages, oldPackages); err != nil {
			a.logger.Errorf("Failed to sync system packages: %v", err)
		} else {
			a.logger.Info("System packages synchronized successfully")
		}

		// Sync custom packages
		oldCustomPackages := make(map[string]types.CustomPackage)
		if oldState != nil {
			oldCustomPackages = oldState.CustomPackages
		}

		if err := a.packageManager.SyncCustomPackages(newState.CustomPackages, oldCustomPackages); err != nil {
			a.logger.Errorf("Failed to sync custom packages: %v", err)
		} else {
			a.logger.Info("Custom packages synchronized successfully")
		}
	}

	// Update the state config in memory
	if err := a.configManager.UpdateStateConfig(newState); err != nil {
		return fmt.Errorf("failed to update state config: %w", err)
	}

	return nil
}

// stateConfigsEqual compares two state configurations for equality
func stateConfigsEqual(a, b *types.StateConfig) bool {
	if a == nil || b == nil {
		return a == b
	}

	// Simple comparison - in a real implementation you might want more sophisticated comparison
	aJSON, _ := json.Marshal(a)
	bJSON, _ := json.Marshal(b)

	return string(aJSON) == string(bJSON)
}

// envMapsEqual compares two environment variable maps for equality
func envMapsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}

	for key, valueA := range a {
		if valueB, exists := b[key]; !exists || valueA != valueB {
			return false
		}
	}

	return true
}

// syncEnvironmentVariables handles the synchronization of environment variables with proper diffing
func (a *CoreAgent) syncEnvironmentVariables(oldEnv, newEnv map[string]string) error {
	// Find variables to remove (in old but not in new)
	varsToRemove := make([]string, 0)
	for key := range oldEnv {
		if _, exists := newEnv[key]; !exists {
			varsToRemove = append(varsToRemove, key)
		}
	}

	// Log the changes
	if len(varsToRemove) > 0 {
		a.logger.Infof("Removing environment variables: %v", varsToRemove)
	}

	// Find variables to add/update
	varsChanged := make(map[string]string)
	for key, newValue := range newEnv {
		if oldValue, exists := oldEnv[key]; !exists || oldValue != newValue {
			varsChanged[key] = newValue
		}
	}

	if len(varsChanged) > 0 {
		a.logger.Infof("Adding/updating environment variables: %v", getKeys(varsChanged))
	}

	// If we have variables to remove, we need to handle the removal
	if len(varsToRemove) > 0 {
		// Get current system environment variables managed by StreamDeploy
		currentSystemEnv, err := a.environmentManager.GetCurrentSystemEnvironment()
		if err != nil {
			a.logger.Errorf("Failed to get current system environment: %v", err)
			// Continue with sync anyway
			currentSystemEnv = make(map[string]string)
		}

		// Remove the variables that should no longer exist
		updatedSystemEnv := make(map[string]string)
		for key, value := range currentSystemEnv {
			shouldRemove := false
			for _, removeKey := range varsToRemove {
				if key == removeKey {
					shouldRemove = true
					break
				}
			}
			if !shouldRemove {
				updatedSystemEnv[key] = value
			}
		}

		// Add the new/updated variables
		for key, value := range newEnv {
			updatedSystemEnv[key] = value
		}

		// Sync the complete updated environment
		return a.environmentManager.SyncSystemEnvironment(updatedSystemEnv)
	}

	// If no variables to remove, just sync the new environment
	return a.environmentManager.SyncSystemEnvironment(newEnv)
}

// getKeys returns the keys of a map as a slice
func getKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	return keys
}
