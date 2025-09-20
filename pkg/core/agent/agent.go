package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/StreamDeploy/streamdeploy-agent/pkg/core/config"
	"github.com/StreamDeploy/streamdeploy-agent/pkg/core/types"
	"github.com/StreamDeploy/streamdeploy-agent/pkg/core/utils"
)

// SelfHealingResult tracks the results of self-healing operations
type SelfHealingResult struct {
	Success     bool              `json:"success"`
	Errors      map[string]string `json:"errors,omitempty"` // task_name -> error_message
	TriggeredBy string            `json:"triggered_by"`     // "api" or "local"
}

// SelfHealingTask represents a specific self-healing task
type SelfHealingTask string

const (
	TaskContainers     SelfHealingTask = "containers"
	TaskPackages       SelfHealingTask = "packages"
	TaskCustomPackages SelfHealingTask = "custom_packages"
	TaskEnvironment    SelfHealingTask = "environment"
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
	sshTunnelManager   types.SSHTunnelManager

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

	// Self-healing result tracking
	selfHealingResult *SelfHealingResult

	// Current system state snapshot for diffing
	currentSystemState *types.StateConfig
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

	// Initialize currentSystemState from device desired state
	agent.currentSystemState = configManager.GetStateConfig()

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

// SetSSHTunnelManager sets the SSH tunnel manager implementation
func (a *CoreAgent) SetSSHTunnelManager(manager types.SSHTunnelManager) {
	a.sshTunnelManager = manager
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
	deviceDesiredState := a.configManager.GetStateConfig()
	if deviceDesiredState == nil {
		return fmt.Errorf("device desired state config is nil")
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
			customMetrics, err := a.metricsCollector.CollectCustomMetrics(deviceDesiredState.CustomMetrics)
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
		deviceDesiredState := a.configManager.GetStateConfig()
		if deviceDesiredState != nil && len(deviceDesiredState.Containers) > 0 {
			// Ensure containers are running
			if err := a.containerManager.EnsureContainersRunning(deviceDesiredState.Containers); err != nil {
				a.logger.Errorf("Failed to ensure containers are running: %v", err)
				containersHealthy = false
			}

			// Perform health checks
			for _, containerConfig := range deviceDesiredState.Containers {
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
		AgentSetting: deviceDesiredState.AgentSetting,
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

	deviceDesiredState := a.configManager.GetStateConfig()
	if deviceDesiredState == nil {
		return fmt.Errorf("device desired state config is nil")
	}

	// Detect actual system state and update currentSystemState
	actualSystemState := a.detectCurrentSystemState()
	a.currentSystemState = cloneStateConfig(actualSystemState)

	// Build status update payload with actual detected system state
	statusUpdate := &types.StatusUpdatePayload{
		UpdateType:   "update_check",
		CurrentState: *actualSystemState,
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

	// Get device desired state from config manager (in-memory state)
	deviceDesiredState := a.configManager.GetStateConfig()
	if deviceDesiredState == nil {
		return fmt.Errorf("device desired state config is nil")
	}

	// Check if actual system state matches the desired state
	// and make corrections if needed
	if err := a.verifyAndCorrectSystemState(deviceDesiredState); err != nil {
		return fmt.Errorf("failed to verify and correct system state: %w", err)
	}

	a.logger.Info("Local state check completed successfully")
	return nil
}

// verifyAndCorrectSystemState verifies that the actual system state matches the in-memory state
func (a *CoreAgent) verifyAndCorrectSystemState(state *types.StateConfig) error {
	_, err := a.verifyAndCorrectSystemStateWithFeedback(state, "local")
	return err
}

// verifyAndCorrectSystemStateWithFeedback verifies system state and sends feedback
func (a *CoreAgent) verifyAndCorrectSystemStateWithFeedback(state *types.StateConfig, triggeredBy string) (*SelfHealingResult, error) {
	// Set self-healing flag to prevent API calls during system corrections
	a.SetSelfHealing(true)
	defer a.SetSelfHealing(false)

	// Initialize self-healing result tracking
	result := &SelfHealingResult{
		Success:     true,
		Errors:      make(map[string]string),
		TriggeredBy: triggeredBy,
	}
	a.selfHealingResult = result

	a.logger.Info("Verifying system state against in-memory configuration...")

	// Verify containers
	if err := a.verifyContainers(state); err != nil {
		a.logger.Errorf("Container verification failed: %v", err)
		result.Success = false
		result.Errors[string(TaskContainers)] = err.Error()
		// Continue with other verifications
	}

	// Verify packages
	if err := a.verifyPackages(state); err != nil {
		a.logger.Errorf("Package verification failed: %v", err)
		result.Success = false
		result.Errors[string(TaskPackages)] = err.Error()
		// Continue with other verifications
	}

	// Custom packages are now verified as part of verifyPackages

	// Verify environment variables
	if err := a.verifyEnvironmentVariables(state); err != nil {
		a.logger.Errorf("Environment variable verification failed: %v", err)
		result.Success = false
		result.Errors[string(TaskEnvironment)] = err.Error()
		// Continue with other verifications
	}

	// Send feedback based on trigger source
	if triggeredBy == "api" {
		// Always send feedback when triggered by API
		a.sendSelfHealingFeedback(result)
	} else {
		// For local self-healing, send feedback for both success and failure
		a.sendSelfHealingFeedback(result)
	}

	return result, nil
}

// detectCurrentSystemState detects the actual current state of the system
func (a *CoreAgent) detectCurrentSystemState() *types.StateConfig {
	currentState := &types.StateConfig{
		SchemaVersion:  "1.0",
		Containers:     []types.ContainerConfig{},
		Packages:       []string{},
		CustomPackages: map[string]types.CustomPackage{},
		Env:            map[string]string{},
	}

	// Get agent settings from current desired state
	if deviceDesiredState := a.configManager.GetStateConfig(); deviceDesiredState != nil {
		currentState.AgentSetting = deviceDesiredState.AgentSetting
		currentState.CustomMetrics = deviceDesiredState.CustomMetrics
	}

	// Detect currently running containers
	if a.containerManager != nil {
		// This would need to be implemented in container manager
		// For now, we'll use the desired state as a baseline
		if deviceDesiredState := a.configManager.GetStateConfig(); deviceDesiredState != nil {
			for _, desiredContainer := range deviceDesiredState.Containers {
				if a.containerManager.IsContainerRunning(desiredContainer.Name) {
					currentState.Containers = append(currentState.Containers, desiredContainer)
				}
			}
		}
	}

	// Detect currently installed packages
	if a.packageManager != nil {
		if deviceDesiredState := a.configManager.GetStateConfig(); deviceDesiredState != nil {
			// Check which packages are actually installed (not missing)
			hasDrift, missingPackages := a.packageManager.CheckPackageDrift(deviceDesiredState.Packages)
			if !hasDrift {
				// All desired packages are installed
				currentState.Packages = deviceDesiredState.Packages
			} else {
				// Only packages that are NOT missing are installed
				installedPackages := []string{}
				missingMap := make(map[string]bool)
				for _, missing := range missingPackages {
					missingMap[missing] = true
				}
				for _, desired := range deviceDesiredState.Packages {
					if !missingMap[desired] {
						installedPackages = append(installedPackages, desired)
					}
				}
				currentState.Packages = installedPackages
			}

			// Check custom packages
			hasCustomDrift, missingCustomPackages := a.packageManager.CheckCustomPackageDrift(deviceDesiredState.CustomPackages)
			if !hasCustomDrift {
				// All desired custom packages are installed
				currentState.CustomPackages = deviceDesiredState.CustomPackages
			} else {
				// Only custom packages that are NOT missing are installed
				installedCustomPackages := make(map[string]types.CustomPackage)
				for name, pkg := range deviceDesiredState.CustomPackages {
					if _, isMissing := missingCustomPackages[name]; !isMissing {
						installedCustomPackages[name] = pkg
					}
				}
				currentState.CustomPackages = installedCustomPackages
			}
		}
	}

	// Detect current environment variables
	if a.environmentManager != nil {
		if currentEnv, err := a.environmentManager.GetCurrentSystemEnvironment(); err == nil {
			currentState.Env = currentEnv
		}
	}

	return currentState
}

// syncSystemToDesiredState synchronizes the actual system state to match the desired state
func (a *CoreAgent) syncSystemToDesiredState(triggeredBy string) (*SelfHealingResult, error) {
	// Get device desired state
	deviceDesiredState := a.configManager.GetStateConfig()
	if deviceDesiredState == nil {
		return nil, fmt.Errorf("device desired state config is nil")
	}

	// Compare currentSystemState with deviceDesiredState to determine what needs to be applied
	if stateConfigsEqual(a.currentSystemState, deviceDesiredState) {
		a.logger.Info("System is already in desired state, no changes needed")
		return &SelfHealingResult{
			Success:     true,
			Errors:      make(map[string]string),
			TriggeredBy: triggeredBy,
		}, nil
	}

	// Apply changes using the same logic as API state changes
	result, err := a.applyStateChangesWithFeedback(a.currentSystemState, deviceDesiredState, triggeredBy)
	if err != nil {
		return result, err
	}

	// Update currentSystemState to reflect what was actually applied successfully
	actualAppliedState := a.createActualAppliedState(a.currentSystemState, deviceDesiredState, result)
	a.currentSystemState = cloneStateConfig(actualAppliedState)

	return result, nil
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

	// Check for drift first without logging synchronization messages
	hasDrift, driftedContainers := a.containerManager.CheckContainerDrift(state.Containers)

	if !hasDrift {
		a.logger.Info("All containers are in desired state, no corrections needed")
		return nil
	}

	a.logger.Infof("Container drift detected for %d containers, applying corrections...", len(driftedContainers))

	// Apply corrections only for drifted containers
	for _, containerConfig := range driftedContainers {
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
			a.logger.Infof("Container %s health check failed, may need restart", containerName)
			// Could restart the container here if needed
		}
	}

	return nil
}

// verifyPackages checks if packages in the specified state are actually installed
func (a *CoreAgent) verifyPackages(state *types.StateConfig) error {
	if a.packageManager == nil {
		a.logger.Info("Package manager not available, skipping package verification")
		return nil
	}

	// Use the provided state parameter, or fall back to device desired state if none provided
	targetState := state
	if targetState == nil {
		targetState = a.configManager.GetStateConfig()
		if targetState == nil {
			a.logger.Info("No state available for package verification, skipping")
			return nil
		}
	}

	if len(targetState.Packages) == 0 && len(targetState.CustomPackages) == 0 {
		a.logger.Info("No packages configured in target state, skipping package verification")
		return nil
	}

	// Check for system package drift first
	if len(targetState.Packages) > 0 {
		hasDrift, missingPackages := a.packageManager.CheckPackageDrift(targetState.Packages)

		if !hasDrift {
			a.logger.Info("All system packages are installed, no corrections needed")
		} else {
			a.logger.Infof("System package drift detected for %d packages, installing missing packages...", len(missingPackages))
			if err := a.packageManager.EnsurePackagesInstalled(missingPackages); err != nil {
				a.logger.Errorf("Failed to install missing packages: %v", err)
			} else {
				a.logger.Info("Missing system packages installed successfully")
			}
		}
	}

	// Check for custom package drift
	if len(targetState.CustomPackages) > 0 {
		hasDrift, missingPackages := a.packageManager.CheckCustomPackageDrift(targetState.CustomPackages)

		if !hasDrift {
			a.logger.Info("All custom packages are installed, no corrections needed")
		} else {
			a.logger.Infof("Custom package drift detected for %d packages, installing missing packages...", len(missingPackages))
			if err := a.packageManager.EnsureCustomPackagesInstalled(missingPackages); err != nil {
				a.logger.Errorf("Failed to install missing custom packages: %v", err)
			} else {
				a.logger.Info("Missing custom packages installed successfully")
			}
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

	// Debug: Log the full response structure for troubleshooting
	a.logger.Infof("Received response with keys: %v", getMapKeys(response))

	// Extract command and new_state from response
	cmd, cmdExists := response["cmd"]
	newStateData, stateExists := response["new_state"]

	// Validate response format - both cmd and new_state should exist or both should be missing
	if cmdExists != stateExists {
		return fmt.Errorf("invalid response format: cmd and new_state must both be present or both be missing")
	}

	// Handle the 4 possible combinations:
	// 1. cmd="" and new_state={} - No change, no command
	// 2. cmd="" and new_state={...} - State change only, no command
	// 3. cmd="..." and new_state={} - Command only, no state change
	// 4. cmd="..." and new_state={...} - Both command and state change

	var hasStateChange bool

	// Execute command if present
	if cmdExists {
		if cmdStr, ok := cmd.(string); ok && cmdStr != "" {
			a.logger.Infof("Received command: %s", cmdStr)
			if err := a.executeCommand(cmd); err != nil {
				a.logger.Errorf("Failed to execute command: %v", err)
				// Continue processing state even if command fails
			} else {
				a.logger.Info("Command executed successfully")
			}
		} else {
			a.logger.Info("Empty command received (no action needed)")
		}
	}

	// Check if we have a valid state change
	if stateExists {
		// Convert to JSON and back to StateConfig
		newStateJSON, err := json.Marshal(newStateData)
		if err != nil {
			return fmt.Errorf("failed to marshal new state: %w", err)
		}

		var newState types.StateConfig
		if err := json.Unmarshal(newStateJSON, &newState); err != nil {
			return fmt.Errorf("failed to unmarshal new state: %w", err)
		}

		// Check if the new state is empty (backend returned {} meaning no change)
		if !a.configManager.IsStateConfigEmpty(&newState) {
			hasStateChange = true
			a.logger.Info("Received new state configuration")

			// Update device desired state with the new state from API
			if err := a.configManager.UpdateStateConfig(&newState); err != nil {
				a.logger.Errorf("Failed to update device desired state: %v", err)
				return err
			}
			a.logger.Info("Device desired state updated with new configuration")
		} else {
			a.logger.Info("Empty state received (no changes needed)")
		}
	}

	// Use unified logic: sync system to desired state (handles both API changes and self-healing)
	triggeredBy := "api"
	if hasStateChange {
		a.logger.Info("State changes received, synchronizing system to desired state...")
	} else {
		a.logger.Info("No state changes received, performing self-healing to ensure system matches desired state...")
	}

	_, err := a.syncSystemToDesiredState(triggeredBy)
	if err != nil {
		a.logger.Errorf("Failed to sync system to desired state: %v", err)
		return err
	}

	return nil
}

// applyStateChangesWithFeedback applies state changes with feedback tracking
func (a *CoreAgent) applyStateChangesWithFeedback(oldState, newState *types.StateConfig, triggeredBy string) (*SelfHealingResult, error) {
	// Set self-healing flag to prevent API calls during state changes
	a.SetSelfHealing(true)
	defer a.SetSelfHealing(false)

	// Initialize self-healing result tracking
	result := &SelfHealingResult{
		Success:     true,
		Errors:      make(map[string]string),
		TriggeredBy: triggeredBy,
	}

	// Sync containers if container manager is available
	if a.containerManager != nil {
		oldContainers := []types.ContainerConfig{}
		if oldState != nil {
			oldContainers = oldState.Containers
		}

		hasChanges, err := a.containerManager.SyncContainers(newState.Containers, oldContainers)
		if err != nil {
			a.logger.Errorf("Failed to sync containers: %v", err)
			result.Success = false
			result.Errors[string(TaskContainers)] = err.Error()
		} else if hasChanges {
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
				result.Success = false
				result.Errors[string(TaskEnvironment)] = err.Error()
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

		hasChanges, err := a.packageManager.SyncPackages(newState.Packages, oldPackages)
		if err != nil {
			a.logger.Errorf("Failed to sync system packages: %v", err)
			result.Success = false
			result.Errors[string(TaskPackages)] = err.Error()
		} else if hasChanges {
			a.logger.Info("System packages synchronized successfully")
		}

		// Sync custom packages
		oldCustomPackages := make(map[string]types.CustomPackage)
		if oldState != nil {
			oldCustomPackages = oldState.CustomPackages
		}

		hasChanges, err = a.packageManager.SyncCustomPackages(newState.CustomPackages, oldCustomPackages)
		if err != nil {
			a.logger.Errorf("Failed to sync custom packages: %v", err)
			result.Success = false
			result.Errors[string(TaskCustomPackages)] = err.Error()
		} else if hasChanges {
			a.logger.Info("Custom packages synchronized successfully")
		}
	}

	// Update state configuration
	if err := a.configManager.UpdateStateConfig(newState); err != nil {
		result.Success = false
		result.Errors["state_config"] = err.Error()
		return result, fmt.Errorf("failed to update state config: %w", err)
	}

	a.logger.Info("State configuration updated")

	// Send feedback based on trigger source
	if triggeredBy == "api" {
		// Always send feedback when triggered by API
		a.sendSelfHealingFeedback(result)
	} else {
		// For local self-healing, send feedback for both success and failure
		a.sendSelfHealingFeedback(result)
	}

	return result, nil
}

// createActualAppliedState creates a state that reflects what was actually applied successfully
func (a *CoreAgent) createActualAppliedState(oldState, newState *types.StateConfig, result *SelfHealingResult) *types.StateConfig {
	// Start with the old state as baseline
	actualApplied := cloneStateConfig(oldState)
	if actualApplied == nil {
		actualApplied = &types.StateConfig{}
	}

	// Only update components that succeeded
	// If no errors occurred, use the full new state
	if result.Success {
		return cloneStateConfig(newState)
	}

	// Check each component and only apply successful changes
	if _, hasError := result.Errors[string(TaskContainers)]; !hasError {
		actualApplied.Containers = newState.Containers
	}

	if _, hasError := result.Errors[string(TaskPackages)]; !hasError {
		actualApplied.Packages = newState.Packages
	}

	if _, hasError := result.Errors[string(TaskCustomPackages)]; !hasError {
		actualApplied.CustomPackages = newState.CustomPackages
	}

	if _, hasError := result.Errors[string(TaskEnvironment)]; !hasError {
		actualApplied.Env = newState.Env
	}

	// Always update agent settings as they don't require system changes
	actualApplied.AgentSetting = newState.AgentSetting
	actualApplied.SchemaVersion = newState.SchemaVersion
	actualApplied.CustomMetrics = newState.CustomMetrics

	a.logger.Infof("Created actual applied state reflecting successful operations. Errors: %v", result.Errors)
	return actualApplied
}

// getMapKeys returns the keys of a map for debugging purposes
func getMapKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// executeCommand executes a command from the cmd field
func (a *CoreAgent) executeCommand(cmd interface{}) error {
	// Handle None/null case
	if cmd == nil {
		a.logger.Info("No command received, skipping execution")
		return nil
	}

	// Convert cmd to string
	command, ok := cmd.(string)
	if !ok {
		a.logger.Infof("Command is not a string (type: %T, value: %v), skipping execution", cmd, cmd)
		return nil
	}

	if command == "" {
		// Empty command - no action needed, return silently
		return nil
	}

	// Check if command starts with "custom"
	if strings.HasPrefix(command, "custom ") {
		a.logger.Infof("Received custom command: %s", command)
		return a.handleCustomCommand(command)
	}

	// Regular command execution
	a.logger.Infof("Executing regular command: %s", command)

	// Set a timeout for command execution (5 minutes)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Execute the command with timeout
	cmdExec := exec.CommandContext(ctx, "sh", "-c", command)

	output, err := cmdExec.CombinedOutput()
	if err != nil {
		a.logger.Errorf("Command failed: %v", err)
		a.logger.Errorf("Command output: %s", string(output))
		return fmt.Errorf("command execution failed: %w", err)
	}

	a.logger.Infof("Command executed successfully")
	if len(output) > 0 {
		a.logger.Infof("Command output: %s", string(output))
	}

	return nil
}

// handleCustomCommand handles custom commands (those starting with "custom ")
func (a *CoreAgent) handleCustomCommand(command string) error {
	// Parse command: "custom ssh user_456 2024-01-01T12:00:00Z"
	parts := strings.Fields(command)

	if len(parts) < 2 {
		return fmt.Errorf("invalid custom command format: %s", command)
	}

	// Check for SSH tunnel command
	if parts[1] == "ssh" {
		return a.handleSSHTunnelCommand(command)
	}

	// Add other custom command types here in the future
	return fmt.Errorf("unknown custom command type: %s", parts[1])
}

// handleSSHTunnelCommand handles SSH tunnel commands
func (a *CoreAgent) handleSSHTunnelCommand(command string) error {
	// Parse command: "custom ssh user_456 2024-01-01T12:00:00Z" or "ssh user123"
	parts := strings.Fields(command)

	var user string
	var expires time.Time
	var err error

	if len(parts) == 2 {
		// Format: "ssh user123" - use default expiration (1 hour from now)
		user = parts[1]
		expires = time.Now().Add(1 * time.Hour)
		a.logger.Infof("Using default expiration time: %s", expires.Format(time.RFC3339))
	} else if len(parts) == 4 {
		// Format: "custom ssh user_456 2024-01-01T12:00:00Z"
		user = parts[2]
		expiresStr := parts[3]

		// Parse expiration time
		expires, err = time.Parse(time.RFC3339, expiresStr)
		if err != nil {
			return fmt.Errorf("invalid expiration time format: %s", expiresStr)
		}
	} else {
		return fmt.Errorf("invalid SSH tunnel command format: %s (expected 'ssh user123' or 'custom ssh user_456 2024-01-01T12:00:00Z')", command)
	}

	// Check if tunnel is already active
	if a.sshTunnelManager != nil && a.sshTunnelManager.IsTunnelActive() {
		a.logger.Info("SSH tunnel already active, stopping existing tunnel")
		a.sshTunnelManager.StopTunnel()
	}

	// Start new tunnel
	a.logger.Infof("Starting SSH tunnel for user: %s, expires: %s", user, expires)

	if err := a.sshTunnelManager.StartTunnel(user, expires); err != nil {
		return fmt.Errorf("failed to start SSH tunnel: %w", err)
	}

	a.logger.Info("SSH tunnel started successfully")
	return nil
}

// sendSelfHealingFeedback sends feedback about self-healing results to the server
func (a *CoreAgent) sendSelfHealingFeedback(result *SelfHealingResult) {
	if result == nil {
		return
	}

	// Determine status based on result
	var status string

	if result.Success {
		status = "update_completed"
	} else {
		status = "update_failed"
	}

	// Build status update payload
	statusUpdate := &types.StatusUpdatePayload{
		UpdateType: status,
	}

	// Set CurrentState based on the result
	if result.Success {
		// Empty state on success
		statusUpdate.CurrentState = types.StateConfig{}
	} else {
		// For error cases, send device desired state from config manager
		// Error details will be logged for debugging
		statusUpdate.CurrentState = *a.configManager.GetStateConfig()
		a.logger.Errorf("Self-healing errors: %v", result.Errors)
	}

	// Send status update based on mode
	mode := a.configManager.GetMode()
	deviceID := a.configManager.GetDeviceID()

	switch mode {
	case "http", "https":
		if a.httpClient == nil {
			a.logger.Errorf("HTTP client not configured, cannot send self-healing feedback")
			return
		}
		response, err := a.httpClient.SendStatusUpdate(statusUpdate, deviceID)
		if err != nil {
			a.logger.Errorf("Failed to send self-healing feedback: %v", err)
			return
		}
		if response.StatusCode >= 200 && response.StatusCode < 300 {
			a.logger.Infof("Self-healing feedback sent successfully: %s", status)
		} else {
			a.logger.Errorf("Self-healing feedback failed with status: %d", response.StatusCode)
		}

	case "mqtt":
		if a.mqttClient == nil {
			a.logger.Errorf("MQTT client not configured, cannot send self-healing feedback")
			return
		}
		if !a.mqttClient.IsConnected() {
			if err := a.mqttClient.Connect(); err != nil {
				a.logger.Errorf("Failed to connect to MQTT for self-healing feedback: %v", err)
				return
			}
		}
		if err := a.mqttClient.PublishStatusUpdate(statusUpdate); err != nil {
			a.logger.Errorf("Failed to publish self-healing feedback: %v", err)
			return
		}
		a.logger.Infof("Self-healing feedback published successfully: %s", status)

	default:
		a.logger.Errorf("Unsupported mode for self-healing feedback: %s", mode)
	}
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

	a.logger.Info("State.json file changed, treating as update...")

	// Lock to prevent concurrent API updates during file-based state change
	a.statusUpdateLock.Lock()
	defer a.statusUpdateLock.Unlock()

	// Validate: Get the new state from state.json file (already loaded by config manager)
	deviceDesiredState := a.configManager.GetStateConfig()
	if deviceDesiredState == nil {
		a.logger.Errorf("Failed to get new state configuration from state.json")
		return
	}

	a.logger.Info("State.json validated successfully, processing update...")

	// Detect: Get actual system state
	actualSystemState := a.detectCurrentSystemState()
	a.currentSystemState = cloneStateConfig(actualSystemState)

	// If logging level is debug, print diff between current system state and desired state
	if strings.ToLower(deviceDesiredState.AgentSetting.LoggingLevel) == "debug" {
		a.logStateDiff(actualSystemState, deviceDesiredState)
	}

	// Sync: Compare currentSystemState vs deviceDesiredState and apply changes
	_, err := a.syncSystemToDesiredState("file")
	if err != nil {
		a.logger.Errorf("Failed to sync system to desired state: %v", err)
		return
	}

	a.logger.Info("File-based state update completed successfully")
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

		hasChanges, err := a.containerManager.SyncContainers(newState.Containers, oldContainers)
		if err != nil {
			a.logger.Errorf("Failed to sync containers: %v", err)
		} else if hasChanges {
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

		hasChanges, err := a.packageManager.SyncPackages(newState.Packages, oldPackages)
		if err != nil {
			a.logger.Errorf("Failed to sync system packages: %v", err)
		} else if hasChanges {
			a.logger.Info("System packages synchronized successfully")
		}

		// Sync custom packages
		oldCustomPackages := make(map[string]types.CustomPackage)
		if oldState != nil {
			oldCustomPackages = oldState.CustomPackages
		}

		hasChanges, err = a.packageManager.SyncCustomPackages(newState.CustomPackages, oldCustomPackages)
		if err != nil {
			a.logger.Errorf("Failed to sync custom packages: %v", err)
		} else if hasChanges {
			a.logger.Info("Custom packages synchronized successfully")
		}
	}

	// Update the state config in memory
	if err := a.configManager.UpdateStateConfig(newState); err != nil {
		return fmt.Errorf("failed to update state config: %w", err)
	}

	return nil
}

// stateConfigsEqual compares two state configurations for equality using deep comparison
func stateConfigsEqual(a, b *types.StateConfig) bool {
	if a == nil || b == nil {
		return a == b
	}

	// Compare all fields individually to avoid JSON ordering issues
	return a.SchemaVersion == b.SchemaVersion &&
		agentSettingsEqual(&a.AgentSetting, &b.AgentSetting) &&
		containersEqual(a.Containers, b.Containers) &&
		envMapsEqual(a.Env, b.Env) &&
		stringSlicesEqual(a.Packages, b.Packages) &&
		customMetricsEqual(a.CustomMetrics, b.CustomMetrics) &&
		customPackagesEqual(a.CustomPackages, b.CustomPackages)
}

// agentSettingsEqual compares two AgentSetting structs for equality
func agentSettingsEqual(a, b *types.AgentSetting) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.HeartbeatFrequency == b.HeartbeatFrequency &&
		a.UpdateFrequency == b.UpdateFrequency &&
		a.Mode == b.Mode &&
		a.AgentVer == b.AgentVer &&
		a.LoggingLevel == b.LoggingLevel
}

// containersEqual compares two slices of ContainerConfig for equality
func containersEqual(a, b []types.ContainerConfig) bool {
	if len(a) != len(b) {
		return false
	}

	// Create maps for comparison (order-independent)
	aMap := make(map[string]types.ContainerConfig)
	bMap := make(map[string]types.ContainerConfig)

	for _, container := range a {
		aMap[container.Name] = container
	}
	for _, container := range b {
		bMap[container.Name] = container
	}

	// Compare each container
	for name, containerA := range aMap {
		containerB, exists := bMap[name]
		if !exists || !containerConfigEqual(containerA, containerB) {
			return false
		}
	}

	return true
}

// containerConfigEqual compares two ContainerConfig structs for equality
func containerConfigEqual(a, b types.ContainerConfig) bool {
	return a.Name == b.Name &&
		a.Image == b.Image &&
		a.Port == b.Port &&
		a.HealthPath == b.HealthPath &&
		envMapsEqual(a.Env, b.Env)
}

// stringSlicesEqual compares two string slices for equality (order-independent)
func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}

	// Create maps for comparison
	aMap := make(map[string]bool)
	bMap := make(map[string]bool)

	for _, s := range a {
		aMap[s] = true
	}
	for _, s := range b {
		bMap[s] = true
	}

	// Compare maps
	for key := range aMap {
		if !bMap[key] {
			return false
		}
	}
	for key := range bMap {
		if !aMap[key] {
			return false
		}
	}

	return true
}

// customMetricsEqual compares two custom metrics maps for equality
func customMetricsEqual(a, b map[string]string) bool {
	return envMapsEqual(a, b)
}

// customPackagesEqual compares two custom packages maps for equality
func customPackagesEqual(a, b map[string]types.CustomPackage) bool {
	if len(a) != len(b) {
		return false
	}

	for name, pkgA := range a {
		pkgB, exists := b[name]
		if !exists || !customPackageEqual(pkgA, pkgB) {
			return false
		}
	}

	return true
}

// customPackageEqual compares two CustomPackage structs for equality
func customPackageEqual(a, b types.CustomPackage) bool {
	return a.Install == b.Install &&
		a.Check == b.Check &&
		a.Uninstall == b.Uninstall
}

// logStateDiff logs a concise diff of two state configs when in debug mode
func (a *CoreAgent) logStateDiff(oldState, newState *types.StateConfig) {
	if oldState == nil {
		a.logger.Info("[DEBUG] No previous state; treating entire state as new")
		return
	}

	// Compare top-level sections
	if oldState.AgentSetting != newState.AgentSetting {
		a.logger.Infof("[DEBUG] AgentSetting changed: old=%v new=%v", oldState.AgentSetting, newState.AgentSetting)
	}
	if !envMapsEqual(oldState.Env, newState.Env) {
		a.logger.Infof("[DEBUG] Env changed: old=%v new=%v", oldState.Env, newState.Env)
	}
	// Containers
	oldC, _ := json.Marshal(oldState.Containers)
	newC, _ := json.Marshal(newState.Containers)
	if string(oldC) != string(newC) {
		a.logger.Infof("[DEBUG] Containers changed: old=%s new=%s", string(oldC), string(newC))
	}
	// Packages
	oldP, _ := json.Marshal(oldState.Packages)
	newP, _ := json.Marshal(newState.Packages)
	if string(oldP) != string(newP) {
		a.logger.Infof("[DEBUG] Packages changed: old=%s new=%s", string(oldP), string(newP))
	}
	// Custom packages
	oldCP, _ := json.Marshal(oldState.CustomPackages)
	newCP, _ := json.Marshal(newState.CustomPackages)
	if string(oldCP) != string(newCP) {
		a.logger.Infof("[DEBUG] CustomPackages changed: old=%s new=%s", string(oldCP), string(newCP))
	}
}

// cloneStateConfig makes a deep copy of a StateConfig
func cloneStateConfig(s *types.StateConfig) *types.StateConfig {
	if s == nil {
		return nil
	}
	data, _ := json.Marshal(s)
	var out types.StateConfig
	_ = json.Unmarshal(data, &out)
	return &out
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
