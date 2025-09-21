package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/StreamDeploy/streamdeploy-agent/pkg/core/agentupdate"
	"github.com/StreamDeploy/streamdeploy-agent/pkg/core/config"
	"github.com/StreamDeploy/streamdeploy-agent/pkg/core/heartbeat"
	"github.com/StreamDeploy/streamdeploy-agent/pkg/core/statusupdate"
	"github.com/StreamDeploy/streamdeploy-agent/pkg/core/types"
	"github.com/StreamDeploy/streamdeploy-agent/pkg/core/utils"
)

type CoreAgent struct {
	configManager        types.ConfigManager
	logger               types.Logger
	httpClient           types.HTTPClient
	mqttClient           types.MQTTClient
	metricsCollector     types.MetricsCollector
	containerManager     types.ContainerManager
	certificateManager   types.CertificateManager
	environmentManager   types.EnvironmentManager
	systemPackageManager types.SystemPackageManager
	customPackageManager types.CustomPackageManager
	sshTunnelManager     types.SSHTunnelManager
	heartbeatManager     heartbeat.ManagerInterface
	statusUpdateManager  statusupdate.ManagerInterface
	agentupdateManager   agentupdate.ManagerInterface

	// Control channels
	ctx     context.Context
	cancel  context.CancelFunc
	running bool

	// Timing
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
	selfHealingResult *statusupdate.SelfHealingResult

	// Desired system state (from config manager, updated via API)
	desiredState *types.StateConfig

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
	agent.certificateCheckInterval = 24 * time.Hour // Check certificates daily

	// Initialize desired state from config manager
	agent.desiredState = configManager.GetStateConfig()

	// Initialize current system state by detecting actual system state
	// This will be properly set when managers are configured
	agent.currentSystemState = nil

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

// UpdateDesiredState updates the desired state from the config manager
func (a *CoreAgent) UpdateDesiredState() {
	a.desiredState = a.configManager.GetStateConfig()
}

// SetSystemPackageManager sets the system package manager implementation
func (a *CoreAgent) SetSystemPackageManager(manager types.SystemPackageManager) {
	a.systemPackageManager = manager
}

// SetCustomPackageManager sets the custom package manager implementation
func (a *CoreAgent) SetCustomPackageManager(manager types.CustomPackageManager) {
	a.customPackageManager = manager
}

// SetUpdateManager sets the update manager implementation
func (a *CoreAgent) SetUpdateManager(manager agentupdate.ManagerInterface) {
	a.agentupdateManager = manager
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
	a.configManager.SetConfigChangeCallback(a.configManager.HandleConfigChange)

	// Set agent reference in config manager
	a.configManager.SetAgent(a)

	// Start config monitoring
	if err := a.configManager.StartMonitoring(); err != nil {
		a.logger.Errorf("Failed to start config monitoring: %v", err)
	}

	// Initialize heartbeat manager
	a.initializeHeartbeatManager()

	// Initialize status update manager
	a.initializeStatusUpdateManager()

	// Initialize update manager
	a.initializeUpdateManager()

	// Start worker goroutines
	if a.certificateManager != nil {
		go a.certificateManager.StartCertificateCheckLoop(a.ctx, a.certificateCheckInterval)
	}

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

	// Stop heartbeat manager
	if a.heartbeatManager != nil {
		a.heartbeatManager.Stop()
	}

	// Stop status update manager
	if a.statusUpdateManager != nil {
		a.statusUpdateManager.Stop()
	}

	// Stop update manager
	if a.agentupdateManager != nil {
		a.agentupdateManager.Stop()
	}

	a.logger.Info("Core agent stopped")
}

// initializeHeartbeatManager initializes the heartbeat manager
func (a *CoreAgent) initializeHeartbeatManager() {
	deviceID := a.configManager.GetDeviceID()
	mode := a.configManager.GetMode()

	// Create heartbeat manager
	heartbeatManager := heartbeat.NewManager(
		a.httpClient,
		a.mqttClient,
		deviceID,
		mode,
		a.metricsCollector,
		a.containerManager,
		a.logger,
	)

	// Set the desired state if available
	if a.desiredState != nil {
		heartbeatManager.SetDesiredState(a.desiredState)
	}

	a.heartbeatManager = heartbeatManager

	// Start heartbeat loop
	heartbeatInterval := a.configManager.GetHeartbeatFrequency()
	if err := heartbeatManager.StartHeartbeatLoop(a.ctx, heartbeatInterval, a.IsUpdating); err != nil {
		a.logger.Errorf("Failed to start heartbeat loop: %v", err)
	}
}

// initializeStatusUpdateManager initializes the status update manager
func (a *CoreAgent) initializeStatusUpdateManager() {
	deviceID := a.configManager.GetDeviceID()
	mode := a.configManager.GetMode()

	// Create status update response handler using the new default handler
	responseHandler := statusupdate.NewDefaultResponseHandler(a)

	// Create status update manager
	statusUpdateManager := statusupdate.NewManager(
		a.httpClient,
		a.mqttClient,
		deviceID,
		mode,
		cloneStateConfig,
		responseHandler,
		a.logger,
		a.containerManager,
		a.systemPackageManager,
		a.customPackageManager,
		a.environmentManager,
		a.desiredState,
	)

	a.statusUpdateManager = statusUpdateManager

	// Initialize current system state by detecting actual system state
	a.currentSystemState = statusupdate.DetectCurrentState(
		a.desiredState,
		a.containerManager,
		a.systemPackageManager,
		a.customPackageManager,
		a.environmentManager,
	)

	// Start status update loop
	statusUpdateInterval := a.configManager.GetStatusFrequency()
	if err := statusUpdateManager.StartStatusUpdateLoop(a.ctx, statusUpdateInterval, a.IsUpdating, a.IsSelfHealing); err != nil {
		a.logger.Errorf("Failed to start status update loop: %v", err)
	}
}

// initializeUpdateManager initializes the update manager
func (a *CoreAgent) initializeUpdateManager() {
	// Create update manager
	agentupdateManager := agentupdate.NewManager(a.logger)

	a.agentupdateManager = agentupdateManager

	// Start update loop
	updateInterval := 1 * time.Hour // Check for agent updates every hour
	if err := agentupdateManager.StartUpdateLoop(a.ctx, updateInterval, a.IsUpdating); err != nil {
		a.logger.Errorf("Failed to start update loop: %v", err)
	}
}

// IsRunning returns whether the agent is running
func (a *CoreAgent) IsRunning() bool {
	return a.running
}

// AgentInterface implementation for statusupdate package

// GetLogger returns the agent's logger
func (a *CoreAgent) GetLogger() types.Logger {
	return a.logger
}

// GetConfigManager returns the agent's config manager
func (a *CoreAgent) GetConfigManager() types.ConfigManager {
	return a.configManager
}

// GetDesiredState returns the agent's desired state
func (a *CoreAgent) GetDesiredState() *types.StateConfig {
	return a.desiredState
}

// SetDesiredState sets the agent's desired state
func (a *CoreAgent) SetDesiredState(state *types.StateConfig) {
	a.desiredState = state
}

// ExecuteCommand executes a command (exposed for statusupdate package)
func (a *CoreAgent) ExecuteCommand(cmd interface{}) error {
	return a.executeCommand(cmd)
}

// SyncSystemToDesiredState syncs the system to the desired state (exposed for statusupdate package)
func (a *CoreAgent) SyncSystemToDesiredState(triggeredBy string) (bool, error) {
	// Use the response handler to sync system to desired state
	responseHandler := statusupdate.NewDefaultResponseHandler(a)
	result, err := responseHandler.SyncSystemToDesiredState(triggeredBy)
	return result.Success, err
}

// VerifyAndCorrectSystemState verifies and corrects the system state (exposed for statusupdate package)
func (a *CoreAgent) VerifyAndCorrectSystemState(desiredState *types.StateConfig) error {
	return a.verifyAndCorrectSystemState(desiredState)
}

// CloneStateConfig clones a state config (exposed for statusupdate package)
func (a *CoreAgent) CloneStateConfig(state *types.StateConfig) *types.StateConfig {
	return cloneStateConfig(state)
}

// GetCurrentSystemState returns the current system state
func (a *CoreAgent) GetCurrentSystemState() *types.StateConfig {
	return a.currentSystemState
}

// SetCurrentSystemState sets the current system state
func (a *CoreAgent) SetCurrentSystemState(state *types.StateConfig) {
	a.currentSystemState = state
}

// GetContainerManager returns the container manager
func (a *CoreAgent) GetContainerManager() types.ContainerManager {
	return a.containerManager
}

// GetSystemPackageManager returns the system package manager
func (a *CoreAgent) GetSystemPackageManager() types.SystemPackageManager {
	return a.systemPackageManager
}

// GetCustomPackageManager returns the custom package manager
func (a *CoreAgent) GetCustomPackageManager() types.CustomPackageManager {
	return a.customPackageManager
}

// GetEnvironmentManager returns the environment manager
func (a *CoreAgent) GetEnvironmentManager() types.EnvironmentManager {
	return a.environmentManager
}

// GetHeartbeatManager returns the heartbeat manager
func (a *CoreAgent) GetHeartbeatManager() interface{} {
	return a.heartbeatManager
}

// GetStatusUpdateManager returns the status update manager
func (a *CoreAgent) GetStatusUpdateManager() interface{} {
	return a.statusUpdateManager
}

// LogStateDiff logs a concise diff of two state configs when in debug mode
func (a *CoreAgent) LogStateDiff(oldState, newState *types.StateConfig) {
	a.logStateDiff(oldState, newState)
}

// WaitForUpdateAndApplyStateChange waits for update to complete and then applies state change
func (a *CoreAgent) WaitForUpdateAndApplyStateChange() {
	a.waitForUpdateAndApplyStateChange()
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

// verifyAndCorrectSystemState verifies that the actual system state matches the in-memory state
func (a *CoreAgent) verifyAndCorrectSystemState(state *types.StateConfig) error {
	_, err := a.statusUpdateManager.VerifyAndCorrectSystemStateWithFeedback(state, "local")
	return err
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
		return a.sshTunnelManager.HandleCustomCommand(command)
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
				a.configManager.HandleStateConfigChange(false)
				return
			}
		case <-timeout:
			a.logger.Errorf("Timeout waiting for update to complete, applying state change anyway...")
			a.configManager.HandleStateConfigChange(false)
			return
		}
	}
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
		packagesEqual(a.Packages, b.Packages) &&
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

// packagesEqual compares two string slices for equality (order-independent)
func packagesEqual(a, b []string) bool {
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
