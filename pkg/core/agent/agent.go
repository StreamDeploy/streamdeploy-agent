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

	// Self-healing lock to prevent status updates during system state corrections
	selfHealingLock sync.RWMutex
	isSelfHealing   bool

	// Desired system state (initialized from config, updated by statusupdate manager)
	desiredState *types.StateConfig

	// Current system state snapshot for diffing
	currentSystemState *types.StateConfig
}

// NewCoreAgent creates a new core agent instance using config for initialization
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
	if agent.desiredState == nil {
		logger.Info("No state config found, creating empty desired state")
		agent.desiredState = &types.StateConfig{
			SchemaVersion: "1.0",
			AgentSetting: types.AgentSetting{
				HeartbeatFrequency: "15s",
				UpdateFrequency:    "30s",
				Mode:               "http",
				LoggingLevel:       "info",
			},
			Containers:     []types.ContainerConfig{},
			Env:            make(map[string]string),
			Packages:       []string{},
			CustomMetrics:  make(map[string]string),
			CustomPackages: make(map[string]types.CustomPackage),
		}
	}

	logger.Info("Core agent initialized successfully with config-based desired state")

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

// Start starts the core agent - orchestration only
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

	// Initialize and start all managers
	a.initializeHeartbeatManager()
	a.initializeStatusUpdateManager()
	a.initializeUpdateManager()

	// Start certificate check loop
	if a.certificateManager != nil {
		go a.certificateManager.StartCertificateCheckLoop(a.ctx, a.certificateCheckInterval)
	}

	a.logger.Info("Core agent started successfully - all managers initialized")
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

	// Stop all managers
	if a.heartbeatManager != nil {
		a.heartbeatManager.Stop()
	}

	if a.statusUpdateManager != nil {
		a.statusUpdateManager.Stop()
	}

	if a.agentupdateManager != nil {
		a.agentupdateManager.Stop()
	}

	a.logger.Info("Core agent stopped")
}

// initializeHeartbeatManager initializes the heartbeat manager
func (a *CoreAgent) initializeHeartbeatManager() {
	deviceID := a.configManager.GetDeviceID()
	mode := a.configManager.GetMode()

	heartbeatManager := heartbeat.NewManager(
		a.httpClient,
		a.mqttClient,
		deviceID,
		mode,
		a.metricsCollector,
		a.containerManager,
		a.logger,
	)

	if a.desiredState != nil {
		heartbeatManager.SetDesiredState(a.desiredState)
	}

	a.heartbeatManager = heartbeatManager

	heartbeatInterval := a.configManager.GetHeartbeatFrequency()
	if err := heartbeatManager.StartHeartbeatLoop(a.ctx, heartbeatInterval, a.IsUpdating); err != nil {
		a.logger.Errorf("Failed to start heartbeat loop: %v", err)
	}
}

// initializeStatusUpdateManager initializes the status update manager
func (a *CoreAgent) initializeStatusUpdateManager() {
	deviceID := a.configManager.GetDeviceID()
	mode := a.configManager.GetMode()

	// Create status update manager - it will handle all the state management logic
	statusUpdateManager := statusupdate.NewManager(
		a.httpClient,
		a.mqttClient,
		deviceID,
		mode,
		a.logger,
		a.containerManager,
		a.systemPackageManager,
		a.customPackageManager,
		a.environmentManager,
		a.configManager,
		a, // Pass agent for orchestration callbacks
	)

	a.statusUpdateManager = statusUpdateManager

	// Start status update loop - the manager handles everything
	statusUpdateInterval := a.configManager.GetStatusFrequency()
	a.logger.Infof("Starting status update loop with interval: %v", statusUpdateInterval)
	if err := statusUpdateManager.StartStatusUpdateLoop(a.ctx, statusUpdateInterval, a.IsUpdating, a.IsSelfHealing); err != nil {
		a.logger.Errorf("Failed to start status update loop: %v", err)
	}
}

// initializeUpdateManager initializes the update manager
func (a *CoreAgent) initializeUpdateManager() {
	agentupdateManager := agentupdate.NewManager(a.logger)
	a.agentupdateManager = agentupdateManager

	updateInterval := 1 * time.Hour
	if err := agentupdateManager.StartUpdateLoop(a.ctx, updateInterval, a.IsUpdating); err != nil {
		a.logger.Errorf("Failed to start update loop: %v", err)
	}
}

// IsRunning returns whether the agent is running
func (a *CoreAgent) IsRunning() bool {
	return a.running
}

// Interface implementations for statusupdate manager callbacks

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

// SetDesiredState sets the agent's desired state (called by statusupdate manager)
func (a *CoreAgent) SetDesiredState(state *types.StateConfig) {
	a.desiredState = state
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

// ExecuteCommand executes a command (called by statusupdate manager)
func (a *CoreAgent) ExecuteCommand(cmd interface{}) error {
	return a.executeCommand(cmd)
}

// GetCurrentSystemState returns the current system state
func (a *CoreAgent) GetCurrentSystemState() *types.StateConfig {
	return a.currentSystemState
}

// SetCurrentSystemState sets the current system state
func (a *CoreAgent) SetCurrentSystemState(state *types.StateConfig) {
	a.currentSystemState = state
}

// GetStatusUpdateManager returns the status update manager
func (a *CoreAgent) GetStatusUpdateManager() interface{} {
	return a.statusUpdateManager
}

// SyncSystemToDesiredState synchronizes the system to the desired state
func (a *CoreAgent) SyncSystemToDesiredState(triggeredBy string) (bool, error) {
	// This is a placeholder - in the new architecture, the statusupdate manager handles this
	a.logger.Infof("SyncSystemToDesiredState called with triggeredBy: %s", triggeredBy)
	return true, nil
}

// VerifyAndCorrectSystemState verifies and corrects the system state
func (a *CoreAgent) VerifyAndCorrectSystemState(desiredState *types.StateConfig) error {
	// This is a placeholder - in the new architecture, the statusupdate manager handles this
	a.logger.Info("VerifyAndCorrectSystemState called")
	return nil
}

// CloneStateConfig clones a state config
func (a *CoreAgent) CloneStateConfig(state *types.StateConfig) *types.StateConfig {
	return cloneStateConfig(state)
}

// SetUpdating sets the update lock
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

// SetSelfHealing sets the self-healing lock
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

// executeCommand executes a command from the cmd field
func (a *CoreAgent) executeCommand(cmd interface{}) error {
	if cmd == nil {
		a.logger.Info("No command received, skipping execution")
		return nil
	}

	command, ok := cmd.(string)
	if !ok {
		a.logger.Infof("Command is not a string (type: %T, value: %v), skipping execution", cmd, cmd)
		return nil
	}

	if command == "" {
		return nil
	}

	if strings.HasPrefix(command, "custom ") {
		a.logger.Infof("Received custom command: %s", command)
		// Delegate to status update manager for custom command handling
		if statusUpdateMgr, ok := a.statusUpdateManager.(interface{ HandleCustomCommand(string) error }); ok {
			return statusUpdateMgr.HandleCustomCommand(command)
		}
		return fmt.Errorf("status update manager does not support custom commands")
	}

	a.logger.Infof("Executing regular command: %s", command)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

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

// WaitForUpdateAndApplyStateChange waits for the current update to complete and then applies state changes
func (a *CoreAgent) WaitForUpdateAndApplyStateChange() {
	a.logger.Info("Waiting for current update to complete before applying state changes...")

	// Wait for update to complete
	for a.IsUpdating() {
		time.Sleep(100 * time.Millisecond)
	}

	a.logger.Info("Update completed, applying state changes...")

	// Get the config manager and trigger state change handling
	if a.configManager != nil {
		a.configManager.HandleStateConfigChange(false)
	}
}

// WaitForUpdateAndApplyDeviceChange waits for the current update to complete and then applies device configuration changes
func (a *CoreAgent) WaitForUpdateAndApplyDeviceChange() {
	a.logger.Info("Waiting for current update to complete before applying device configuration changes...")

	// Wait for update to complete
	for a.IsUpdating() {
		time.Sleep(100 * time.Millisecond)
	}

	a.logger.Info("Update completed, applying device configuration changes...")

	// Get the config manager and trigger device change handling
	if a.configManager != nil {
		a.configManager.HandleDeviceConfigChange(false)
	}
}

// LogStateDiff logs the differences between old and new state configurations
func (a *CoreAgent) LogStateDiff(oldState, newState *types.StateConfig) {
	if oldState == nil || newState == nil {
		a.logger.Info("Cannot log state diff - one or both states are nil")
		return
	}

	a.logger.Info("=== State Configuration Differences ===")

	// Compare agent settings
	if oldState.AgentSetting.HeartbeatFrequency != newState.AgentSetting.HeartbeatFrequency {
		a.logger.Infof("Heartbeat frequency: %s -> %s", oldState.AgentSetting.HeartbeatFrequency, newState.AgentSetting.HeartbeatFrequency)
	}
	if oldState.AgentSetting.UpdateFrequency != newState.AgentSetting.UpdateFrequency {
		a.logger.Infof("Update frequency: %s -> %s", oldState.AgentSetting.UpdateFrequency, newState.AgentSetting.UpdateFrequency)
	}
	if oldState.AgentSetting.Mode != newState.AgentSetting.Mode {
		a.logger.Infof("Mode: %s -> %s", oldState.AgentSetting.Mode, newState.AgentSetting.Mode)
	}
	if oldState.AgentSetting.LoggingLevel != newState.AgentSetting.LoggingLevel {
		a.logger.Infof("Logging level: %s -> %s", oldState.AgentSetting.LoggingLevel, newState.AgentSetting.LoggingLevel)
	}

	// Compare containers
	oldContainerCount := len(oldState.Containers)
	newContainerCount := len(newState.Containers)
	if oldContainerCount != newContainerCount {
		a.logger.Infof("Container count: %d -> %d", oldContainerCount, newContainerCount)
	}

	// Compare packages
	oldPackageCount := len(oldState.Packages)
	newPackageCount := len(newState.Packages)
	if oldPackageCount != newPackageCount {
		a.logger.Infof("Package count: %d -> %d", oldPackageCount, newPackageCount)
	}

	// Compare custom packages
	oldCustomPackageCount := len(oldState.CustomPackages)
	newCustomPackageCount := len(newState.CustomPackages)
	if oldCustomPackageCount != newCustomPackageCount {
		a.logger.Infof("Custom package count: %d -> %d", oldCustomPackageCount, newCustomPackageCount)
	}

	// Compare environment variables
	oldEnvCount := len(oldState.Env)
	newEnvCount := len(newState.Env)
	if oldEnvCount != newEnvCount {
		a.logger.Infof("Environment variable count: %d -> %d", oldEnvCount, newEnvCount)
	}

	a.logger.Info("=== End State Configuration Differences ===")
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
