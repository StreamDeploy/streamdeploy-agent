package statusupdate

import (
	"context"
	"fmt"
	"time"

	"github.com/StreamDeploy/streamdeploy-agent/pkg/core/types"
)

// ManagerInterface defines the interface for status update management
type ManagerInterface interface {
	StartStatusUpdateLoop(ctx context.Context, interval time.Duration, isUpdating func() bool, isSelfHealing func() bool) error
	StartAgentUpdateLoop(ctx context.Context, interval time.Duration, isUpdating func() bool) error
	SendStatusUpdate(updateType string) error
	CheckForAgentUpdate() error
	VerifyAndCorrectSystemStateWithFeedback(state *types.StateConfig, triggeredBy string) (*SelfHealingResult, error)
	Stop()
}

// Manager provides a complete status update management solution
type Manager struct {
	*StatusUpdateSender
	payloadBuilder       *PayloadBuilder
	logger               types.Logger
	running              bool
	stopChan             chan struct{}
	responseHandler      StatusUpdateResponseHandler
	containerManager     types.ContainerManager
	systemPackageManager types.SystemPackageManager
	customPackageManager types.CustomPackageManager
	environmentManager   types.EnvironmentManager
	desiredState         *types.StateConfig
	currentState         *types.StateConfig
}

// NewManager creates a new status update manager
func NewManager(
	httpClient types.HTTPClient,
	mqttClient types.MQTTClient,
	deviceID string,
	mode string,
	cloneStateConfig func(*types.StateConfig) *types.StateConfig,
	responseHandler StatusUpdateResponseHandler,
	logger types.Logger,
	containerManager types.ContainerManager,
	systemPackageManager types.SystemPackageManager,
	customPackageManager types.CustomPackageManager,
	environmentManager types.EnvironmentManager,
	desiredState *types.StateConfig,
) *Manager {
	baseSender := NewStatusUpdateSender(httpClient, mqttClient, deviceID, mode, logger)

	return &Manager{
		StatusUpdateSender:   baseSender.(*StatusUpdateSender),
		payloadBuilder:       NewPayloadBuilder(cloneStateConfig),
		logger:               logger,
		stopChan:             make(chan struct{}),
		running:              false,
		responseHandler:      responseHandler,
		containerManager:     containerManager,
		systemPackageManager: systemPackageManager,
		customPackageManager: customPackageManager,
		environmentManager:   environmentManager,
		desiredState:         desiredState,
		currentState:         nil,
	}
}

// StartStatusUpdateLoop starts the status update loop
func (m *Manager) StartStatusUpdateLoop(ctx context.Context, interval time.Duration, isUpdating func() bool, isSelfHealing func() bool) error {
	if m.running {
		return fmt.Errorf("status update loop is already running")
	}

	m.running = true
	m.logger.Infof("Status update loop started with interval: %v", interval)

	go m.statusUpdateLoop(ctx, interval, isUpdating, isSelfHealing)
	return nil
}

// statusUpdateLoop runs the status update loop
func (m *Manager) statusUpdateLoop(ctx context.Context, interval time.Duration, isUpdating func() bool, isSelfHealing func() bool) {
	m.logger.Infof("Starting status update loop with interval: %v", interval)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopChan:
			m.logger.Info("Status update loop stopped")
			m.running = false
			return
		case <-ctx.Done():
			m.logger.Info("Status update loop stopped due to context cancellation")
			m.running = false
			return
		case <-ticker.C:
			m.logger.Infof("Status update ticker triggered, interval was: %v", interval)
			// Skip update check if agent is updating or self-healing
			if isUpdating() {
				m.logger.Info("Skipping status update - agent is updating")
				continue
			}
			if isSelfHealing() {
				m.logger.Info("Skipping status update - agent is self-healing")
				continue
			}

			if err := m.SendStatusUpdate("update_check"); err != nil {
				m.logger.Errorf("Status update failed: %v", err)
			}
		}
	}
}

// SendStatusUpdate sends a status update with the specified type
// Flow: check current status -> send API -> update desired status if change -> sync by comparing current and desired status -> run command if present
func (m *Manager) SendStatusUpdate(updateType string) error {
	// Step 1: Check current status - detect current state to update the currentState in memory
	m.detectCurrentState()

	// Step 2: Build status update payload using the detected current state
	payload, clonedState, err := m.buildStatusUpdatePayload(updateType)
	if err != nil {
		return fmt.Errorf("failed to build status update payload: %w", err)
	}

	// Step 3: Send API - send the status update to the server
	sendResult := m.StatusUpdateSender.SendStatusUpdateWithResult(payload)
	if sendResult.Error != nil {
		return fmt.Errorf("failed to send status update: %w", sendResult.Error)
	}

	// Step 4: Process response which handles:
	// - Update desired status if change (via response handler)
	// - Sync by comparing current and desired status (via response handler)
	// - Run command if present (via response handler)
	selfHealResult := m.StatusUpdateSender.PerformSelfHeal(sendResult, m.responseHandler)
	if selfHealResult.Error != nil {
		return fmt.Errorf("self-healing failed: %w", selfHealResult.Error)
	}

	// Return the cloned state for the caller to use if needed
	// This allows the agent to update its currentSystemState
	_ = clonedState // For now, we'll let the agent handle this

	return nil
}

// detectCurrentState detects the current state and updates the currentState in memory
func (m *Manager) detectCurrentState() {
	m.currentState = DetectCurrentState(
		m.desiredState,
		m.containerManager,
		m.systemPackageManager,
		m.customPackageManager,
		m.environmentManager,
	)
}

// buildStatusUpdatePayload builds a status update payload using the current state
func (m *Manager) buildStatusUpdatePayload(updateType string) (*types.StatusUpdatePayload, *types.StateConfig, error) {
	if m.currentState == nil {
		return nil, nil, fmt.Errorf("current state not detected")
	}

	// Use the payload builder to build the payload
	return m.payloadBuilder.BuildStatusUpdatePayload(updateType, m.currentState)
}

// StartAgentUpdateLoop starts the agent update check loop
func (m *Manager) StartAgentUpdateLoop(ctx context.Context, interval time.Duration, isUpdating func() bool) error {
	m.logger.Infof("Agent update loop started with interval: %v", interval)

	go m.agentUpdateLoop(ctx, interval, isUpdating)
	return nil
}

// agentUpdateLoop runs the agent update check loop
func (m *Manager) agentUpdateLoop(ctx context.Context, interval time.Duration, isUpdating func() bool) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			m.logger.Info("Agent update loop stopped due to context cancellation")
			return
		case <-ticker.C:
			// Only check for agent updates if not already updating
			if !isUpdating() {
				if err := m.CheckForAgentUpdate(); err != nil {
					m.logger.Errorf("Agent update check failed: %v", err)
				}
			} else {
				m.logger.Info("Skipping agent update check - already updating")
			}
		}
	}
}

// CheckForAgentUpdate checks if the agent binary itself needs updating
func (m *Manager) CheckForAgentUpdate() error {
	// This method can be called to check if the agent needs to update itself
	// For now, we'll implement a simple check that can be extended
	// In a real implementation, this would check for new agent versions

	m.logger.Info("Checking for agent self-update...")

	// TODO: Implement actual agent update logic here
	// This could involve:
	// 1. Checking for new agent versions from the API
	// 2. Downloading new agent binary
	// 3. Replacing current binary
	// 4. Restarting the agent service

	m.logger.Info("Agent self-update check completed")
	return nil
}

// Stop stops the status update manager
func (m *Manager) Stop() {
	if m.running {
		close(m.stopChan)
		m.running = false
	}
}

// SendSystemHealingFeedback sends feedback about system healing results to the server
func (m *Manager) SendSystemHealingFeedback(result *SelfHealingResult) {
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

	// Log self-healing errors if any
	if !result.Success {
		m.logger.Errorf("Self-healing errors: %v", result.Errors)
	}

	// Send the feedback via status update
	if err := m.SendStatusUpdate(status); err != nil {
		m.logger.Errorf("Failed to send system healing feedback: %v", err)
	} else {
		m.logger.Infof("System healing feedback sent successfully: %s", status)
	}
}

// VerifyAndCorrectSystemStateWithFeedback verifies system state and sends feedback
func (m *Manager) VerifyAndCorrectSystemStateWithFeedback(state *types.StateConfig, triggeredBy string) (*SelfHealingResult, error) {
	// Initialize self-healing result tracking
	result := &SelfHealingResult{
		Success:     true,
		Errors:      make(map[string]string),
		TriggeredBy: triggeredBy,
	}

	m.logger.Info("Verifying system state against configuration...")

	// Verify containers
	if err := m.verifyContainers(state); err != nil {
		m.logger.Errorf("Container verification failed: %v", err)
		result.Success = false
		result.Errors[string(TaskContainers)] = err.Error()
		// Continue with other verifications
	}

	// Verify packages
	if err := m.verifyPackages(state); err != nil {
		m.logger.Errorf("Package verification failed: %v", err)
		result.Success = false
		result.Errors[string(TaskPackages)] = err.Error()
		// Continue with other verifications
	}

	// Verify custom packages
	if err := m.verifyCustomPackages(state); err != nil {
		m.logger.Errorf("Custom package verification failed: %v", err)
		result.Success = false
		result.Errors[string(TaskCustomPackages)] = err.Error()
		// Continue with other verifications
	}

	// Verify environment variables
	if err := m.verifyEnvironmentVariables(state); err != nil {
		m.logger.Errorf("Environment variable verification failed: %v", err)
		result.Success = false
		result.Errors[string(TaskEnvironment)] = err.Error()
		// Continue with other verifications
	}

	// Send feedback
	m.SendSystemHealingFeedback(result)

	return result, nil
}

// verifyContainers checks if containers in the state are actually running
func (m *Manager) verifyContainers(state *types.StateConfig) error {
	if m.containerManager == nil {
		m.logger.Info("Container manager not available, skipping container verification")
		return nil
	}

	if len(state.Containers) == 0 {
		m.logger.Info("No containers configured, skipping container verification")
		return nil
	}

	// Check for drift first without logging synchronization messages
	hasDrift, driftedContainers := m.containerManager.CheckContainerDrift(state.Containers)

	if !hasDrift {
		m.logger.Info("All containers are in desired state, no corrections needed")
		return nil
	}

	m.logger.Infof("Container drift detected for %d containers, applying corrections...", len(driftedContainers))

	// Apply corrections only for drifted containers
	for _, containerConfig := range driftedContainers {
		containerName := containerConfig.Name

		// Check if container is running
		if !m.containerManager.IsContainerRunning(containerName) {
			m.logger.Infof("Container %s is not running, attempting to start it...", containerName)

			// Try to start the container
			if err := m.containerManager.EnsureContainersRunning([]types.ContainerConfig{containerConfig}); err != nil {
				m.logger.Errorf("Failed to start container %s: %v", containerName, err)
				continue
			}

			m.logger.Infof("Container %s started successfully", containerName)
		} else {
			m.logger.Infof("Container %s health check failed, may need restart", containerName)
			// Could restart the container here if needed
		}
	}

	return nil
}

// verifyPackages checks which packages from desired state are actually installed
func (m *Manager) verifyPackages(state *types.StateConfig) error {
	if m.systemPackageManager == nil && m.customPackageManager == nil {
		m.logger.Info("No package managers available, skipping package verification")
		return nil
	}

	// Use the provided state parameter, or fall back to device desired state if none provided
	targetState := state
	if targetState == nil {
		targetState = m.desiredState
		if targetState == nil {
			m.logger.Info("No state available for package verification, skipping")
			return nil
		}
	}

	if len(targetState.Packages) == 0 && len(targetState.CustomPackages) == 0 {
		m.logger.Info("No packages configured in target state, skipping package verification")
		return nil
	}

	// Check which system packages are currently installed
	if len(targetState.Packages) > 0 && m.systemPackageManager != nil {
		// Use DetectCurrentState to get currently installed packages
		currentPackages := m.systemPackageManager.DetectCurrentState(targetState)

		if len(currentPackages) == len(targetState.Packages) {
			m.logger.Info("All desired system packages are currently installed")
			// Update current state with all desired packages
			state.Packages = targetState.Packages
		} else {
			var missingNames []string
			currentPackageMap := make(map[string]bool)
			for _, pkg := range currentPackages {
				currentPackageMap[pkg] = true
			}
			for _, pkg := range targetState.Packages {
				if !currentPackageMap[pkg] {
					missingNames = append(missingNames, pkg)
				}
			}
			m.logger.Infof("Some desired system packages are not installed: %v", missingNames)
			// Update current state with only the packages that are actually installed
			state.Packages = currentPackages
			m.logger.Infof("Updated current state with %d installed packages out of %d desired",
				len(currentPackages), len(targetState.Packages))
		}
	}

	return nil
}

// verifyCustomPackages checks which custom packages from desired state are actually installed
func (m *Manager) verifyCustomPackages(state *types.StateConfig) error {
	if m.customPackageManager == nil {
		m.logger.Info("Custom package manager not available, skipping custom package verification")
		return nil
	}

	if len(state.CustomPackages) == 0 {
		m.logger.Info("No custom packages configured, skipping custom package verification")
		return nil
	}

	// Use DetectCurrentState to get currently installed custom packages
	currentCustomPackagesMap := m.customPackageManager.DetectCurrentState(state)

	if len(currentCustomPackagesMap) == len(state.CustomPackages) {
		m.logger.Info("All desired custom packages are currently installed")
		// Update current state with all desired custom packages
		state.CustomPackages = currentCustomPackagesMap
	} else {
		var missingNames []string
		for name := range state.CustomPackages {
			if _, exists := currentCustomPackagesMap[name]; !exists {
				missingNames = append(missingNames, name)
			}
		}
		m.logger.Infof("Some desired custom packages are not installed: %v", missingNames)
		// Update current state with only the custom packages that are actually installed
		state.CustomPackages = currentCustomPackagesMap
		m.logger.Infof("Updated current state with %d installed custom packages out of %d desired",
			len(currentCustomPackagesMap), len(state.CustomPackages))
	}

	return nil
}

// verifyEnvironmentVariables checks if environment variables in the state are actually set
func (m *Manager) verifyEnvironmentVariables(state *types.StateConfig) error {
	if m.environmentManager == nil {
		m.logger.Info("Environment manager not available, skipping environment variable verification")
		return nil
	}

	if len(state.Env) == 0 {
		m.logger.Info("No environment variables configured, skipping environment variable verification")
		return nil
	}

	m.logger.Info("Verifying environment variable state...")

	// Get current system environment
	currentEnv, err := m.environmentManager.GetCurrentSystemEnvironment()
	if err != nil {
		return fmt.Errorf("failed to get current system environment: %w", err)
	}

	// Check if environment variables match
	needsUpdate := false
	for key, expectedValue := range state.Env {
		if currentValue, exists := currentEnv[key]; !exists || currentValue != expectedValue {
			m.logger.Infof("Environment variable %s mismatch (expected: %s, current: %s)",
				key, expectedValue, currentValue)
			needsUpdate = true
		}
	}

	// If there are mismatches, sync the environment
	if needsUpdate {
		m.logger.Info("Environment variables need updating, syncing...")
		if err := m.environmentManager.SyncSystemEnvironment(state.Env); err != nil {
			return fmt.Errorf("failed to sync environment variables: %w", err)
		}
		m.logger.Info("Environment variables synced successfully")
	} else {
		m.logger.Info("Environment variables are correctly set")
	}

	return nil
}
