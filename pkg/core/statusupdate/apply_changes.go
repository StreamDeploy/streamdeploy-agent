package statusupdate

import (
	"encoding/json"
	"fmt"

	"github.com/StreamDeploy/streamdeploy-agent/pkg/core/types"
)

// StatusUpdateResponseHandler handles status update specific response processing
type StatusUpdateResponseHandler interface {
	HandleStatusUpdateResponse(responseBody []byte) error
	PerformLocalStateCheck() error
	PerformSelfHealing() error
	ProcessStatusUpdateSelfHeal(apiCallSuccessful bool, apiError error, response *types.HTTPResponse, responseHandler StatusUpdateResponseHandler) *SelfHealResult
}

// SelfHealResult represents the result of self-healing operations
type SelfHealResult struct {
	Success           bool
	APICallSuccessful bool
	Error             error
	ResponseBody      []byte
}

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
	TaskEnvironment    SelfHealingTask = "env"
)

// DefaultResponseHandler implements the StatusUpdateResponseHandler interface
type DefaultResponseHandler struct {
	agent AgentInterface
}

// NewDefaultResponseHandler creates a new default response handler
func NewDefaultResponseHandler(agent AgentInterface) *DefaultResponseHandler {
	return &DefaultResponseHandler{
		agent: agent,
	}
}

// HandleStatusUpdateResponse handles status update response
func (h *DefaultResponseHandler) HandleStatusUpdateResponse(responseBody []byte) error {
	var response map[string]interface{}
	if err := json.Unmarshal(responseBody, &response); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	// Debug: Log the full response structure for troubleshooting
	h.agent.GetLogger().Infof("Received response with keys: %v", getMapKeys(response))

	// Extract command and new_state from response
	// Both cmd and new_state always exist in the response
	cmd := response["cmd"]
	newStateData := response["new_state"]

	// Handle the 4 possible combinations:
	// 1. cmd="" or null and new_state={} - No change, no command
	// 2. cmd="" or null and new_state={...} - State change only, no command
	// 3. cmd="..." and new_state={} - Command only, no state change
	// 4. cmd="..." and new_state={...} - Both command and state change

	var hasCommand bool
	var hasStateChange bool
	var commandStr string

	// Check if we have a valid command (not empty string or null)
	if cmd != nil {
		if cmdStr, ok := cmd.(string); ok && cmdStr != "" {
			hasCommand = true
			commandStr = cmdStr
		}
	}

	// Check if we have a valid state change (not empty object)
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
	if !h.agent.GetConfigManager().IsStateConfigEmpty(&newState) {
		hasStateChange = true
	}

	// Determine what type of change we received and log appropriately
	if !hasCommand && !hasStateChange {
		h.agent.GetLogger().Info("No changes received (empty command and empty state)")
	} else if hasCommand && !hasStateChange {
		h.agent.GetLogger().Infof("Received command only: %s", commandStr)
	} else if !hasCommand && hasStateChange {
		h.agent.GetLogger().Info("Received state change only")
	} else {
		h.agent.GetLogger().Infof("Received both command and state change: %s", commandStr)
	}

	// Step 1: Update desired status if change
	if hasStateChange {
		h.agent.GetLogger().Info("Applying new state configuration")

		// Update device desired state with the new state from API
		if err := h.agent.GetConfigManager().UpdateStateConfig(&newState); err != nil {
			h.agent.GetLogger().Errorf("Failed to update device desired state: %v", err)
			return err
		}
		// Update our internal desired state field
		h.agent.SetDesiredState(h.agent.CloneStateConfig(&newState))
		h.agent.GetLogger().Info("Device desired state updated with new configuration")
	}

	// Step 2: Sync by comparing current and desired status
	triggeredBy := "api"
	if hasStateChange {
		h.agent.GetLogger().Info("State changes received, synchronizing system to desired state...")
	} else {
		h.agent.GetLogger().Info("No state changes received, performing self-healing to ensure system matches desired state...")
	}

	_, err = h.agent.SyncSystemToDesiredState(triggeredBy)
	if err != nil {
		h.agent.GetLogger().Errorf("Failed to sync system to desired state: %v", err)
		return err
	}

	// Step 3: Run command if present (after state sync is complete)
	if hasCommand {
		h.agent.GetLogger().Infof("Executing command: %s", commandStr)
		if err := h.agent.ExecuteCommand(cmd); err != nil {
			h.agent.GetLogger().Errorf("Failed to execute command: %v", err)
			// Continue processing even if command fails
		} else {
			h.agent.GetLogger().Info("Command executed successfully")
		}
	}

	return nil
}

// PerformLocalStateCheck performs local state check
func (h *DefaultResponseHandler) PerformLocalStateCheck() error {
	h.agent.GetLogger().Info("Performing local state check...")

	// Get device desired state from our internal field
	deviceDesiredState := h.agent.GetDesiredState()
	if deviceDesiredState == nil {
		return fmt.Errorf("device desired state config is nil")
	}

	// Check if actual system state matches the desired state
	// and make corrections if needed
	if err := h.agent.VerifyAndCorrectSystemState(deviceDesiredState); err != nil {
		return fmt.Errorf("failed to verify and correct system state: %w", err)
	}

	h.agent.GetLogger().Info("Local state check completed successfully")
	return nil
}

// PerformSelfHealing performs self-healing operations
func (h *DefaultResponseHandler) PerformSelfHealing() error {
	// Get device desired state from our internal field
	deviceDesiredState := h.agent.GetDesiredState()
	if deviceDesiredState == nil {
		return fmt.Errorf("device desired state config is nil")
	}

	// Check if actual system state matches the desired state
	// and make corrections if needed
	if err := h.agent.VerifyAndCorrectSystemState(deviceDesiredState); err != nil {
		return fmt.Errorf("failed to verify and correct system state: %w", err)
	}

	return nil
}

// HandleHTTPResponse handles HTTP response after sending status update
func (h *DefaultResponseHandler) HandleHTTPResponse(response *types.HTTPResponse, responseHandler func([]byte) error) error {
	if response.StatusCode >= 200 && response.StatusCode < 300 {
		h.agent.GetLogger().Info("Status update sent successfully")

		// Parse response for new state if body is present
		if len(response.Body) > 0 {
			if responseHandler != nil {
				if err := responseHandler(response.Body); err != nil {
					return fmt.Errorf("failed to handle status update response: %w", err)
				}
			}
		}
		return nil
	}

	return fmt.Errorf("status update failed with status: %d", response.StatusCode)
}

// HandleMQTTSuccess handles successful MQTT publication
func (h *DefaultResponseHandler) HandleMQTTSuccess() {
	h.agent.GetLogger().Info("Status update published successfully")
}

// HandleSuccessfulAPI handles successful API calls and performs self-healing
func (h *DefaultResponseHandler) HandleSuccessfulAPI(responseHandler StatusUpdateResponseHandler) error {
	// Perform self-healing after successful API call
	if responseHandler != nil {
		if err := responseHandler.PerformSelfHealing(); err != nil {
			h.agent.GetLogger().Errorf("Self-healing failed: %v", err)
			return fmt.Errorf("self-healing failed: %w", err)
		}
		h.agent.GetLogger().Info("Self-healing completed successfully")
	}
	return nil
}

// HandleAPIFailure handles API call failures and performs local state check
func (h *DefaultResponseHandler) HandleAPIFailure(apiError error, localStateChecker func() error) error {
	h.agent.GetLogger().Infof("API call failed (%v), performing local state check", apiError)

	if localStateChecker != nil {
		if err := localStateChecker(); err != nil {
			h.agent.GetLogger().Errorf("Local state check failed: %v", err)
			// Return the original API error, not the local state check error
			return apiError
		}
		h.agent.GetLogger().Info("Local state check completed successfully")
	}

	return apiError
}

// ProcessStatusUpdateSelfHeal processes all self-healing operations for status updates
func (h *DefaultResponseHandler) ProcessStatusUpdateSelfHeal(
	apiCallSuccessful bool,
	apiError error,
	response *types.HTTPResponse,
	responseHandler StatusUpdateResponseHandler,
) *SelfHealResult {
	result := &SelfHealResult{
		APICallSuccessful: apiCallSuccessful,
	}

	if apiCallSuccessful {
		// Handle successful API call
		if response != nil {
			if err := h.HandleHTTPResponse(response, responseHandler.HandleStatusUpdateResponse); err != nil {
				result.Error = err
				return result
			}
			result.ResponseBody = response.Body
		} else {
			// MQTT success
			h.HandleMQTTSuccess()
		}

		// Perform self-healing after successful API call
		if err := h.HandleSuccessfulAPI(responseHandler); err != nil {
			result.Error = err
			return result
		}

		result.Success = true
	} else {
		// Handle API failure with local state check
		result.Error = h.HandleAPIFailure(apiError, responseHandler.PerformLocalStateCheck)
	}

	return result
}

// ProcessSelfHeal processes all self-healing operations (generic version)
func (h *DefaultResponseHandler) ProcessSelfHeal(
	apiCallSuccessful bool,
	apiError error,
	response *types.HTTPResponse,
	responseHandler func([]byte) error,
	localStateChecker func() error,
) *SelfHealResult {
	result := &SelfHealResult{
		APICallSuccessful: apiCallSuccessful,
	}

	if apiCallSuccessful {
		// Handle successful API call
		if response != nil {
			if err := h.HandleHTTPResponse(response, responseHandler); err != nil {
				result.Error = err
				return result
			}
			result.ResponseBody = response.Body
		} else {
			// MQTT success
			h.HandleMQTTSuccess()
		}
		result.Success = true
	} else {
		// Handle API failure
		result.Error = h.HandleAPIFailure(apiError, localStateChecker)
	}

	return result
}

// getMapKeys is a helper function to extract keys from a map
func getMapKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// SyncSystemToDesiredState synchronizes the actual system state to match the desired state
func (h *DefaultResponseHandler) SyncSystemToDesiredState(triggeredBy string) (*SelfHealingResult, error) {
	// Use our internal desired state
	deviceDesiredState := h.agent.GetDesiredState()
	if deviceDesiredState == nil {
		return nil, fmt.Errorf("device desired state config is nil")
	}

	// Get current system state for comparison
	currentSystemState := h.agent.GetCurrentSystemState()
	if currentSystemState == nil {
		// If no current state, detect it
		currentSystemState = DetectCurrentState(
			deviceDesiredState,
			h.agent.GetContainerManager(),
			h.agent.GetSystemPackageManager(),
			h.agent.GetCustomPackageManager(),
			h.agent.GetEnvironmentManager(),
		)
	}

	// Compare currentSystemState with deviceDesiredState to determine what needs to be applied
	if stateConfigsEqual(currentSystemState, deviceDesiredState) {
		h.agent.GetLogger().Info("System is already in desired state, no changes needed")
		return &SelfHealingResult{
			Success:     true,
			Errors:      make(map[string]string),
			TriggeredBy: triggeredBy,
		}, nil
	}

	// In the new architecture, the statusupdate manager handles state consolidation
	// This method is now a placeholder since the real work is done in the manager
	healingResult := &SelfHealingResult{
		Success:     true,
		Errors:      make(map[string]string),
		TriggeredBy: triggeredBy,
	}

	// Update currentSystemState to reflect the desired state after successful application
	h.agent.SetCurrentSystemState(h.agent.CloneStateConfig(deviceDesiredState))

	return healingResult, nil
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
	// Compare basic fields
	if a.Name != b.Name || a.Image != b.Image || a.HealthPath != b.HealthPath {
		return false
	}

	// Compare environment variables
	if !envMapsEqual(a.Env, b.Env) {
		return false
	}

	// Compare port mappings
	if len(a.Ports) != len(b.Ports) {
		return false
	}
	for i, portA := range a.Ports {
		portB := b.Ports[i]
		if portA.HostPort != portB.HostPort || portA.ContainerPort != portB.ContainerPort || portA.Protocol != portB.Protocol {
			return false
		}
	}

	// Compare other fields that might be relevant for basic equality checks
	if a.EnvFile != b.EnvFile || a.WorkingDir != b.WorkingDir || a.User != b.User ||
		a.Hostname != b.Hostname || a.Network != b.Network || a.Restart != b.Restart ||
		a.Runtime != b.Runtime || a.IPC != b.IPC {
		return false
	}

	// Compare labels
	if !envMapsEqual(a.Labels, b.Labels) {
		return false
	}

	// Compare sysctls
	if !envMapsEqual(a.Sysctls, b.Sysctls) {
		return false
	}

	// Note: For a basic equality check, we're not comparing all fields like volumes, resources, etc.
	// This is a simplified comparison for status update purposes.
	return true
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
