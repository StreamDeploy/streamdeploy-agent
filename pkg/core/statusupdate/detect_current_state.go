package statusupdate

import (
	"github.com/StreamDeploy/streamdeploy-agent/pkg/core/types"
)

// DetectCurrentState detects the actual current state of the system based on desired state
// This function only tracks the state of things declared in desired state
// It delegates to each manager's DetectCurrentState function
func DetectCurrentState(
	desiredState *types.StateConfig,
	containerManager types.ContainerManager,
	systemPackageManager types.SystemPackageManager,
	customPackageManager types.CustomPackageManager,
	environmentManager types.EnvironmentManager,
) *types.StateConfig {
	if desiredState == nil {
		return &types.StateConfig{
			SchemaVersion:  "1.0",
			Containers:     []types.ContainerConfig{},
			Packages:       []string{},
			CustomPackages: map[string]types.CustomPackage{},
			Env:            map[string]string{},
		}
	}

	currentState := &types.StateConfig{
		SchemaVersion:  desiredState.SchemaVersion,
		AgentSetting:   desiredState.AgentSetting,
		CustomMetrics:  desiredState.CustomMetrics,
		Containers:     []types.ContainerConfig{},
		Packages:       []string{},
		CustomPackages: map[string]types.CustomPackage{},
		Env:            map[string]string{},
	}

	// Detect Docker containers using container manager's DetectCurrentState
	// For containers, we track ALL containers, not just those in desired state
	if containerManager != nil {
		if detectorManager, ok := containerManager.(interface {
			DetectCurrentState(*types.StateConfig) []types.ContainerConfig
		}); ok {
			currentState.Containers = detectorManager.DetectCurrentState(desiredState)
		}
	}

	// Detect system packages using system package manager's DetectCurrentState
	if systemPackageManager != nil && len(desiredState.Packages) > 0 {
		if detectorManager, ok := systemPackageManager.(interface {
			DetectCurrentState(*types.StateConfig) []string
		}); ok {
			currentState.Packages = detectorManager.DetectCurrentState(desiredState)
		}
	}

	// Detect custom packages using custom package manager's DetectCurrentState
	if customPackageManager != nil && len(desiredState.CustomPackages) > 0 {
		currentState.CustomPackages = customPackageManager.DetectCurrentState(desiredState)
	}

	// Detect environment variables using environment manager's DetectCurrentState
	if environmentManager != nil && len(desiredState.Env) > 0 {
		if detectorManager, ok := environmentManager.(interface {
			DetectCurrentState(*types.StateConfig) map[string]string
		}); ok {
			currentState.Env = detectorManager.DetectCurrentState(desiredState)
		}
	}

	return currentState
}
