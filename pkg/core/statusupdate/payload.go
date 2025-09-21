package statusupdate

import (
	"fmt"

	"github.com/StreamDeploy/streamdeploy-agent/pkg/core/types"
)

// PayloadBuilder builds status update payloads
type PayloadBuilder struct {
	cloneStateConfig func(*types.StateConfig) *types.StateConfig
}

// NewPayloadBuilder creates a new status update payload builder
func NewPayloadBuilder(
	cloneStateConfig func(*types.StateConfig) *types.StateConfig,
) *PayloadBuilder {
	return &PayloadBuilder{
		cloneStateConfig: cloneStateConfig,
	}
}

// BuildStatusUpdatePayload builds a complete status update payload
func (b *PayloadBuilder) BuildStatusUpdatePayload(updateType string, currentState *types.StateConfig) (*types.StatusUpdatePayload, *types.StateConfig, error) {
	if currentState == nil {
		return nil, nil, fmt.Errorf("current state is nil")
	}

	// Clone the state for currentSystemState tracking
	var clonedState *types.StateConfig
	if b.cloneStateConfig != nil {
		clonedState = b.cloneStateConfig(currentState)
	}

	// Build status update payload
	statusUpdate := &types.StatusUpdatePayload{
		UpdateType:   updateType,
		CurrentState: *currentState,
	}

	return statusUpdate, clonedState, nil
}
