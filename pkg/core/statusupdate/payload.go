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

// BuildStatusUpdatePayload builds a complete status update payload for /status-update endpoint
func (b *PayloadBuilder) BuildStatusUpdatePayload(currentState *types.StateConfig) (*types.StatusUpdatePayload, *types.StateConfig, error) {
	if currentState == nil {
		return nil, nil, fmt.Errorf("current state is nil")
	}

	// Clone the state for currentSystemState tracking
	var clonedState *types.StateConfig
	if b.cloneStateConfig != nil {
		clonedState = b.cloneStateConfig(currentState)
	}

	// Build status update payload (only current_state field)
	statusUpdate := &types.StatusUpdatePayload{
		CurrentState: *currentState,
	}

	return statusUpdate, clonedState, nil
}

// BuildUpdateFeedbackPayload builds a feedback payload for /v1-device/update-feedback endpoint
func (b *PayloadBuilder) BuildUpdateFeedbackPayload(status string, receiveFeedback interface{}, state interface{}) *types.UpdateFeedbackPayload {
	payload := &types.UpdateFeedbackPayload{
		Status: status,
	}

	// Only include receiveFeedback if it's not nil
	if receiveFeedback != nil {
		payload.ReceiveFeedback = receiveFeedback
	}

	// Only include state if it's not nil
	if state != nil {
		payload.State = state
	}

	return payload
}
