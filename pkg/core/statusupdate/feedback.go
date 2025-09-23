package statusupdate

import (
	"fmt"

	"github.com/StreamDeploy/streamdeploy-agent/pkg/core/types"
)

// FeedbackStatus represents the possible feedback status values
type FeedbackStatus string

const (
	UpdateFailed      FeedbackStatus = "update_failed"
	UpdateCompleted   FeedbackStatus = "update_completed"
	SelfhealFail      FeedbackStatus = "selfheal_fail"
	SelfhealCompleted FeedbackStatus = "selfheal_completed"
)

// FeedbackManager handles the logic for determining feedback status and sending feedback
type FeedbackManager struct {
	payloadBuilder *PayloadBuilder
	sender         Sender
	logger         types.Logger
}

// NewFeedbackManager creates a new feedback manager
func NewFeedbackManager(payloadBuilder *PayloadBuilder, sender Sender, logger types.Logger) *FeedbackManager {
	return &FeedbackManager{
		payloadBuilder: payloadBuilder,
		sender:         sender,
		logger:         logger,
	}
}

// SendFeedback determines the appropriate feedback status and sends it to the backend
// This should only be called when operations were actually performed
func (fm *FeedbackManager) SendFeedback(
	apiSuccess bool,
	consolidationErrors map[string]error,
	isUpdate bool, // true if this was triggered by an API update, false if it's self-healing
) error {
	// Determine the feedback status based on success and operation type
	var status FeedbackStatus
	var data interface{}

	if isUpdate {
		// This was triggered by an API update
		if apiSuccess && len(consolidationErrors) == 0 {
			status = UpdateCompleted
			// No data needed for success
		} else {
			status = UpdateFailed
			// Send consolidation errors as data for failures
			data = fm.buildConsolidationErrorsData(consolidationErrors)
		}
	} else {
		// This is self-healing
		if len(consolidationErrors) == 0 {
			status = SelfhealCompleted
			// No data needed for success
		} else {
			status = SelfhealFail
			// Send consolidation errors as data for failures
			data = fm.buildConsolidationErrorsData(consolidationErrors)
		}
	}

	// Build and send the feedback payload
	feedbackPayload := fm.payloadBuilder.BuildUpdateFeedbackPayload(string(status), data)

	// Send feedback using the new feedback endpoint
	sendResult := fm.sender.SendUpdateFeedbackWithResult(feedbackPayload)

	if sendResult.Error != nil {
		return fmt.Errorf("failed to send feedback: %w", sendResult.Error)
	}

	fm.logger.Infof("Feedback sent successfully: %s", status)
	return nil
}

// buildConsolidationErrorsData converts consolidation errors to the data format expected by the API
func (fm *FeedbackManager) buildConsolidationErrorsData(consolidationErrors map[string]error) map[string]string {
	errors := make(map[string]string)
	for component, err := range consolidationErrors {
		errors[component] = err.Error()
	}
	return errors
}
