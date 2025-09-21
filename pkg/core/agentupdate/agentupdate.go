package agentupdate

import (
	"context"
	"fmt"
	"time"

	"github.com/StreamDeploy/streamdeploy-agent/pkg/core/types"
)

// ManagerInterface defines the interface for agent update management
type ManagerInterface interface {
	StartUpdateLoop(ctx context.Context, interval time.Duration, isUpdating func() bool) error
	CheckForAgentUpdate() error
	Stop()
}

// Manager provides agent update management functionality
type Manager struct {
	logger   types.Logger
	running  bool
	stopChan chan struct{}
}

// NewManager creates a new update manager
func NewManager(logger types.Logger) *Manager {
	return &Manager{
		logger:   logger,
		running:  false,
		stopChan: make(chan struct{}),
	}
}

// StartUpdateLoop starts the agent update check loop
func (m *Manager) StartUpdateLoop(ctx context.Context, interval time.Duration, isUpdating func() bool) error {
	if m.running {
		return fmt.Errorf("update loop is already running")
	}

	m.running = true
	m.logger.Infof("Agent update loop started with interval: %v", interval)

	go m.updateLoop(ctx, interval, isUpdating)
	return nil
}

// updateLoop runs the agent update check loop
func (m *Manager) updateLoop(ctx context.Context, interval time.Duration, isUpdating func() bool) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopChan:
			m.logger.Info("Agent update loop stopped")
			m.running = false
			return
		case <-ctx.Done():
			m.logger.Info("Agent update loop stopped due to context cancellation")
			m.running = false
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

// Stop stops the update manager
func (m *Manager) Stop() {
	if m.running {
		close(m.stopChan)
		m.running = false
	}
}
