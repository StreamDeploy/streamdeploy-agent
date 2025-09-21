package environment

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// updateEtcEnvironment updates /etc/environment with StreamDeploy variables
func (m *Manager) updateEtcEnvironment(envVars map[string]string) error {
	envFile := "/etc/environment"

	// Read existing environment file
	var existingLines []string
	if data, err := os.ReadFile(envFile); err == nil {
		existingLines = strings.Split(string(data), "\n")
	}

	// Filter out existing StreamDeploy variables and empty lines
	var filteredLines []string
	for _, line := range existingLines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			filteredLines = append(filteredLines, line)
			continue
		}

		// Check if this is a StreamDeploy variable
		isStreamDeployVar := false
		for key := range envVars {
			if strings.HasPrefix(line, key+"=") {
				isStreamDeployVar = true
				break
			}
		}

		if !isStreamDeployVar {
			filteredLines = append(filteredLines, line)
		}
	}

	// Add StreamDeploy variables
	filteredLines = append(filteredLines, "# StreamDeploy Agent Environment Variables")
	for key, value := range envVars {
		filteredLines = append(filteredLines, fmt.Sprintf("%s=%s", key, value))
	}

	// Write back to file
	content := strings.Join(filteredLines, "\n") + "\n"
	if err := os.WriteFile(envFile, []byte(content), 0644); err != nil {
		return fmt.Errorf("failed to write %s: %w", envFile, err)
	}

	m.logger.Infof("Updated %s with %d environment variables", envFile, len(envVars))
	return nil
}

// updateProfileD creates a profile.d script for shell sessions
func (m *Manager) updateProfileD(envVars map[string]string) error {
	profileDir := "/etc/profile.d"
	profileFile := filepath.Join(profileDir, "streamdeploy.sh")

	// Ensure profile.d directory exists
	if err := os.MkdirAll(profileDir, 0755); err != nil {
		return fmt.Errorf("failed to create profile.d directory: %w", err)
	}

	// Create shell script content
	var content strings.Builder
	content.WriteString("#!/bin/bash\n")
	content.WriteString("# StreamDeploy Agent Environment Variables\n")
	content.WriteString("# This file is automatically managed by StreamDeploy Agent\n\n")

	for key, value := range envVars {
		content.WriteString(fmt.Sprintf("export %s=%s\n", key, value))
	}

	// Write the profile script
	if err := os.WriteFile(profileFile, []byte(content.String()), 0644); err != nil {
		return fmt.Errorf("failed to write profile script: %w", err)
	}

	m.logger.Infof("Created profile script: %s", profileFile)
	return nil
}

// updateSystemdEnvironment updates systemd environment for services
func (m *Manager) updateSystemdEnvironment(envVars map[string]string) error {
	// Check if systemctl is available
	if _, err := exec.LookPath("systemctl"); err != nil {
		m.logger.Info("systemctl not available, skipping systemd environment update")
		return nil
	}

	systemdEnvDir := "/etc/systemd/system.conf.d"
	envFile := filepath.Join(systemdEnvDir, "streamdeploy-env.conf")

	// Create systemd config directory if it doesn't exist
	if err := os.MkdirAll(systemdEnvDir, 0755); err != nil {
		return fmt.Errorf("failed to create systemd config directory: %w", err)
	}

	// Create systemd environment configuration
	var content strings.Builder
	content.WriteString("[Manager]\n")
	content.WriteString("# StreamDeploy Agent Environment Variables\n")

	for key, value := range envVars {
		content.WriteString(fmt.Sprintf("DefaultEnvironment=%s=%s\n", key, value))
	}

	// Write the systemd environment file
	if err := os.WriteFile(envFile, []byte(content.String()), 0644); err != nil {
		return fmt.Errorf("failed to write systemd environment file: %w", err)
	}

	// Reload systemd configuration
	cmd := exec.Command("systemctl", "daemon-reload")
	if err := cmd.Run(); err != nil {
		m.logger.Errorf("Failed to reload systemd configuration: %v", err)
		// Don't return error as the file was written successfully
	}

	m.logger.Infof("Updated systemd environment configuration: %s", envFile)
	return nil
}

// removeFromEtcEnvironment removes StreamDeploy variables from /etc/environment
func (m *Manager) removeFromEtcEnvironment() error {
	envFile := "/etc/environment"

	// Read existing environment file
	data, err := os.ReadFile(envFile)
	if err != nil {
		return fmt.Errorf("failed to read %s: %w", envFile, err)
	}

	lines := strings.Split(string(data), "\n")
	var filteredLines []string
	inStreamDeploySection := false

	for _, line := range lines {
		if strings.TrimSpace(line) == "# StreamDeploy Agent Environment Variables" {
			inStreamDeploySection = true
			continue
		}

		// Skip StreamDeploy variables
		if inStreamDeploySection && strings.Contains(line, "=") && !strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}

		// Reset section flag if we hit another comment or empty line after StreamDeploy section
		if inStreamDeploySection && (strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "#")) {
			if strings.TrimSpace(line) != "" {
				inStreamDeploySection = false
			}
		}

		if !inStreamDeploySection {
			filteredLines = append(filteredLines, line)
		}
	}

	// Write back to file
	content := strings.Join(filteredLines, "\n")
	if err := os.WriteFile(envFile, []byte(content), 0644); err != nil {
		return fmt.Errorf("failed to write %s: %w", envFile, err)
	}

	return nil
}
