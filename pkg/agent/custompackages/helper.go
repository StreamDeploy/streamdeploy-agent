package custompackages

import (
	"fmt"
	"os/exec"
	"time"

	"github.com/StreamDeploy/streamdeploy-agent/pkg/core/types"
)

// executeCommand executes a shell command with timeout
func (m *Manager) executeCommand(command, operation string) error {
	if command == "" {
		return fmt.Errorf("empty command for %s operation", operation)
	}

	m.logger.Infof("Executing %s command: %s", operation, command)

	cmd := exec.Command("sh", "-c", command)

	// Set a timeout for command execution
	done := make(chan error, 1)
	go func() {
		done <- cmd.Run()
	}()

	select {
	case err := <-done:
		if err != nil {
			return fmt.Errorf("command failed: %w", err)
		}
		m.logger.Infof("Command executed successfully")
		return nil
	case <-time.After(2 * time.Minute): // 2 minute timeout
		cmd.Process.Kill()
		return fmt.Errorf("command timed out after 2 minutes")
	}
}

// isCustomPackageInstalled checks if a list of custom packages are installed
// Returns a slice of boolean values corresponding to each package
func (m *Manager) isCustomPackageInstalled(packages map[string]types.CustomPackage) []bool {
	results := make([]bool, 0, len(packages))

	for name, pkg := range packages {
		if pkg.Check == "" {
			// If no check command, assume not installed
			results = append(results, false)
			continue
		}

		m.logger.Infof("Checking if custom package '%s' is installed using command: %s", name, pkg.Check)

		cmd := exec.Command("sh", "-c", pkg.Check)

		// Set a timeout for check command execution
		done := make(chan error, 1)
		go func() {
			done <- cmd.Run()
		}()

		var err error
		select {
		case err = <-done:
			// Command completed
		case <-time.After(2 * time.Minute): // 2 minute timeout
			cmd.Process.Kill()
			err = fmt.Errorf("check command timed out after 2 minutes")
		}

		installed := err == nil
		results = append(results, installed)
		m.logger.Infof("Custom package '%s' installed status: %t", name, installed)
	}

	return results
}

// compareCustomPackages compares two CustomPackage structs field by field
// Returns true if they are identical, false if any field differs
// Note: Name field is not compared as it's handled by the map key
func (m *Manager) compareCustomPackages(pkg1, pkg2 types.CustomPackage) bool {
	return pkg1.Install == pkg2.Install &&
		pkg1.Check == pkg2.Check &&
		pkg1.Uninstall == pkg2.Uninstall
}

// buildCurrentState checks which packages are installed and builds current state
func (m *Manager) buildCurrentState(desiredPackages map[string]types.CustomPackage) map[string]types.CustomPackage {
	currentState := make(map[string]types.CustomPackage)

	// Get installation status for all packages
	installedStatus := m.isCustomPackageInstalled(desiredPackages)

	// Build current state based on installation status
	index := 0
	for name, pkg := range desiredPackages {
		if installedStatus[index] {
			currentState[name] = pkg
		}
		index++
	}

	return currentState
}
