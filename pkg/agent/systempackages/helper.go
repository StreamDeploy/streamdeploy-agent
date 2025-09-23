package systempackages

import (
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// PackageInfo represents a parsed system package with optional version
type PackageInfo struct {
	Name       string
	Version    string
	HasVersion bool
}

// parsePackageString parses a package string to extract name and version
// Supports formats: "package", "package=version", "package version", "package==version"
func parsePackageString(pkgStr string) PackageInfo {
	pkgStr = strings.TrimSpace(pkgStr)

	// Check for == format (package==version) - used by pip and some package managers
	if strings.Contains(pkgStr, "==") {
		parts := strings.SplitN(pkgStr, "==", 2)
		if len(parts) == 2 {
			return PackageInfo{
				Name:       strings.TrimSpace(parts[0]),
				Version:    strings.TrimSpace(parts[1]),
				HasVersion: true,
			}
		}
	}

	// Check for = format (package=version) - used by apt, yum, etc.
	if strings.Contains(pkgStr, "=") {
		parts := strings.SplitN(pkgStr, "=", 2)
		if len(parts) == 2 {
			version := strings.TrimSpace(parts[1])
			// Special case: "any" version means no specific version requirement
			if version == "any" {
				return PackageInfo{
					Name:       strings.TrimSpace(parts[0]),
					Version:    "any",
					HasVersion: false, // "any" means no specific version requirement
				}
			}
			return PackageInfo{
				Name:       strings.TrimSpace(parts[0]),
				Version:    version,
				HasVersion: true,
			}
		}
	}

	// Check for space format (package version) - only if it looks like a version
	// More flexible regex to handle various version formats
	versionRegex := regexp.MustCompile(`^[0-9]+(\.[0-9]+)*([.-][a-zA-Z0-9]+)*([-][a-zA-Z0-9]+)*$`)
	parts := strings.Fields(pkgStr)
	if len(parts) == 2 && versionRegex.MatchString(parts[1]) {
		return PackageInfo{
			Name:       parts[0],
			Version:    parts[1],
			HasVersion: true,
		}
	}

	// No version specified, just package name
	return PackageInfo{
		Name:       pkgStr,
		Version:    "",
		HasVersion: false,
	}
}

// checkMultiplePackagesWithConfiguredPackageManager checks multiple packages at once using the package manager's list command
func (m *Manager) checkMultiplePackagesWithConfiguredPackageManager(packageInfos []PackageInfo) map[string]bool {
	results := make(map[string]bool)

	// Initialize all packages as not installed
	for _, pkgInfo := range packageInfos {
		results[pkgInfo.Name] = false
	}

	if m.packageManager == nil || m.packageManager.CheckCmd == "" {
		m.logger.Errorf("No package manager configuration available for bulk package check")
		return results
	}

	// Run the package manager's list command to get all installed packages
	cmd := exec.Command("sh", "-c", m.packageManager.CheckCmd)
	output, err := cmd.Output()
	if err != nil {
		m.logger.Errorf("Failed to execute package list command: %v", err)
		return results
	}

	// Parse the output to get installed packages
	installedPackages, err := m.parsePackageManagerOutput(string(output))
	if err != nil {
		m.logger.Errorf("Failed to parse package manager output: %v", err)
		return results
	}

	// Check which packages from our list are installed
	for _, pkgInfo := range packageInfos {
		if _, exists := installedPackages[pkgInfo.Name]; exists {
			results[pkgInfo.Name] = true
		}
	}

	return results
}

// parsePackageManagerOutput parses the output from the package manager's list command
func (m *Manager) parsePackageManagerOutput(output string) (map[string]string, error) {
	switch m.packageManager.Type {
	case "apt":
		return m.parseAptOutput(output), nil
	case "yum", "dnf", "zypper":
		return m.parseRpmOutput(output), nil
	case "apk":
		return m.parseApkOutput(output), nil
	case "pacman":
		return m.parsePacmanOutput(output), nil
	default:
		return nil, fmt.Errorf("unsupported package manager type: %s", m.packageManager.Type)
	}
}

// executeCommandWithRetry executes a command with retry logic for APT lock conflicts
func (m *Manager) executeCommandWithRetry(command, operation string, maxRetries int) error {
	var lastErr error

	for attempt := 1; attempt <= maxRetries; attempt++ {
		cmd := exec.Command("sh", "-c", command)

		// Set a timeout for command execution
		done := make(chan error, 1)
		go func() {
			done <- cmd.Run()
		}()

		var err error
		select {
		case err = <-done:
			// Command completed
		case <-time.After(5 * time.Minute): // 5 minute timeout
			cmd.Process.Kill()
			err = fmt.Errorf("command timed out after 5 minutes")
		}

		if err == nil {
			m.logger.Infof("Command executed successfully on attempt %d", attempt)
			return nil // Success
		}

		lastErr = err

		// Check if it's an APT lock error by running a quick check
		lockCheckCmd := exec.Command("sh", "-c", "lsof /var/lib/dpkg/lock-frontend 2>/dev/null || echo 'no lock'")
		lockOutput, _ := lockCheckCmd.Output()
		lockStr := string(lockOutput)

		if strings.Contains(lockStr, "apt") || strings.Contains(lockStr, "dpkg") {
			if attempt < maxRetries {
				waitTime := time.Duration(attempt) * 2 * time.Second
				m.logger.Infof("APT lock conflict detected (attempt %d/%d), waiting %v before retry...",
					attempt, maxRetries, waitTime)
				time.Sleep(waitTime)
				continue
			}
		}

		// If it's not a lock error or we've exhausted retries, return the error
		return fmt.Errorf("%s command failed: %w", operation, err)
	}

	return fmt.Errorf("%s command failed after %d attempts: %w", operation, maxRetries, lastErr)
}

// commandExists checks if a command exists in PATH
func (m *Manager) commandExists(command string) bool {
	cmd := exec.Command("which", command)
	err := cmd.Run()
	return err == nil
}

// wrapCommandDetectReadOnly wraps commands to handle read-only filesystems
func (m *Manager) wrapCommandDetectReadOnly(command string) string {
	// Check if filesystem is read-only by testing write access to /tmp
	if m.isReadOnlyFilesystem() {
		m.logger.Info("Detected read-only filesystem, remounting as read-write for package operations")
		// Use proper shell command chaining with error handling
		return fmt.Sprintf("(mount -o remount,rw / && %s; exit_code=$?; mount -o remount,ro /; exit $exit_code)", command)
	}
	return command
}

// isReadOnlyFilesystem checks if the root filesystem is mounted read-only
func (m *Manager) isReadOnlyFilesystem() bool {
	// Method 1: Check mount options for root filesystem
	cmd := exec.Command("sh", "-c", "mount | grep 'on / ' | grep -q 'ro,'")
	err1 := cmd.Run()
	if err1 == nil {
		return true // Found read-only mount
	}

	// Method 2: Try to create a temporary file in /tmp to test write access
	cmd = exec.Command("sh", "-c", "touch /tmp/.streamdeploy-test-write 2>/dev/null && rm -f /tmp/.streamdeploy-test-write")
	err2 := cmd.Run()
	if err2 != nil {
		return true // Cannot write to filesystem
	}

	return false // Filesystem appears to be writable
}

// arePackagesInstalled checks if multiple system packages are installed using bulk check
func (m *Manager) arePackagesInstalled(packageNames []string) map[string]bool {
	results := make(map[string]bool)

	// Parse all package strings
	packageInfos := make([]PackageInfo, len(packageNames))
	for i, pkgName := range packageNames {
		packageInfos[i] = parsePackageString(pkgName)
	}

	// Use configured package manager if available
	if m.packageManager != nil && m.packageManager.CheckCmd != "" {
		return m.checkMultiplePackagesWithConfiguredPackageManager(packageInfos)
	}

	// No package manager configuration available - mark all as not installed
	m.logger.Errorf("No package manager configuration available for bulk package check")
	for _, pkgName := range packageNames {
		results[pkgName] = false
	}

	return results
}

// installPackages installs multiple system packages in bulk
func (m *Manager) installPackages(packageNames []string) error {
	if len(packageNames) == 0 {
		return nil // Nothing to install
	}

	// Parse all package strings
	packageInfos := make([]PackageInfo, len(packageNames))
	for i, pkgName := range packageNames {
		packageInfos[i] = parsePackageString(pkgName)
	}

	// Check which packages are already installed
	installedStatus := m.arePackagesInstalled(packageNames)

	// Filter out packages that are already installed
	var packagesToInstall []string
	var alreadyInstalled []string

	for _, pkgName := range packageNames {
		if installedStatus[pkgName] {
			alreadyInstalled = append(alreadyInstalled, pkgName)
		} else {
			packagesToInstall = append(packagesToInstall, pkgName)
		}
	}

	// Log already installed packages
	if len(alreadyInstalled) > 0 {
		m.logger.Infof("Packages already installed, skipping: %v", alreadyInstalled)
	}

	if len(packagesToInstall) == 0 {
		m.logger.Info("All requested packages are already installed")
		return nil
	}

	m.logger.Infof("Installing system packages: %v", packagesToInstall)

	// Use package manager configuration from agent.json or auto-detected config
	if m.packageManager == nil || m.packageManager.InstallCmd == "" {
		return fmt.Errorf("no package manager configuration available")
	}
	installCmd := m.packageManager.InstallCmd

	// Construct the full command with all packages to install
	var fullCmd string
	if len(packagesToInstall) == 1 {
		// Single package - use version handling
		pkgInfo := parsePackageString(packagesToInstall[0])
		if pkgInfo.HasVersion {
			fullCmd = m.buildVersionedPackageCommand(installCmd, pkgInfo)
		} else {
			fullCmd = fmt.Sprintf("%s %s", installCmd, pkgInfo.Name)
		}
	} else {
		// Multiple packages - extract names only (most package managers don't support mixed versioning in bulk)
		var packageNames []string
		for _, pkgStr := range packagesToInstall {
			pkgInfo := parsePackageString(pkgStr)
			packageNames = append(packageNames, pkgInfo.Name)
		}
		fullCmd = fmt.Sprintf("%s %s", installCmd, strings.Join(packageNames, " "))
	}

	// Handle read-only filesystem for all package managers
	if m.packageManager != nil {
		fullCmd = m.wrapCommandDetectReadOnly(fullCmd)
	}

	m.logger.Infof("Executing bulk package installation command: %s", fullCmd)

	// Use retry logic for APT operations to handle lock conflicts
	if m.packageManager != nil && m.packageManager.Type == "apt" {
		if err := m.executeCommandWithRetry(fullCmd, "bulk package installation", 3); err != nil {
			return fmt.Errorf("failed to install packages %v: %w", packagesToInstall, err)
		}
	} else {
		// For non-APT package managers, use regular execution
		cmd := exec.Command("sh", "-c", fullCmd)
		output, err := cmd.CombinedOutput()
		if err != nil {
			m.logger.Errorf("Bulk package installation failed for %v: %v, output: %s", packagesToInstall, err, string(output))
			return fmt.Errorf("failed to install packages %v: %w, output: %s", packagesToInstall, err, string(output))
		}
	}

	m.logger.Infof("Successfully installed packages: %v", packagesToInstall)
	return nil
}

// buildVersionedPackageCommand builds a package installation command with proper version formatting
func (m *Manager) buildVersionedPackageCommand(installCmd string, pkgInfo PackageInfo) string {
	switch m.packageManager.Type {
	case "apt":
		// APT uses package=version format
		return fmt.Sprintf("%s %s=%s", installCmd, pkgInfo.Name, pkgInfo.Version)
	case "yum", "dnf":
		// YUM/DNF can use package-version format
		return fmt.Sprintf("%s %s-%s", installCmd, pkgInfo.Name, pkgInfo.Version)
	case "zypper":
		// Zypper uses package=version format
		return fmt.Sprintf("%s %s=%s", installCmd, pkgInfo.Name, pkgInfo.Version)
	case "apk":
		// APK uses package=version format
		return fmt.Sprintf("%s %s=%s", installCmd, pkgInfo.Name, pkgInfo.Version)
	case "pacman":
		// Pacman uses package=version format
		return fmt.Sprintf("%s %s=%s", installCmd, pkgInfo.Name, pkgInfo.Version)
	default:
		// Fallback to space format for unknown package managers
		return fmt.Sprintf("%s %s %s", installCmd, pkgInfo.Name, pkgInfo.Version)
	}
}

// removePackages removes multiple system packages in bulk
func (m *Manager) removePackages(packageNames []string) error {
	if len(packageNames) == 0 {
		return nil // Nothing to remove
	}

	// Parse all package strings to extract names
	var packageNamesOnly []string
	for _, pkgName := range packageNames {
		pkgInfo := parsePackageString(pkgName)
		packageNamesOnly = append(packageNamesOnly, pkgInfo.Name)
	}

	// Check which packages are actually installed
	installedStatus := m.arePackagesInstalled(packageNames)

	// Filter out packages that are not installed
	var packagesToRemove []string
	var notInstalled []string

	for i, pkgName := range packageNames {
		if installedStatus[pkgName] {
			packagesToRemove = append(packagesToRemove, packageNamesOnly[i])
		} else {
			notInstalled = append(notInstalled, packageNamesOnly[i])
		}
	}

	// Log not installed packages
	if len(notInstalled) > 0 {
		m.logger.Infof("Packages not installed, skipping removal: %v", notInstalled)
	}

	if len(packagesToRemove) == 0 {
		m.logger.Info("All requested packages are not installed")
		return nil
	}

	m.logger.Infof("Removing system packages: %v", packagesToRemove)

	// Use package manager configuration from agent.json or auto-detected config
	if m.packageManager == nil || m.packageManager.RemoveCmd == "" {
		return fmt.Errorf("no package manager configuration available")
	}
	removeCmd := m.packageManager.RemoveCmd

	// Construct the full command with all packages to remove
	fullCmd := fmt.Sprintf("%s %s", removeCmd, strings.Join(packagesToRemove, " "))

	// Handle read-only filesystem for all package managers
	if m.packageManager != nil {
		fullCmd = m.wrapCommandDetectReadOnly(fullCmd)
	}

	m.logger.Infof("Executing bulk package removal command: %s", fullCmd)
	cmd := exec.Command("sh", "-c", fullCmd)
	output, err := cmd.CombinedOutput()
	if err != nil {
		m.logger.Errorf("Bulk package removal failed for %v: %v, output: %s", packagesToRemove, err, string(output))
		return fmt.Errorf("failed to remove packages %v: %w, output: %s", packagesToRemove, err, string(output))
	}

	m.logger.Infof("Successfully removed packages: %v", packagesToRemove)
	return nil
}

// ApplyChanges applies package changes in the correct order: destroy first, then create
func (m *Manager) ApplyChanges(toDestroy, toCreate []string) error {
	if len(toDestroy) == 0 && len(toCreate) == 0 {
		m.logger.Info("No package changes needed")
		return nil
	}

	m.logger.Info("Applying package changes")

	// Step 1: Remove packages that need to be destroyed (bulk operation)
	if len(toDestroy) > 0 {
		m.logger.Infof("Destroying %d packages: %v", len(toDestroy), toDestroy)
		if err := m.removePackages(toDestroy); err != nil {
			m.logger.Errorf("Failed to destroy packages %v: %v", toDestroy, err)
			return fmt.Errorf("failed to destroy packages %v: %w", toDestroy, err)
		}
		m.logger.Info("Successfully destroyed packages")
	}

	// Step 2: Install packages that need to be created (bulk operation)
	if len(toCreate) > 0 {
		m.logger.Infof("Creating %d packages: %v", len(toCreate), toCreate)
		if err := m.installPackages(toCreate); err != nil {
			m.logger.Errorf("Failed to create packages %v: %v", toCreate, err)
			return fmt.Errorf("failed to create packages %v: %w", toCreate, err)
		}
		m.logger.Info("Successfully created packages")
	}

	m.logger.Info("Successfully applied all package changes")
	return nil
}

// updateCurrentStateAfterChanges updates the current state by removing destroyed packages and adding created packages
func (m *Manager) updateCurrentStateAfterChanges(currentState []string, toDestroy, toCreate []string) []string {
	// Create a map of packages to destroy for efficient lookup
	destroyMap := make(map[string]bool)
	for _, pkg := range toDestroy {
		destroyMap[pkg] = true
	}

	// Start with current state and remove destroyed packages
	var updatedState []string
	for _, pkg := range currentState {
		if !destroyMap[pkg] {
			updatedState = append(updatedState, pkg)
		}
	}

	// Add created packages
	updatedState = append(updatedState, toCreate...)

	return updatedState
}
