package packages

import (
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/StreamDeploy/streamdeploy-agent/pkg/core/types"
)

// Manager implements the PackageManager interface
type Manager struct {
	logger types.Logger
}

// NewManager creates a new package manager
func NewManager(logger types.Logger) *Manager {
	return &Manager{
		logger: logger,
	}
}

// IsPackageInstalled checks if a system package is installed
func (m *Manager) IsPackageInstalled(packageName string) bool {
	// Try common package managers
	packageManagers := []string{"dpkg", "rpm", "apk", "pacman"}

	for _, pm := range packageManagers {
		if m.checkWithPackageManager(pm, packageName) {
			return true
		}
	}

	return false
}

// checkWithPackageManager checks if package is installed using specific package manager
func (m *Manager) checkWithPackageManager(manager, packageName string) bool {
	var cmd *exec.Cmd

	switch manager {
	case "dpkg":
		cmd = exec.Command("dpkg", "-l", packageName)
	case "rpm":
		cmd = exec.Command("rpm", "-q", packageName)
	case "apk":
		cmd = exec.Command("apk", "info", packageName)
	case "pacman":
		cmd = exec.Command("pacman", "-Q", packageName)
	default:
		return false
	}

	output, err := cmd.Output()
	if err != nil {
		return false
	}

	// Check if package name appears in output
	return strings.Contains(strings.ToLower(string(output)), strings.ToLower(packageName))
}

// InstallPackage installs a system package
func (m *Manager) InstallPackage(packageName string) error {
	m.logger.Infof("Installing system package: %s", packageName)

	// Detect package manager and install
	installCmd := m.detectInstallCommand()
	if installCmd == "" {
		return fmt.Errorf("no supported package manager found")
	}

	cmd := exec.Command("sh", "-c", installCmd+" "+packageName)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to install package %s: %w, output: %s", packageName, err, string(output))
	}

	m.logger.Infof("Successfully installed package: %s", packageName)
	return nil
}

// RemovePackage removes a system package
func (m *Manager) RemovePackage(packageName string) error {
	m.logger.Infof("Removing system package: %s", packageName)

	// Detect package manager and remove
	removeCmd := m.detectRemoveCommand()
	if removeCmd == "" {
		return fmt.Errorf("no supported package manager found")
	}

	cmd := exec.Command("sh", "-c", removeCmd+" "+packageName)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to remove package %s: %w, output: %s", packageName, err, string(output))
	}

	m.logger.Infof("Successfully removed package: %s", packageName)
	return nil
}

// EnsurePackagesInstalled ensures all specified system packages are installed
func (m *Manager) EnsurePackagesInstalled(packages []string) error {
	for _, pkg := range packages {
		if !m.IsPackageInstalled(pkg) {
			if err := m.InstallPackage(pkg); err != nil {
				return fmt.Errorf("failed to ensure package %s is installed: %w", pkg, err)
			}
		} else {
			m.logger.Infof("Package %s is already installed", pkg)
		}
	}
	return nil
}

// EnsureCustomPackagesInstalled ensures all custom packages are installed
func (m *Manager) EnsureCustomPackagesInstalled(packages map[string]types.CustomPackage) error {
	for name, pkg := range packages {
		if !m.isCustomPackageInstalled(name, pkg) {
			m.logger.Infof("Installing custom package: %s", name)
			if err := m.executeCommand(pkg.Install, "install"); err != nil {
				return fmt.Errorf("failed to install custom package %s: %w", name, err)
			}
		} else {
			m.logger.Infof("Custom package %s is already installed", name)
		}
	}
	return nil
}

// SyncPackages synchronizes system packages based on new and old configurations
func (m *Manager) SyncPackages(newPackages, oldPackages []string) error {
	m.logger.Info("Synchronizing system packages")

	// Create maps for easier lookup
	newPackageMap := make(map[string]bool)
	oldPackageMap := make(map[string]bool)

	for _, pkg := range newPackages {
		newPackageMap[pkg] = true
	}

	for _, pkg := range oldPackages {
		oldPackageMap[pkg] = true
	}

	// Remove packages that are no longer needed
	for pkg := range oldPackageMap {
		if !newPackageMap[pkg] {
			m.logger.Infof("Removing package: %s", pkg)
			if err := m.RemovePackage(pkg); err != nil {
				m.logger.Errorf("Failed to remove package %s: %v", pkg, err)
			}
		}
	}

	// Install new packages
	for pkg := range newPackageMap {
		if !oldPackageMap[pkg] {
			if err := m.InstallPackage(pkg); err != nil {
				return fmt.Errorf("failed to install new package %s: %w", pkg, err)
			}
		}
	}

	m.logger.Info("System package synchronization completed")
	return nil
}

// SyncCustomPackages synchronizes custom packages based on new and old configurations
func (m *Manager) SyncCustomPackages(newPackages, oldPackages map[string]types.CustomPackage) error {
	m.logger.Info("Synchronizing custom packages")

	// Remove packages that are no longer needed
	for name, pkg := range oldPackages {
		if _, exists := newPackages[name]; !exists {
			m.logger.Infof("Removing custom package: %s", name)
			if err := m.executeCommand(pkg.Uninstall, "uninstall"); err != nil {
				m.logger.Errorf("Failed to remove custom package %s: %v", name, err)
			}
		}
	}

	// Install or update packages
	for name, pkg := range newPackages {
		oldPkg, exists := oldPackages[name]

		if !exists {
			// New package, install it
			m.logger.Infof("Installing new custom package: %s", name)
			if err := m.executeCommand(pkg.Install, "install"); err != nil {
				return fmt.Errorf("failed to install new custom package %s: %w", name, err)
			}
		} else if !m.customPackagesEqual(oldPkg, pkg) {
			// Package configuration changed, reinstall
			m.logger.Infof("Updating custom package: %s", name)
			if err := m.executeCommand(oldPkg.Uninstall, "uninstall"); err != nil {
				m.logger.Errorf("Failed to uninstall old version of %s: %v", name, err)
			}
			if err := m.executeCommand(pkg.Install, "install"); err != nil {
				return fmt.Errorf("failed to install updated custom package %s: %w", name, err)
			}
		} else {
			// Package unchanged, just ensure it's installed
			if !m.isCustomPackageInstalled(name, pkg) {
				m.logger.Infof("Reinstalling custom package: %s", name)
				if err := m.executeCommand(pkg.Install, "install"); err != nil {
					return fmt.Errorf("failed to reinstall custom package %s: %w", name, err)
				}
			}
		}
	}

	m.logger.Info("Custom package synchronization completed")
	return nil
}

// isCustomPackageInstalled checks if a custom package is installed
func (m *Manager) isCustomPackageInstalled(name string, pkg types.CustomPackage) bool {
	if pkg.Check == "" {
		// If no check command, assume not installed
		return false
	}

	cmd := exec.Command("sh", "-c", pkg.Check)
	err := cmd.Run()
	return err == nil
}

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
	case <-time.After(5 * time.Minute): // 5 minute timeout
		cmd.Process.Kill()
		return fmt.Errorf("command timed out after 5 minutes")
	}
}

// customPackagesEqual compares two custom package configurations
func (m *Manager) customPackagesEqual(a, b types.CustomPackage) bool {
	return a.Install == b.Install && a.Check == b.Check && a.Uninstall == b.Uninstall
}

// detectInstallCommand detects the appropriate install command for the system
func (m *Manager) detectInstallCommand() string {
	// Check for common package managers
	if m.commandExists("apt-get") {
		return "apt-get update && apt-get install -y"
	}
	if m.commandExists("yum") {
		return "yum install -y"
	}
	if m.commandExists("dnf") {
		return "dnf install -y"
	}
	if m.commandExists("apk") {
		return "apk add"
	}
	if m.commandExists("pacman") {
		return "pacman -S --noconfirm"
	}
	if m.commandExists("zypper") {
		return "zypper install -y"
	}
	return ""
}

// detectRemoveCommand detects the appropriate remove command for the system
func (m *Manager) detectRemoveCommand() string {
	// Check for common package managers
	if m.commandExists("apt-get") {
		return "apt-get remove -y"
	}
	if m.commandExists("yum") {
		return "yum remove -y"
	}
	if m.commandExists("dnf") {
		return "dnf remove -y"
	}
	if m.commandExists("apk") {
		return "apk del"
	}
	if m.commandExists("pacman") {
		return "pacman -R --noconfirm"
	}
	if m.commandExists("zypper") {
		return "zypper remove -y"
	}
	return ""
}

// commandExists checks if a command exists in PATH
func (m *Manager) commandExists(command string) bool {
	cmd := exec.Command("which", command)
	err := cmd.Run()
	return err == nil
}
