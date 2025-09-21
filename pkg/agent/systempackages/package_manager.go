package systempackages

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/StreamDeploy/streamdeploy-agent/pkg/core/types"
)

// detectPackageManager detects the package manager and populates packageManager
func (m *Manager) detectPackageManager() *types.PackageManagerConfig {
	m.logger.Info("Detecting package manager...")

	// Check for common package managers in order of preference
	if m.commandExists("apt-get") {
		m.logger.Info("Detected APT package manager")
		return &types.PackageManagerConfig{
			Type:       "apt",
			InstallCmd: "apt-get update && apt-get install -y",
			CheckCmd:   "dpkg -l",
			RemoveCmd:  "apt-get remove -y",
		}
	}

	if m.commandExists("yum") {
		m.logger.Info("Detected YUM package manager")
		return &types.PackageManagerConfig{
			Type:       "yum",
			InstallCmd: "yum install -y",
			CheckCmd:   "rpm -qa",
			RemoveCmd:  "yum remove -y",
		}
	}

	if m.commandExists("dnf") {
		m.logger.Info("Detected DNF package manager")
		return &types.PackageManagerConfig{
			Type:       "dnf",
			InstallCmd: "dnf install -y",
			CheckCmd:   "rpm -qa",
			RemoveCmd:  "dnf remove -y",
		}
	}

	if m.commandExists("apk") {
		m.logger.Info("Detected APK package manager")
		return &types.PackageManagerConfig{
			Type:       "apk",
			InstallCmd: "apk add",
			CheckCmd:   "apk info",
			RemoveCmd:  "apk del",
		}
	}

	if m.commandExists("pacman") {
		m.logger.Info("Detected Pacman package manager")
		return &types.PackageManagerConfig{
			Type:       "pacman",
			InstallCmd: "pacman -S --noconfirm",
			CheckCmd:   "pacman -Q",
			RemoveCmd:  "pacman -R --noconfirm",
		}
	}

	if m.commandExists("zypper") {
		m.logger.Info("Detected Zypper package manager")
		return &types.PackageManagerConfig{
			Type:       "zypper",
			InstallCmd: "zypper install -y",
			CheckCmd:   "rpm -qa",
			RemoveCmd:  "zypper remove -y",
		}
	}

	m.logger.Error("No supported package manager found")
	return &types.PackageManagerConfig{
		Type:       "unknown",
		InstallCmd: "",
		CheckCmd:   "",
		RemoveCmd:  "",
	}
}

// getSystemPackages runs the package manager command and parses the output
func (m *Manager) getSystemPackages() (map[string]string, error) {
	if m.packageManager == nil || m.packageManager.CheckCmd == "" {
		return nil, fmt.Errorf("no package manager check command available")
	}

	cmd := exec.Command("sh", "-c", m.packageManager.CheckCmd)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to execute check command: %w", err)
	}

	switch m.packageManager.Type {
	case "apt":
		return m.parseAptOutput(string(output)), nil
	case "yum", "dnf", "zypper":
		return m.parseRpmOutput(string(output)), nil
	case "apk":
		return m.parseApkOutput(string(output)), nil
	case "pacman":
		return m.parsePacmanOutput(string(output)), nil
	default:
		packages := make(map[string]string)
		return packages, fmt.Errorf("unsupported package manager type: %s", m.packageManager.Type)
	}
}

// parseAptOutput parses dpkg -l output
func (m *Manager) parseAptOutput(output string) map[string]string {
	packages := make(map[string]string)
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "ii ") { // Only installed packages
			fields := strings.Fields(line)
			if len(fields) >= 3 {
				name := fields[1]
				version := fields[2]
				packages[name] = version
			}
		}
	}

	return packages
}

// parseRpmOutput parses rpm -qa output
func (m *Manager) parseRpmOutput(output string) map[string]string {
	packages := make(map[string]string)
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// RPM format: package-version-release.arch
		// Find the last occurrence of version pattern
		parts := strings.Split(line, "-")
		if len(parts) >= 2 {
			// Try to find where version starts (usually after package name)
			for i := 1; i < len(parts); i++ {
				if strings.Contains(parts[i], ".") || isNumeric(parts[i][0:1]) {
					name := strings.Join(parts[:i], "-")
					version := strings.Join(parts[i:], "-")
					packages[name] = version
					break
				}
			}
		}
	}

	return packages
}

// parseApkOutput parses apk info output
func (m *Manager) parseApkOutput(output string) map[string]string {
	packages := make(map[string]string)
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// APK format: package-version
		lastDash := strings.LastIndex(line, "-")
		if lastDash > 0 {
			name := line[:lastDash]
			version := line[lastDash+1:]
			packages[name] = version
		}
	}

	return packages
}

// parsePacmanOutput parses pacman -Q output
func (m *Manager) parsePacmanOutput(output string) map[string]string {
	packages := make(map[string]string)
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Pacman format: package version
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			name := fields[0]
			version := fields[1]
			packages[name] = version
		}
	}

	return packages
}

// parseDesiredState parses the desired state list
// Supports "package_name", "package_name=version", "package_name version"
func (m *Manager) parseDesiredState(packages []string) map[string]PackageInfo {
	desired := make(map[string]PackageInfo)

	for _, pkg := range packages {
		info := parsePackageString(pkg)
		desired[info.Name] = info
	}

	return desired
}

// buildCurrentState compares system state with desired state and builds current state
// Format: if version exists, use "package=version", if not, use "package=any"
func (m *Manager) buildCurrentState(systemPackages map[string]string, desiredPackages map[string]PackageInfo) []string {
	var currentState []string

	for desiredName, desiredInfo := range desiredPackages {
		if systemVersion, exists := systemPackages[desiredName]; exists {
			// Package exists in system
			if desiredInfo.HasVersion {
				// Version specified in desired state - include with actual system version
				currentState = append(currentState, fmt.Sprintf("%s=%s", desiredName, systemVersion))
			} else {
				// No version specified in desired state - any version is acceptable
				currentState = append(currentState, fmt.Sprintf("%s=any", desiredName))
			}
		}
		// If package not in system state, don't include it in current state
	}

	return currentState
}

// isNumeric checks if a string starts with a number
func isNumeric(s string) bool {
	if len(s) == 0 {
		return false
	}
	return s[0] >= '0' && s[0] <= '9'
}
