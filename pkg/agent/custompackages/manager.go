package custompackages

import (
	"fmt"
	"sync"

	"github.com/StreamDeploy/streamdeploy-agent/pkg/core/types"
)

// Manager implements the CustomPackageManager interface
type Manager struct {
	logger         types.Logger
	mutex          sync.Mutex                     // Protects package operations from concurrent access
	customPackages map[string]types.CustomPackage // Stores current custom package definitions
}

// NewManager creates a new custom package manager
func NewManager(logger types.Logger) *Manager {
	return &Manager{
		logger:         logger,
		customPackages: make(map[string]types.CustomPackage),
	}
}

// DetectCurrentState detects the current state of custom packages
// Runs the check command defined in each custom package and builds current state
func (m *Manager) DetectCurrentState(desiredState *types.StateConfig) map[string]types.CustomPackage {
	if desiredState == nil || len(desiredState.CustomPackages) == 0 {
		return make(map[string]types.CustomPackage)
	}

	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.logger.Info("Detecting current custom package state")

	// Build current state by checking which packages are installed
	currentState := m.buildCurrentState(desiredState.CustomPackages)

	m.logger.Infof("Detected %d custom packages in current state", len(currentState))
	return currentState
}

// CompareStates compares current state with desired state and returns what needs to be destroyed and created
// Compares all fields (Name, Install, Check, Uninstall) to determine if packages are different
func (m *Manager) CompareStates(currentState, desiredState map[string]types.CustomPackage) (map[string]types.CustomPackage, map[string]types.CustomPackage) {
	toDestroy := make(map[string]types.CustomPackage)
	toCreate := make(map[string]types.CustomPackage)

	// Find packages to destroy (in current but not in desired, or different in desired)
	for name, currentPkg := range currentState {
		if desiredPkg, exists := desiredState[name]; !exists {
			// Package exists in current but not in desired - destroy it
			toDestroy[name] = currentPkg
		} else if !m.compareCustomPackages(currentPkg, desiredPkg) {
			// Package exists in both but fields are different - destroy current and create new
			toDestroy[name] = currentPkg
			toCreate[name] = desiredPkg
		}
	}

	// Find packages to create (in desired but not in current)
	for name, desiredPkg := range desiredState {
		if _, exists := currentState[name]; !exists {
			toCreate[name] = desiredPkg
		}
	}

	return toDestroy, toCreate
}

// Destroy removes custom packages that are no longer needed
func (m *Manager) Destroy(packages map[string]types.CustomPackage) ([]string, error) {
	if len(packages) == 0 {
		return []string{}, nil
	}

	m.logger.Info("Destroying custom packages")

	var destroyedPackages []string
	var errors []string

	// Execute uninstall command for each custom package
	for name, pkg := range packages {
		if pkg.Uninstall == "" {
			errorMsg := fmt.Sprintf("no uninstall command defined for package %s", name)
			m.logger.Errorf(errorMsg)
			errors = append(errors, errorMsg)
			continue
		}

		if err := m.executeCommand(pkg.Uninstall, "uninstall"); err != nil {
			errorMsg := fmt.Sprintf("failed to destroy package %s: %v", name, err)
			m.logger.Errorf(errorMsg)
			errors = append(errors, errorMsg)
			continue
		}

		destroyedPackages = append(destroyedPackages, name)
		m.logger.Infof("Successfully destroyed package %s", name)
	}

	if len(errors) > 0 {
		return destroyedPackages, fmt.Errorf("errors occurred during destruction: %v", errors)
	}

	m.logger.Infof("Successfully destroyed %d custom packages: %v", len(destroyedPackages), destroyedPackages)
	return destroyedPackages, nil
}

// Create installs new custom packages
func (m *Manager) Create(packages map[string]types.CustomPackage) ([]string, error) {
	if len(packages) == 0 {
		return []string{}, nil
	}

	m.logger.Info("Creating custom packages")

	var createdPackages []string
	var errors []string

	// Execute install command for each custom package
	for name, pkg := range packages {
		if pkg.Install == "" {
			errorMsg := fmt.Sprintf("no install command defined for package %s", name)
			m.logger.Errorf(errorMsg)
			errors = append(errors, errorMsg)
			continue
		}

		m.logger.Infof("Starting installation of package %s", name)
		if err := m.executeCommand(pkg.Install, "install"); err != nil {
			errorMsg := fmt.Sprintf("failed to create package %s: %v", name, err)
			m.logger.Errorf(errorMsg)
			errors = append(errors, errorMsg)
			continue
		}

		createdPackages = append(createdPackages, name)
		m.logger.Infof("Successfully created package %s", name)
	}

	if len(errors) > 0 {
		return createdPackages, fmt.Errorf("errors occurred during creation: %v", errors)
	}

	m.logger.Infof("Successfully created %d custom packages: %v", len(createdPackages), createdPackages)
	return createdPackages, nil
}

// StateConsolidation performs a complete state consolidation process:
// 1. Calls CompareStates to determine what needs to be done
// 2. Applies Delete or Install operations
// 3. Reports errors if failed
// 4. Returns the updated current state based on what succeeded
func (m *Manager) StateConsolidation(currentState, desiredState map[string]types.CustomPackage) (map[string]types.CustomPackage, bool, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.logger.Info("Starting state consolidation for custom packages")
	m.logger.Infof("Current state: %d packages, Desired state: %d packages", len(currentState), len(desiredState))

	// Step 1: Compare states to determine what needs to be done
	toDestroy, toCreate := m.CompareStates(currentState, desiredState)
	m.logger.Infof("State comparison: %d to destroy, %d to create", len(toDestroy), len(toCreate))

	// Step 2: Apply changes if needed
	changesMade := len(toDestroy) > 0 || len(toCreate) > 0
	if changesMade {
		m.logger.Info("Applying package changes")

		// Apply changes in the correct order: destroy first, then create
		destroyed, created, err := m.ApplyChanges(toDestroy, toCreate)
		if err != nil {
			m.logger.Errorf("Failed to apply package changes: %v", err)
			m.logger.Infof("Successfully destroyed %d packages: %v", len(destroyed), destroyed)
			m.logger.Infof("Successfully created %d packages: %v", len(created), created)
			// Return updated current state even if changes failed, as some operations might have succeeded
			updatedState := m.updateCurrentStateAfterChanges(currentState, toDestroy, toCreate)
			return updatedState, changesMade, err
		}

		m.logger.Infof("Package changes applied successfully: %d destroyed, %d created", len(destroyed), len(created))
	} else {
		m.logger.Info("No package changes needed")
	}

	// Step 3: Return updated current state based on what succeeded
	updatedCurrentState := m.updateCurrentStateAfterChanges(currentState, toDestroy, toCreate)
	m.logger.Infof("State consolidation completed. Final state: %d packages", len(updatedCurrentState))

	return updatedCurrentState, changesMade, nil
}

// ApplyChanges applies package changes in the correct order: destroy first, then create
func (m *Manager) ApplyChanges(toDestroy, toCreate map[string]types.CustomPackage) ([]string, []string, error) {
	if len(toDestroy) == 0 && len(toCreate) == 0 {
		m.logger.Info("No package changes needed")
		return []string{}, []string{}, nil
	}

	m.logger.Info("Applying package changes")

	var destroyedPackages []string
	var createdPackages []string
	var allErrors []string

	// Step 1: Remove packages that need to be destroyed
	if len(toDestroy) > 0 {
		destroyNames := make([]string, 0, len(toDestroy))
		for name := range toDestroy {
			destroyNames = append(destroyNames, name)
		}
		m.logger.Infof("Destroying %d packages: %v", len(toDestroy), destroyNames)

		destroyed, err := m.Destroy(toDestroy)
		destroyedPackages = append(destroyedPackages, destroyed...)
		if err != nil {
			allErrors = append(allErrors, fmt.Sprintf("destroy errors: %v", err))
		}
	}

	// Step 2: Install packages that need to be created
	if len(toCreate) > 0 {
		createNames := make([]string, 0, len(toCreate))
		for name := range toCreate {
			createNames = append(createNames, name)
		}
		m.logger.Infof("Creating %d packages: %v", len(toCreate), createNames)

		created, err := m.Create(toCreate)
		createdPackages = append(createdPackages, created...)
		if err != nil {
			allErrors = append(allErrors, fmt.Sprintf("create errors: %v", err))
		}
	}

	// Return results and any errors
	var finalError error
	if len(allErrors) > 0 {
		finalError = fmt.Errorf("errors occurred during package changes: %v", allErrors)
	}

	m.logger.Infof("Package changes completed: %d destroyed, %d created", len(destroyedPackages), len(createdPackages))
	return destroyedPackages, createdPackages, finalError
}

// updateCurrentStateAfterChanges updates the current state by removing destroyed packages and adding created packages
func (m *Manager) updateCurrentStateAfterChanges(currentState map[string]types.CustomPackage, toDestroy, toCreate map[string]types.CustomPackage) map[string]types.CustomPackage {
	// Start with current state and remove destroyed packages
	updatedState := make(map[string]types.CustomPackage)
	for name, pkg := range currentState {
		if _, shouldDestroy := toDestroy[name]; !shouldDestroy {
			updatedState[name] = pkg
		}
	}

	// Add created packages
	for name, pkg := range toCreate {
		updatedState[name] = pkg
	}

	return updatedState
}
