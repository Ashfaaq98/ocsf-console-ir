package plugins

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/bus"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/store"
)

// DefaultPluginManager implements the PluginManager interface
type DefaultPluginManager struct {
	registry     PluginRegistry
	bus          bus.Bus
	store        *store.Store
	logger       *log.Logger
	pluginsDir   string
	
	// State management
	mu           sync.RWMutex
	running      bool
	ctx          context.Context
	cancel       context.CancelFunc
	
	// Plugin processes
	processes    map[string]*exec.Cmd
	processStats map[string]*PluginStatus
}

// DefaultPluginRegistry implements the PluginRegistry interface
type DefaultPluginRegistry struct {
	mu              sync.RWMutex
	corePlugins     map[string]CorePlugin
	externalPlugins map[string]*ExternalPlugin
	logger          *log.Logger
}

// NewPluginManager creates a new plugin manager
func NewPluginManager(eventBus bus.Bus, store *store.Store, pluginsDir string, logger *log.Logger) *DefaultPluginManager {
	if logger == nil {
		logger = log.New(os.Stderr, "[PluginManager] ", log.LstdFlags)
	}

	ctx, cancel := context.WithCancel(context.Background())

	registry := &DefaultPluginRegistry{
		corePlugins:     make(map[string]CorePlugin),
		externalPlugins: make(map[string]*ExternalPlugin),
		logger:          logger,
	}

	return &DefaultPluginManager{
		registry:     registry,
		bus:          eventBus,
		store:        store,
		logger:       logger,
		pluginsDir:   pluginsDir,
		ctx:          ctx,
		cancel:       cancel,
		processes:    make(map[string]*exec.Cmd),
		processStats: make(map[string]*PluginStatus),
	}
}

// Start starts all enabled plugins
func (pm *DefaultPluginManager) Start(ctx context.Context) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if pm.running {
		return fmt.Errorf("plugin manager is already running")
	}

	pm.logger.Println("Starting plugin manager")

	// Rebind the manager context to the caller's context so shutdown via signals/cancellation
	// is visible to all plugin monitors. This ensures we can suppress expected TERM/KILL noise.
	if pm.cancel != nil {
		// Cancel any prior context if Start was previously invoked
		pm.cancel()
	}
	pm.ctx, pm.cancel = context.WithCancel(ctx)

	// Discover external plugins
	if err := pm.discoverExternalPlugins(); err != nil {
		pm.logger.Printf("Warning: failed to discover external plugins: %v", err)
	}

	// Start core plugins
	for name, plugin := range pm.registry.(*DefaultPluginRegistry).corePlugins {
		if err := plugin.Start(ctx); err != nil {
			pm.logger.Printf("Failed to start core plugin %s: %v", name, err)
			continue
		}
		pm.logger.Printf("Started core plugin: %s", name)
	}

	// Start external plugins
	for name, plugin := range pm.registry.(*DefaultPluginRegistry).externalPlugins {
		if !plugin.Enabled {
			pm.logger.Printf("Skipping disabled external plugin: %s", name)
			continue
		}

		if err := pm.startExternalPlugin(ctx, plugin); err != nil {
			pm.logger.Printf("Failed to start external plugin %s: %v", name, err)
			continue
		}
		pm.logger.Printf("Started external plugin: %s", name)
	}

	pm.running = true

	// Start monitoring goroutine
	go pm.monitorPlugins()

	return nil
}

/*
Stop stops all running plugins.

Key changes:
- Avoid holding pm.mu while stopping plugins to prevent shutdown hangs.
- Snapshot core plugins and processes under lock, then release the lock before stopping.
- Do not block waiting for external plugin processes here; monitorExternalPlugin owns cmd.Wait().
*/
func (pm *DefaultPluginManager) Stop() error {
	pm.mu.Lock()

	if !pm.running {
		pm.mu.Unlock()
		return nil
	}

	pm.logger.Println("Stopping plugin manager")

	// Mark not running and cancel context under lock
	pm.running = false
	pm.cancel()

	// Snapshot core plugins and processes, then release the lock to avoid blocking while stopping
	corePlugins := make(map[string]CorePlugin, len(pm.registry.(*DefaultPluginRegistry).corePlugins))
	for name, plugin := range pm.registry.(*DefaultPluginRegistry).corePlugins {
		corePlugins[name] = plugin
	}
	procs := make(map[string]*exec.Cmd, len(pm.processes))
	for name, cmd := range pm.processes {
		procs[name] = cmd
	}

	pm.mu.Unlock()

	// Stop core plugins (outside the lock)
	for name, plugin := range corePlugins {
		if err := plugin.Stop(); err != nil {
			pm.logger.Printf("Error stopping core plugin %s: %v", name, err)
		} else {
			pm.logger.Printf("Stopped core plugin: %s", name)
		}
	}

	// Initiate shutdown for external plugins (do not call Wait() here)
	for name, cmd := range procs {
		if err := pm.stopExternalPlugin(name, cmd); err != nil {
			pm.logger.Printf("Error stopping external plugin %s: %v", name, err)
		} else {
			pm.logger.Printf("Stopped external plugin: %s", name)
		}
	}

	return nil
}

// StartPlugin starts a specific plugin
func (pm *DefaultPluginManager) StartPlugin(ctx context.Context, name string) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	// Try core plugin first
	if plugin, exists := pm.registry.(*DefaultPluginRegistry).corePlugins[name]; exists {
		return plugin.Start(ctx)
	}

	// Try external plugin
	if plugin, exists := pm.registry.(*DefaultPluginRegistry).externalPlugins[name]; exists {
		return pm.startExternalPlugin(ctx, plugin)
	}

	return fmt.Errorf("plugin not found: %s", name)
}

// StopPlugin stops a specific plugin
func (pm *DefaultPluginManager) StopPlugin(name string) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	// Try core plugin first
	if plugin, exists := pm.registry.(*DefaultPluginRegistry).corePlugins[name]; exists {
		return plugin.Stop()
	}

	// Try external plugin
	if cmd, exists := pm.processes[name]; exists {
		return pm.stopExternalPlugin(name, cmd)
	}

	return fmt.Errorf("plugin not found or not running: %s", name)
}

// RestartPlugin restarts a specific plugin
func (pm *DefaultPluginManager) RestartPlugin(ctx context.Context, name string) error {
	if err := pm.StopPlugin(name); err != nil {
		pm.logger.Printf("Warning: failed to stop plugin %s: %v", name, err)
	}

	// Wait a moment for cleanup
	time.Sleep(1 * time.Second)

	return pm.StartPlugin(ctx, name)
}

// GetRegistry returns the plugin registry
func (pm *DefaultPluginManager) GetRegistry() PluginRegistry {
	return pm.registry
}

// ProcessEvent processes an event through all applicable plugins
func (pm *DefaultPluginManager) ProcessEvent(ctx context.Context, event bus.EventMessage) error {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	// Process through core plugins
	for name, plugin := range pm.registry.(*DefaultPluginRegistry).corePlugins {
		enrichments, err := plugin.Process(ctx, event)
		if err != nil {
			pm.logger.Printf("Error processing event through core plugin %s: %v", name, err)
			continue
		}

		// Apply enrichments to the database
		for _, enrichment := range enrichments {
			if err := pm.store.ApplyEnrichment(ctx, event.EventID, enrichment); err != nil {
				pm.logger.Printf("Error applying enrichment from plugin %s: %v", name, err)
			}
		}
	}

	// External plugins process events via Redis streams automatically
	return nil
}

// HealthCheck performs health checks on all plugins
func (pm *DefaultPluginManager) HealthCheck(ctx context.Context) (map[string]error, error) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	results := make(map[string]error)

	// Check core plugins
	for name, plugin := range pm.registry.(*DefaultPluginRegistry).corePlugins {
		results[name] = plugin.HealthCheck(ctx)
	}

	// Check external plugins (basic process check)
	for name, cmd := range pm.processes {
		if cmd.Process == nil {
			results[name] = fmt.Errorf("process not found")
		} else if cmd.ProcessState != nil && cmd.ProcessState.Exited() {
			results[name] = fmt.Errorf("process exited")
		} else {
			results[name] = nil // Healthy
		}
	}

	return results, nil
}

// GetStats returns plugin statistics
func (pm *DefaultPluginManager) GetStats() map[string]interface{} {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	stats := map[string]interface{}{
		"running":         pm.running,
		"core_plugins":    len(pm.registry.(*DefaultPluginRegistry).corePlugins),
		"external_plugins": len(pm.registry.(*DefaultPluginRegistry).externalPlugins),
		"active_processes": len(pm.processes),
	}

	// Add individual plugin stats
	pluginStats := make(map[string]interface{})
	for name, status := range pm.processStats {
		pluginStats[name] = status
	}
	stats["plugin_status"] = pluginStats

	return stats
}

// discoverExternalPlugins discovers external plugins in the plugins directory.
//
// Change: Do NOT auto-start all discovered executables by default. External
// plugins must be explicitly enabled by creating a marker file next to the
// executable (plugin-binary -> plugin-binary.enabled) to opt-in. This makes
// the default behavior safe for repositories that ship plugin binaries.
func (pm *DefaultPluginManager) discoverExternalPlugins() error {
	if pm.pluginsDir == "" {
		return nil
	}

	if _, err := os.Stat(pm.pluginsDir); os.IsNotExist(err) {
		pm.logger.Printf("Plugins directory does not exist: %s", pm.pluginsDir)
		return nil
	}

	return filepath.Walk(pm.pluginsDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip directories and non-executable files
		if info.IsDir() || (info.Mode()&0111) == 0 {
			return nil
		}

		// Require explicit enablement via a marker file beside the executable.
		// Example: plugins/llm/llm  -> plugins/llm/llm.enabled
		enabledMarker := path + ".enabled"
		if _, statErr := os.Stat(enabledMarker); os.IsNotExist(statErr) {
			pm.logger.Printf("Skipping external plugin %s (not enabled). To enable: create %s", filepath.Base(path), enabledMarker)
			return nil
		} else if statErr != nil {
			// If Stat returns an unexpected error, propagate it.
			return statErr
		}

		// Create external plugin entry (explicitly enabled)
		name := filepath.Base(path)
		plugin := &ExternalPlugin{
			Name:        name,
			Command:     path,
			Enabled:     true,
			Description: fmt.Sprintf("Explicitly enabled external plugin: %s", name),
			Timeout:     30 * time.Second,
		}

		return pm.registry.RegisterExternalPlugin(plugin)
	})
}

// startExternalPlugin starts an external plugin process
func (pm *DefaultPluginManager) startExternalPlugin(ctx context.Context, plugin *ExternalPlugin) error {
	cmd := exec.CommandContext(ctx, plugin.Command, plugin.Args...)
	
	// Set environment variables
	cmd.Env = os.Environ()
	for key, value := range plugin.Env {
		cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", key, value))
	}

	// Set working directory
	if plugin.WorkingDir != "" {
		cmd.Dir = plugin.WorkingDir
	}

	// Start the process
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start plugin process: %w", err)
	}

	// Store process reference
	pm.processes[plugin.Name] = cmd

	// Initialize status
	pm.processStats[plugin.Name] = &PluginStatus{
		Name:         plugin.Name,
		Type:         "external",
		Status:       "running",
		LastActivity: time.Now(),
	}

	// Monitor process in background
	go pm.monitorExternalPlugin(plugin.Name, cmd)

	return nil
}

/*
stopExternalPlugin initiates a graceful shutdown for an external plugin without
calling cmd.Wait() (which is owned by the monitor goroutine). It:
- Sends SIGTERM
- Polls briefly to see if the process exits
- Escalates to Kill if still running
- Avoids double-wait/double-delete races with monitorExternalPlugin
*/
func (pm *DefaultPluginManager) stopExternalPlugin(name string, cmd *exec.Cmd) error {
	if cmd == nil || cmd.Process == nil {
		return nil
	}

	// If already exited, mark and return
	if cmd.ProcessState != nil && cmd.ProcessState.Exited() {
		pm.mu.Lock()
		if status, exists := pm.processStats[name]; exists {
			status.Status = "stopped"
		}
		pm.mu.Unlock()
		return nil
	}

	// Mark status as stopping (best-effort)
	pm.mu.Lock()
	if status, exists := pm.processStats[name]; exists {
		status.Status = "stopping"
	}
	pm.mu.Unlock()

	// Try graceful shutdown first
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil && err.Error() != "os: process already finished" {
		pm.logger.Printf("Failed to send SIGTERM to plugin %s: %v", name, err)
	}

	// Poll for up to 2 seconds (20 x 100ms) for the process to exit.
	// We avoid calling Wait() here because monitorExternalPlugin() owns it.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		// On Unix, signal 0 can be used to test if the process is still alive.
		if err := cmd.Process.Signal(syscall.Signal(0)); err != nil {
			// Process no longer exists
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}

	// Force kill if still running
	if err := cmd.Process.Kill(); err != nil && err.Error() != "os: process already finished" {
		pm.logger.Printf("Failed to kill plugin %s: %v", name, err)
	}
	return nil
}

// monitorPlugins monitors plugin health and restarts failed plugins
func (pm *DefaultPluginManager) monitorPlugins() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-pm.ctx.Done():
			return
		case <-ticker.C:
			pm.performHealthChecks()
		}
	}
}

/*
monitorExternalPlugin waits for the external plugin process to exit and updates status.
During manager shutdown (pm.ctx canceled), suppress logging "error" exits caused by SIGTERM
to avoid terminal noise when quitting the application.
*/
func (pm *DefaultPluginManager) monitorExternalPlugin(name string, cmd *exec.Cmd) {
	err := cmd.Wait()

	// Detect manager shutdown
	shuttingDown := pm.ctx.Err() != nil

	// Determine if the process exited due to SIGTERM
	expectedTerm := false
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			if ws, ok := exitErr.Sys().(syscall.WaitStatus); ok {
				if ws.Signaled() && ws.Signal() == syscall.SIGTERM {
					expectedTerm = true
				}
			}
		}
	}

	pm.mu.Lock()
	defer pm.mu.Unlock()

	if status, exists := pm.processStats[name]; exists {
		if err != nil {
			// Suppress error logs if we're shutting down and the process was terminated by SIGTERM
			if shuttingDown && expectedTerm {
				status.Status = "stopped"
			} else {
				status.Status = "error"
				status.Errors++
				pm.logger.Printf("External plugin %s exited with error: %v", name, err)
			}
		} else {
			status.Status = "stopped"
			pm.logger.Printf("External plugin %s exited normally", name)
		}
	}

	// Remove from active processes
	delete(pm.processes, name)
}

// performHealthChecks performs periodic health checks
func (pm *DefaultPluginManager) performHealthChecks() {
	ctx, cancel := context.WithTimeout(pm.ctx, 10*time.Second)
	defer cancel()

	results, err := pm.HealthCheck(ctx)
	if err != nil {
		pm.logger.Printf("Error performing health checks: %v", err)
		return
	}

	for name, err := range results {
		if err != nil {
			pm.logger.Printf("Plugin %s health check failed: %v", name, err)
			// TODO: Implement restart logic for failed plugins
		}
	}
}

// Registry implementation

// RegisterCorePlugin registers an internal Go plugin
func (dr *DefaultPluginRegistry) RegisterCorePlugin(plugin CorePlugin) error {
	dr.mu.Lock()
	defer dr.mu.Unlock()

	name := plugin.Name()
	if _, exists := dr.corePlugins[name]; exists {
		return fmt.Errorf("core plugin already registered: %s", name)
	}

	dr.corePlugins[name] = plugin
	dr.logger.Printf("Registered core plugin: %s", name)
	return nil
}

 // RegisterExternalPlugin registers an external executable plugin
func (dr *DefaultPluginRegistry) RegisterExternalPlugin(plugin *ExternalPlugin) error {
	dr.mu.Lock()
	defer dr.mu.Unlock()

	if _, exists := dr.externalPlugins[plugin.Name]; exists {
		// Treat duplicate registration as a no-op to avoid noisy warnings during discovery
		dr.logger.Printf("Skipping duplicate external plugin registration: %s", plugin.Name)
		return nil
	}

	dr.externalPlugins[plugin.Name] = plugin
	dr.logger.Printf("Registered external plugin: %s", plugin.Name)
	return nil
}

// GetCorePlugin returns a core plugin by name
func (dr *DefaultPluginRegistry) GetCorePlugin(name string) (CorePlugin, bool) {
	dr.mu.RLock()
	defer dr.mu.RUnlock()

	plugin, exists := dr.corePlugins[name]
	return plugin, exists
}

// GetExternalPlugin returns an external plugin by name
func (dr *DefaultPluginRegistry) GetExternalPlugin(name string) (*ExternalPlugin, bool) {
	dr.mu.RLock()
	defer dr.mu.RUnlock()

	plugin, exists := dr.externalPlugins[name]
	return plugin, exists
}

// ListCorePlugins returns all registered core plugins
func (dr *DefaultPluginRegistry) ListCorePlugins() []CorePlugin {
	dr.mu.RLock()
	defer dr.mu.RUnlock()

	plugins := make([]CorePlugin, 0, len(dr.corePlugins))
	for _, plugin := range dr.corePlugins {
		plugins = append(plugins, plugin)
	}
	return plugins
}

// ListExternalPlugins returns all registered external plugins
func (dr *DefaultPluginRegistry) ListExternalPlugins() []*ExternalPlugin {
	dr.mu.RLock()
	defer dr.mu.RUnlock()

	plugins := make([]*ExternalPlugin, 0, len(dr.externalPlugins))
	for _, plugin := range dr.externalPlugins {
		plugins = append(plugins, plugin)
	}
	return plugins
}

// GetPluginStatus returns the status of a plugin
func (dr *DefaultPluginRegistry) GetPluginStatus(name string) (*PluginStatus, error) {
	dr.mu.RLock()
	defer dr.mu.RUnlock()

	// Check core plugins
	if _, exists := dr.corePlugins[name]; exists {
		status := &PluginStatus{
			Name:   name,
			Type:   "core",
			Status: "running",
		}

		return status, nil
	}

	// Check external plugins
	if _, exists := dr.externalPlugins[name]; exists {
		return &PluginStatus{
			Name:   name,
			Type:   "external",
			Status: "registered",
		}, nil
	}

	return nil, fmt.Errorf("plugin not found: %s", name)
}

// GetAllStatuses returns the status of all plugins
func (dr *DefaultPluginRegistry) GetAllStatuses() ([]*PluginStatus, error) {
	dr.mu.RLock()
	defer dr.mu.RUnlock()

	var statuses []*PluginStatus

	// Get core plugin statuses
	for name := range dr.corePlugins {
		if status, err := dr.GetPluginStatus(name); err == nil {
			statuses = append(statuses, status)
		}
	}

	// Get external plugin statuses
	for name := range dr.externalPlugins {
		if status, err := dr.GetPluginStatus(name); err == nil {
			statuses = append(statuses, status)
		}
	}

	return statuses, nil
}