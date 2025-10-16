package cmd

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/bus"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/ingest"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/llm"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/plugins"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/store"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/ui"
	"github.com/spf13/cobra"
)

var (
	noTUI    bool
	forceTUI bool

	// HTTP ingestion flags
	httpIngestEnable bool
	httpIngestBind   string
	httpIngestToken  string
	httpIngestRPS    int
	httpIngestBurst  int
	httpIngestDir    string
)

// serveCmd represents the serve command
var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the TUI and plugin processing services",
	Long: `Start the Console-IR server which includes:

1. Terminal User Interface (TUI) for case management
2. Redis Streams consumers for plugin coordination
3. Enrichment processing pipeline
4. Plugin lifecycle management

The serve command runs until interrupted (Ctrl+C) and handles:
- Real-time event processing through plugins
- Case management and visualization
- Plugin health monitoring and restart
- Graceful shutdown of all components

Examples:
  # Start with TUI (default)
  console-ir serve

  # Start without TUI (headless mode)
  console-ir serve --no-tui

  # Start with custom plugins directory
  console-ir serve --plugins-dir /path/to/plugins`,
	RunE: runServe,
}

func init() {
	rootCmd.AddCommand(serveCmd)
	
	serveCmd.Flags().BoolVar(&noTUI, "no-tui", false, "Run in headless mode without TUI")
	serveCmd.Flags().BoolVar(&forceTUI, "force-tui", false, "Force TUI mode even in unsupported terminals")

	// HTTP ingestion flags
	serveCmd.Flags().BoolVar(&httpIngestEnable, "http-ingest-enable", false, "Enable HTTP ingestion server")
	serveCmd.Flags().StringVar(&httpIngestBind, "http-ingest-bind", "127.0.0.1:8081", "Bind address for HTTP ingestion")
	serveCmd.Flags().StringVar(&httpIngestToken, "http-ingest-token", "", "Bearer token required for HTTP ingestion (optional)")
	serveCmd.Flags().IntVar(&httpIngestRPS, "http-ingest-rps", 10, "Max HTTP ingestion requests per second")
	serveCmd.Flags().IntVar(&httpIngestBurst, "http-ingest-burst", 20, "Burst size for HTTP ingestion rate limiter")
	serveCmd.Flags().StringVar(&httpIngestDir, "http-ingest-dir", "data/incoming", "Directory to write ingested payloads")
}

func runServe(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	config := GetConfig()

	// Initialize logger - use file logging for TUI mode to keep terminal clean
	var logger *log.Logger
	willUseTUI := determineTUIMode(cmd, args)

	if willUseTUI {
		// Silent TUI mode: logs go to file, errors still visible on terminal
		logFile := setupFileLogger()
		if logFile != nil {
			// Use multi-writer: file for all logs, stderr for errors only
			logger = log.New(io.MultiWriter(logFile, &errorFilterWriter{os.Stderr}), "[serve] ", log.LstdFlags)
			defer logFile.Close()
		} else {
			// Fallback to stderr if file creation fails
			logger = log.New(os.Stderr, "[serve] ", log.LstdFlags)
		}
	} else {
		// Headless mode: normal stderr logging
		logger = log.New(os.Stderr, "[serve] ", log.LstdFlags)
	}

	logger.Println("Starting Console-IR server")

	// Pre-determine if we'll use TUI so we can configure logging/bus before starting services
	willUseTUI = determineTUIMode(cmd, args)

	// Initialize store
	logger.Println("Initializing database...")
	baseDir := getWorkingDir()
	resolvedDBPath := resolvePathRelativeToBase(baseDir, config.Database.Path)
	logger.Printf("Using database at %s", resolvedDBPath)
	st, err := store.NewStore(resolvedDBPath)
	if err != nil {
		return fmt.Errorf("failed to initialize store: %w", err)
	}
	defer st.Close()

	// Initialize bus (Redis or Null)
	logger.Println("Connecting to event bus...")
	var busLogger *log.Logger = logger
	if willUseTUI {
		// Silence bus logs while TUI is active to avoid bottom-of-screen noise
		busLogger = log.New(io.Discard, "", 0)
	}
	eventBus := bus.NewBus(config.Redis.URL, busLogger)
	defer eventBus.Close()

	// Initialize LLM provider from settings (default: ollama). Fall back to LocalStub at runtime only if build fails.
	settings, _ := llm.LoadSettings("config/llm_settings.json")
	p, err := llm.Build(ctx, settings.Active, logger)
	if err != nil || p == nil {
		logger.Printf("LLM provider build failed: %v; falling back to local stub for runtime resilience", err)
		llmProvider := llm.NewLocalStub()
		_ = llmProvider // keep variable for later usage
		// Use the LocalStub instance as the provider
		p = llm.NewLocalStub()
	}
	llmProvider := p

	// Initialize plugin manager
	logger.Println("Initializing plugin manager...")
	pluginManager := plugins.NewPluginManager(eventBus, st, config.Plugins.Dir, logger)

	// Start plugin manager
	if err := pluginManager.Start(ctx); err != nil {
		return fmt.Errorf("failed to start plugin manager: %w", err)
	}
	defer pluginManager.Stop()

	// Create service coordinator (silence service logs when TUI is active)
	var svcLogger *log.Logger = logger
	if willUseTUI {
		svcLogger = log.New(io.Discard, "", 0)
	}

	// Create a cancellable context for the service coordinator
	// This allows us to properly shut down background services when TUI exits
	svcCtx, svcCancel := context.WithCancel(ctx)
	defer svcCancel() // Ensure cleanup happens

	coordinator := &ServiceCoordinator{
		store:         st,
		bus:           eventBus,
		pluginManager: pluginManager,
		llmProvider:   llmProvider,
		logger:        svcLogger,
		ctx:           svcCtx,
	}

	// Start background services
	logger.Println("Starting background services...")
	if err := coordinator.Start(); err != nil {
		return fmt.Errorf("failed to start services: %w", err)
	}
	defer coordinator.Stop()

	// Optional HTTP ingestion server (runs alongside services and TUI/headless)
	if httpIngestEnable {
		httpLogger := svcLogger // silent when TUI is active to avoid corrupting screen
		opts := ingest.HTTPIngestOptions{
			Bind:   httpIngestBind,
			Token:  httpIngestToken,
			Dir:    httpIngestDir,
			RPS:    httpIngestRPS,
			Burst:  httpIngestBurst,
			Logger: httpLogger,
		}
		httpSrv, err := ingest.NewHTTPIngestServer(opts)
		if err != nil {
			logger.Printf("HTTP ingest init error: %v", err)
		} else {
			if err := httpSrv.Start(svcCtx); err != nil {
				logger.Printf("HTTP ingest start error: %v", err)
			} else {
				logger.Printf("HTTP ingest server enabled on %s writing to %s", httpIngestBind, httpIngestDir)
			}
		}
	}

	// Auto-seeding removed: sample cases/events will no longer be auto-created on startup.

	// Start TUI if not in headless mode
	if !noTUI {
		logger.Println("Starting TUI...")
		logger.Printf("Terminal info: %s", getTerminalInfo())
		
		// Test if TUI can be initialized (unless forced)
		if !forceTUI && !canInitializeTUI() {
			// Check if we can fix this with pseudo-TTY
			if needsPseudoTTY() {
				logger.Println("No TTY available, using script command for pseudo-TTY...")
				return runWithPseudoTTY(cmd, args)
			}
			logger.Println("TUI cannot be initialized in this terminal environment")
			logger.Println("Automatically switching to headless mode...")
			logger.Println("")
			logger.Println("For full TUI experience, use:")
			logger.Println("  1. Native terminal (gnome-terminal, iTerm2, etc.)")
			logger.Println("  2. SSH with proper TERM settings")
			logger.Println("")
			logger.Println("Current alternatives:")
			logger.Println("  - CLI commands: ./bin/console-ir list cases")
			logger.Println("  - Headless mode: ./bin/console-ir serve --no-tui")
			logger.Println("")
			
			// Switch to headless mode
			noTUI = true
		} else {
			// Create a silent logger for background services when TUI is active
			silentLogger := log.New(io.Discard, "", 0)
			coordinator.logger = silentLogger
				
			// Create logs directory and a file-backed logger for UI to prevent terminal corruption
			baseDir := getWorkingDir()
			logDir := filepath.Join(baseDir, "logs")
			if err := os.MkdirAll(logDir, 0755); err != nil {
				logger.Printf("Warning: Could not create logs directory: %v", err)
			}
			logPath := filepath.Join(logDir, "console-ir-ui.log")
			logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
			if err != nil {
				// Fallback to discard if file creation fails
				logger.Printf("Warning: Could not create UI log file at %s: %v", logPath, err)
				logFile = nil
			}
				
			var uiLogger *log.Logger
			if logFile != nil {
				uiLogger = log.New(logFile, "[UI] ", log.LstdFlags)
				// Emit an initial marker to the UI log so it's easy to find and verify.
				uiLogger.Printf("UI logger initialized (path=%s)", logPath)
				_ = logFile.Sync()
				defer logFile.Close()
			} else {
				uiLogger = log.New(io.Discard, "[UI] ", log.LstdFlags)
			}

			// Skip auto-creating any cases; only users can create cases via the TUI.

			// Start background folder ingestion for TUI (watch relative CWD path)
			ingestDir := "data/incoming"
			if err := os.MkdirAll(ingestDir, 0755); err != nil {
				logger.Printf("Warning: Could not create ingest directory %s: %v", ingestDir, err)
			}
			parser := ingest.NewParser()
			fopts := ingest.FolderOptions{
				Dir:         ingestDir,
				Watch:       true,
				Patterns:    []string{"*.jsonl", "*.json"},
				CaseTitle:   "",
				// Route folder-ingestor logs to the UI file logger to avoid corrupting TUI output
				Logger:      uiLogger,
				// Avoid re-ingesting existing JSONL lines on each startup; begin tailing from EOF.
				TailFromEnd: true,
			}
			// Use the real event bus so folder ingestion publishes events for plugins
			fbus := eventBus
			fing := ingest.NewFolderIngestor(parser, st, fbus, fopts)
			go func() {
				if err := fing.Run(ctx); err != nil && ctx.Err() == nil {
					logger.Printf("Folder ingest error: %v", err)
				}
			}()

			ui := ui.NewUI(ctx, st, llmProvider, uiLogger)
			
			// Start TUI directly - tcell can handle terminal compatibility
			if err := ui.Start(ctx); err != nil {
				return fmt.Errorf("TUI error: %w", err)
			}
		}
	}

	// Cancel service context when TUI exits to properly shut down background services
	if !noTUI {
		logger.Println("TUI exited, cancelling background services...")
		svcCancel()
	}

	if noTUI {
		logger.Println("Running in headless mode...")
		// Wait for context cancellation
		<-ctx.Done()
		logger.Println("Received shutdown signal")
	}

	logger.Println("Console-IR server stopped")
	return nil
}

// isTUISupported checks if the current terminal supports TUI
func isTUISupported() bool {
	// --- TEMPORARY FIX ---
	// Always return true to bypass the restrictive terminal check.
	// This allows the TUI library (tcell/tview) to handle compatibility detection.
	return true
	// --- END TEMPORARY FIX ---
	
	// Original compatibility scoring logic (commented out)
	// score := getTerminalCompatibilityScore()
	// return score >= 60 // Require at least 60% compatibility
}

// canInitializeTUI tests if tcell can actually be initialized
func canInitializeTUI() bool {
	screen, err := tcell.NewScreen()
	if err != nil {
		return false
	}
	
	err = screen.Init()
	if err != nil {
		return false
	}
	
	// Clean up immediately
	screen.Fini()
	return true
}

// getTerminalCompatibilityScore returns a compatibility score (0-100)
func getTerminalCompatibilityScore() int {
	score := 0
	term := strings.ToLower(os.Getenv("TERM"))
	termProgram := strings.ToLower(os.Getenv("TERM_PROGRAM"))
	
	// Base score for having a terminal
	if isTerminal() {
		score += 20
	}
	
	// TERM environment variable scoring
	switch {
	case term == "":
		score -= 30 // No TERM set
	case term == "dumb":
		score -= 40 // Explicitly dumb terminal
	case strings.Contains(term, "xterm"):
		score += 40 // xterm family - excellent support
	case strings.Contains(term, "screen"):
		score += 35 // screen/tmux - very good
	case strings.Contains(term, "tmux"):
		score += 35 // tmux - very good
	case strings.Contains(term, "linux"):
		score += 30 // Linux console - good
	case strings.Contains(term, "ansi"):
		score += 25 // ANSI terminal - decent
	case strings.Contains(term, "vt"):
		score += 20 // VT terminal - basic
	case term != "":
		score += 10 // Some TERM set - minimal
	}
	
	// Terminal program scoring
	switch {
	case strings.Contains(termProgram, "iterm"):
		score += 20 // iTerm2 - excellent
	case strings.Contains(termProgram, "terminal"):
		score += 15 // Terminal.app, gnome-terminal, etc.
	case strings.Contains(termProgram, "konsole"):
		score += 15 // KDE Konsole
	case strings.Contains(termProgram, "vscode"):
		score -= 20 // VS Code integrated terminal
	}
	
	// Terminal size check
	if hasTerminalSize() {
		score += 15
	}
	
	// Color support check
	if supportsColors() {
		score += 10
	}
	
	// Ensure score is within bounds
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	
	return score
}

// getTerminalInfo returns detailed terminal information
func getTerminalInfo() string {
	var info []string
	
	term := os.Getenv("TERM")
	if term == "" {
		info = append(info, "TERM=<not set>")
	} else {
		info = append(info, fmt.Sprintf("TERM=%s", term))
	}
	
	termProgram := os.Getenv("TERM_PROGRAM")
	if termProgram != "" {
		info = append(info, fmt.Sprintf("TERM_PROGRAM=%s", termProgram))
	}
	
	if width, height := getTerminalSize(); width > 0 && height > 0 {
		info = append(info, fmt.Sprintf("Size=%dx%d", width, height))
	}
	
	if isTerminal() {
		info = append(info, "TTY=yes")
	} else {
		info = append(info, "TTY=no")
	}
	
	if supportsColors() {
		info = append(info, "Colors=yes")
	} else {
		info = append(info, "Colors=no")
	}
	
	return strings.Join(info, ", ")
}

// getExecutableDir returns the directory of the running executable.
// Falls back to current directory on error.
func getExecutableDir() string {
	exe, err := os.Executable()
	if err != nil {
		return "."
	}
	return filepath.Dir(exe)
}

// getWorkingDir returns the current working directory.
// Falls back to executable directory if os.Getwd fails.
func getWorkingDir() string {
	if wd, err := os.Getwd(); err == nil && wd != "" {
		return wd
	}
	return getExecutableDir()
}

// resolvePathRelativeToBase resolves a possibly relative path against a base directory.
// Absolute paths are returned unchanged.
func resolvePathRelativeToBase(base, p string) string {
	if filepath.IsAbs(p) {
		return p
	}
	// Normalize leading "./" for consistent joining
	p = strings.TrimPrefix(p, "./")
	return filepath.Join(base, p)
}

// isTerminal checks if stdout is a terminal
func isTerminal() bool {
	if fileInfo, err := os.Stdout.Stat(); err == nil {
		return (fileInfo.Mode() & os.ModeCharDevice) != 0
	}
	return false
}

// hasTerminalSize checks if we can get terminal dimensions
func hasTerminalSize() bool {
	width, height := getTerminalSize()
	return width > 0 && height > 0
}

// supportsColors checks if terminal supports colors
func supportsColors() bool {
	term := strings.ToLower(os.Getenv("TERM"))
	
	// Check for color support indicators
	colorTerms := []string{"color", "256", "truecolor", "24bit"}
	for _, colorTerm := range colorTerms {
		if strings.Contains(term, colorTerm) {
			return true
		}
	}
	
	// Check COLORTERM environment variable
	if colorTerm := os.Getenv("COLORTERM"); colorTerm != "" {
		return true
	}
	
	// Known color-supporting terminals
	supportedTerms := []string{"xterm", "screen", "tmux", "linux", "ansi"}
	for _, supported := range supportedTerms {
		if strings.Contains(term, supported) {
			return true
		}
	}
	
	return false
}

// ServiceCoordinator manages background services
type ServiceCoordinator struct {
	store         *store.Store
	bus           bus.Bus
	pluginManager plugins.PluginManager
	llmProvider   llm.LLMProvider
	logger        *log.Logger
	ctx           context.Context
	
	// Service state
	wg      sync.WaitGroup
	running bool
}

// Start starts all background services
func (sc *ServiceCoordinator) Start() error {
	if sc.running {
		return fmt.Errorf("services already running")
	}

	sc.running = true

	// Start enrichment processor
	sc.wg.Add(1)
	go sc.runEnrichmentProcessor()

	// Start plugin health monitor
	sc.wg.Add(1)
	go sc.runHealthMonitor()

	// Start metrics collector
	sc.wg.Add(1)
	go sc.runMetricsCollector()

	sc.logger.Println("Background services started")
	return nil
}

// Stop stops all background services
func (sc *ServiceCoordinator) Stop() {
	if !sc.running {
		return
	}

	sc.logger.Println("Stopping background services...")
	sc.running = false
	
	// Wait for all goroutines to finish
	sc.wg.Wait()
	
	sc.logger.Println("Background services stopped")
}

// runEnrichmentProcessor processes enrichments from Redis streams
func (sc *ServiceCoordinator) runEnrichmentProcessor() {
	defer sc.wg.Done()

	sc.logger.Println("Starting enrichment processor")

	handler := func(ctx context.Context, enrichment bus.EnrichmentMessage) error {
		// Convert to store enrichment
		storeEnrichment := store.Enrichment{
			EventID: enrichment.EventID,
			Source:  enrichment.Source,
			Type:    enrichment.Type,
			Data:    enrichment.Data,
		}

		// Apply enrichment to database
		if err := sc.store.ApplyEnrichment(ctx, enrichment.EventID, storeEnrichment); err != nil {
			sc.logger.Printf("Failed to apply enrichment for event %s: %v", enrichment.EventID, err)
			return err
		}

		sc.logger.Printf("Applied enrichment from %s for event %s", enrichment.PluginName, enrichment.EventID)
		return nil
	}

	// Read from enrichments stream
	for {
		select {
		case <-sc.ctx.Done():
			sc.logger.Println("Enrichment processor stopping")
			return
		default:
			if err := sc.bus.ReadEnrichmentsStream(sc.ctx, "console-ir", "enricher", handler); err != nil {
				if sc.ctx.Err() != nil {
					return // Context cancelled
				}
				sc.logger.Printf("Error reading enrichments stream: %v", err)
				time.Sleep(5 * time.Second) // Wait before retrying
			}
		}
	}
}

// runHealthMonitor monitors plugin health and restarts failed plugins
func (sc *ServiceCoordinator) runHealthMonitor() {
	defer sc.wg.Done()

	sc.logger.Println("Starting health monitor")
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-sc.ctx.Done():
			sc.logger.Println("Health monitor stopping")
			return
		case <-ticker.C:
			sc.performHealthChecks()
		}
	}
}

// runMetricsCollector collects and logs system metrics
func (sc *ServiceCoordinator) runMetricsCollector() {
	defer sc.wg.Done()

	sc.logger.Println("Starting metrics collector")
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-sc.ctx.Done():
			sc.logger.Println("Metrics collector stopping")
			return
		case <-ticker.C:
			sc.collectMetrics()
		}
	}
}

// performHealthChecks checks the health of all components
func (sc *ServiceCoordinator) performHealthChecks() {
	ctx, cancel := context.WithTimeout(sc.ctx, 30*time.Second)
	defer cancel()

	// Check Redis connection
	if err := sc.bus.HealthCheck(ctx); err != nil {
		sc.logger.Printf("Redis health check failed: %v", err)
	}

	// Check plugin health
	results, err := sc.pluginManager.HealthCheck(ctx)
	if err != nil {
		sc.logger.Printf("Plugin health check error: %v", err)
		return
	}

	unhealthyCount := 0
	for name, err := range results {
		if err != nil {
			sc.logger.Printf("Plugin %s is unhealthy: %v", name, err)
			unhealthyCount++
			
			// TODO: Implement plugin restart logic
			// if sc.shouldRestartPlugin(name) {
			//     sc.restartPlugin(name)
			// }
		}
	}

	if unhealthyCount == 0 {
		sc.logger.Printf("All plugins healthy (%d checked)", len(results))
	} else {
		sc.logger.Printf("Health check: %d unhealthy plugins out of %d", unhealthyCount, len(results))
	}
}

// collectMetrics collects and logs system metrics
func (sc *ServiceCoordinator) collectMetrics() {
	ctx, cancel := context.WithTimeout(sc.ctx, 30*time.Second)
	defer cancel()

	// Get Redis stats
	redisStats, err := sc.bus.GetStats(ctx)
	if err != nil {
		sc.logger.Printf("Failed to get Redis stats: %v", err)
	} else {
		sc.logger.Printf("Redis stats: %+v", redisStats)
	}

	// Get plugin stats
	pluginStats := sc.pluginManager.GetStats()
	sc.logger.Printf("Plugin stats: %+v", pluginStats)

	// Get case/event counts from database
	cases, err := sc.store.ListCases(ctx)
	if err != nil {
		sc.logger.Printf("Failed to get case count: %v", err)
	} else {
		totalEvents := 0
		for _, case_ := range cases {
			totalEvents += case_.EventCount
		}
		sc.logger.Printf("Database stats: %d cases, %d total events", len(cases), totalEvents)
	}
}

// createSampleData creates sample data for demonstration (if database is empty)
	// createSampleData removed to prevent automatic creation of sample cases/events.
	// Automatic sample data seeding was intentionally deleted to ensure that when
	// cases/events are removed by the user, they are not recreated on restart.

// getServiceStatus returns the status of all services
func (sc *ServiceCoordinator) getServiceStatus() map[string]interface{} {
	status := map[string]interface{}{
		"running": sc.running,
		"services": map[string]string{
			"enrichment_processor": "running",
			"health_monitor":      "running",
			"metrics_collector":   "running",
		},
	}

	// Add plugin manager stats
	if sc.pluginManager != nil {
		status["plugins"] = sc.pluginManager.GetStats()
	}

	return status
}

// handleGracefulShutdown handles graceful shutdown of services
func (sc *ServiceCoordinator) handleGracefulShutdown() {
	sc.logger.Println("Initiating graceful shutdown...")

	// Stop plugin manager first
	if sc.pluginManager != nil {
		if err := sc.pluginManager.Stop(); err != nil {
			sc.logger.Printf("Error stopping plugin manager: %v", err)
		}
	}

	// Stop other services
	sc.Stop()

	sc.logger.Println("Graceful shutdown completed")
}

// needsPseudoTTY checks if we need to use script command for pseudo-TTY
func needsPseudoTTY() bool {
	// Try to actually open /dev/tty (not just check if it exists)
	if file, err := os.OpenFile("/dev/tty", os.O_RDWR, 0); err == nil {
		file.Close()
		return false
	}
	return true
}

// runWithPseudoTTY re-executes the command using script for pseudo-TTY
func runWithPseudoTTY(cmd *cobra.Command, args []string) error {
	// Get the current executable path
	executable, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}
	
	// Build the command arguments
	cmdArgs := []string{"serve"}
	cmdArgs = append(cmdArgs, args...)
	
	// Add force-tui flag if not already present
	hasForceTUI := false
	for _, arg := range args {
		if arg == "--force-tui" {
			hasForceTUI = true
			break
		}
	}
	if !hasForceTUI {
		cmdArgs = append(cmdArgs, "--force-tui")
	}
	
	// Build the full command string with proper quoting
	quotedExecutable := fmt.Sprintf(`"%s"`, executable)
	quotedArgs := make([]string, len(cmdArgs))
	for i, arg := range cmdArgs {
		quotedArgs[i] = fmt.Sprintf(`"%s"`, arg)
	}
	
	fullCmd := fmt.Sprintf("TERM=%s %s %s",
		os.Getenv("TERM"),
		quotedExecutable,
		strings.Join(quotedArgs, " "))
	
	// Use script command to create pseudo-TTY
	scriptCmd := exec.Command("script", "-qec", fullCmd, "/dev/null")
	scriptCmd.Stdin = os.Stdin
	scriptCmd.Stdout = os.Stdout
	scriptCmd.Stderr = os.Stderr
	
	// Set environment variables
	scriptCmd.Env = os.Environ()
	
	return scriptCmd.Run()
}

// determineTUIMode determines if TUI will be used (extracted for logging setup)
func determineTUIMode(cmd *cobra.Command, args []string) bool {
	if noTUI {
		return false
	}
	if !forceTUI && !canInitializeTUI() {
		// Check if we can fix this with pseudo-TTY
		if needsPseudoTTY() {
			// Will use pseudo-TTY, so TUI mode
			return true
		}
		// Will fall back to headless
		return false
	}
	return true
}

// setupFileLogger creates a log file for TUI mode
func setupFileLogger() *os.File {
	baseDir := getWorkingDir()
	logDir := filepath.Join(baseDir, "logs")
	if err := os.MkdirAll(logDir, 0755); err != nil {
		// If we can't create logs directory, we'll fall back to stderr
		return nil
	}

	logPath := filepath.Join(logDir, "console-ir-serve.log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		// If we can't create the log file, we'll fall back to stderr
		return nil
	}

	return logFile
}

// errorFilterWriter only writes error messages to the underlying writer
type errorFilterWriter struct {
	writer io.Writer
}

func (w *errorFilterWriter) Write(p []byte) (n int, err error) {
	// Only write if the log message contains error indicators
	logMsg := string(p)
	lc := strings.ToLower(logMsg)

	// Suppress expected plugin termination noise on shutdown in TUI mode.
	// These lines can look like:
	//   "External plugin X exited with error: signal: terminated"
	//   "External plugin X exited with error: signal: killed"
	if strings.Contains(lc, "external plugin") && strings.Contains(lc, "exited with error: signal") {
		return len(p), nil
	}

	if strings.Contains(lc, "error") ||
		strings.Contains(lc, "failed") ||
		strings.Contains(lc, "panic") {
		return w.writer.Write(p)
	}
	// Suppress non-error logs in TUI mode
	return len(p), nil
}