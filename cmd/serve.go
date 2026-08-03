package cmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/bus"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/ingest"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/llm"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/logging"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/paths"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/plugins"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/store"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/ui"
	"github.com/gdamore/tcell/v2"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
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

	// ingestDir is the drop folder watched while the TUI runs.
	ingestDir string
)

// defaultIngestDir is owned by the ingest package, so the folder watcher, the
// HTTP receiver and this flag cannot disagree about where files land.
const defaultIngestDir = ingest.DefaultDir

// serveCmd is the pre-v0.2 name for launching the TUI, kept as a hidden alias.
// Running the bare binary is now the documented way in — "serve" implied a
// daemon, which this is not.
var serveCmd = &cobra.Command{
	Use:    "serve",
	Hidden: true,
	Short:  "Start the terminal UI and enrichment pipeline (alias for running console-ir with no arguments)",
	Long: `Start the Console-IR server which includes:

1. Terminal User Interface (TUI) for case management
2. In-process enrichment (GeoIP, WHOIS) with no external services
3. Folder ingestion: OCSF JSONL/JSON dropped into ./incoming/
4. Optional distributed mode via Redis (only when --redis is set)

The serve command runs until interrupted (Ctrl+C).

Note: headless mode (--no-tui) is experimental. Folder ingestion and
enrichment currently run only with the TUI active.

Examples:
  # Start with TUI (default)
  console-ir serve

  # Explore a sample incident in a throwaway database
  console-ir demo

  # Start without TUI (experimental headless mode)
  console-ir serve --no-tui`,
	// The same guard the root command carries, and for the same reason: without
	// it any stray word launches the TUI instead of reporting an unknown
	// command. `serve live-events` was a real subcommand until recently, so it
	// has to say it is gone rather than silently open the interface.
	Args: cobra.NoArgs,
	RunE: runServe,
}

func init() {
	rootCmd.AddCommand(serveCmd)

	// Every entry point that ends up in runServe takes the same flags, bound to
	// the same variables, so they all behave identically.
	addTUIFlags(rootCmd.Flags())
	addTUIFlags(serveCmd.Flags())
	addTUIFlags(demoCmd.Flags())
}

// addTUIFlags registers the flags runServe reads. Registering them per command
// rather than persistently keeps them off `version` and `list`, which have no
// TUI, no plugins and no bus.
func addTUIFlags(fs *pflag.FlagSet) {
	fs.BoolVar(&noTUI, "no-tui", false, "Run in headless mode without TUI")
	fs.BoolVar(&forceTUI, "force-tui", false, "Force TUI mode even in unsupported terminals")
	fs.StringVar(&ingestDir, "ingest-dir", defaultIngestDir, "Directory watched for dropped OCSF files")

	fs.BoolVar(&httpIngestEnable, "http-ingest-enable", false, "Enable HTTP ingestion server")
	fs.StringVar(&httpIngestBind, "http-ingest-bind", "127.0.0.1:8081", "Bind address for HTTP ingestion")
	fs.StringVar(&httpIngestToken, "http-ingest-token", os.Getenv("INGEST_TOKEN"), "Bearer token required for HTTP ingestion (env: INGEST_TOKEN)")
	fs.IntVar(&httpIngestRPS, "http-ingest-rps", 10, "Max HTTP ingestion requests per second")
	fs.IntVar(&httpIngestBurst, "http-ingest-burst", 20, "Burst size for HTTP ingestion rate limiter")
	fs.StringVar(&httpIngestDir, "http-ingest-dir", "", "Directory HTTP ingestion writes to (defaults to --ingest-dir)")

	// Only the TUI path runs enrichment plugins or the optional bus.
	fs.StringVar(&redisURL, "redis", "", "Redis URL for distributed mode; empty (default) runs standalone")
	fs.StringVar(&pluginsDir, "plugins-dir", "./plugins", "Directory containing plugins")
}

func runServe(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	config := GetConfig()

	// Initialize logger - use file logging for TUI mode to keep terminal clean
	var logger *logging.Logger
	willUseTUI := determineTUIMode(cmd, args)

	if willUseTUI {
		// TUI mode: everything to the shared file, errors also on the terminal.
		logger = runtimeLoggerConsole("serve", &errorFilterWriter{os.Stderr})
	} else {
		// Headless mode: the file plus plain stderr.
		logger = runtimeLoggerConsole("serve", os.Stderr)
	}

	// The HTTP receiver writes each POST as a file into the drop folder; the
	// folder watcher is what actually ingests those files, and it only starts
	// alongside the TUI. Headless, the receiver would answer 202 Accepted and
	// leave the events on disk unread — a pipeline pointed at it would look
	// healthy while losing everything. Refuse the combination rather than
	// accept data we will not store.
	if httpIngestEnable && !willUseTUI {
		return fmt.Errorf("HTTP ingestion is not supported without the TUI: " +
			"POSTed events would be accepted and never ingested. " +
			"Run without --no-tui, or use `console-ir ingest <dir> --watch`, which is fully headless")
	}

	logger.Println("Starting Console-IR server")

	// Pre-determine if we'll use TUI so we can configure logging/bus before starting services
	willUseTUI = determineTUIMode(cmd, args)

	baseDir := getWorkingDir()
	resolvedDBPath := resolvePathRelativeToBase(baseDir, config.Database.Path)

	// Entry routing: a missing database means a first run, which gets the
	// Welcome Screen. There are exactly two destinations — no database goes to
	// Welcome, a database goes to the main UI — and no branch on whether that
	// database holds any findings, cases or events. An existing but empty
	// database opens the app, which renders its own empty states.
	//
	// This runs before store.NewStore below, which would otherwise create the
	// file and make the check answer yes on every run.
	if willUseTUI && !databaseExists(resolvedDBPath) {
		logger.Info("no database at %s; showing the welcome screen", resolvedDBPath)
		res, err := runWelcome(cmd, resolvedDBPath)
		if err != nil {
			return err
		}
		if res.Action == ui.WelcomeQuit {
			logger.Info("welcome screen quit without creating a database")
			return nil
		}
		if res.Action == ui.WelcomeWatch {
			// So the folder watcher started below is the one that was asked for.
			ingestDir = res.Path
		}
	}

	// Initialize store
	logger.Println("Initializing database...")
	logger.Printf("Using database at %s", resolvedDBPath)
	st, err := store.NewStore(resolvedDBPath)
	if err != nil {
		return fmt.Errorf("failed to initialize store: %w", err)
	}
	defer st.Close()

	// Initialize bus (Redis or Null)
	logger.Println("Connecting to event bus...")
	// The bus logs to the file under its own tag. It used to be discarded
	// entirely while the TUI ran, so nothing it reported was ever recoverable.
	busLogger := runtimeLogger("bus")
	if !willUseTUI {
		busLogger = runtimeLoggerConsole("bus", os.Stderr)
	}
	eventBus := bus.NewBus(config.Redis.URL, busLogger)
	defer eventBus.Close()

	// Initialize LLM provider from settings (default: ollama). Fall back to LocalStub at runtime only if build fails.
	settings, _ := llm.LoadSettings(paths.Current().ConfigFile(paths.LLMSettingsName))
	p, err := llm.Build(ctx, settings.Active, logger)
	if err != nil || p == nil {
		logger.Printf("LLM provider build failed: %v; falling back to local stub for runtime resilience", err)
		llmProvider := llm.NewLocalStub()
		_ = llmProvider // keep variable for later usage
		// Use the LocalStub instance as the provider
		p = llm.NewLocalStub()
	}
	llmProvider := p

	// Initialize plugin manager. Plugins share the bus's TUI-silent logger so
	// their runtime logs (e.g. per-lookup failures during enrichment) never
	// corrupt the TUI screen; in headless mode this is the normal logger.
	logger.Println("Initializing plugin manager...")
	pluginLogger := runtimeLogger("plugins")
	pluginManager := plugins.NewPluginManager(eventBus, st, config.Plugins.Dir, pluginLogger)

	// Register embedded (in-process) core enrichments. These run inside the
	// binary via the plugin manager's enrichment queue, with no Redis broker
	// or subprocess required. The set comes from coreEnrichers so the
	// queue-driven and one-shot ingest paths enrich with the same plugins.
	registerCoreEnrichers(pluginManager, pluginLogger)

	// Start plugin manager
	if err := pluginManager.Start(ctx); err != nil {
		return fmt.Errorf("failed to start plugin manager: %w", err)
	}
	defer pluginManager.Stop()

	// Create service coordinator (silence service logs when TUI is active)
	svcLogger := runtimeLogger("services")
	if !willUseTUI {
		svcLogger = runtimeLoggerConsole("services", os.Stderr)
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
		if strings.TrimSpace(httpIngestDir) == "" {
			httpIngestDir = resolvePathRelativeToBase(baseDir, ingestDir)
		}
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
			// Background services keep logging to the file while the TUI runs;
			// only the terminal is kept clean.
			coordinator.logger = runtimeLogger("services")

			// A file-backed logger for the UI, to prevent terminal corruption.
			uiLogger := runtimeLogger("ui")
			// Emit an initial marker so the log is easy to find and verify.
			uiLogger.Printf("UI logger initialized (path=%s)", runtimeLogPath())

			// Skip auto-creating any cases; only users can create cases via the TUI.

			// Start background folder ingestion for the TUI.
			ingestDir := resolvePathRelativeToBase(baseDir, ingestDir)
			if err := os.MkdirAll(ingestDir, 0755); err != nil {
				logger.Printf("Warning: Could not create ingest directory %s: %v", ingestDir, err)
			}
			parser := ingest.NewParser()
			fopts := ingest.FolderOptions{
				Dir:       ingestDir,
				Watch:     true,
				Patterns:  []string{"*.jsonl", "*.json"},
				CaseTitle: "",
				// Route folder-ingestor logs to the UI file logger to avoid corrupting TUI output
				Logger: uiLogger,
				// Ingest files already present in the drop folder on startup, then
				// tail. Persisted offsets prevent re-ingesting on restart, so we do
				// not skip to EOF (which silently ignored staged files).
				TailFromEnd: false,
				// Drive embedded core enrichments in-process for each ingested event.
				Enricher: pluginManager,
			}
			// Use the real event bus so folder ingestion publishes events for plugins
			fbus := eventBus
			fing := ingest.NewFolderIngestor(parser, st, fbus, fopts)
			go func() {
				if err := fing.Run(ctx); err != nil && ctx.Err() == nil {
					logger.Printf("Folder ingest error: %v", err)
				}
			}()

			tui := ui.NewUI(ctx, st, llmProvider, uiLogger, GetVersion())
			// So empty-state hints name the folder that is genuinely watched,
			// which --ingest-dir can move.
			tui.SetIngestDir(ingestDir)

			// The evidence pulse reports on two subsystems the store knows
			// nothing about. Both are read through a function so the ui package
			// depends on a shape rather than on ingest and plugins.
			tui.SetWatcherStatus(func() ui.WatcherStatus {
				s := fing.Status()
				return ui.WatcherStatus{
					Dir:      s.Dir,
					Active:   s.Watching,
					Errors:   s.Errors,
					LastErr:  s.LastErr,
					Ingested: s.Ingested,
				}
			})
			tui.SetEnrichmentStatus(func() ui.EnrichmentStatus {
				q := pluginManager.EnrichmentQueue()
				return ui.EnrichmentStatus{
					Pending: q.Pending,
					Failed:  q.Failed,
					Dropped: q.Dropped,
				}
			})

			// Start TUI directly - tcell can handle terminal compatibility
			if err := tui.Start(ctx); err != nil {
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
	logger        *logging.Logger
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

	// VULN-4: Avoid shell command string interpolation to prevent injection via
	// TERM env var or executable path. Use exec.Command with separate arguments
	// and pass TERM safely through the environment.
	innerCmd := exec.Command(executable, cmdArgs...)
	innerCmd.Stdin = os.Stdin
	innerCmd.Stdout = os.Stdout
	innerCmd.Stderr = os.Stderr

	// Inherit environment and ensure TERM is set
	innerCmd.Env = os.Environ()

	return innerCmd.Run()
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
