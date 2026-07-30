package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/paths"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfgFile    string
	dbPath     string
	redisURL   string
	logLevel   string
	pluginsDir string

	// Runtime directory overrides. Empty means "use the per-user default".
	dataDirFlag   string
	configDirFlag string
	logDirFlag    string
	portableMode  bool
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "console-ir",
	Short: "Terminal-first OCSF-based incident response manager",
	Long: `Console-IR is a terminal-first incident response tool that processes OCSF events,
provides a TUI for case management, and supports extensible plugins for enrichment.

Features:
- OCSF event ingestion and normalization
- Terminal-based user interface for case management
- In-process enrichment plugins (optional Redis Streams for distributed mode)
- SQLite storage with full-text search
- Extensible enrichment pipeline

Run with no arguments to open the terminal UI.`,
	// Running the bare binary opens the TUI. NoArgs matters: without it a typo
	// like "console-ir ingst file.jsonl" would silently launch the UI instead of
	// reporting an unknown command.
	Args: cobra.NoArgs,
	RunE: runServe,
	// A runtime failure is not a usage mistake. Without this, any error
	// returned from RunE prints the full flag list after it — 38 lines that
	// bury the one line explaining what went wrong. Cobra still prints usage
	// for genuine usage errors (unknown flags, bad arguments), which it
	// detects before RunE runs.
	SilenceUsage: true,
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute(ctx context.Context) error {
	// The shared log file outlives every command, so it is closed here rather
	// than by the subsystems that write to it.
	defer closeRuntimeLog()
	return rootCmd.ExecuteContext(ctx)
}

func init() {
	cobra.OnInitialize(initConfig)

	// Global flags
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is <config dir>/console-ir.yaml)")
	rootCmd.PersistentFlags().StringVar(&dbPath, "db", "", "SQLite database path (default is <data dir>/"+paths.DBName+")")
	rootCmd.PersistentFlags().StringVar(&logLevel, "log-level", "info", "Log level (debug, info, warn, error)")

	// Runtime locations. Defaults follow the XDG base directory spec, with
	// platform-native fallbacks; run `console-ir version` to see the resolved
	// values.
	rootCmd.PersistentFlags().StringVar(&dataDirFlag, "data-dir", "", "Directory for the database (default is $XDG_DATA_HOME/console-ir)")
	rootCmd.PersistentFlags().StringVar(&configDirFlag, "config-dir", "", "Directory for configuration (default is $XDG_CONFIG_HOME/console-ir)")
	rootCmd.PersistentFlags().StringVar(&logDirFlag, "log-dir", "", "Directory for logs (default is $XDG_STATE_HOME/console-ir)")
	rootCmd.PersistentFlags().BoolVar(&portableMode, "portable", false, "Keep data, config and logs beside the working directory (pre-v0.2.0 behaviour)")

	// --redis and --plugins-dir are registered only on the commands that use
	// them (the TUI and ingest); they were previously advertised on every
	// command, including version and list, which touch neither.

	// Bind flags to viper
	viper.BindPFlag("database.path", rootCmd.PersistentFlags().Lookup("db"))
	viper.BindPFlag("log.level", rootCmd.PersistentFlags().Lookup("log-level"))
}

// configName is the config file looked for inside the per-user config
// directory. The legacy dotfile name is still honoured from $HOME.
const configName = "console-ir.yaml"

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// initConfig resolves the runtime directories, then reads the config file and
// environment variables. Cobra runs it after flag parsing and before any
// command body, so nothing opens a database or a log before paths are settled.
func initConfig() {
	dirs := paths.Resolve(paths.Options{
		Data:     dataDirFlag,
		Config:   configDirFlag,
		State:    logDirFlag,
		Portable: portableMode,
	})
	cobra.CheckErr(dirs.MkdirAll())
	paths.Set(dirs)
	migrateLegacyLayout(dirs)

	switch {
	case cfgFile != "":
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	case fileExists(dirs.ConfigFile(configName)):
		// The per-user config directory is preferred once it holds a file.
		viper.SetConfigFile(dirs.ConfigFile(configName))
	default:
		// Fall back to the legacy search so an existing ~/.console-ir.yaml or a
		// project-local one keeps working.
		home, err := os.UserHomeDir()
		cobra.CheckErr(err)
		viper.AddConfigPath(home)
		viper.AddConfigPath(".")
		viper.SetConfigType("yaml")
		viper.SetConfigName(".console-ir")
	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	}

	// Set defaults. database.path is resolved rather than constant because it
	// now depends on --data-dir/--portable; viper ranks SetDefault above a
	// flag's own default, so an unset --db lands here.
	viper.SetDefault("database.path", dirs.DB())
	viper.SetDefault("redis.url", "")
	viper.SetDefault("log.level", "info")
	viper.SetDefault("plugins.dir", "./plugins")
	viper.SetDefault("plugins.external", []map[string]interface{}{})
}

// migrateLegacyLayout moves a pre-v0.2.0 working-directory database and LLM
// settings into the resolved directories, announcing every move. Switching
// paths silently would be indistinguishable from having lost every case.
//
// It is skipped in portable mode (which is the legacy layout) and when --db was
// passed explicitly, since the caller has already said where the database is.
func migrateLegacyLayout(dirs paths.Dirs) {
	if portableMode || rootCmd.PersistentFlags().Changed("db") {
		return
	}
	moved, err := paths.MigrateLegacy(dirs)
	for _, m := range moved {
		fmt.Fprintf(os.Stderr, "Moved %s -> %s\n", m.From, m.To)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not move legacy files (they were left in place): %v\n", err)
	}
}

// GetConfig returns the current configuration values
func GetConfig() Config {
	var external []map[string]interface{}
	if raw := viper.Get("plugins.external"); raw != nil {
		switch v := raw.(type) {
		case []map[string]interface{}:
			external = v
		case []interface{}:
			for _, item := range v {
				if m, ok := item.(map[string]interface{}); ok {
					external = append(external, m)
				}
			}
		}
	}

	// redisURL and pluginsDir are bound to per-command flags rather than to
	// viper, so an explicitly passed flag wins and config/defaults fill the rest.
	redis := redisURL
	if redis == "" {
		redis = viper.GetString("redis.url")
	}
	plugDir := pluginsDir
	if plugDir == "" {
		plugDir = viper.GetString("plugins.dir")
	}

	return Config{
		Database: DatabaseConfig{
			Path: viper.GetString("database.path"),
		},
		Redis: RedisConfig{
			URL: redis,
		},
		Log: LogConfig{
			Level: viper.GetString("log.level"),
		},
		Plugins: PluginsConfig{
			Dir:      plugDir,
			External: external,
		},
	}
}

// Config represents the application configuration
type Config struct {
	Database DatabaseConfig `mapstructure:"database"`
	Redis    RedisConfig    `mapstructure:"redis"`
	Log      LogConfig      `mapstructure:"log"`
	Plugins  PluginsConfig  `mapstructure:"plugins"`
}

type DatabaseConfig struct {
	Path string `mapstructure:"path"`
}

type RedisConfig struct {
	URL string `mapstructure:"url"`
}

type LogConfig struct {
	Level string `mapstructure:"level"`
}

type PluginsConfig struct {
	Dir      string                   `mapstructure:"dir"`
	External []map[string]interface{} `mapstructure:"external"`
}
