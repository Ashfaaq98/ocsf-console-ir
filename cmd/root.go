package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfgFile    string
	dbPath     string
	redisURL   string
	logLevel   string
	pluginsDir string
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
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute(ctx context.Context) error {
	return rootCmd.ExecuteContext(ctx)
}

func init() {
	cobra.OnInitialize(initConfig)

	// Global flags
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.console-ir.yaml)")
	rootCmd.PersistentFlags().StringVar(&dbPath, "db", "./data/console-ir.db", "SQLite database path")
	rootCmd.PersistentFlags().StringVar(&logLevel, "log-level", "info", "Log level (debug, info, warn, error)")

	// --redis and --plugins-dir are registered only on the commands that use
	// them (the TUI and ingest); they were previously advertised on every
	// command, including version and list, which touch neither.

	// Bind flags to viper
	viper.BindPFlag("database.path", rootCmd.PersistentFlags().Lookup("db"))
	viper.BindPFlag("log.level", rootCmd.PersistentFlags().Lookup("log-level"))
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := os.UserHomeDir()
		cobra.CheckErr(err)

		// Search config in home directory with name ".console-ir" (without extension).
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

	// Set defaults
	viper.SetDefault("database.path", "./data/console-ir.db")
	viper.SetDefault("redis.url", "")
	viper.SetDefault("log.level", "info")
	viper.SetDefault("plugins.dir", "./plugins")
	viper.SetDefault("plugins.external", []map[string]interface{}{})
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
