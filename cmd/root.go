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
- Redis Streams-based plugin architecture
- SQLite storage with full-text search
- Extensible enrichment pipeline`,
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
	rootCmd.PersistentFlags().StringVar(&redisURL, "redis", "redis://localhost:6379", "Redis connection URL")
	rootCmd.PersistentFlags().StringVar(&logLevel, "log-level", "info", "Log level (debug, info, warn, error)")
	rootCmd.PersistentFlags().StringVar(&pluginsDir, "plugins-dir", "./plugins", "Directory containing plugins")

	// Bind flags to viper
	viper.BindPFlag("database.path", rootCmd.PersistentFlags().Lookup("db"))
	viper.BindPFlag("redis.url", rootCmd.PersistentFlags().Lookup("redis"))
	viper.BindPFlag("log.level", rootCmd.PersistentFlags().Lookup("log-level"))
	viper.BindPFlag("plugins.dir", rootCmd.PersistentFlags().Lookup("plugins-dir"))
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
	viper.SetDefault("redis.url", "redis://localhost:6379")
	viper.SetDefault("log.level", "info")
	viper.SetDefault("plugins.dir", "./plugins")
	viper.SetDefault("plugins.external", []map[string]interface{}{})
}

// GetConfig returns the current configuration values
func GetConfig() Config {
	return Config{
		Database: DatabaseConfig{
			Path: viper.GetString("database.path"),
		},
		Redis: RedisConfig{
			URL: viper.GetString("redis.url"),
		},
		Log: LogConfig{
			Level: viper.GetString("log.level"),
		},
		Plugins: PluginsConfig{
			Dir:      viper.GetString("plugins.dir"),
			External: viper.Get("plugins.external").([]map[string]interface{}),
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