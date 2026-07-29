package cmd

import (
	"fmt"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/paths"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	appVersion string
	appCommit  string
	buildTime  string
)

// SetVersion sets version/build metadata and wires Cobra's --version flag.
func SetVersion(v, c, bt string) {
	appVersion = v
	appCommit = c
	buildTime = bt
	rootCmd.Version = buildVersionString(v, c, bt)
	rootCmd.SetVersionTemplate("console-ir {{.Version}}\n")
}

// GetVersion returns the current version string
func GetVersion() string {
	if appVersion == "" {
		return "dev"
	}
	return appVersion
}

// GetBuildTime returns the build timestamp
func GetBuildTime() string {
	if buildTime == "" {
		return "unknown"
	}
	return buildTime
}

func getCommit() string {
	if appCommit == "" {
		return "none"
	}
	return appCommit
}

func buildVersionString(v, c, bt string) string {
	return fmt.Sprintf("%s (%s) built %s", defaultValue(v, "dev"), defaultValue(c, "none"), defaultValue(bt, "unknown"))
}

func defaultValue(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

// versionCmd prints version information and the resolved runtime paths.
// The paths are here because "where is my database?" is otherwise only
// answerable by reading the source — and since the defaults are per-user rather
// than per-directory, being able to confirm them from any working directory is
// how you check the two agree.
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information and resolved runtime paths",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("console-ir %s\n", buildVersionString(GetVersion(), getCommit(), GetBuildTime()))
		dirs := paths.Current()
		fmt.Printf("\ndatabase  %s\n", viper.GetString("database.path"))
		fmt.Printf("config    %s\n", dirs.Config)
		fmt.Printf("logs      %s\n", dirs.LogFile(logName))
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
