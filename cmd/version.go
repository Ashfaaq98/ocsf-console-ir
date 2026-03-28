package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
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

// versionCmd prints detailed version information.
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("console-ir %s\n", buildVersionString(GetVersion(), getCommit(), GetBuildTime()))
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
