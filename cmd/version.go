package cmd

import (
	"fmt"
	"runtime"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/buildinfo"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/ocsf"
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
	rootCmd.Version = buildinfo.Display(v)
	rootCmd.SetVersionTemplate("console-ir {{.Version}}\n")
}

// GetVersion returns the raw build version. Callers that display it should pass
// it through buildinfo.Display first.
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

// versionCmd prints what you are running, how it was built, and where it keeps
// its files.
//
// The paths are here because "where is my database?" is otherwise only
// answerable by reading the source — and since the defaults are per-user rather
// than per-directory, being able to confirm them from any working directory is
// how you check the two agree.
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information and resolved runtime paths",
	Run: func(cmd *cobra.Command, args []string) {
		dirs := paths.Current()

		// The headline matches the TUI header exactly — two surfaces answering
		// "what am I running" differently is worse than either answer.
		fmt.Printf("console-ir %s\n\n", buildinfo.Display(GetVersion()))

		commit := getCommit()
		if buildinfo.IsDirty(GetVersion()) {
			// Worth saying plainly: this binary does not correspond to any commit.
			commit += " (uncommitted changes)"
		}

		for _, row := range [][2]string{
			{"commit", commit},
			{"built", buildinfo.BuildTime(GetBuildTime())},
			{"go", runtime.Version()},
			{"OCSF", ocsf.SchemaVersion()},
			{"", ""},
			{"database", viper.GetString("database.path")},
			{"config", dirs.Config},
			{"logs", dirs.LogFile(logName)},
		} {
			if row[0] == "" {
				fmt.Println()
				continue
			}
			fmt.Printf("  %-9s %s\n", row[0], row[1])
		}
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
