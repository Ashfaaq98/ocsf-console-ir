package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	appVersion string
	buildTime  string
)

// SetVersion sets version/build metadata and wires Cobra's --version flag.
func SetVersion(v, bt string) {
	appVersion = v
	buildTime = bt
	// Enable --version flag output via Cobra when Version is non-empty
	rootCmd.Version = v
}

// versionCmd prints detailed version information.
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(cmd *cobra.Command, args []string) {
		v := appVersion
		if v == "" {
			v = "dev"
		}
		fmt.Printf("Console-IR %s\n", v)
		if buildTime != "" {
			fmt.Printf("Build Time: %s\n", buildTime)
		}
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}