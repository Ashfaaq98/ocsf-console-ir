package cmd

import (
	"fmt"
	"os"
	"time"

	ir "github.com/Ashfaaq98/ocsf-console-ir/internal/report"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/store"
	"github.com/spf13/cobra"
)

var reportOut string

var reportCmd = &cobra.Command{
	Use:   "report [case]",
	Args:  cobra.MaximumNArgs(1),
	Short: "Write a case up as Markdown",
	Long: `Write a case up as Markdown: what happened, which detections fired, the
evidence behind them, the indicators, and the decisions recorded against it.

Output goes to stdout, so it pipes and redirects like any other command. Run it
with no case to see what there is to report on.

A case is named by its id, by enough of the id to be unique, or by any part of
its title.

Examples:
  # What can be reported on
  console-ir report

  # To the terminal
  console-ir report "account compromise"

  # To a file
  console-ir report case_ccd9 --out incident.md

  # Straight into something else
  console-ir report case_ccd9 | pandoc -o incident.pdf`,
	RunE: runReport,
}

func init() {
	rootCmd.AddCommand(reportCmd)
	reportCmd.Flags().StringVar(&reportOut, "out", "",
		"Write to this file instead of standard output")
}

func runReport(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	config := GetConfig()

	st, err := store.NewStore(config.Database.Path)
	if err != nil {
		return fmt.Errorf("failed to open the database: %w", err)
	}
	defer st.Close()

	cases, err := st.ListCases(ctx)
	if err != nil {
		return fmt.Errorf("failed to read cases: %w", err)
	}
	if len(cases) == 0 {
		return fmt.Errorf("there are no cases to report on")
	}

	// No argument lists what there is, rather than failing with usage. Someone
	// who does not know a case id is exactly who typed this.
	if len(args) == 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "Cases to report on:")
		for _, c := range cases {
			fmt.Fprintf(cmd.OutOrStdout(), "  %-40s  %s\n", c.ID, c.Title)
		}
		fmt.Fprintln(cmd.OutOrStdout(), "\nconsole-ir report <case>")
		return nil
	}

	target, err := ir.ResolveCase(cases, args[0])
	if err != nil {
		return err
	}

	built, err := ir.BuildCase(ctx, st, target.ID, GetVersion(), time.Now())
	if err != nil {
		return err
	}
	markdown := built.Markdown()

	if reportOut == "" {
		_, err := fmt.Fprint(cmd.OutOrStdout(), markdown)
		return err
	}

	if err := os.WriteFile(reportOut, []byte(markdown), 0o644); err != nil {
		return fmt.Errorf("failed to write %s: %w", reportOut, err)
	}
	// To stderr, so a redirected stdout holds the report and nothing else.
	fmt.Fprintf(os.Stderr, "Report written to %s\n", reportOut)
	return nil
}
