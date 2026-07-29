package cmd

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/store"
	"github.com/spf13/cobra"
)

// listCmd represents the list command
var listCmd = &cobra.Command{
	Use:   "list [findings|cases|events]",
	Short: "List findings, cases and events",
	Long: `List findings, cases and events from the database in plain text.

Works in any terminal, including ones the TUI cannot run in, and is the path to
use over SSH without a TTY or from a script.

Examples:
  # Findings awaiting triage (the default)
  console-ir list

  # Everything, including triaged findings
  console-ir list findings --all

  # Cases
  console-ir list cases

  # Events for a specific case
  console-ir list events --case-id case_123`,
	RunE: runList,
}

var (
	listType string
	listAll  bool
	caseID   string
	limit    int
	sinceStr string
	untilStr string
)

func init() {
	rootCmd.AddCommand(listCmd)

	listCmd.Flags().StringVar(&listType, "type", "findings", "What to list: findings, cases, events")
	listCmd.Flags().BoolVar(&listAll, "all", false, "Include findings that have already been triaged")
	listCmd.Flags().StringVar(&caseID, "case-id", "", "Case ID for listing events")
	listCmd.Flags().IntVar(&limit, "limit", 20, "Maximum number of items to show")
	listCmd.Flags().StringVar(&sinceStr, "since", "", "Filter events since RFC3339 time, e.g. 2025-08-26T20:00:00Z")
	listCmd.Flags().StringVar(&untilStr, "until", "", "Filter events until RFC3339 time, e.g. 2025-08-26T21:00:00Z")
}

func runList(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	config := GetConfig()

	// Initialize store
	store, err := store.NewStore(config.Database.Path)
	if err != nil {
		return fmt.Errorf("failed to initialize store: %w", err)
	}
	defer store.Close()

	// Determine what to list from args or flags
	var targetType string
	if len(args) > 0 {
		targetType = strings.ToLower(args[0])
	} else {
		targetType = strings.ToLower(listType)
	}

	switch targetType {
	case "findings", "finding":
		return listFindings(ctx, store, limit, listAll)
	case "cases", "case":
		return listCases(ctx, store)
	case "events":
		// Parse optional time filters
		var since, until time.Time
		var err error
		if sinceStr != "" {
			since, err = time.Parse(time.RFC3339, sinceStr)
			if err != nil {
				return fmt.Errorf("invalid --since value: %w", err)
			}
		}
		if untilStr != "" {
			until, err = time.Parse(time.RFC3339, untilStr)
			if err != nil {
				return fmt.Errorf("invalid --until value: %w", err)
			}
		}
		return listEvents(ctx, store, caseID, limit, since, until)
	default:
		return fmt.Errorf("unknown list type: %s (use 'cases' or 'events')", targetType)
	}
}

// listFindings prints the triage queue. Findings are the default listing
// because they are what an analyst works; events are the corroboration beneath.
func listFindings(ctx context.Context, st *store.Store, limit int, all bool) error {
	filter := store.FindingFilter{Limit: limit, OpenOnly: !all}

	findings, err := st.GetFindings(ctx, filter)
	if err != nil {
		return fmt.Errorf("failed to list findings: %w", err)
	}
	total, err := st.CountFindings(ctx, filter)
	if err != nil {
		total = len(findings)
	}

	scope := "open"
	if all {
		scope = "all"
	}
	fmt.Printf("Findings (%s): %d\n\n", scope, total)

	if len(findings) == 0 {
		if !all {
			fmt.Println("No open findings. Use --all to include triaged ones.")
		} else {
			fmt.Println("No findings. Findings come from OCSF Findings classes (class_uid 2001-2008)")
			fmt.Println("or events flagged is_alert; plain telemetry produces events instead.")
		}
		return nil
	}

	fmt.Printf("%-8s  %-12s  %-15s  %5s  %s\n", "SEVERITY", "STATUS", "VERDICT", "RISK", "TITLE")
	for _, f := range findings {
		verdict := f.VerdictName()
		if verdict == "" {
			verdict = "-"
		}
		risk := "-"
		if f.RiskScore > 0 {
			risk = fmt.Sprintf("%d", f.RiskScore)
		}
		title := f.Title
		if len(title) > 60 {
			title = title[:57] + "..."
		}
		fmt.Printf("%-8s  %-12s  %-15s  %5s  %s\n", f.Severity, f.StatusName(), verdict, risk, title)
	}
	return nil
}

func listCases(ctx context.Context, store *store.Store) error {
	cases, err := store.ListCases(ctx)
	if err != nil {
		return fmt.Errorf("failed to list cases: %w", err)
	}

	if len(cases) == 0 {
		fmt.Println("No cases found.")
		return nil
	}

	fmt.Printf("Found %d cases:\n\n", len(cases))

	for i, case_ := range cases {
		fmt.Printf("%d. [%s] %s\n", i+1, strings.ToUpper(case_.Severity), case_.Title)
		fmt.Printf("   ID: %s\n", case_.ID)
		fmt.Printf("   Status: %s\n", case_.Status)
		fmt.Printf("   Events: %d\n", case_.EventCount)
		fmt.Printf("   Created: %s\n", case_.CreatedAt.Format("2006-01-02 15:04:05"))
		if case_.Description != "" {
			fmt.Printf("   Description: %s\n", case_.Description)
		}
		fmt.Println()
	}

	return nil
}

func listEvents(ctx context.Context, storeInstance *store.Store, caseID string, limit int, since, until time.Time) error {
	var events []store.Event
	var err error

	if !since.IsZero() || !until.IsZero() {
		events, err = storeInstance.GetEventsByTimeRange(ctx, caseID, since, until, limit)
		if err != nil {
			return fmt.Errorf("failed to get events by time range: %w", err)
		}
		if caseID != "" {
			fmt.Printf("Events for case %s", caseID)
		} else {
			fmt.Printf("Events (all cases)")
		}
		if !since.IsZero() || !until.IsZero() {
			fmt.Printf(" filtered by time")
		}
		fmt.Printf(":\n\n")
	} else if caseID != "" {
		events, err = storeInstance.GetEventsByCase(ctx, caseID)
		if err != nil {
			return fmt.Errorf("failed to get events for case %s: %w", caseID, err)
		}
		fmt.Printf("Events for case %s:\n\n", caseID)
	} else {
		// Get all events directly from the database
		events, err = storeInstance.GetAllEvents(ctx, limit)
		if err != nil {
			return fmt.Errorf("failed to get events: %w", err)
		}
		fmt.Println("Recent events:")
	}

	if len(events) == 0 {
		fmt.Println("No events found.")
		return nil
	}

	fmt.Printf("Showing %d events:\n\n", len(events))

	for i, event := range events {
		fmt.Printf("%d. [%s] %s\n", i+1, strings.ToUpper(event.Severity), event.EventType)
		fmt.Printf("   ID: %s\n", event.ID)
		fmt.Printf("   Time: %s\n", event.Timestamp.Format("2006-01-02 15:04:05"))
		if event.Host != "" {
			fmt.Printf("   Host: %s\n", event.Host)
		}
		if event.SrcIP != "" {
			fmt.Printf("   Source: %s", event.SrcIP)
			if event.SrcPort > 0 {
				fmt.Printf(":%d", event.SrcPort)
			}
			fmt.Println()
		}
		if event.DstIP != "" {
			fmt.Printf("   Destination: %s", event.DstIP)
			if event.DstPort > 0 {
				fmt.Printf(":%d", event.DstPort)
			}
			fmt.Println()
		}
		if event.ProcessName != "" {
			fmt.Printf("   Process: %s\n", event.ProcessName)
		}
		if event.UserName != "" {
			fmt.Printf("   User: %s\n", event.UserName)
		}
		fmt.Printf("   Message: %s\n", event.Message)
		fmt.Println()
	}

	return nil
}
