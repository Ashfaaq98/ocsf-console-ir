package cmd

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/ocsf"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/store"
	"github.com/spf13/cobra"
)

var seedCmd = &cobra.Command{
	Use:   "seed",
	Short: "Seed sample cases and events into the database",
	Long: `Seed sample cases and associated events into the SQLite database.
This is useful for local testing when the database has empty cases or no events.`,
	RunE: runSeed,
}

func init() {
	rootCmd.AddCommand(seedCmd)
}

func runSeed(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	config := GetConfig()

	logger := log.New(cmd.OutOrStdout(), "[seed] ", log.LstdFlags)
	logger.Println("Seeding sample data...")

	// Initialize store
	st, err := store.NewStore(config.Database.Path)
	if err != nil {
		return fmt.Errorf("failed to initialize store: %w", err)
	}
	defer st.Close()

	// Ensure we have cases (reuse same defaults as serve)
	cases, err := st.ListCases(ctx)
	if err != nil {
		return fmt.Errorf("failed to list cases: %w", err)
	}

	if len(cases) == 0 {
		logger.Println("No cases found, creating sample cases...")
		sampleCases := []store.Case{
			{
				Title:       "Suspicious Network Activity",
				Description: "Multiple failed connection attempts detected from external IP",
				Severity:    "high",
				Status:      "open",
				EventCount:  0,
			},
			{
				Title:       "Malware Detection",
				Description: "Potential malware execution detected on workstation",
				Severity:    "critical",
				Status:      "investigating",
				EventCount:  0,
			},
			{
				Title:       "Authentication Anomaly",
				Description: "Unusual login patterns detected for user account",
				Severity:    "medium",
				Status:      "open",
				EventCount:  0,
			},
		}

		for _, c := range sampleCases {
			if _, err := st.CreateOrUpdateCase(ctx, c); err != nil {
				logger.Printf("Failed to create sample case: %v", err)
			}
		}
		// Reload cases to get IDs
		cases, err = st.ListCases(ctx)
		if err != nil {
			return fmt.Errorf("failed to list cases after creation: %w", err)
		}
	}

	// For each case with zero events, create sample events and assign them
	for _, case_ := range cases {
		evts, err := st.GetEventsByCase(ctx, case_.ID)
		if err != nil {
			logger.Printf("Failed to get events for case %s: %v", case_.ID, err)
			continue
		}
		if len(evts) > 0 {
			logger.Printf("Case %s already has %d events, skipping", case_.ID, len(evts))
			continue
		}

		logger.Printf("Seeding events for case %s (%s)...", case_.ID, case_.Title)
		now := time.Now()
		sampleCount := 5
		for i := 0; i < sampleCount; i++ {
			classUID := 4001 // network
			message := fmt.Sprintf("Sample network connection %d for case: %s", i+1, case_.Title)
			switch i % 3 {
			case 1:
				classUID = 1001 // process
				message = fmt.Sprintf("Sample process execution %d for case: %s", i+1, case_.Title)
			case 2:
				classUID = 3001 // authentication
				message = fmt.Sprintf("Sample authentication event %d for case: %s", i+1, case_.Title)
			}

			sevID := 2 + (i % 3) // low/medium/high
			e := &ocsf.Event{
				Time:        now.Add(-time.Duration(i) * time.Minute),
				ClassUID:    classUID,
				CategoryUID: 1,
				ActivityID:  1,
				TypeUID:     classUID*100 + 1,
				SeverityID:  sevID,
				Message:     message,
				Device: &ocsf.Device{
					Hostname: fmt.Sprintf("seed-host-%02d", i+1),
					IP:       fmt.Sprintf("10.10.0.%d", 50+i),
				},
				SrcEndpoint: &ocsf.Endpoint{
					IP:   fmt.Sprintf("172.16.0.%d", 10+i),
					Port: 20000 + i,
				},
				DstEndpoint: &ocsf.Endpoint{
					IP:   "8.8.4.4",
					Port: 53,
				},
				Process: &ocsf.Process{
					Name:        "seed.exe",
					CommandLine: "seed.exe --demo",
				},
				User: &ocsf.User{
					Name: fmt.Sprintf("demo_user_%02d", i+1),
				},
			}

			eventID, err := st.SaveEvent(ctx, e)
			if err != nil {
				logger.Printf("Failed to save sample event: %v", err)
				continue
			}
			if err := st.AssignEventToCase(ctx, eventID, case_.ID); err != nil {
				logger.Printf("Failed to assign event %s to case %s: %v", eventID, case_.ID, err)
				continue
			}
		}

		// Sync event_count
		if err := st.UpdateCaseEventCount(ctx, case_.ID); err != nil {
			logger.Printf("Failed to update event_count for case %s: %v", case_.ID, err)
		} else {
			logger.Printf("Seeded events and updated count for case %s", case_.ID)
		}
	}

	logger.Println("Seeding completed")
	return nil
}