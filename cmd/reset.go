package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-redis/redis/v8"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	confirmReset bool
	resetRedis   bool
	resetDB      bool
)

// resetCmd represents the reset command
var resetCmd = &cobra.Command{
	Use:   "reset",
	Short: "Reset Redis data and/or database",
	Long: `Reset command clears Redis data and/or SQLite database.

By default, both Redis and database are reset. You can selectively reset
only Redis or only the database using the --redis-only or --db-only flags.

WARNING: This operation is irreversible and will permanently delete all data.

Examples:
  # Reset both Redis and database (requires confirmation)
  console-ir reset

  # Reset with automatic confirmation
  console-ir reset --yes

  # Reset only Redis data
  console-ir reset --redis-only

  # Reset only database
  console-ir reset --db-only`,
	RunE: runReset,
}

func init() {
	rootCmd.AddCommand(resetCmd)

	resetCmd.Flags().BoolVarP(&confirmReset, "yes", "y", false, "Automatically confirm reset operation")
	resetCmd.Flags().BoolVar(&resetRedis, "redis-only", false, "Reset only Redis data")
	resetCmd.Flags().BoolVar(&resetDB, "db-only", false, "Reset only database")
}

func runReset(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()

	// Determine what to reset
	resetBoth := !resetRedis && !resetDB
	if resetBoth {
		resetRedis = true
		resetDB = true
	}

	// Show what will be reset
	var targets []string
	if resetRedis {
		targets = append(targets, "Redis data")
	}
	if resetDB {
		targets = append(targets, "SQLite database")
	}

	fmt.Printf("This will permanently delete: %s\n", strings.Join(targets, " and "))

	// Confirm operation unless --yes flag is used
	if !confirmReset {
		fmt.Print("Are you sure you want to continue? (y/N): ")
		var response string
		fmt.Scanln(&response)
		if strings.ToLower(response) != "y" && strings.ToLower(response) != "yes" {
			fmt.Println("Reset operation cancelled.")
			return nil
		}
	}

	// Reset Redis if requested
	if resetRedis {
		if err := resetRedisData(ctx); err != nil {
			fmt.Printf("Warning: Failed to reset Redis data: %v\n", err)
			
			// If user requested both Redis and DB, offer to continue with just DB
			resetBoth := !cmd.Flags().Changed("redis-only") && !cmd.Flags().Changed("db-only")
			if resetBoth && resetDB && !confirmReset {
				fmt.Print("Would you like to continue with database reset only? (y/N): ")
				var response string
				fmt.Scanln(&response)
				if strings.ToLower(response) != "y" && strings.ToLower(response) != "yes" {
					return fmt.Errorf("reset operation cancelled due to Redis connection failure")
				}
			} else if !resetDB {
				// If only Redis was requested and it failed, exit with error
				return fmt.Errorf("failed to reset Redis data: %w", err)
			}
			// If --yes flag was used or only DB reset continues, we continue silently
		} else {
			fmt.Println("✓ Redis data cleared successfully")
		}
	}

	// Reset database if requested
	if resetDB {
		if err := resetDatabase(ctx); err != nil {
			return fmt.Errorf("failed to reset database: %w", err)
		}
		fmt.Println("✓ Database cleared successfully")
	}

	fmt.Println("Reset operation completed successfully!")
	return nil
}

func resetRedisData(ctx context.Context) error {
	// Get Redis configuration
	redisURL := viper.GetString("redis.url")
	if redisURL == "" {
		redisURL = "redis://localhost:6379"
	}

	// Parse Redis URL and create client
	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		return fmt.Errorf("failed to parse Redis URL: %w", err)
	}

	client := redis.NewClient(opts)
	defer client.Close()

	// Test connection
	if err := client.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("failed to connect to Redis: %w", err)
	}

	// Get all keys to understand what we're deleting
	keys, err := client.Keys(ctx, "*").Result()
	if err != nil {
		return fmt.Errorf("failed to get Redis keys: %w", err)
	}

	if len(keys) == 0 {
		fmt.Println("No Redis data found to clear")
		return nil
	}

	fmt.Printf("Clearing %d Redis keys/streams...\n", len(keys))

	// Clear all Redis data
	if err := client.FlushDB(ctx).Err(); err != nil {
		return fmt.Errorf("failed to flush Redis database: %w", err)
	}

	return nil
}

func resetDatabase(ctx context.Context) error {
	// Get database path from configuration
	dbPath := viper.GetString("database.path")
	if dbPath == "" {
		dbPath = "./data/console-ir.db"
	}

	// Remove SQLite database files
	dbFiles := []string{
		dbPath,
		dbPath + "-shm", // Shared memory file
		dbPath + "-wal", // Write-ahead log file
	}

	var removedFiles []string
	for _, file := range dbFiles {
		if _, err := os.Stat(file); err == nil {
			if err := os.Remove(file); err != nil {
				return fmt.Errorf("failed to remove database file %s: %w", file, err)
			}
			removedFiles = append(removedFiles, filepath.Base(file))
		}
	}

	if len(removedFiles) == 0 {
		fmt.Println("No database files found to remove")
		return nil
	}

	fmt.Printf("Removed database files: %s\n", strings.Join(removedFiles, ", "))
	return nil
}
