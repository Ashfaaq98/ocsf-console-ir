package store

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/ocsf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewStore(t *testing.T) {
	// Test creating a new store with in-memory database
	store, err := NewStore(":memory:")
	require.NoError(t, err)
	require.NotNil(t, store)
	defer store.Close()

	// Verify tables were created
	var count int
	err = store.db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table'").Scan(&count)
	require.NoError(t, err)
	assert.Greater(t, count, 0, "Expected tables to be created")
}

func TestSaveEvent(t *testing.T) {
	store, err := NewStore(":memory:")
	require.NoError(t, err)
	defer store.Close()

	ctx := context.Background()

	// Create a test OCSF event
	ocsfEvent := &ocsf.Event{
		Time:        time.Now(),
		ClassUID:    4001, // Network Activity
		CategoryUID: 4,
		ActivityID:  1,
		TypeUID:     400101,
		SeverityID:  3,
		Message:     "Test network connection",
		Device: &ocsf.Device{
			Hostname: "test-host",
			IP:       "192.168.1.100",
		},
		SrcEndpoint: &ocsf.Endpoint{
			IP:   "192.168.1.100",
			Port: 12345,
		},
		DstEndpoint: &ocsf.Endpoint{
			IP:   "8.8.8.8",
			Port: 53,
		},
		User: &ocsf.User{
			Name: "testuser",
		},
	}

	// Save the event
	eventID, err := store.SaveEvent(ctx, ocsfEvent)
	require.NoError(t, err)
	assert.NotEmpty(t, eventID)

	// Verify the event was saved
	var count int
	err = store.db.QueryRow("SELECT COUNT(*) FROM events WHERE id = ?", eventID).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 1, count)

	// Verify event data
	var savedEvent Event
	var timestamp int64
	err = store.db.QueryRow(`
		SELECT id, timestamp, event_type, severity, message, host, src_ip, dst_ip, src_port, dst_port, user_name
		FROM events WHERE id = ?`, eventID).Scan(
		&savedEvent.ID, &timestamp, &savedEvent.EventType, &savedEvent.Severity,
		&savedEvent.Message, &savedEvent.Host, &savedEvent.SrcIP, &savedEvent.DstIP,
		&savedEvent.SrcPort, &savedEvent.DstPort, &savedEvent.UserName)
	require.NoError(t, err)

	assert.Equal(t, eventID, savedEvent.ID)
	assert.Equal(t, "network", savedEvent.EventType)
	assert.Equal(t, "medium", savedEvent.Severity)
	assert.Equal(t, "Test network connection", savedEvent.Message)
	assert.Equal(t, "test-host", savedEvent.Host)
	assert.Equal(t, "192.168.1.100", savedEvent.SrcIP)
	assert.Equal(t, "8.8.8.8", savedEvent.DstIP)
	assert.Equal(t, 12345, savedEvent.SrcPort)
	assert.Equal(t, 53, savedEvent.DstPort)
	assert.Equal(t, "testuser", savedEvent.UserName)
}

func TestCreateOrUpdateCase(t *testing.T) {
	store, err := NewStore(":memory:")
	require.NoError(t, err)
	defer store.Close()

	ctx := context.Background()

	// Test creating a new case
	testCase := Case{
		Title:       "Test Incident",
		Description: "Test incident description",
		Severity:    "high",
		Status:      "open",
		AssignedTo:  "analyst1",
		EventCount:  5,
	}

	caseID, err := store.CreateOrUpdateCase(ctx, testCase)
	require.NoError(t, err)
	assert.NotEmpty(t, caseID)

	// Verify the case was created
	var count int
	err = store.db.QueryRow("SELECT COUNT(*) FROM cases WHERE id = ?", caseID).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 1, count)

	// Test updating the case
	testCase.ID = caseID
	testCase.Status = "investigating"
	testCase.EventCount = 10

	updatedCaseID, err := store.CreateOrUpdateCase(ctx, testCase)
	require.NoError(t, err)
	assert.Equal(t, caseID, updatedCaseID)

	// Verify the case was updated
	var savedCase Case
	var createdAt, updatedAt int64
	err = store.db.QueryRow(`
		SELECT id, title, description, severity, status, assigned_to, event_count, created_at, updated_at
		FROM cases WHERE id = ?`, caseID).Scan(
		&savedCase.ID, &savedCase.Title, &savedCase.Description, &savedCase.Severity,
		&savedCase.Status, &savedCase.AssignedTo, &savedCase.EventCount, &createdAt, &updatedAt)
	require.NoError(t, err)

	assert.Equal(t, caseID, savedCase.ID)
	assert.Equal(t, "Test Incident", savedCase.Title)
	assert.Equal(t, "investigating", savedCase.Status)
	assert.Equal(t, 10, savedCase.EventCount)
	assert.Greater(t, updatedAt, createdAt, "Updated timestamp should be greater than created timestamp")
}

func TestListCases(t *testing.T) {
	store, err := NewStore(":memory:")
	require.NoError(t, err)
	defer store.Close()

	ctx := context.Background()

	// Create multiple test cases
	testCases := []Case{
		{
			Title:       "Incident 1",
			Description: "First incident",
			Severity:    "high",
			Status:      "open",
			EventCount:  3,
		},
		{
			Title:       "Incident 2",
			Description: "Second incident",
			Severity:    "medium",
			Status:      "investigating",
			EventCount:  7,
		},
		{
			Title:       "Incident 3",
			Description: "Third incident",
			Severity:    "low",
			Status:      "closed",
			EventCount:  1,
		},
	}

	// Save all test cases
	for _, testCase := range testCases {
		_, err := store.CreateOrUpdateCase(ctx, testCase)
		require.NoError(t, err)
	}

	// List all cases
	cases, err := store.ListCases(ctx)
	require.NoError(t, err)
	assert.Len(t, cases, 3)

	// Verify cases are sorted by created_at DESC
	assert.Equal(t, "Incident 3", cases[0].Title) // Most recent
	assert.Equal(t, "Incident 2", cases[1].Title)
	assert.Equal(t, "Incident 1", cases[2].Title) // Oldest
}

func TestGetEventsByCase(t *testing.T) {
	store, err := NewStore(":memory:")
	require.NoError(t, err)
	defer store.Close()

	ctx := context.Background()

	// Create a test case
	testCase := Case{
		Title:      "Test Case",
		Severity:   "medium",
		Status:     "open",
		EventCount: 0,
	}

	caseID, err := store.CreateOrUpdateCase(ctx, testCase)
	require.NoError(t, err)

	// Create test events for the case
	baseTime := time.Now()
	for i := 0; i < 3; i++ {
		ocsfEvent := &ocsf.Event{
			Time:        baseTime.Add(time.Duration(i) * time.Minute),
			ClassUID:    4001,
			CategoryUID: 4,
			ActivityID:  1,
			TypeUID:     400101,
			SeverityID:  2,
			Message:     fmt.Sprintf("Test event %d", i+1),
			Device: &ocsf.Device{
				Hostname: "test-host",
			},
		}

		eventID, err := store.SaveEvent(ctx, ocsfEvent)
		require.NoError(t, err)

		// Associate event with case
		_, err = store.db.ExecContext(ctx, "UPDATE events SET case_id = ? WHERE id = ?", caseID, eventID)
		require.NoError(t, err)
	}

	// Get events by case
	events, err := store.GetEventsByCase(ctx, caseID)
	require.NoError(t, err)
	assert.Len(t, events, 3)

	// Verify events are sorted by timestamp DESC (newest first)
	assert.Equal(t, "Test event 3", events[0].Message)
	assert.Equal(t, "Test event 2", events[1].Message)
	assert.Equal(t, "Test event 1", events[2].Message)
}

func TestApplyEnrichment(t *testing.T) {
	store, err := NewStore(":memory:")
	require.NoError(t, err)
	defer store.Close()

	ctx := context.Background()

	// Create a test event
	ocsfEvent := &ocsf.Event{
		Time:        time.Now(),
		ClassUID:    4001,
		CategoryUID: 4,
		ActivityID:  1,
		TypeUID:     400101,
		SeverityID:  2,
		Message:     "Test event for enrichment",
	}

	eventID, err := store.SaveEvent(ctx, ocsfEvent)
	require.NoError(t, err)

	// Create test enrichment
	enrichment := Enrichment{
		Source: "geoip",
		Type:   "location",
		Data: map[string]string{
			"country":      "United States",
			"country_code": "US",
			"city":         "San Francisco",
			"latitude":     "37.7749",
			"longitude":    "-122.4194",
		},
	}

	// Apply enrichment
	err = store.ApplyEnrichment(ctx, eventID, enrichment)
	require.NoError(t, err)

	// Verify enrichment was saved
	var count int
	err = store.db.QueryRow("SELECT COUNT(*) FROM enrichments WHERE event_id = ?", eventID).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 1, count)

	// Verify enrichment data
	var savedEnrichment Enrichment
	var dataJSON string
	err = store.db.QueryRow(`
		SELECT event_id, source, type, data FROM enrichments WHERE event_id = ?`, eventID).Scan(
		&savedEnrichment.EventID, &savedEnrichment.Source, &savedEnrichment.Type, &dataJSON)
	require.NoError(t, err)

	assert.Equal(t, eventID, savedEnrichment.EventID)
	assert.Equal(t, "geoip", savedEnrichment.Source)
	assert.Equal(t, "location", savedEnrichment.Type)
	assert.Contains(t, dataJSON, "United States")
}

func TestSearchEvents(t *testing.T) {
	store, err := NewStore(":memory:")
	require.NoError(t, err)
	defer store.Close()

	ctx := context.Background()

	// Create test events with different content
	testEvents := []*ocsf.Event{
		{
			Time:        time.Now(),
			ClassUID:    4001,
			CategoryUID: 4,
			ActivityID:  1,
			TypeUID:     400101,
			SeverityID:  2,
			Message:     "Suspicious network connection to malicious domain",
			Device: &ocsf.Device{
				Hostname: "workstation-01",
			},
		},
		{
			Time:        time.Now(),
			ClassUID:    1001,
			CategoryUID: 1,
			ActivityID:  1,
			TypeUID:     100101,
			SeverityID:  3,
			Message:     "Process execution detected",
			Process: &ocsf.Process{
				Name: "powershell.exe",
			},
			Device: &ocsf.Device{
				Hostname: "server-01",
			},
		},
		{
			Time:        time.Now(),
			ClassUID:    2001,
			CategoryUID: 2,
			ActivityID:  2,
			TypeUID:     200102,
			SeverityID:  4,
			Message:     "File modification detected",
			File: &ocsf.File{
				Name: "important.doc",
			},
			Device: &ocsf.Device{
				Hostname: "workstation-02",
			},
		},
	}

	// Save all test events
	for _, event := range testEvents {
		_, err := store.SaveEvent(ctx, event)
		require.NoError(t, err)
	}

	// Test search for "suspicious"
	results, err := store.SearchEvents(ctx, "suspicious", 10)
	require.NoError(t, err)
	assert.Len(t, results, 1)
	assert.Contains(t, results[0].Message, "Suspicious")

	// Test search for "workstation"
	results, err = store.SearchEvents(ctx, "workstation", 10)
	require.NoError(t, err)
	assert.Len(t, results, 2)

	// Test search for "powershell"
	results, err = store.SearchEvents(ctx, "powershell", 10)
	require.NoError(t, err)
	assert.Len(t, results, 1)
	assert.Equal(t, "powershell.exe", results[0].ProcessName)
}

func TestEventTypeMapping(t *testing.T) {
	store, err := NewStore(":memory:")
	require.NoError(t, err)
	defer store.Close()

	ctx := context.Background()

	testCases := []struct {
		name         string
		classUID     int
		expectedType string
	}{
		{"Network Activity", 4001, "network"},
		{"Process Activity", 1001, "process"},
		{"File Activity", 2001, "file"},
		{"Authentication", 3001, "authentication"},
		{"Unknown", 9999, "unknown"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ocsfEvent := &ocsf.Event{
				Time:        time.Now(),
				ClassUID:    tc.classUID,
				CategoryUID: 1,
				ActivityID:  1,
				TypeUID:     tc.classUID*100 + 1,
				SeverityID:  2,
				Message:     fmt.Sprintf("Test %s event", tc.name),
			}

			eventID, err := store.SaveEvent(ctx, ocsfEvent)
			require.NoError(t, err)

			// Verify event type was mapped correctly
			var eventType string
			err = store.db.QueryRow("SELECT event_type FROM events WHERE id = ?", eventID).Scan(&eventType)
			require.NoError(t, err)
			assert.Equal(t, tc.expectedType, eventType)
		})
	}
}

func TestSeverityMapping(t *testing.T) {
	store, err := NewStore(":memory:")
	require.NoError(t, err)
	defer store.Close()

	ctx := context.Background()

	testCases := []struct {
		severityID       int
		expectedSeverity string
	}{
		{1, "informational"},
		{2, "low"},
		{3, "medium"},
		{4, "high"},
		{5, "critical"},
		{99, "unknown"},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("SeverityID_%d", tc.severityID), func(t *testing.T) {
			ocsfEvent := &ocsf.Event{
				Time:        time.Now(),
				ClassUID:    4001,
				CategoryUID: 4,
				ActivityID:  1,
				TypeUID:     400101,
				SeverityID:  tc.severityID,
				Message:     "Test severity mapping",
			}

			eventID, err := store.SaveEvent(ctx, ocsfEvent)
			require.NoError(t, err)

			// Verify severity was mapped correctly
			var severity string
			err = store.db.QueryRow("SELECT severity FROM events WHERE id = ?", eventID).Scan(&severity)
			require.NoError(t, err)
			assert.Equal(t, tc.expectedSeverity, severity)
		})
	}
}

func TestComplexEventMapping(t *testing.T) {
	store, err := NewStore(":memory:")
	require.NoError(t, err)
	defer store.Close()

	ctx := context.Background()

	// Create a complex OCSF event with multiple fields
	ocsfEvent := &ocsf.Event{
		Time:        time.Now(),
		ClassUID:    1001, // Process Activity
		CategoryUID: 1,
		ActivityID:  1,
		TypeUID:     100101,
		SeverityID:  4, // High
		Message:     "Suspicious process execution detected",
		Device: &ocsf.Device{
			Hostname: "compromised-host",
			IP:       "192.168.1.50",
		},
		Process: &ocsf.Process{
			Name:        "malware.exe",
			PID:         1337,
			CommandLine: "malware.exe --stealth --persist",
			User: &ocsf.User{
				Name:   "victim-user",
				Domain: "corporate.local",
			},
			File: &ocsf.File{
				Name: "malware.exe",
				Path: "C:\\temp\\malware.exe",
				Hashes: map[string]string{
					"sha256": "deadbeefcafebabe1234567890abcdef",
					"md5":    "5d41402abc4b2a76b9719d911017c592",
				},
			},
		},
		User: &ocsf.User{
			Name:   "admin-user",
			Domain: "corporate.local",
		},
	}

	eventID, err := store.SaveEvent(ctx, ocsfEvent)
	require.NoError(t, err)

	// Verify all fields were mapped correctly
	var savedEvent Event
	var timestamp int64
	err = store.db.QueryRow(`
		SELECT id, timestamp, event_type, severity, message, host, 
		       process_name, file_name, file_hash, user_name
		FROM events WHERE id = ?`, eventID).Scan(
		&savedEvent.ID, &timestamp, &savedEvent.EventType, &savedEvent.Severity,
		&savedEvent.Message, &savedEvent.Host, &savedEvent.ProcessName,
		&savedEvent.FileName, &savedEvent.FileHash, &savedEvent.UserName)
	require.NoError(t, err)

	assert.Equal(t, eventID, savedEvent.ID)
	assert.Equal(t, "process", savedEvent.EventType)
	assert.Equal(t, "high", savedEvent.Severity)
	assert.Equal(t, "Suspicious process execution detected", savedEvent.Message)
	assert.Equal(t, "compromised-host", savedEvent.Host)
	assert.Equal(t, "malware.exe", savedEvent.ProcessName)
	assert.Equal(t, "malware.exe", savedEvent.FileName)
	assert.Equal(t, "deadbeefcafebabe1234567890abcdef", savedEvent.FileHash) // SHA256 preferred
	assert.Equal(t, "victim-user", savedEvent.UserName) // Process user preferred over event user
}

func TestDatabaseIndexes(t *testing.T) {
	store, err := NewStore(":memory:")
	require.NoError(t, err)
	defer store.Close()

	// Verify that indexes were created
	rows, err := store.db.Query("SELECT name FROM sqlite_master WHERE type='index' AND name LIKE 'idx_%'")
	require.NoError(t, err)
	defer rows.Close()

	var indexes []string
	for rows.Next() {
		var indexName string
		err := rows.Scan(&indexName)
		require.NoError(t, err)
		indexes = append(indexes, indexName)
	}

	// Verify expected indexes exist
	expectedIndexes := []string{
		"idx_events_id",
		"idx_events_case_id",
		"idx_events_timestamp",
		"idx_events_event_type",
		"idx_events_severity",
		"idx_events_src_ip",
		"idx_events_dst_ip",
		"idx_events_host",
		"idx_cases_id",
		"idx_cases_status",
		"idx_cases_severity",
		"idx_cases_created_at",
		"idx_enrichments_event_id",
		"idx_enrichments_source",
		"idx_enrichments_type",
	}

	for _, expectedIndex := range expectedIndexes {
		assert.Contains(t, indexes, expectedIndex, "Expected index %s to exist", expectedIndex)
	}
}

func TestFullTextSearch(t *testing.T) {
	store, err := NewStore(":memory:")
	require.NoError(t, err)
	defer store.Close()

	// Verify FTS table was created
	var count int
	err = store.db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='events_fts'").Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 1, count, "FTS table should be created")

	// Verify FTS triggers were created
	err = store.db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='trigger' AND name LIKE 'events_fts_%'").Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 3, count, "FTS triggers should be created")
}

// Benchmark tests
func BenchmarkSaveEvent(b *testing.B) {
	store, err := NewStore(":memory:")
	require.NoError(b, err)
	defer store.Close()

	ctx := context.Background()
	ocsfEvent := &ocsf.Event{
		Time:        time.Now(),
		ClassUID:    4001,
		CategoryUID: 4,
		ActivityID:  1,
		TypeUID:     400101,
		SeverityID:  2,
		Message:     "Benchmark test event",
		Device: &ocsf.Device{
			Hostname: "benchmark-host",
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := store.SaveEvent(ctx, ocsfEvent)
		require.NoError(b, err)
	}
}

func BenchmarkSearchEvents(b *testing.B) {
	store, err := NewStore(":memory:")
	require.NoError(b, err)
	defer store.Close()

	ctx := context.Background()

	// Create test data
	for i := 0; i < 1000; i++ {
		ocsfEvent := &ocsf.Event{
			Time:        time.Now(),
			ClassUID:    4001,
			CategoryUID: 4,
			ActivityID:  1,
			TypeUID:     400101,
			SeverityID:  2,
			Message:     fmt.Sprintf("Test event %d with searchable content", i),
			Device: &ocsf.Device{
				Hostname: fmt.Sprintf("host-%d", i%10),
			},
		}
		_, err := store.SaveEvent(ctx, ocsfEvent)
		require.NoError(b, err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := store.SearchEvents(ctx, "searchable", 10)
		require.NoError(b, err)
	}
}
// --- Added tests for filtered queries and pagination ---

func TestGetEventsFilteredAndCount(t *testing.T) {
	store, err := NewStore(":memory:")
	require.NoError(t, err)
	defer store.Close()

	ctx := context.Background()

	// Create two cases
	case1ID, err := store.CreateOrUpdateCase(ctx, Case{
		Title:    "Case 1",
		Severity: "medium",
		Status:   "open",
	})
	require.NoError(t, err)

	case2ID, err := store.CreateOrUpdateCase(ctx, Case{
		Title:    "Case 2",
		Severity: "high",
		Status:   "open",
	})
	require.NoError(t, err)

	// Helper to create and optionally assign events with deterministic times/types/severity.
	base := time.Unix(1_700_000_000, 0) // fixed timestamp baseline for repeatability
	mk := func(minOffset int, classUID, severityID int, msg string, assignToCase string) string {
		ev := &ocsf.Event{
			Time:        base.Add(time.Duration(minOffset) * time.Minute),
			ClassUID:    classUID,
			CategoryUID: 1,
			ActivityID:  1,
			TypeUID:     classUID*100 + 1,
			SeverityID:  severityID,
			Message:     msg,
		}
		id, err := store.SaveEvent(ctx, ev)
		require.NoError(t, err)
		if assignToCase != "" {
			require.NoError(t, store.AssignEventToCase(ctx, id, assignToCase))
		}
		return id
	}

	// Dataset:
	// ALL (no case)
	_ = mk(40, 4001, 4, "all_net_high_t1", "")        // network, high (t1)
	_ = mk(50, 1001, 5, "all_proc_critical_t2", "")   // process, critical (t2)
	_ = mk(10, 2001, 2, "all_file_low_t0", "")        // file, low (t0) -- excluded by severity/type in main filter

	// Case 1
	_ = mk(40, 4001, 3, "case1_net_medium_t1", case1ID) // network, medium (excluded by severity)
	_ = mk(50, 1001, 4, "case1_proc_high_t2", case1ID)  // process, high (included)

	// Case 2
	_ = mk(50, 3001, 4, "case2_auth_high_t2", case2ID) // authentication, high (excluded by type)

	// Filter: time window [t1..t2], severities {high,critical}, types {network,process}
	start := base.Add(30 * time.Minute)
	end := base.Add(60 * time.Minute)
	severities := []string{"high", "critical"}
	types := []string{"network", "process"}

	// ALL contexts (caseID="")
	totalAll, err := store.CountEventsFiltered(ctx, "", start, end, severities, types)
	require.NoError(t, err)
	assert.Equal(t, 3, totalAll, "Expected 3 events across ALL contexts (all_net_high_t1, all_proc_critical_t2, case1_proc_high_t2)")

	rowsAll, err := store.GetEventsFiltered(ctx, "", start, end, severities, types, 0, 0)
	require.NoError(t, err)
	require.Len(t, rowsAll, 3)

	// Verify messages set (order by timestamp desc is expected but may tie at same minute)
	gotMsgs := map[string]bool{}
	for _, e := range rowsAll {
		gotMsgs[e.Message] = true
		// Ensure every event is within the requested time window and types/severities
		assert.True(t, (e.Timestamp.Equal(start) || e.Timestamp.After(start)) && (e.Timestamp.Equal(end) || e.Timestamp.Before(end)))
		assert.Contains(t, []string{"network", "process"}, e.EventType)
		assert.Contains(t, []string{"high", "critical"}, e.Severity)
	}
	assert.True(t, gotMsgs["all_net_high_t1"])
	assert.True(t, gotMsgs["all_proc_critical_t2"])
	assert.True(t, gotMsgs["case1_proc_high_t2"])

	// Case 1 only
	totalCase1, err := store.CountEventsFiltered(ctx, case1ID, start, end, severities, types)
	require.NoError(t, err)
	assert.Equal(t, 1, totalCase1, "Expected 1 match in Case 1")

	rowsCase1, err := store.GetEventsFiltered(ctx, case1ID, start, end, severities, types, 0, 0)
	require.NoError(t, err)
	require.Len(t, rowsCase1, 1)
	assert.Equal(t, "case1_proc_high_t2", rowsCase1[0].Message)

	// Case 2 only (should be 0 because type is authentication)
	totalCase2, err := store.CountEventsFiltered(ctx, case2ID, start, end, severities, types)
	require.NoError(t, err)
	assert.Equal(t, 0, totalCase2)

	rowsCase2, err := store.GetEventsFiltered(ctx, case2ID, start, end, severities, types, 0, 0)
	require.NoError(t, err)
	require.Len(t, rowsCase2, 0)
}

func TestGetEventsFiltered_Pagination(t *testing.T) {
	store, err := NewStore(":memory:")
	require.NoError(t, err)
	defer store.Close()

	ctx := context.Background()

	// Create 5 events in ALL, same type/severity, spaced by minutes so ordering is deterministic (DESC by timestamp).
	base := time.Unix(1_700_100_000, 0)
	mk := func(minOffset int, msg string) {
		ev := &ocsf.Event{
			Time:        base.Add(time.Duration(minOffset) * time.Minute),
			ClassUID:    4001,                   // network
			CategoryUID: 4,
			ActivityID:  1,
			TypeUID:     4001*100 + 1,
			SeverityID:  4,                      // high
			Message:     msg,
		}
		_, err := store.SaveEvent(ctx, ev)
		require.NoError(t, err)
	}
	mk(0, "p0")
	mk(1, "p1")
	mk(2, "p2")
	mk(3, "p3")
	mk(4, "p4")

	start := base.Add(-1 * time.Minute)   // include from slightly before first
	end := base.Add(10 * time.Minute)     // include beyond last
	severities := []string{"high"}
	types := []string{"network"}

	total, err := store.CountEventsFiltered(ctx, "", start, end, severities, types)
	require.NoError(t, err)
	assert.Equal(t, 5, total)

	// Page 1: limit=2, offset=0 (newest first => p4, p3)
	rows, err := store.GetEventsFiltered(ctx, "", start, end, severities, types, 2, 0)
	require.NoError(t, err)
	require.Len(t, rows, 2)
	assert.Equal(t, "p4", rows[0].Message)
	assert.Equal(t, "p3", rows[1].Message)

	// Page 2: next two => p2, p1
	rows, err = store.GetEventsFiltered(ctx, "", start, end, severities, types, 2, 2)
	require.NoError(t, err)
	require.Len(t, rows, 2)
	assert.Equal(t, "p2", rows[0].Message)
	assert.Equal(t, "p1", rows[1].Message)

	// Page 3: last => p0
	rows, err = store.GetEventsFiltered(ctx, "", start, end, severities, types, 2, 4)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Equal(t, "p0", rows[0].Message)

	// Beyond
	rows, err = store.GetEventsFiltered(ctx, "", start, end, severities, types, 2, 6)
	require.NoError(t, err)
	require.Len(t, rows, 0)
}
func TestDeleteEvents_RemovesEnrichmentsAndUpdatesCounts(t *testing.T) {
store, err := NewStore(":memory:")
require.NoError(t, err)
defer store.Close()

ctx := context.Background()

// Create a case
caseID, err := store.CreateOrUpdateCase(ctx, Case{
Title:    "Case A",
Severity: "medium",
Status:   "open",
})
require.NoError(t, err)
require.NotEmpty(t, caseID)

// Helper to create an event with deterministic mapping
mk := func(classUID, severityID int, msg string) string {
ev := &ocsf.Event{
Time:        time.Now(),
ClassUID:    classUID,
CategoryUID: 1,
ActivityID:  1,
TypeUID:     classUID*100 + 1,
SeverityID:  severityID,
Message:     msg,
}
id, err := store.SaveEvent(ctx, ev)
require.NoError(t, err)
return id
}

// Create three events: two assigned to the case, one unassigned
e1 := mk(4001, 3, "e1_caseA") // network, medium
e2 := mk(1001, 4, "e2_caseA") // process, high
e3 := mk(2001, 2, "e3_all")   // file, low (unassigned)

// Assign e1, e2 to case
require.NoError(t, store.AssignEventToCase(ctx, e1, caseID))
require.NoError(t, store.AssignEventToCase(ctx, e2, caseID))

// Add enrichments for all three events
for _, id := range []string{e1, e2, e3} {
require.NoError(t, store.ApplyEnrichment(ctx, id, Enrichment{
Source: "test",
Type:   "check",
Data:   map[string]string{"k": "v"},
}))
}

// Initialize event_count for the case
require.NoError(t, store.UpdateCaseEventCount(ctx, caseID))
var cntBefore int
require.NoError(t, store.db.QueryRow("SELECT event_count FROM cases WHERE id = ?", caseID).Scan(&cntBefore))
assert.Equal(t, 2, cntBefore)

// Act: delete e1 and e2
require.NoError(t, store.DeleteEvents(ctx, []string{e1, e2}))

// Events e1, e2 removed; e3 remains
var removedCount int
require.NoError(t, store.db.QueryRow("SELECT COUNT(1) FROM events WHERE id IN (?,?)", e1, e2).Scan(&removedCount))
assert.Equal(t, 0, removedCount)

var remainingCount int
require.NoError(t, store.db.QueryRow("SELECT COUNT(1) FROM events WHERE id = ?", e3).Scan(&remainingCount))
assert.Equal(t, 1, remainingCount)

// Enrichments for e1, e2 removed; enrichment for e3 remains
var enrRemoved int
require.NoError(t, store.db.QueryRow("SELECT COUNT(1) FROM enrichments WHERE event_id IN (?,?)", e1, e2).Scan(&enrRemoved))
assert.Equal(t, 0, enrRemoved)

var enrRemain int
require.NoError(t, store.db.QueryRow("SELECT COUNT(1) FROM enrichments WHERE event_id = ?", e3).Scan(&enrRemain))
assert.Equal(t, 1, enrRemain)

// Case event_count updated (was 2, now 0 after deletion)
var cntAfter int
require.NoError(t, store.db.QueryRow("SELECT event_count FROM cases WHERE id = ?", caseID).Scan(&cntAfter))
assert.Equal(t, 0, cntAfter)

// FTS rows for deleted events should also be gone (trigger-backed compatibility always exists)
var ftsCount int
require.NoError(t, store.db.QueryRow("SELECT COUNT(1) FROM events_fts WHERE id IN (?,?)", e1, e2).Scan(&ftsCount))
assert.Equal(t, 0, ftsCount)
}