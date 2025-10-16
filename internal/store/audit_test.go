package store

import (
	"context"
	"path/filepath"
	"testing"
)

func TestAuditNotesAndEntriesFlow(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	s, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore error: %v", err)
	}
	defer func() { _ = s.Close() }()

	if err := s.SetupAuditTables(); err != nil {
		t.Fatalf("SetupAuditTables error: %v", err)
	}

	ctx := context.Background()

	// Add a note
	noteID, err := s.AddNote(ctx, Note{
		CaseID:  "case_test",
		Content: "note body",
		Author:  "tester",
	})
	if err != nil {
		t.Fatalf("AddNote error: %v", err)
	}
	if noteID == "" {
		t.Fatalf("expected non-empty note id")
	}

	notes, err := s.GetNotes(ctx, "case_test")
	if err != nil {
		t.Fatalf("GetNotes error: %v", err)
	}
	if len(notes) != 1 {
		t.Fatalf("expected 1 note, got %d", len(notes))
	}
	if notes[0].Content != "note body" || notes[0].Author != "tester" {
		t.Fatalf("unexpected note content/author: %+v", notes[0])
	}

	// Log a copilot query
	if err := s.LogCopilotQuery(ctx, "case_test", "tester", "hello", "world", 123, 0.246); err != nil {
		t.Fatalf("LogCopilotQuery error: %v", err)
	}

	entries, err := s.GetAuditEntries(ctx, "case_test", 10)
	if err != nil {
		t.Fatalf("GetAuditEntries error: %v", err)
	}
	if len(entries) == 0 {
		t.Fatalf("expected at least one audit entry")
	}
	found := false
	for _, e := range entries {
		if e.Action == "copilot_query" {
			if e.Metadata["tokens"] != "123" {
				t.Fatalf("expected tokens=123, got %q", e.Metadata["tokens"])
			}
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("copilot_query entry not found")
	}

	// Add a generic audit entry
	if err := s.AddAuditEntry(ctx, AuditEntry{
		CaseID:  "case_test",
		Action:  "test_action",
		Actor:   "tester",
		Details: map[string]interface{}{"k": "v"},
	}); err != nil {
		t.Fatalf("AddAuditEntry error: %v", err)
	}

	entries2, err := s.GetAuditEntries(ctx, "case_test", 0)
	if err != nil {
		t.Fatalf("GetAuditEntries(0) error: %v", err)
	}
	if len(entries2) < 2 {
		t.Fatalf("expected at least 2 entries, got %d", len(entries2))
	}
}