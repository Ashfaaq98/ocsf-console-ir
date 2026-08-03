package cmd

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/bus"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/ingest"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/logging"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/store"
)

// ingestLines runs the ingest loop over the given records and returns the stats
// the summary is built from.
func ingestLines(t *testing.T, lines ...string) *IngestStats {
	t.Helper()

	st, err := store.NewStore(":memory:")
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer st.Close()

	eventBus := bus.NewBus("", logging.New(os.Stdout, logging.LevelError, "test"))
	defer eventBus.Close()

	stats, err := processEvents(context.Background(), strings.NewReader(strings.Join(lines, "\n")),
		ingest.NewParser(), st, eventBus, nil, logging.New(os.Stdout, logging.LevelError, "test"))
	if err != nil {
		t.Fatalf("processEvents: %v", err)
	}
	return stats
}

const validOCSF = `{"class_uid":4001,"category_uid":4,"time":1700000000,"message":"conn"}`

// Records that are not OCSF are counted as their own thing. Reported as plain
// failures they read as a bug in Console-IR; the actual remedy is to convert
// the source, which is only sayable if the cause is known.
func TestNonOCSFRecordsAreCountedSeparately(t *testing.T) {
	stats := ingestLines(t,
		validOCSF,
		`{"EventID":1,"Computer":"WS-01"}`,
		`{"foo":"bar"}`,
	)

	if stats.SuccessfulEvents != 1 {
		t.Errorf("ingested %d events, want the 1 valid one", stats.SuccessfulEvents)
	}
	if stats.NotOCSFEvents != 2 {
		t.Errorf("counted %d not-OCSF records, want 2", stats.NotOCSFEvents)
	}
	// They are failures too, so the exit status still reflects them.
	if stats.FailedEvents != 2 {
		t.Errorf("FailedEvents = %d, want the not-OCSF records to count as failures", stats.FailedEvents)
	}
	if !strings.Contains(stats.NotOCSFSample, "EventID") {
		t.Errorf("sample = %q, want the first offending record", stats.NotOCSFSample)
	}
}

// A file of valid OCSF reports nothing unrecognised — the gate must not cost
// anyone their working ingest.
func TestValidFileReportsNothingUnrecognised(t *testing.T) {
	stats := ingestLines(t, validOCSF, validOCSF, validOCSF)

	if stats.SuccessfulEvents != 3 {
		t.Errorf("ingested %d of 3 valid events", stats.SuccessfulEvents)
	}
	if stats.NotOCSFEvents != 0 || stats.FailedEvents != 0 {
		t.Errorf("a valid file reported %d not-OCSF and %d failed",
			stats.NotOCSFEvents, stats.FailedEvents)
	}
}

// A malformed line is a failure but not a not-OCSF one: telling someone to
// convert a file that is actually truncated sends them the wrong way.
func TestMalformedLinesAreNotCountedAsNonOCSF(t *testing.T) {
	stats := ingestLines(t, validOCSF, `{"class_uid":4001`)

	if stats.FailedEvents != 1 {
		t.Errorf("FailedEvents = %d, want 1", stats.FailedEvents)
	}
	if stats.NotOCSFEvents != 0 {
		t.Errorf("a truncated line was counted as not-OCSF")
	}
}

// The counters aggregate across batches, or a large file reports only its last
// batch. batchSize records of padding push the offenders into a second batch.
func TestCountsSurviveBatching(t *testing.T) {
	lines := make([]string, 0, batchSize+2)
	for i := 0; i < batchSize; i++ {
		lines = append(lines, validOCSF)
	}
	lines = append(lines, `{"EventID":1}`, `{"nope":true}`)

	stats := ingestLines(t, lines...)
	if stats.NotOCSFEvents != 2 {
		t.Errorf("counted %d not-OCSF across batches, want 2", stats.NotOCSFEvents)
	}
	if stats.NotOCSFSample == "" {
		t.Error("the sample was lost when batches were merged")
	}
}
