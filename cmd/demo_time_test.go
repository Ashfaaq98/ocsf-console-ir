package cmd

import (
	"strings"
	"testing"
	"time"
)

// The dataset's last day must land on today, or the demo opens showing nothing
// happening now: every age reads in days, the "last 24 hours" filter is empty,
// and the queue looks abandoned.
func TestDemoShiftLandsTheLastDayOnToday(t *testing.T) {
	for _, tc := range []struct{ name, newest, now string }{
		{"mid-morning", "2026-01-10T23:43:00Z", "2026-08-03T10:31:00Z"},
		{"just after midnight", "2026-01-10T23:43:00Z", "2026-08-03T00:05:00Z"},
		{"late evening", "2026-01-10T01:00:00Z", "2026-08-03T23:50:00Z"},
		{"same day", "2026-08-03T09:00:00Z", "2026-08-03T10:00:00Z"},
	} {
		newest := mustTime(t, tc.newest)
		now := mustTime(t, tc.now)

		shifted := newest.Add(demoTimeShift(newest, now))
		if shifted.Format("2006-01-02") != now.Format("2006-01-02") {
			t.Errorf("%s: the last day landed on %s, want today (%s)",
				tc.name, shifted.Format("2006-01-02"), now.Format("2006-01-02"))
		}
		// The time of day is what makes the story believable — overnight VPN
		// activity has to stay overnight — so the shift is whole days only.
		if shifted.Format("15:04:05") != newest.Format("15:04:05") {
			t.Errorf("%s: the time of day moved from %s to %s",
				tc.name, newest.Format("15:04:05"), shifted.Format("15:04:05"))
		}
	}
}

// Every timestamp in a record moves together. A finding whose first_seen sits
// months before the event it cites is worse than one that is simply old.
func TestShiftMovesEveryTimestampInARecord(t *testing.T) {
	raw := []byte(`{
		"time":"2026-01-10T09:00:00Z",
		"class_uid":2004,
		"start_time":"2026-01-10T08:59:00Z",
		"finding_info":{
			"created_time":"2026-01-10T09:00:00Z",
			"first_seen_time":"2026-01-10T08:00:00Z",
			"related_events":[{"uid":"e1","observed":"2026-01-10T07:30:00Z"}]
		},
		"message":"not a time"
	}`)

	shifted, err := shiftDemoRecord(raw, 48*time.Hour)
	if err != nil {
		t.Fatalf("shiftDemoRecord: %v", err)
	}
	got := string(shifted)

	for _, want := range []string{
		"2026-01-12T09:00:00Z", // time
		"2026-01-12T08:59:00Z", // start_time
		"2026-01-12T08:00:00Z", // nested in finding_info
		"2026-01-12T07:30:00Z", // nested inside an array
	} {
		if !strings.Contains(got, want) {
			t.Errorf("shifted record is missing %s\n%s", want, got)
		}
	}
	if !strings.Contains(got, "not a time") {
		t.Error("a non-timestamp string was mangled")
	}
	if strings.Contains(got, "2026-01-10T") {
		t.Errorf("a timestamp was left behind\n%s", got)
	}
}

// A shift of zero leaves the bytes untouched, so a dataset already anchored to
// today is not needlessly re-encoded.
func TestZeroShiftIsAPassThrough(t *testing.T) {
	raw := []byte(`{"time":"2026-01-10T09:00:00Z","class_uid":4001}`)
	got, err := shiftDemoRecord(raw, 0)
	if err != nil {
		t.Fatalf("shiftDemoRecord: %v", err)
	}
	if string(got) != string(raw) {
		t.Errorf("a zero shift rewrote the record:\n%s", got)
	}
}

// The newest timestamp is found wherever it lives, including inside nested
// objects — the shift is computed from it, so missing one moves the whole
// dataset to the wrong day.
func TestNewestDemoTimeSearchesNestedFields(t *testing.T) {
	records := [][]byte{
		[]byte(`{"time":"2026-01-05T09:00:00Z"}`),
		[]byte(`{"time":"2026-01-06T09:00:00Z","finding_info":{"last_seen_time":"2026-01-10T23:43:00Z"}}`),
		[]byte(`not json`),
	}
	got := newestDemoTime(records)
	if want := mustTime(t, "2026-01-10T23:43:00Z"); !got.Equal(want) {
		t.Errorf("newest = %s, want %s", got, want)
	}
}

func mustTime(t *testing.T, s string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatalf("bad fixture %q: %v", s, err)
	}
	return parsed
}
