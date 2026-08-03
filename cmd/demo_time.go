package cmd

import (
	"encoding/json"
	"time"
)

// The demo dataset carries fixed timestamps, and a demo whose newest finding is
// four months old is not a demo of a triage queue: every age reads in months,
// the "last 24 hours" filter matches nothing, and the whole queue looks stale
// before the user has done anything.
//
// So the dataset is shifted forward at seed time. The shift is a **whole number
// of days**, which is what keeps it believable — an event written for 09:14 stays
// a mid-morning event, the overnight VPN activity stays overnight, and the
// spacing between records is untouched. Only the calendar dates move.

// demoTimeShift computes how far to move the dataset so its newest record lands
// today, without landing in the future.
func demoTimeShift(newest, now time.Time) time.Duration {
	if newest.IsZero() {
		return 0
	}
	// Whole days between the two calendar dates, ignoring both times of day.
	//
	// Subtracting the instants and dividing by 24 does not do this: a dataset
	// ending at 23:43 is 204.4 days from a 10:31 "now", which truncates to 204
	// and lands the last day on *yesterday* — leaving the newest activity ten
	// hours old and today empty, which is exactly what this shift exists to
	// prevent.
	from := time.Date(newest.Year(), newest.Month(), newest.Day(), 0, 0, 0, 0, time.UTC)
	to := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	return to.Sub(from)
}

// newestDemoTime finds the latest timestamp in a set of raw OCSF records.
func newestDemoTime(records [][]byte) time.Time {
	var newest time.Time
	for _, raw := range records {
		var doc map[string]any
		if err := json.Unmarshal(raw, &doc); err != nil {
			continue
		}
		walkDemoTimes(doc, func(t time.Time) time.Time {
			if t.After(newest) {
				newest = t
			}
			return t
		})
	}
	return newest
}

// shiftDemoRecord moves every timestamp in a record by delta.
//
// It walks the document rather than naming fields: an OCSF record carries times
// at the top level, inside finding_info, and inside nested objects a future
// story may add. Missing one leaves a finding whose first_seen is months before
// the event it cites.
func shiftDemoRecord(raw []byte, delta time.Duration) ([]byte, error) {
	if delta == 0 {
		return raw, nil
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	walkDemoTimes(doc, func(t time.Time) time.Time { return t.Add(delta) })
	return json.Marshal(doc)
}

// walkDemoTimes visits every RFC3339 string in a decoded document, replacing it
// with the result of fn.
func walkDemoTimes(node any, fn func(time.Time) time.Time) {
	switch v := node.(type) {
	case map[string]any:
		for key, child := range v {
			if s, ok := child.(string); ok {
				if t, err := time.Parse(time.RFC3339, s); err == nil {
					v[key] = fn(t).Format(time.RFC3339)
				}
				continue
			}
			walkDemoTimes(child, fn)
		}
	case []any:
		for _, child := range v {
			walkDemoTimes(child, fn)
		}
	}
}
