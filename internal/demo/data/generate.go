//go:build ignore

// Generates the demo dataset.
//
//	go run ./internal/demo/data/generate.go
//
// The dataset is committed rather than generated at build time, so a checkout
// and an installed binary carry exactly the same bytes. Regenerate it when the
// story changes, and commit the result.
//
// # Why a generator rather than a hand-written file
//
// The narrative records — the findings an analyst reads, the events they cite —
// are written out longhand below, because they have to read as though a person
// wrote them. The *background* is generated: several hundred ordinary events
// across the same hosts and users, so that clustering, ranking and the "last 24
// hours" filter have something to work on. Hand-typing those would produce a
// smaller, more repetitive corpus and no better story.
//
// # Time
//
// Every record is anchored to demoAnchor and carries a day offset from it. The
// seeder shifts the whole set forward by a whole number of days so the newest
// record lands today, which keeps each record's time of day intact — an event
// written for 09:14 stays a mid-morning event forever. See shiftToToday in
// cmd/demo.go.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"
)

// demoAnchor is the notional first day of the dataset. Its absolute value does
// not matter — the seeder shifts everything relative to it — but it is a Monday,
// so the generated business-hours traffic falls on weekdays.
var demoAnchor = time.Date(2026, 1, 5, 0, 0, 0, 0, time.UTC)

// spanDays is how many days the story covers. Long enough that the triage
// queue's age column varies and "last 24 hours" is a real filter, short enough
// that everything still reads as one working week.
const spanDays = 5

// The estate. Every record draws from these, so a pivot on a host or a user
// crosses storylines the way it would in a real environment.
var (
	workstations = []host{
		{"workstation-14", "10.20.4.14"},
		{"workstation-22", "10.20.4.22"},
		{"ws-fin-07", "10.20.5.7"},
		{"ws-eng-31", "10.20.6.31"},
	}
	servers = []host{
		{"dc-01", "10.20.1.10"},
		{"srv-file-01", "10.20.1.25"},
		{"srv-sql-02", "10.20.1.32"},
		{"build-agent-03", "10.20.7.3"},
		{"mx-01", "10.20.2.5"},
		{"fw-edge-01", "10.20.0.1"},
		{"vpn-gw-01", "10.20.0.9"},
	}
	people = []string{"j.rivera", "m.chen", "p.osei", "a.novak", "d.silva", "admin.jkim"}
)

type host struct {
	Name string
	IP   string
}

func (h host) device() map[string]any {
	return map[string]any{"hostname": h.Name, "ip": h.IP}
}

// rec is one OCSF record plus the day it belongs to.
type rec struct {
	day  int
	at   time.Duration // time of day
	body map[string]any
}

var records []rec

// add registers a record at a day offset and time of day.
func add(day int, hour, min int, body map[string]any) {
	at := time.Duration(hour)*time.Hour + time.Duration(min)*time.Minute
	records = append(records, rec{day: day, at: at, body: body})
}

func ts(day int, at time.Duration) string {
	return demoAnchor.AddDate(0, 0, day).Add(at).Format(time.RFC3339)
}

// ---------------------------------------------------------------------------
// Builders
// ---------------------------------------------------------------------------

func event(classUID, categoryUID, activityID, severityID int, msg string, extra map[string]any) map[string]any {
	m := map[string]any{
		"class_uid":    classUID,
		"category_uid": categoryUID,
		"activity_id":  activityID,
		"type_uid":     classUID*100 + activityID,
		"severity_id":  severityID,
		"message":      msg,
		"metadata": map[string]any{
			"version": "1.8.0",
			"product": map[string]any{"name": "EDR", "vendor_name": "Acme"},
		},
	}
	for k, v := range extra {
		m[k] = v
	}
	return m
}

func obs(name string, typeID int, value string) map[string]any {
	return map[string]any{"name": name, "type_id": typeID, "value": value}
}

type findingSpec struct {
	UID        string
	Title      string
	Desc       string
	Severity   int // severity_id
	Risk       int // 0 leaves risk_score unset
	Status     string
	StatusID   int
	Confidence string
	ConfID     int
	Analytic   string
	RuleUID    string
	Tactic     [2]string // name, uid
	Technique  [2]string
	Verdict    string
	VerdictID  int
	Related    []string
	Observable []map[string]any
	Device     host
	User       string
}

func finding(day, hour, min int, s findingSpec) {
	at := time.Duration(hour)*time.Hour + time.Duration(min)*time.Minute
	when := ts(day, at)

	info := map[string]any{
		"uid":             s.UID,
		"title":           s.Title,
		"desc":            s.Desc,
		"created_time":    when,
		"first_seen_time": when,
		"last_seen_time":  when,
		"analytic": map[string]any{
			"name": s.Analytic, "type": "Rule", "type_id": 1, "uid": s.RuleUID,
		},
		"types": []string{"Behavioral"},
	}
	if s.Tactic[0] != "" {
		info["attacks"] = []map[string]any{{
			"tactic":    map[string]any{"name": s.Tactic[0], "uid": s.Tactic[1]},
			"technique": map[string]any{"name": s.Technique[0], "uid": s.Technique[1]},
			"version":   "14",
		}}
	}
	if len(s.Related) > 0 {
		rel := []map[string]any{}
		for _, uid := range s.Related {
			rel = append(rel, map[string]any{"uid": uid})
		}
		info["related_events"] = rel
		info["related_events_count"] = len(rel)
	}

	body := map[string]any{
		"class_uid":     2004,
		"category_uid":  2,
		"activity_id":   1,
		"activity_name": "Create",
		"type_uid":      200401,
		"severity_id":   s.Severity,
		"status":        s.Status,
		"status_id":     s.StatusID,
		"confidence":    s.Confidence,
		"confidence_id": s.ConfID,
		"is_alert":      true,
		// The message is the producer's own explanation, and the inspector
		// shows it as "why it matters". Repeating the title there leaves that
		// panel empty on every finding.
		"message":      s.Desc,
		"start_time":   when,
		"end_time":     when,
		"finding_info": info,
		"metadata": map[string]any{
			"version": "1.8.0",
			"product": map[string]any{"name": "EDR", "vendor_name": "Acme"},
		},
	}
	if s.Risk > 0 {
		body["risk_score"] = s.Risk
		body["risk_level_id"] = riskLevel(s.Risk)
	}
	if s.Verdict != "" {
		body["verdict"] = s.Verdict
		body["verdict_id"] = s.VerdictID
	}
	if s.Device.Name != "" {
		body["device"] = s.Device.device()
	}
	if s.User != "" {
		body["user"] = map[string]any{"name": s.User, "domain": "CORP"}
	}
	if len(s.Observable) > 0 {
		body["observables"] = s.Observable
	}
	add(day, hour, min, body)
}

func riskLevel(score int) int {
	switch {
	case score >= 80:
		return 4
	case score >= 50:
		return 3
	case score >= 20:
		return 2
	default:
		return 1
	}
}

func main() {
	buildStory()
	buildBackground()

	sort.SliceStable(records, func(i, j int) bool {
		if records[i].day != records[j].day {
			return records[i].day < records[j].day
		}
		return records[i].at < records[j].at
	})

	out, err := os.Create("internal/demo/data/scenario.jsonl")
	if err != nil {
		panic(err)
	}
	defer out.Close()

	enc := json.NewEncoder(out)
	findings, events := 0, 0
	for _, r := range records {
		r.body["time"] = ts(r.day, r.at)
		if r.body["class_uid"] == 2004 {
			findings++
		} else {
			events++
		}
		if err := enc.Encode(r.body); err != nil {
			panic(err)
		}
	}
	fmt.Fprintf(os.Stderr, "wrote %d records (%d findings, %d events) over %d days\n",
		len(records), findings, events, spanDays)
}
