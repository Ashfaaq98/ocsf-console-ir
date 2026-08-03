package cmd

import (
	"context"
	"fmt"
	"time"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/store"
)

// The demo's cases.
//
// They are built here rather than ingested because Console-IR does not yet read
// OCSF Incident Findings (class 2005) back into cases — that is a roadmap item.
// Until it does, a demo with no cases would open on an empty Cases screen and
// leave the case room, which is where an investigation is actually conducted,
// with nothing to show.
//
// Each case is at a different point in its life, because that is what makes the
// screen legible: one being worked with a briefing written, one nobody has
// picked up, one closed as a true positive, one closed as a false positive. An
// analyst learns more from the contrast than from four identical cases.

// demoCase describes a case and everything hanging off it.
type demoCase struct {
	Title       string
	Description string
	Severity    string
	Status      string
	Owner       string

	// FindingUIDs are OCSF finding_info.uid values, resolved to rows after ingest.
	FindingUIDs []string
	// EvidenceHosts names the hosts whose events belong to this case. Stated
	// rather than derived: a finding records no host of its own, and "the events
	// on these machines" is the judgement an analyst actually makes when
	// deciding what the case covers.
	EvidenceHosts []string
	// PinnedEventMessages pin the evidence an analyst judged decisive. Matched on
	// message, because event ids are generated at ingest.
	PinnedEventMessages []string

	// OpenedAgoHours backdates the case. A case created seconds ago whose notes
	// are two days old is the first thing that gives a seeded demo away, and the
	// header reports the age on every screen.
	OpenedAgoHours int

	Statement   string
	Hypotheses  []store.Hypothesis
	NextActions []store.NextAction
	Summary     string
	Notes       []demoNote
	Audit       []demoAudit
}

type demoNote struct {
	// AgoHours places the note relative to the end of the story.
	AgoHours int
	Author   string
	Body     string
}

type demoAudit struct {
	AgoHours int
	Action   string
	Actor    string
	Details  map[string]interface{}
}

func demoCases() []demoCase {
	return []demoCase{
		{
			Title: "Phishing-led intrusion on workstation-14",
			Description: "Maldoc to encoded PowerShell to C2, with credential access on the host " +
				"and a domain controller logon that has not been explained.",
			Severity: "critical", Status: "investigating", Owner: "p.osei",
			OpenedAgoHours: 31,
			FindingUIDs: []string{
				"fnd-phish-0001", "fnd-exec-0002", "fnd-c2-0003", "fnd-cred-0004", "fnd-lat-0005",
			},
			EvidenceHosts: []string{"workstation-14", "mx-01", "dc-01", "fw-edge-01"},
			PinnedEventMessages: []string{
				"Process opened a handle to LSASS",
				"Firewall blocked outbound connection to known C2 infrastructure",
			},
			Statement: "A macro-enabled invoice reached j.rivera, ran encoded PowerShell under Word, " +
				"and established fifteen-minute beaconing to cdn-metrics.example. An unsigned binary " +
				"then read LSASS, and j.rivera authenticated to dc-01 half an hour later. " +
				"workstation-14 is isolated; the domain controller logon is not yet accounted for.",
			Hypotheses: []store.Hypothesis{
				{Text: "Initial access was the invoice-88213.docm attachment", Confidence: store.ConfidenceConfirmed},
				{Text: "Credentials cached on workstation-14 were dumped and reused", Confidence: store.ConfidenceLikely},
				{Text: "The dc-01 logon is the attacker rather than the user", Confidence: store.ConfidenceOpen},
				{Text: "A second host was reached from dc-01", Confidence: store.ConfidenceOpen},
			},
			NextActions: []store.NextAction{
				{Text: "Isolate workstation-14", Done: true},
				{Text: "Block 198.51.100.73 and cdn-metrics.example at the edge", Done: true},
				{Text: "Force password reset for j.rivera and revoke Kerberos tickets"},
				{Text: "Confirm whether the dc-01 logon was the user or the attacker"},
				{Text: "Sweep the estate for the svc_update.exe hash"},
			},
			Summary: "Eight beacons at a fifteen-minute interval, request and response sizes within " +
				"5% of each other. The destination domain was registered four days before first contact.",
			Notes: []demoNote{
				{AgoHours: 30, Author: "p.osei",
					Body: "Picked this up from the queue. Starting with the mail gateway record to " +
						"establish delivery time, then working forward through the process tree."},
				{AgoHours: 27, Author: "p.osei",
					Body: "Isolated workstation-14 at 10:42 on the network team's authority (ticket " +
						"CHG-4471). The user is aware and has a loaner machine.\n\nNot reimaging yet — " +
						"we still need the disk for the svc_update.exe binary."},
				{AgoHours: 22, Author: "d.silva",
					Body: "Edge block in place for 198.51.100.73 and the domain. Firewall logs show one " +
						"attempt after the block, at 10:41, which failed."},
				{AgoHours: 6, Author: "p.osei",
					Body: "Open question for whoever picks this up next: the dc-01 logon at 10:22 is the " +
						"thing that decides whether this is one host or the whole domain. j.rivera says " +
						"they were in a meeting. Pulling the DC's own logs to compare."},
			},
			Audit: []demoAudit{
				{AgoHours: 31, Action: "create_case", Actor: "p.osei"},
				{AgoHours: 30, Action: "status_changed", Actor: "p.osei",
					Details: map[string]interface{}{"from": "open", "to": "investigating"}},
				{AgoHours: 27, Action: "assign_event", Actor: "p.osei"},
				{AgoHours: 22, Action: "assign_event", Actor: "d.silva"},
			},
		},
		{
			// Deliberately unowned and unwritten: this is what the case header's
			// next-action prompt exists to catch.
			Title:       "Suspected account compromise — m.chen",
			Description: "Impossible travel sign-in followed by repeated denied MFA prompts.",
			Severity:    "high", Status: "open", Owner: "",
			OpenedAgoHours: 20,
			FindingUIDs:    []string{"fnd-ident-0010", "fnd-ident-0011"},
			EvidenceHosts:  []string{"vpn-gw-01"},
			Audit: []demoAudit{
				{AgoHours: 20, Action: "create_case", Actor: "system"},
			},
		},
		{
			Title: "Cryptominer on build-agent-03",
			Description: "A miner reached a CI host through an unpinned dependency and ran for " +
				"five hours before the CPU alert fired.",
			Severity: "medium", Status: "resolved", Owner: "d.silva",
			OpenedAgoHours:      76,
			FindingUIDs:         []string{"fnd-miner-0020", "fnd-miner-0021"},
			EvidenceHosts:       []string{"build-agent-03"},
			PinnedEventMessages: []string{"Process started with a mining pool argument"},
			Statement: "An unpinned CI dependency dropped a miner into a build workspace on " +
				"build-agent-03, which ran at 90% CPU for five hours against pool.minexmr.example. " +
				"No credential access and no lateral movement; the host has been rebuilt and the " +
				"dependency pinned.",
			Hypotheses: []store.Hypothesis{
				{Text: "Delivery was the unpinned npm dependency in the nightly job", Confidence: store.ConfidenceConfirmed},
				{Text: "Impact was limited to CPU on the one agent", Confidence: store.ConfidenceConfirmed},
			},
			NextActions: []store.NextAction{
				{Text: "Rebuild build-agent-03 from the golden image", Done: true},
				{Text: "Pin the dependency and add a lockfile check to CI", Done: true},
				{Text: "Block the pool domain at the edge", Done: true},
			},
			Notes: []demoNote{
				{AgoHours: 74, Author: "d.silva",
					Body: "CPU alert first, miner detection second — the detections agree, so this is " +
						"one incident rather than two."},
				{AgoHours: 60, Author: "d.silva",
					Body: "Agent rebuilt and dependency pinned. Closing as a true positive: real " +
						"execution, contained, no evidence of anything beyond resource use."},
			},
			Audit: []demoAudit{
				{AgoHours: 76, Action: "create_case", Actor: "d.silva"},
				{AgoHours: 74, Action: "status_changed", Actor: "d.silva",
					Details: map[string]interface{}{"from": "open", "to": "investigating"}},
				{AgoHours: 60, Action: "status_changed", Actor: "d.silva",
					Details: map[string]interface{}{"from": "investigating", "to": "resolved"}},
			},
		},
		{
			Title:       "Scanner activity raised as detections",
			Description: "Three findings traced to the authenticated vulnerability scanner.",
			Severity:    "low", Status: "resolved", Owner: "a.novak",
			OpenedAgoHours: 52,
			FindingUIDs:    []string{"fnd-scan-0030", "fnd-scan-0031", "fnd-scan-0032"},
			EvidenceHosts:  []string{"ws-eng-31", "srv-sql-02"},
			Statement: "All three findings originate from 10.20.9.40, the authenticated scanner, " +
				"inside its Tuesday window and matching change record CHG-4390. Closed as false " +
				"positives and kept rather than deleted, so the detections remain auditable.",
			Hypotheses: []store.Hypothesis{
				{Text: "All three are the scheduled scan", Confidence: store.ConfidenceConfirmed},
			},
			NextActions: []store.NextAction{
				{Text: "Add 10.20.9.40 to the scanner allowlist for these three rules", Done: true},
				{Text: "Ask the platform team to record the ticket reference on the scan job"},
			},
			Notes: []demoNote{
				{AgoHours: 50, Author: "a.novak",
					Body: "Confirmed against the change record: scanner window is 19:00–21:00 Tuesdays, " +
						"which covers all three.\n\nWorth tuning rather than suppressing — the TLS rule " +
						"is useful when it fires from anything that is not the scanner."},
			},
			Audit: []demoAudit{
				{AgoHours: 52, Action: "create_case", Actor: "a.novak"},
				{AgoHours: 50, Action: "status_changed", Actor: "a.novak",
					Details: map[string]interface{}{"from": "open", "to": "resolved"}},
			},
		},
	}
}

// seedDemoCases builds the cases and everything hanging off them.
//
// end is the moment the story finishes — the same instant the shifted dataset
// ends — so notes and audit entries sit relative to the incident rather than to
// whenever the demo happens to be run.
func seedDemoCases(ctx context.Context, st *store.Store, shift time.Duration) error {
	findings, err := st.GetFindings(ctx, store.FindingFilter{Limit: 500})
	if err != nil {
		return fmt.Errorf("could not read the ingested findings: %w", err)
	}
	byUID := map[string]store.Finding{}
	for _, f := range findings {
		byUID[f.FindingUID] = f
	}

	events, err := st.GetEvents(ctx, store.EventFilter{Limit: 2000})
	if err != nil {
		return fmt.Errorf("could not read the ingested events: %w", err)
	}

	end := time.Now().UTC()

	for _, dc := range demoCases() {
		caseID, err := st.CreateOrUpdateCase(ctx, store.Case{
			Title:       dc.Title,
			Description: dc.Description,
			Severity:    dc.Severity,
			Status:      dc.Status,
			AssignedTo:  dc.Owner,
			CreatedAt:   end.Add(-time.Duration(dc.OpenedAgoHours) * time.Hour),
		})
		if err != nil {
			return fmt.Errorf("could not create %q: %w", dc.Title, err)
		}

		author := dc.Owner
		if author == "" {
			author = "system"
		}

		// Findings are what the case is about.
		attached := map[string]bool{}
		for _, uid := range dc.FindingUIDs {
			f, ok := byUID[uid]
			if !ok {
				// A story record was renamed without updating the case.
				return fmt.Errorf("case %q references finding %q, which is not in the dataset", dc.Title, uid)
			}
			if err := st.AddCaseMember(ctx, store.CaseMember{
				CaseID: caseID, MemberType: store.MemberTypeFinding, MemberID: f.ID,
				Role: store.DefaultRoleFor(store.MemberTypeFinding), AddedBy: author, AddedAt: end,
			}); err != nil {
				return fmt.Errorf("could not attach %q: %w", uid, err)
			}
			attached[f.ID] = true
		}

		// Evidence: what was happening on the case's hosts *around* its findings.
		//
		// Not simply everything ever seen on those machines — that attached a
		// hundred and fifty unrelated logons to a case about a vulnerability
		// scanner, and made its scope read as every user in the company. An
		// analyst pulls in the window either side of what fired.
		hosts := map[string]bool{}
		for _, h := range dc.EvidenceHosts {
			hosts[h] = true
		}
		windows := [][2]time.Time{}
		for _, uid := range dc.FindingUIDs {
			if f, ok := byUID[uid]; ok && !f.FirstSeen.IsZero() {
				windows = append(windows, [2]time.Time{
					f.FirstSeen.Add(-evidenceWindow), f.LastSeen.Add(evidenceWindow),
				})
			}
		}
		pinned := map[string]bool{}
		for _, msg := range dc.PinnedEventMessages {
			pinned[msg] = true
		}

		for _, e := range events {
			if !hosts[e.Host] || !within(e.Timestamp, windows) {
				continue
			}
			if err := st.AddCaseMember(ctx, store.CaseMember{
				CaseID: caseID, MemberType: store.MemberTypeEvent, MemberID: e.ID,
				Role: store.DefaultRoleFor(store.MemberTypeEvent), AddedBy: author, AddedAt: end,
			}); err != nil {
				return fmt.Errorf("could not attach an event to %q: %w", dc.Title, err)
			}
			if pinned[e.Message] {
				if err := st.SetMemberPinned(ctx, caseID, store.MemberTypeEvent, e.ID, true); err != nil {
					return fmt.Errorf("could not pin evidence on %q: %w", dc.Title, err)
				}
			}
		}

		// The briefing.
		if dc.Statement != "" {
			if err := st.SetStatement(ctx, caseID, author, dc.Statement); err != nil {
				return fmt.Errorf("could not write the statement for %q: %w", dc.Title, err)
			}
		}
		if len(dc.Hypotheses) > 0 {
			if err := st.SetHypotheses(ctx, caseID, author, dc.Hypotheses); err != nil {
				return fmt.Errorf("could not write the hypotheses for %q: %w", dc.Title, err)
			}
		}
		if len(dc.NextActions) > 0 {
			if err := st.SetNextActions(ctx, caseID, author, dc.NextActions); err != nil {
				return fmt.Errorf("could not write the next actions for %q: %w", dc.Title, err)
			}
		}
		if dc.Summary != "" {
			if err := st.AcceptSummary(ctx, caseID, author, dc.Summary); err != nil {
				return fmt.Errorf("could not write the summary for %q: %w", dc.Title, err)
			}
		}

		// The decision log.
		for _, n := range dc.Notes {
			if _, err := st.AddNote(ctx, store.Note{
				CaseID: caseID, Content: n.Body, Author: n.Author,
				CreatedAt: end.Add(-time.Duration(n.AgoHours) * time.Hour),
			}); err != nil {
				return fmt.Errorf("could not write a note on %q: %w", dc.Title, err)
			}
		}

		// The audit trail, at the times the actions were taken. LogCaseAction
		// stamps "now", which would file a case opened two days ago and closed
		// yesterday as though both happened this minute.
		for _, a := range dc.Audit {
			if err := st.AddAuditEntry(ctx, store.AuditEntry{
				CaseID: caseID, Action: a.Action, Actor: a.Actor, Details: a.Details,
				Timestamp: end.Add(-time.Duration(a.AgoHours) * time.Hour),
			}); err != nil {
				return fmt.Errorf("could not write the audit trail for %q: %w", dc.Title, err)
			}
		}
	}
	return nil
}

// evidenceWindow is how far either side of a finding an event is still part of
// the same story. Two hours covers the run-up and the response without dragging
// in the rest of the day.
const evidenceWindow = 2 * time.Hour

// within reports whether t falls inside any of the windows.
func within(t time.Time, windows [][2]time.Time) bool {
	for _, w := range windows {
		if !t.Before(w[0]) && !t.After(w[1]) {
			return true
		}
	}
	return false
}
