package ingest

import (
	"encoding/json"
	"fmt"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/ocsf"
)

// RecordKind distinguishes what a raw OCSF payload turned out to be.
type RecordKind int

const (
	// RecordEvent is an activity-class observation.
	RecordEvent RecordKind = iota
	// RecordFinding is a Findings-category record, or any alertable event.
	RecordFinding
)

// Record is the result of parsing a raw OCSF payload.
//
// An alertable event (is_alert = true on an activity class) yields BOTH: the
// finding drives triage, while the event stays queryable as telemetry. OCSF
// models this deliberately — the security_control profile marks an activity as
// alertable without turning it into a Detection Finding.
type Record struct {
	Kind    RecordKind
	Event   *ocsf.Event
	Finding *ocsf.Finding
}

// IsFinding reports whether the record produced a finding.
func (r Record) IsFinding() bool { return r.Finding != nil }

// OCSFEvent and OCSFFinding satisfy the store's record interface, letting the
// store persist a record without importing this package (which would cycle).
func (r Record) OCSFEvent() *ocsf.Event     { return r.Event }
func (r Record) OCSFFinding() *ocsf.Finding { return r.Finding }

// EventType returns the bus label for the record, preferring the finding's class
// grouping when the record produced one.
func (r Record) EventType() string {
	if r.Finding != nil {
		return string(r.Finding.GetEventType())
	}
	if r.Event != nil {
		return string(r.Event.GetEventType())
	}
	return string(ocsf.EventTypeUnknown)
}

// Timestamp returns the record's event time.
func (r Record) Timestamp() int64 {
	if r.Finding != nil {
		return r.Finding.Time.Unix()
	}
	if r.Event != nil {
		return r.Event.Time.Unix()
	}
	return 0
}

// Parse routes a raw OCSF payload to the right shape.
//
// Routing rules:
//   - category_uid 2 (Findings)      -> Finding
//   - is_alert = true on any class    -> Finding *and* Event
//   - anything else                   -> Event
func (p *Parser) Parse(rawJSON []byte) (Record, error) {
	event, err := p.ParseEvent(rawJSON)
	if err != nil {
		return Record{}, err
	}

	isAlert := false
	var probe struct {
		IsAlert *bool `json:"is_alert"`
	}
	if err := json.Unmarshal(rawJSON, &probe); err == nil && probe.IsAlert != nil {
		isAlert = *probe.IsAlert
	}

	if event.GetCategoryUID() != ocsf.CategoryFindings && !isAlert {
		return Record{Kind: RecordEvent, Event: event}, nil
	}

	finding, err := p.ParseFinding(rawJSON, event)
	if err != nil {
		return Record{}, err
	}

	rec := Record{Kind: RecordFinding, Finding: finding}
	// An alertable activity event is still telemetry: keep it queryable as an
	// event as well as surfacing it for triage.
	if event.GetCategoryUID() != ocsf.CategoryFindings {
		rec.Event = event
	}
	return rec, nil
}

// ParseFinding builds a Finding from a raw payload and its already-parsed base
// event. finding_info.uid is required by OCSF; when a producer omits it a stable
// identity is synthesized so lifecycle updates still collapse onto one record.
func (p *Parser) ParseFinding(rawJSON []byte, event *ocsf.Event) (*ocsf.Finding, error) {
	if event == nil {
		var err error
		event, err = p.ParseEvent(rawJSON)
		if err != nil {
			return nil, err
		}
	}

	var doc findingDoc
	if err := json.Unmarshal(rawJSON, &doc); err != nil {
		return nil, fmt.Errorf("failed to unmarshal finding: %w", err)
	}

	f := &ocsf.Finding{
		Event:             *event,
		ActivityName:      doc.ActivityName,
		Status:            doc.Status,
		StatusID:          doc.StatusID,
		IsAlert:           doc.IsAlert,
		Confidence:        doc.Confidence,
		ConfidenceID:      doc.ConfidenceID,
		ConfidenceScore:   doc.ConfidenceScore,
		RiskLevel:         doc.RiskLevel,
		RiskLevelID:       doc.RiskLevelID,
		RiskScore:         doc.RiskScore,
		Impact:            doc.Impact,
		ImpactID:          doc.ImpactID,
		ImpactScore:       doc.ImpactScore,
		Verdict:           doc.Verdict,
		VerdictID:         doc.VerdictID,
		Priority:          doc.Priority,
		PriorityID:        doc.PriorityID,
		Assignee:          doc.Assignee,
		AssigneeGroup:     doc.AssigneeGroup,
		IsSuspectedBreach: doc.IsSuspectedBreach,
		Evidences:         doc.Evidences,
	}

	if doc.FindingInfo != nil {
		f.FindingInfo = p.convertFindingInfo(*doc.FindingInfo)
	}
	for _, fi := range doc.FindingInfoList {
		f.FindingInfoList = append(f.FindingInfoList, p.convertFindingInfo(fi))
	}

	if t, err := p.parseTime(doc.StartTime); err == nil {
		f.StartTime = t
	}
	if t, err := p.parseTime(doc.EndTime); err == nil {
		f.EndTime = t
	}

	// A finding with no uid cannot be updated in place, so derive a stable one
	// rather than letting every update create a duplicate record.
	if f.FindingInfo.UID == "" {
		f.FindingInfo.UID = syntheticFindingUID(f)
	}

	// Default an unspecified lifecycle state to New so the triage queue is not
	// full of blank statuses.
	if f.StatusID == ocsf.FindingStatusUnknown && f.Status == "" {
		f.StatusID = ocsf.FindingStatusNew
	}

	return f, nil
}

// syntheticFindingUID derives a stable identity for producers that omit
// finding_info.uid. metadata.uid is preferred; otherwise the analytic and title
// are used, so repeated reports of the same detection collapse onto one record.
func syntheticFindingUID(f *ocsf.Finding) string {
	if f.Metadata.UID != "" {
		return f.Metadata.UID
	}
	if f.Metadata.CorrelationUID != "" {
		return f.Metadata.CorrelationUID
	}
	base := f.AnalyticName() + "|" + f.Title()
	if base == "|" {
		base = fmt.Sprintf("class-%d", f.ClassUID)
	}
	return "synthetic:" + base
}

func (p *Parser) convertFindingInfo(in findingInfoDoc) ocsf.FindingInfo {
	out := ocsf.FindingInfo{
		UID:                in.UID,
		Title:              in.Title,
		Desc:               in.Desc,
		Analytic:           in.Analytic,
		Attacks:            in.Attacks,
		RelatedEvents:      in.RelatedEvents,
		RelatedEventsCount: in.RelatedEventsCount,
		SrcURL:             in.SrcURL,
		Types:              in.Types,
		UIDAlt:             in.UIDAlt,
	}
	if t, err := p.parseTime(in.CreatedTime); err == nil {
		out.CreatedTime = t
	}
	if t, err := p.parseTime(in.FirstSeenTime); err == nil {
		out.FirstSeenTime = t
	}
	if t, err := p.parseTime(in.LastSeenTime); err == nil {
		out.LastSeenTime = t
	}
	if t, err := p.parseTime(in.ModifiedTime); err == nil {
		out.ModifiedTime = t
	}
	if out.RelatedEventsCount == 0 {
		out.RelatedEventsCount = len(out.RelatedEvents)
	}
	return out
}

// findingDoc decodes the finding-specific attributes. Timestamps stay as
// interface{} so the parser's own parseTime can handle both the Unix integers
// OCSF uses and RFC3339 strings; encoding/json cannot decode the former into
// time.Time.
type findingDoc struct {
	ActivityName string `json:"activity_name"`

	Status   string `json:"status"`
	StatusID int    `json:"status_id"`

	StartTime interface{} `json:"start_time"`
	EndTime   interface{} `json:"end_time"`

	IsAlert         bool `json:"is_alert"`
	Confidence      string
	ConfidenceID    int    `json:"confidence_id"`
	ConfidenceScore int    `json:"confidence_score"`
	RiskLevel       string `json:"risk_level"`
	RiskLevelID     int    `json:"risk_level_id"`
	RiskScore       int    `json:"risk_score"`
	Impact          string
	ImpactID        int `json:"impact_id"`
	ImpactScore     int `json:"impact_score"`

	Verdict           string
	VerdictID         int `json:"verdict_id"`
	Priority          string
	PriorityID        int    `json:"priority_id"`
	Assignee          string `json:"assignee"`
	AssigneeGroup     string `json:"assignee_group"`
	IsSuspectedBreach bool   `json:"is_suspected_breach"`

	Evidences []ocsf.Evidence `json:"evidences"`

	FindingInfo     *findingInfoDoc  `json:"finding_info"`
	FindingInfoList []findingInfoDoc `json:"finding_info_list"`
}

type findingInfoDoc struct {
	UID   string `json:"uid"`
	Title string `json:"title"`
	Desc  string `json:"desc"`

	Analytic *ocsf.Analytic `json:"analytic"`
	Attacks  []ocsf.Attack  `json:"attacks"`

	CreatedTime   interface{} `json:"created_time"`
	FirstSeenTime interface{} `json:"first_seen_time"`
	LastSeenTime  interface{} `json:"last_seen_time"`
	ModifiedTime  interface{} `json:"modified_time"`

	RelatedEvents      []ocsf.RelatedEvent `json:"related_events"`
	RelatedEventsCount int                 `json:"related_events_count"`

	SrcURL string   `json:"src_url"`
	Types  []string `json:"types"`
	UIDAlt string   `json:"uid_alt"`
}
