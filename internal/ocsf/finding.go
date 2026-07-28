package ocsf

import (
	"encoding/json"
	"time"
)

// Finding is an event in the OCSF Findings category (class_uid 2001–2008).
//
// A Finding is not just another log line: it is an analytic's conclusion, and it
// has a lifecycle. activity_id reports Create/Update/Close against a stable
// finding_info.uid, so the same finding arrives repeatedly as its severity is
// revised, evidence is added, and it is eventually closed. Storing each arrival
// as a new record would turn one alert into many.
type Finding struct {
	// Embedding Event gives a Finding the base-event identity — class_uid,
	// metadata, time, severity, observables — since a Finding *is* an OCSF event.
	Event

	// finding_info is required on every class deriving from `finding`.
	FindingInfo FindingInfo `json:"finding_info"`

	ActivityName string `json:"activity_name,omitempty"`

	// Lifecycle state (base `finding` class).
	Status   string `json:"status,omitempty"`
	StatusID int    `json:"status_id,omitempty"`

	StartTime time.Time `json:"start_time,omitempty"`
	EndTime   time.Time `json:"end_time,omitempty"`

	// Detection Finding attributes.
	IsAlert         bool       `json:"is_alert,omitempty"`
	Confidence      string     `json:"confidence,omitempty"`
	ConfidenceID    int        `json:"confidence_id,omitempty"`
	ConfidenceScore int        `json:"confidence_score,omitempty"`
	RiskLevel       string     `json:"risk_level,omitempty"`
	RiskLevelID     int        `json:"risk_level_id,omitempty"`
	RiskScore       int        `json:"risk_score,omitempty"`
	Impact          string     `json:"impact,omitempty"`
	ImpactID        int        `json:"impact_id,omitempty"`
	ImpactScore     int        `json:"impact_score,omitempty"`
	Evidences       []Evidence `json:"evidences,omitempty"`

	// Incident profile / Incident Finding attributes.
	Verdict           string `json:"verdict,omitempty"`
	VerdictID         int    `json:"verdict_id,omitempty"`
	Priority          string `json:"priority,omitempty"`
	PriorityID        int    `json:"priority_id,omitempty"`
	Assignee          string `json:"assignee,omitempty"`
	AssigneeGroup     string `json:"assignee_group,omitempty"`
	IsSuspectedBreach bool   `json:"is_suspected_breach,omitempty"`

	// Incident Finding (2005) aggregates other findings. Required on that class.
	FindingInfoList []FindingInfo `json:"finding_info_list,omitempty"`
}

// FindingInfo mirrors the OCSF finding_info object. uid is its only required
// attribute and is the stable identity a finding is updated against.
type FindingInfo struct {
	UID   string `json:"uid"`
	Title string `json:"title,omitempty"`
	Desc  string `json:"desc,omitempty"`

	Analytic *Analytic `json:"analytic,omitempty"`
	Attacks  []Attack  `json:"attacks,omitempty"`

	CreatedTime   time.Time `json:"created_time,omitempty"`
	FirstSeenTime time.Time `json:"first_seen_time,omitempty"`
	LastSeenTime  time.Time `json:"last_seen_time,omitempty"`
	ModifiedTime  time.Time `json:"modified_time,omitempty"`

	// RelatedEvents are the events the analytic examined. This is the documented
	// route from a finding back to the telemetry that produced it.
	RelatedEvents      []RelatedEvent `json:"related_events,omitempty"`
	RelatedEventsCount int            `json:"related_events_count,omitempty"`

	SrcURL string   `json:"src_url,omitempty"`
	Types  []string `json:"types,omitempty"`
	UIDAlt string   `json:"uid_alt,omitempty"`
}

// RelatedEvent references an event that contributed to a finding.
type RelatedEvent struct {
	UID     string `json:"uid,omitempty"`
	TypeUID int    `json:"type_uid,omitempty"`
	Type    string `json:"type,omitempty"`
}

// Analytic describes the rule or model that produced a finding.
type Analytic struct {
	Name      string `json:"name,omitempty"`
	UID       string `json:"uid,omitempty"`
	Type      string `json:"type,omitempty"`
	TypeID    int    `json:"type_id,omitempty"`
	Category  string `json:"category,omitempty"`
	Desc      string `json:"desc,omitempty"`
	Algorithm string `json:"algorithm,omitempty"`
	Version   string `json:"version,omitempty"`
}

// Attack is a MITRE ATT&CK tactic/technique association.
type Attack struct {
	Tactic       *AttackNode  `json:"tactic,omitempty"`
	Tactics      []AttackNode `json:"tactics,omitempty"`
	Technique    *AttackNode  `json:"technique,omitempty"`
	SubTechnique *AttackNode  `json:"sub_technique,omitempty"`
	Version      string       `json:"version,omitempty"`
}

// AttackNode is a named ATT&CK entity (tactic, technique or sub-technique).
type AttackNode struct {
	Name   string `json:"name,omitempty"`
	UID    string `json:"uid,omitempty"`
	SrcURL string `json:"src_url,omitempty"`
}

// Evidence mirrors the OCSF evidences object — the artifacts associated with the
// activity that triggered a detection. Only the subset Console-IR renders is
// modelled; the complete object is preserved in the finding's raw JSON.
type Evidence struct {
	Name        string          `json:"name,omitempty"`
	UID         string          `json:"uid,omitempty"`
	Verdict     string          `json:"verdict,omitempty"`
	VerdictID   int             `json:"verdict_id,omitempty"`
	Actor       *Actor          `json:"actor,omitempty"`
	Device      *Device         `json:"device,omitempty"`
	Process     *Process        `json:"process,omitempty"`
	File        *File           `json:"file,omitempty"`
	User        *User           `json:"user,omitempty"`
	SrcEndpoint *Endpoint       `json:"src_endpoint,omitempty"`
	DstEndpoint *Endpoint       `json:"dst_endpoint,omitempty"`
	Data        json.RawMessage `json:"data,omitempty"`
}

// Finding activity_id values. A finding is a mutable object represented as an
// append-only stream of these.
const (
	FindingActivityUnknown = 0
	FindingActivityCreate  = 1
	FindingActivityUpdate  = 2
	FindingActivityClose   = 3
)

// status_id for classes deriving from the base `finding` class.
const (
	FindingStatusUnknown    = 0
	FindingStatusNew        = 1
	FindingStatusInProgress = 2
	FindingStatusSuppressed = 3
	FindingStatusResolved   = 4
	FindingStatusArchived   = 5
	FindingStatusDeleted    = 6
)

// status_id for Incident Finding (2005), which defines its own set.
const (
	IncidentStatusNew        = 1
	IncidentStatusInProgress = 2
	IncidentStatusOnHold     = 3
	IncidentStatusResolved   = 4
	IncidentStatusClosed     = 5
)

// verdict_id, shared by the incident profile and the evidences object.
const (
	VerdictUnknown          = 0
	VerdictFalsePositive    = 1
	VerdictTruePositive     = 2
	VerdictDisregard        = 3
	VerdictSuspicious       = 4
	VerdictBenign           = 5
	VerdictTest             = 6
	VerdictInsufficientData = 7
	VerdictSecurityRisk     = 8
	VerdictManagedExternal  = 9
	VerdictDuplicate        = 10
)

var findingStatusNames = map[int]string{
	FindingStatusUnknown:    "Unknown",
	FindingStatusNew:        "New",
	FindingStatusInProgress: "In Progress",
	FindingStatusSuppressed: "Suppressed",
	FindingStatusResolved:   "Resolved",
	FindingStatusArchived:   "Archived",
	FindingStatusDeleted:    "Deleted",
}

var incidentStatusNames = map[int]string{
	0:                        "Unknown",
	IncidentStatusNew:        "New",
	IncidentStatusInProgress: "In Progress",
	IncidentStatusOnHold:     "On Hold",
	IncidentStatusResolved:   "Resolved",
	IncidentStatusClosed:     "Closed",
}

var verdictNames = map[int]string{
	VerdictUnknown:          "Unknown",
	VerdictFalsePositive:    "False Positive",
	VerdictTruePositive:     "True Positive",
	VerdictDisregard:        "Disregard",
	VerdictSuspicious:       "Suspicious",
	VerdictBenign:           "Benign",
	VerdictTest:             "Test",
	VerdictInsufficientData: "Insufficient Data",
	VerdictSecurityRisk:     "Security Risk",
	VerdictManagedExternal:  "Managed Externally",
	VerdictDuplicate:        "Duplicate",
	99:                      "Other",
}

// Low/Medium/High/Critical, shared by priority_id, impact_id and confidence_id
// (confidence stops at High).
var severityScaleNames = map[int]string{
	0: "Unknown", 1: "Low", 2: "Medium", 3: "High", 4: "Critical", 99: "Other",
}

// FindingStatusName resolves a status_id caption. Incident Finding (2005)
// defines a different set from the other Findings classes, so the class matters.
func FindingStatusName(classUID, statusID int) string {
	table := findingStatusNames
	if classUID == ClassIncidentFinding {
		table = incidentStatusNames
	}
	if name, ok := table[statusID]; ok {
		return name
	}
	return "Unknown"
}

// FindingStatuses lists the selectable triage states for a class, in enum order.
func FindingStatuses(classUID int) []int {
	if classUID == ClassIncidentFinding {
		return []int{IncidentStatusNew, IncidentStatusInProgress, IncidentStatusOnHold,
			IncidentStatusResolved, IncidentStatusClosed}
	}
	return []int{FindingStatusNew, FindingStatusInProgress, FindingStatusSuppressed,
		FindingStatusResolved, FindingStatusArchived}
}

// VerdictName resolves a verdict_id caption.
func VerdictName(id int) string {
	if name, ok := verdictNames[id]; ok {
		return name
	}
	return "Unknown"
}

// Verdicts lists the selectable verdicts an analyst can assign, in enum order.
func Verdicts() []int {
	return []int{VerdictTruePositive, VerdictFalsePositive, VerdictSuspicious,
		VerdictBenign, VerdictDisregard, VerdictInsufficientData, VerdictDuplicate}
}

// ConfidenceName resolves a confidence_id caption (Unknown/Low/Medium/High).
func ConfidenceName(id int) string {
	if id == 4 { // confidence_id stops at High; 4 is not defined
		return "Unknown"
	}
	if name, ok := severityScaleNames[id]; ok {
		return name
	}
	return "Unknown"
}

// PriorityName resolves a priority_id caption.
func PriorityName(id int) string {
	if name, ok := severityScaleNames[id]; ok {
		return name
	}
	return "Unknown"
}

// ImpactName resolves an impact_id caption.
func ImpactName(id int) string { return PriorityName(id) }

// Title returns the best available human label for the finding. Findings carry
// their text in finding_info.title rather than message, so falling back to
// message alone leaves most findings blank.
func (f *Finding) Title() string {
	if f.FindingInfo.Title != "" {
		return f.FindingInfo.Title
	}
	if f.Message != "" {
		return f.Message
	}
	if f.FindingInfo.Desc != "" {
		return f.FindingInfo.Desc
	}
	return f.GetClassName()
}

// UID is the stable identity a finding is updated against.
func (f *Finding) UID() string { return f.FindingInfo.UID }

// AnalyticName returns the rule or model that produced the finding.
func (f *Finding) AnalyticName() string {
	if f.FindingInfo.Analytic != nil {
		return f.FindingInfo.Analytic.Name
	}
	return ""
}

// StatusName resolves the finding's status caption, preferring the producer's
// own label when supplied.
func (f *Finding) StatusName() string {
	if f.Status != "" {
		return f.Status
	}
	return FindingStatusName(f.ClassUID, f.StatusID)
}

// VerdictName resolves the finding's verdict caption.
func (f *Finding) VerdictName() string {
	if f.Verdict != "" {
		return f.Verdict
	}
	if f.VerdictID == VerdictUnknown {
		return ""
	}
	return VerdictName(f.VerdictID)
}

// AttackTechniques returns the ATT&CK technique identifiers on the finding, for
// compact display (e.g. "T1059.001").
func (f *Finding) AttackTechniques() []string {
	var out []string
	for _, a := range f.FindingInfo.Attacks {
		if a.SubTechnique != nil && a.SubTechnique.UID != "" {
			out = append(out, a.SubTechnique.UID)
			continue
		}
		if a.Technique != nil && a.Technique.UID != "" {
			out = append(out, a.Technique.UID)
		}
	}
	return out
}

// FirstSeen reports when the earliest contributing activity occurred, falling
// back through the finding's own timestamps.
//
// OCSF is explicit that `time` on a finding is "the finding creation time — when
// the finding was first generated, not when the underlying activity occurred",
// while start_time is "the time of the earliest event or finding that
// contributed". A timeline that uses `time` alone misplaces the activity.
func (f *Finding) FirstSeen() time.Time {
	if !f.FindingInfo.FirstSeenTime.IsZero() {
		return f.FindingInfo.FirstSeenTime
	}
	if !f.StartTime.IsZero() {
		return f.StartTime
	}
	return f.Time
}

// LastSeen reports when the most recent contributing activity occurred.
func (f *Finding) LastSeen() time.Time {
	if !f.FindingInfo.LastSeenTime.IsZero() {
		return f.FindingInfo.LastSeenTime
	}
	if !f.EndTime.IsZero() {
		return f.EndTime
	}
	return f.Time
}
