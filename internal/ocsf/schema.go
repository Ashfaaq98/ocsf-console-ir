package ocsf

import (
	"encoding/json"
	"strconv"
	"time"
)

// EventType is the coarse, category-derived grouping persisted in
// events.event_type. It is a display and filtering convenience only — class_uid
// and category_uid are the authoritative OCSF identity.
type EventType string

const (
	EventTypeSystem      EventType = "system"
	EventTypeFindings    EventType = "findings"
	EventTypeIAM         EventType = "iam"
	EventTypeNetwork     EventType = "network"
	EventTypeDiscovery   EventType = "discovery"
	EventTypeApplication EventType = "application"
	EventTypeRemediation EventType = "remediation"
	EventTypeUnmanned    EventType = "unmanned"
	EventTypeUnknown     EventType = "unknown"
)

// Event represents a normalized OCSF event with core fields
type Event struct {
	// Core OCSF fields
	ActivityID  int       `json:"activity_id"`
	CategoryUID int       `json:"category_uid"`
	ClassUID    int       `json:"class_uid"`
	Count       int       `json:"count,omitempty"`
	Message     string    `json:"message,omitempty"`
	Severity    string    `json:"severity,omitempty"`
	SeverityID  int       `json:"severity_id,omitempty"`
	Time        time.Time `json:"time"`
	TypeName    string    `json:"type_name,omitempty"`
	TypeUID     int       `json:"type_uid"`

	// Metadata
	Metadata Metadata `json:"metadata"`

	// Actor (user/process that initiated the event)
	Actor *Actor `json:"actor,omitempty"`

	// Device information
	Device *Device `json:"device,omitempty"`

	// Network connection details
	SrcEndpoint *Endpoint `json:"src_endpoint,omitempty"`
	DstEndpoint *Endpoint `json:"dst_endpoint,omitempty"`

	// Process information
	Process *Process `json:"process,omitempty"`
	Parent  *Process `json:"parent,omitempty"`

	// File information
	File *File `json:"file,omitempty"`

	// Authentication details
	User *User `json:"user,omitempty"`

	// Observables (IOCs, artifacts)
	Observables []Observable `json:"observables,omitempty"`

	// Raw event data for preservation
	RawData json.RawMessage `json:"raw_data,omitempty"`
}

// Metadata contains event metadata
type Metadata struct {
	// UID is metadata.uid: the producer's unique identifier for this event.
	// It is the stable identity an observable's event_uid refers back to.
	UID            string            `json:"uid,omitempty"`
	CorrelationUID string            `json:"correlation_uid,omitempty"`
	EventCode      string            `json:"event_code,omitempty"`
	LogLevel       string            `json:"log_level,omitempty"`
	LogName        string            `json:"log_name,omitempty"`
	LogProvider    string            `json:"log_provider,omitempty"`
	Product        Product           `json:"product,omitempty"`
	Profiles       []string          `json:"profiles,omitempty"`
	Version        string            `json:"version,omitempty"`
	Extensions     map[string]string `json:"extensions,omitempty"`
}

// Product information
type Product struct {
	Name    string `json:"name,omitempty"`
	Vendor  string `json:"vendor_name,omitempty"`
	Version string `json:"version,omitempty"`
	Feature string `json:"feature,omitempty"`
}

// Actor represents the entity that initiated the event
type Actor struct {
	Process *Process `json:"process,omitempty"`
	User    *User    `json:"user,omitempty"`
	Session *Session `json:"session,omitempty"`
}

// Device represents a host/device
type Device struct {
	Hostname string `json:"hostname,omitempty"`
	IP       string `json:"ip,omitempty"`
	MAC      string `json:"mac,omitempty"`
	Name     string `json:"name,omitempty"`
	Type     string `json:"type,omitempty"`
	UID      string `json:"uid,omitempty"`
	OS       *OS    `json:"os,omitempty"`
}

// OS represents operating system information
type OS struct {
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`
	Build   string `json:"build,omitempty"`
}

// Endpoint represents a network endpoint
type Endpoint struct {
	IP       string `json:"ip,omitempty"`
	Port     int    `json:"port,omitempty"`
	Hostname string `json:"hostname,omitempty"`
	MAC      string `json:"mac,omitempty"`
	Domain   string `json:"domain,omitempty"`
}

// Process represents process information
type Process struct {
	Name        string   `json:"name,omitempty"`
	PID         int      `json:"pid,omitempty"`
	UID         string   `json:"uid,omitempty"`
	CommandLine string   `json:"cmd_line,omitempty"`
	File        *File    `json:"file,omitempty"`
	User        *User    `json:"user,omitempty"`
	Session     *Session `json:"session,omitempty"`
}

// File represents file information
type File struct {
	Name      string            `json:"name,omitempty"`
	Path      string            `json:"path,omitempty"`
	Size      int64             `json:"size,omitempty"`
	Type      string            `json:"type,omitempty"`
	MimeType  string            `json:"mime_type,omitempty"`
	Hashes    map[string]string `json:"hashes,omitempty"`
	Signature *Signature        `json:"signature,omitempty"`
}

// Signature represents file signature information
type Signature struct {
	Algorithm   string `json:"algorithm,omitempty"`
	Certificate string `json:"certificate,omitempty"`
	Developer   string `json:"developer,omitempty"`
}

// User represents user information
type User struct {
	Name   string   `json:"name,omitempty"`
	UID    string   `json:"uid,omitempty"`
	Domain string   `json:"domain,omitempty"`
	Email  string   `json:"email,omitempty"`
	Groups []string `json:"groups,omitempty"`
}

// Session represents session information
type Session struct {
	UID         string    `json:"uid,omitempty"`
	CreatedTime time.Time `json:"created_time,omitempty"`
	IsRemote    bool      `json:"is_remote,omitempty"`
}

// Observable represents an observable artifact or IOC.
//
// Per the OCSF docs, observables are "a pivot element that contains related
// information found in many places in the event" — they reference data that
// already exists elsewhere in the event, as a query optimization. Name is
// therefore a pointer to the source attribute (e.g. "src_endpoint.ip"), not a
// human label.
type Observable struct {
	Name string `json:"name"`
	Type string `json:"type,omitempty"`
	// TypeID is the only required attribute of the OCSF observable object.
	TypeID int    `json:"type_id"`
	Value  string `json:"value,omitempty"`
	// EventUID is metadata.uid of the event this observable was extracted from.
	EventUID   string      `json:"event_uid,omitempty"`
	Reputation *Reputation `json:"reputation,omitempty"`
}

// Reputation describes the reputation/risk score of an entity. OCSF models this
// as an object; treating it as a bare integer silently discards the provider and
// the normalized score.
type Reputation struct {
	BaseScore float64 `json:"base_score,omitempty"`
	Provider  string  `json:"provider,omitempty"`
	Score     string  `json:"score,omitempty"`
	ScoreID   int     `json:"score_id,omitempty"`
}

// newObservable builds an observable with its type caption resolved from the
// vendored enum, so Type and TypeID never disagree.
func newObservable(name string, typeID int, value string) Observable {
	return Observable{
		Name:   name,
		Type:   ObservableTypeName(typeID),
		TypeID: typeID,
		Value:  value,
	}
}

// GetEventType returns the coarse category grouping for the event.
//
// The class registry is authoritative: class_uid identifies the class, and the
// class knows which category it belongs to. Only when the class is absent from
// the registry — an extension, or a class added after this build's OCSF release
// — do we fall back to the category_uid the producer declared.
func (e *Event) GetEventType() EventType {
	return EventType(CategorySlug(e.GetCategoryUID()))
}

// GetClassName returns the OCSF caption for the event's class, e.g. "Detection Finding".
func (e *Event) GetClassName() string { return ClassName(e.ClassUID) }

// GetCategoryName returns the OCSF caption for the event's category.
func (e *Event) GetCategoryName() string { return CategoryName(e.GetCategoryUID()) }

// GetCategoryUID returns the effective category for the event.
//
// A class found in the registry is authoritative, except for Base Event
// (class_uid 0), which is deliberately uncategorized — for that, and for classes
// absent from the registry, the producer's declared category_uid is used.
func (e *Event) GetCategoryUID() int {
	if c, ok := LookupClass(e.ClassUID); ok && c.CategoryUID != CategoryUncategorized {
		return c.CategoryUID
	}
	return e.CategoryUID
}

// IsFinding reports whether this event belongs to the OCSF Findings category.
func (e *Event) IsFinding() bool { return e.GetCategoryUID() == CategoryFindings }

// The OCSF severity_id enum.
//
// Note that Other is 99 rather than 7: it is a sentinel, not the top of the
// scale. Any comparison of the form `severity_id >= Critical` is wrong for that
// reason, and must enumerate the levels it means instead.
const (
	SeverityUnknown       = 0
	SeverityInformational = 1
	SeverityLow           = 2
	SeverityMedium        = 3
	SeverityHigh          = 4
	SeverityCritical      = 5
	SeverityFatal         = 6
	SeverityOther         = 99
)

// GetSeverityLevel returns a normalized severity level, covering the full OCSF
// severity_id enum (0, 1-6, 99).
func (e *Event) GetSeverityLevel() string {
	if e.Severity != "" {
		return e.Severity
	}

	switch e.SeverityID {
	case SeverityUnknown:
		return "unknown"
	case SeverityInformational:
		return "informational"
	case SeverityLow:
		return "low"
	case SeverityMedium:
		return "medium"
	case SeverityHigh:
		return "high"
	case SeverityCritical:
		return "critical"
	case SeverityFatal:
		return "fatal"
	case SeverityOther:
		return "other"
	default:
		return "unknown"
	}
}

// DeriveObservables builds observables from the event's structured fields.
//
// It returns ONLY the derived set — it deliberately excludes e.Observables, which
// are the producer's own assertions. Keeping the two apart matters: an analyst
// should be able to tell an indicator the source vouched for from one this tool
// inferred.
//
// Names follow the OCSF convention of pointing at the source attribute, so a
// derived observable is shaped like an asserted one.
func (e *Event) DeriveObservables() []Observable {
	var observables []Observable

	if e.SrcEndpoint != nil {
		if e.SrcEndpoint.IP != "" {
			observables = append(observables, newObservable("src_endpoint.ip", ObservableTypeIPAddress, e.SrcEndpoint.IP))
		}
		if e.SrcEndpoint.Hostname != "" {
			observables = append(observables, newObservable("src_endpoint.hostname", ObservableTypeHostname, e.SrcEndpoint.Hostname))
		}
	}
	if e.DstEndpoint != nil {
		if e.DstEndpoint.IP != "" {
			observables = append(observables, newObservable("dst_endpoint.ip", ObservableTypeIPAddress, e.DstEndpoint.IP))
		}
		if e.DstEndpoint.Hostname != "" {
			observables = append(observables, newObservable("dst_endpoint.hostname", ObservableTypeHostname, e.DstEndpoint.Hostname))
		}
	}

	if e.File != nil {
		if e.File.Name != "" {
			observables = append(observables, newObservable("file.name", ObservableTypeFileName, e.File.Name))
		}
		for hashType, hashValue := range e.File.Hashes {
			if hashValue != "" {
				observables = append(observables, newObservable("file.hashes."+hashType, ObservableTypeHash, hashValue))
			}
		}
	}

	if e.Process != nil {
		if e.Process.Name != "" {
			observables = append(observables, newObservable("process.name", ObservableTypeProcessName, e.Process.Name))
		}
		if e.Process.File != nil {
			for hashType, hashValue := range e.Process.File.Hashes {
				if hashValue != "" {
					observables = append(observables, newObservable("process.file.hashes."+hashType, ObservableTypeHash, hashValue))
				}
			}
		}
	}

	if e.Device != nil {
		if e.Device.Hostname != "" {
			observables = append(observables, newObservable("device.hostname", ObservableTypeHostname, e.Device.Hostname))
		}
		if e.Device.IP != "" {
			observables = append(observables, newObservable("device.ip", ObservableTypeIPAddress, e.Device.IP))
		}
	}

	if e.User != nil {
		if e.User.Name != "" {
			observables = append(observables, newObservable("user.name", ObservableTypeUserName, e.User.Name))
		}
		if e.User.Email != "" {
			observables = append(observables, newObservable("user.email", ObservableTypeEmail, e.User.Email))
		}
	}

	// Stamp the source event so a pivot can navigate back to it.
	if e.Metadata.UID != "" {
		for i := range observables {
			observables[i].EventUID = e.Metadata.UID
		}
	}

	return observables
}

// NormalizeObservable fills in whichever of Type/TypeID the producer omitted, so
// the two never disagree and pivot queries can rely on TypeID.
func (e *Event) NormalizeObservable(o Observable) Observable {
	if o.TypeID == ObservableTypeUnknown && o.Type != "" {
		if id, ok := ObservableTypeIDFor(o.Type); ok {
			o.TypeID = id
		}
	}
	// Keep the caption in step with the id. Informal spellings ("ip", "sha256")
	// resolve to a type_id, and storing the canonical caption alongside it stops
	// the two disagreeing. Unknown/Other keep whatever the producer supplied,
	// since that is where vendor-specific detail lives.
	switch o.TypeID {
	case ObservableTypeUnknown, ObservableTypeOther:
	default:
		o.Type = ObservableTypeName(o.TypeID)
	}
	if o.EventUID == "" {
		o.EventUID = e.Metadata.UID
	}
	return o
}

// ExtractObservables returns the producer-asserted observables followed by the
// derived ones, deduplicated on (type_id, value) with asserted entries winning.
func (e *Event) ExtractObservables() []Observable {
	out := make([]Observable, 0, len(e.Observables))
	seen := make(map[string]bool, len(e.Observables))

	key := func(o Observable) string {
		return strconv.Itoa(o.TypeID) + "\x00" + o.Value
	}

	for _, o := range e.Observables {
		o = e.NormalizeObservable(o)
		if seen[key(o)] {
			continue
		}
		seen[key(o)] = true
		out = append(out, o)
	}

	for _, o := range e.DeriveObservables() {
		if seen[key(o)] {
			continue
		}
		seen[key(o)] = true
		out = append(out, o)
	}

	return out
}
