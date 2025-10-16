package ocsf

import (
	"encoding/json"
	"time"
)

// EventType represents the type of OCSF event
type EventType string

const (
	EventTypeNetwork        EventType = "network"
	EventTypeProcess        EventType = "process"
	EventTypeFile           EventType = "file"
	EventTypeAuthentication EventType = "authentication"
	EventTypeUnknown        EventType = "unknown"
)

// Event represents a normalized OCSF event with core fields
type Event struct {
	// Core OCSF fields
	ActivityID   int       `json:"activity_id"`
	CategoryUID  int       `json:"category_uid"`
	ClassUID     int       `json:"class_uid"`
	Count        int       `json:"count,omitempty"`
	Message      string    `json:"message,omitempty"`
	Severity     string    `json:"severity,omitempty"`
	SeverityID   int       `json:"severity_id,omitempty"`
	Time         time.Time `json:"time"`
	TypeName     string    `json:"type_name,omitempty"`
	TypeUID      int       `json:"type_uid"`
	
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
	EventCode    string            `json:"event_code,omitempty"`
	LogLevel     string            `json:"log_level,omitempty"`
	LogName      string            `json:"log_name,omitempty"`
	LogProvider  string            `json:"log_provider,omitempty"`
	Product      Product           `json:"product,omitempty"`
	Profiles     []string          `json:"profiles,omitempty"`
	Version      string            `json:"version,omitempty"`
	Extensions   map[string]string `json:"extensions,omitempty"`
}

// Product information
type Product struct {
	Name     string `json:"name,omitempty"`
	Vendor   string `json:"vendor_name,omitempty"`
	Version  string `json:"version,omitempty"`
	Feature  string `json:"feature,omitempty"`
}

// Actor represents the entity that initiated the event
type Actor struct {
	Process *Process `json:"process,omitempty"`
	User    *User    `json:"user,omitempty"`
	Session *Session `json:"session,omitempty"`
}

// Device represents a host/device
type Device struct {
	Hostname   string `json:"hostname,omitempty"`
	IP         string `json:"ip,omitempty"`
	MAC        string `json:"mac,omitempty"`
	Name       string `json:"name,omitempty"`
	Type       string `json:"type,omitempty"`
	UID        string `json:"uid,omitempty"`
	OS         *OS    `json:"os,omitempty"`
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
	Name       string            `json:"name,omitempty"`
	Path       string            `json:"path,omitempty"`
	Size       int64             `json:"size,omitempty"`
	Type       string            `json:"type,omitempty"`
	MimeType   string            `json:"mime_type,omitempty"`
	Hashes     map[string]string `json:"hashes,omitempty"`
	Signature  *Signature        `json:"signature,omitempty"`
}

// Signature represents file signature information
type Signature struct {
	Algorithm   string `json:"algorithm,omitempty"`
	Certificate string `json:"certificate,omitempty"`
	Developer   string `json:"developer,omitempty"`
}

// User represents user information
type User struct {
	Name     string   `json:"name,omitempty"`
	UID      string   `json:"uid,omitempty"`
	Domain   string   `json:"domain,omitempty"`
	Email    string   `json:"email,omitempty"`
	Groups   []string `json:"groups,omitempty"`
}

// Session represents session information
type Session struct {
	UID        string    `json:"uid,omitempty"`
	CreatedTime time.Time `json:"created_time,omitempty"`
	IsRemote   bool      `json:"is_remote,omitempty"`
}

// Observable represents an observable artifact or IOC
type Observable struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Value    string `json:"value"`
	Reputation int `json:"reputation,omitempty"`
}

// GetEventType determines the event type based on OCSF class UID
func (e *Event) GetEventType() EventType {
	switch e.ClassUID {
	case 4001, 4002, 4003, 4004, 4005, 4006: // Network Activity classes
		return EventTypeNetwork
	case 1001, 1002, 1003, 1004, 1005: // Process Activity classes
		return EventTypeProcess
	case 2001, 2002, 2003, 2004, 2005: // File Activity classes
		return EventTypeFile
	case 3001, 3002, 3003, 3004, 3005: // Authentication classes
		return EventTypeAuthentication
	default:
		return EventTypeUnknown
	}
}

// GetSeverityLevel returns a normalized severity level
func (e *Event) GetSeverityLevel() string {
	if e.Severity != "" {
		return e.Severity
	}
	
	// Map severity ID to level
	switch e.SeverityID {
	case 1:
		return "informational"
	case 2:
		return "low"
	case 3:
		return "medium"
	case 4:
		return "high"
	case 5:
		return "critical"
	default:
		return "unknown"
	}
}

// ExtractObservables extracts potential observables from the event
func (e *Event) ExtractObservables() []Observable {
	var observables []Observable
	
	// Add existing observables
	observables = append(observables, e.Observables...)
	
	// Extract IP addresses
	if e.SrcEndpoint != nil && e.SrcEndpoint.IP != "" {
		observables = append(observables, Observable{
			Name:  "source_ip",
			Type:  "ip",
			Value: e.SrcEndpoint.IP,
		})
	}
	
	if e.DstEndpoint != nil && e.DstEndpoint.IP != "" {
		observables = append(observables, Observable{
			Name:  "destination_ip",
			Type:  "ip",
			Value: e.DstEndpoint.IP,
		})
	}
	
	// Extract file hashes
	if e.File != nil && e.File.Hashes != nil {
		for hashType, hashValue := range e.File.Hashes {
			observables = append(observables, Observable{
				Name:  "file_hash",
				Type:  hashType,
				Value: hashValue,
			})
		}
	}
	
	// Extract hostnames
	if e.Device != nil && e.Device.Hostname != "" {
		observables = append(observables, Observable{
			Name:  "hostname",
			Type:  "hostname",
			Value: e.Device.Hostname,
		})
	}
	
	return observables
}