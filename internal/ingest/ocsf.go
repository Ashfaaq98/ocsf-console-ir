package ingest

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/ocsf"
)

// Parser handles OCSF event parsing and normalization
type Parser struct{}

// NewParser creates a new OCSF parser
func NewParser() *Parser {
	return &Parser{}
}

// ParseEvent parses raw JSON into an OCSF event
func (p *Parser) ParseEvent(rawJSON []byte) (*ocsf.Event, error) {
	var rawEvent map[string]interface{}
	if err := json.Unmarshal(rawJSON, &rawEvent); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON: %w", err)
	}

	event := &ocsf.Event{
		RawData: json.RawMessage(rawJSON),
	}

	// Parse core OCSF fields
	if err := p.parseCoreFields(rawEvent, event); err != nil {
		return nil, fmt.Errorf("failed to parse core fields: %w", err)
	}

	// Parse metadata
	if metadata, ok := rawEvent["metadata"].(map[string]interface{}); ok {
		event.Metadata = p.parseMetadata(metadata)
	}

	// Parse device information
	if device, ok := rawEvent["device"].(map[string]interface{}); ok {
		event.Device = p.parseDevice(device)
	}

	// Parse network endpoints
	if srcEndpoint, ok := rawEvent["src_endpoint"].(map[string]interface{}); ok {
		event.SrcEndpoint = p.parseEndpoint(srcEndpoint)
	}
	if dstEndpoint, ok := rawEvent["dst_endpoint"].(map[string]interface{}); ok {
		event.DstEndpoint = p.parseEndpoint(dstEndpoint)
	}

	// Parse process information
	if process, ok := rawEvent["process"].(map[string]interface{}); ok {
		event.Process = p.parseProcess(process)
	}
	if parent, ok := rawEvent["parent"].(map[string]interface{}); ok {
		event.Parent = p.parseProcess(parent)
	}

	// Parse file information
	if file, ok := rawEvent["file"].(map[string]interface{}); ok {
		event.File = p.parseFile(file)
	}

	// Parse user information
	if user, ok := rawEvent["user"].(map[string]interface{}); ok {
		event.User = p.parseUser(user)
	}

	// Parse actor information
	if actor, ok := rawEvent["actor"].(map[string]interface{}); ok {
		event.Actor = p.parseActor(actor)
	}

	// Parse observables
	if observables, ok := rawEvent["observables"].([]interface{}); ok {
		event.Observables = p.parseObservables(observables)
	}

	// Auto-extract additional observables
	event.Observables = append(event.Observables, event.ExtractObservables()...)

	return event, nil
}

// parseCoreFields parses the core OCSF fields
func (p *Parser) parseCoreFields(rawEvent map[string]interface{}, event *ocsf.Event) error {
	// Activity ID
	if activityID, ok := rawEvent["activity_id"]; ok {
		if id, err := p.toInt(activityID); err == nil {
			event.ActivityID = id
		}
	}

	// Category UID
	if categoryUID, ok := rawEvent["category_uid"]; ok {
		if uid, err := p.toInt(categoryUID); err == nil {
			event.CategoryUID = uid
		}
	}

	// Class UID (required for event type determination)
	if classUID, ok := rawEvent["class_uid"]; ok {
		if uid, err := p.toInt(classUID); err == nil {
			event.ClassUID = uid
		}
	}

	// Type UID
	if typeUID, ok := rawEvent["type_uid"]; ok {
		if uid, err := p.toInt(typeUID); err == nil {
			event.TypeUID = uid
		}
	}

	// Count
	if count, ok := rawEvent["count"]; ok {
		if c, err := p.toInt(count); err == nil {
			event.Count = c
		}
	}

	// Message
	if message, ok := rawEvent["message"].(string); ok {
		event.Message = message
	}

	// Severity
	if severity, ok := rawEvent["severity"].(string); ok {
		event.Severity = severity
	}

	// Severity ID
	if severityID, ok := rawEvent["severity_id"]; ok {
		if id, err := p.toInt(severityID); err == nil {
			event.SeverityID = id
		}
	}

	// Time (required field)
	if timeField, ok := rawEvent["time"]; ok {
		if t, err := p.parseTime(timeField); err == nil {
			event.Time = t
		} else {
			return fmt.Errorf("invalid time field: %w", err)
		}
	} else {
		// Default to current time if not provided
		event.Time = time.Now()
	}

	// Type name
	if typeName, ok := rawEvent["type_name"].(string); ok {
		event.TypeName = typeName
	}

	return nil
}

// parseMetadata parses metadata information
func (p *Parser) parseMetadata(metadata map[string]interface{}) ocsf.Metadata {
	meta := ocsf.Metadata{}

	if eventCode, ok := metadata["event_code"].(string); ok {
		meta.EventCode = eventCode
	}
	if logLevel, ok := metadata["log_level"].(string); ok {
		meta.LogLevel = logLevel
	}
	if logName, ok := metadata["log_name"].(string); ok {
		meta.LogName = logName
	}
	if logProvider, ok := metadata["log_provider"].(string); ok {
		meta.LogProvider = logProvider
	}
	if version, ok := metadata["version"].(string); ok {
		meta.Version = version
	}

	// Parse product information
	if product, ok := metadata["product"].(map[string]interface{}); ok {
		meta.Product = p.parseProduct(product)
	}

	// Parse profiles
	if profiles, ok := metadata["profiles"].([]interface{}); ok {
		for _, profile := range profiles {
			if profileStr, ok := profile.(string); ok {
				meta.Profiles = append(meta.Profiles, profileStr)
			}
		}
	}

	// Parse extensions
	if extensions, ok := metadata["extensions"].(map[string]interface{}); ok {
		meta.Extensions = make(map[string]string)
		for key, value := range extensions {
			if valueStr, ok := value.(string); ok {
				meta.Extensions[key] = valueStr
			}
		}
	}

	return meta
}

// parseProduct parses product information
func (p *Parser) parseProduct(product map[string]interface{}) ocsf.Product {
	prod := ocsf.Product{}

	if name, ok := product["name"].(string); ok {
		prod.Name = name
	}
	if vendor, ok := product["vendor_name"].(string); ok {
		prod.Vendor = vendor
	}
	if version, ok := product["version"].(string); ok {
		prod.Version = version
	}
	if feature, ok := product["feature"].(string); ok {
		prod.Feature = feature
	}

	return prod
}

// parseDevice parses device information
func (p *Parser) parseDevice(device map[string]interface{}) *ocsf.Device {
	dev := &ocsf.Device{}

	if hostname, ok := device["hostname"].(string); ok {
		dev.Hostname = hostname
	}
	if ip, ok := device["ip"].(string); ok {
		dev.IP = ip
	}
	if mac, ok := device["mac"].(string); ok {
		dev.MAC = mac
	}
	if name, ok := device["name"].(string); ok {
		dev.Name = name
	}
	if deviceType, ok := device["type"].(string); ok {
		dev.Type = deviceType
	}
	if uid, ok := device["uid"].(string); ok {
		dev.UID = uid
	}

	// Parse OS information
	if os, ok := device["os"].(map[string]interface{}); ok {
		dev.OS = p.parseOS(os)
	}

	return dev
}

// parseOS parses operating system information
func (p *Parser) parseOS(os map[string]interface{}) *ocsf.OS {
	osInfo := &ocsf.OS{}

	if name, ok := os["name"].(string); ok {
		osInfo.Name = name
	}
	if version, ok := os["version"].(string); ok {
		osInfo.Version = version
	}
	if build, ok := os["build"].(string); ok {
		osInfo.Build = build
	}

	return osInfo
}

// parseEndpoint parses network endpoint information
func (p *Parser) parseEndpoint(endpoint map[string]interface{}) *ocsf.Endpoint {
	ep := &ocsf.Endpoint{}

	if ip, ok := endpoint["ip"].(string); ok {
		ep.IP = ip
	}
	if port, ok := endpoint["port"]; ok {
		if portInt, err := p.toInt(port); err == nil {
			ep.Port = portInt
		}
	}
	if hostname, ok := endpoint["hostname"].(string); ok {
		ep.Hostname = hostname
	}
	if mac, ok := endpoint["mac"].(string); ok {
		ep.MAC = mac
	}
	if domain, ok := endpoint["domain"].(string); ok {
		ep.Domain = domain
	}

	return ep
}

// parseProcess parses process information
func (p *Parser) parseProcess(process map[string]interface{}) *ocsf.Process {
	proc := &ocsf.Process{}

	if name, ok := process["name"].(string); ok {
		proc.Name = name
	}
	if pid, ok := process["pid"]; ok {
		if pidInt, err := p.toInt(pid); err == nil {
			proc.PID = pidInt
		}
	}
	if uid, ok := process["uid"].(string); ok {
		proc.UID = uid
	}
	if cmdLine, ok := process["cmd_line"].(string); ok {
		proc.CommandLine = cmdLine
	}

	// Parse file information
	if file, ok := process["file"].(map[string]interface{}); ok {
		proc.File = p.parseFile(file)
	}

	// Parse user information
	if user, ok := process["user"].(map[string]interface{}); ok {
		proc.User = p.parseUser(user)
	}

	// Parse session information
	if session, ok := process["session"].(map[string]interface{}); ok {
		proc.Session = p.parseSession(session)
	}

	return proc
}

// parseFile parses file information
func (p *Parser) parseFile(file map[string]interface{}) *ocsf.File {
	f := &ocsf.File{}

	if name, ok := file["name"].(string); ok {
		f.Name = name
	}
	if path, ok := file["path"].(string); ok {
		f.Path = path
	}
	if size, ok := file["size"]; ok {
		if sizeInt, err := p.toInt64(size); err == nil {
			f.Size = sizeInt
		}
	}
	if fileType, ok := file["type"].(string); ok {
		f.Type = fileType
	}
	if mimeType, ok := file["mime_type"].(string); ok {
		f.MimeType = mimeType
	}

	// Parse hashes
	if hashes, ok := file["hashes"].(map[string]interface{}); ok {
		f.Hashes = make(map[string]string)
		for hashType, hashValue := range hashes {
			if hashStr, ok := hashValue.(string); ok {
				f.Hashes[hashType] = hashStr
			}
		}
	}

	// Parse signature information
	if signature, ok := file["signature"].(map[string]interface{}); ok {
		f.Signature = p.parseSignature(signature)
	}

	return f
}

// parseSignature parses file signature information
func (p *Parser) parseSignature(signature map[string]interface{}) *ocsf.Signature {
	sig := &ocsf.Signature{}

	if algorithm, ok := signature["algorithm"].(string); ok {
		sig.Algorithm = algorithm
	}
	if certificate, ok := signature["certificate"].(string); ok {
		sig.Certificate = certificate
	}
	if developer, ok := signature["developer"].(string); ok {
		sig.Developer = developer
	}

	return sig
}

// parseUser parses user information
func (p *Parser) parseUser(user map[string]interface{}) *ocsf.User {
	u := &ocsf.User{}

	if name, ok := user["name"].(string); ok {
		u.Name = name
	}
	if uid, ok := user["uid"].(string); ok {
		u.UID = uid
	}
	if domain, ok := user["domain"].(string); ok {
		u.Domain = domain
	}
	if email, ok := user["email"].(string); ok {
		u.Email = email
	}

	// Parse groups
	if groups, ok := user["groups"].([]interface{}); ok {
		for _, group := range groups {
			if groupStr, ok := group.(string); ok {
				u.Groups = append(u.Groups, groupStr)
			}
		}
	}

	return u
}

// parseSession parses session information
func (p *Parser) parseSession(session map[string]interface{}) *ocsf.Session {
	s := &ocsf.Session{}

	if uid, ok := session["uid"].(string); ok {
		s.UID = uid
	}
	if createdTime, ok := session["created_time"]; ok {
		if t, err := p.parseTime(createdTime); err == nil {
			s.CreatedTime = t
		}
	}
	if isRemote, ok := session["is_remote"].(bool); ok {
		s.IsRemote = isRemote
	}

	return s
}

// parseActor parses actor information
func (p *Parser) parseActor(actor map[string]interface{}) *ocsf.Actor {
	a := &ocsf.Actor{}

	if process, ok := actor["process"].(map[string]interface{}); ok {
		a.Process = p.parseProcess(process)
	}
	if user, ok := actor["user"].(map[string]interface{}); ok {
		a.User = p.parseUser(user)
	}
	if session, ok := actor["session"].(map[string]interface{}); ok {
		a.Session = p.parseSession(session)
	}

	return a
}

// parseObservables parses observable information
func (p *Parser) parseObservables(observables []interface{}) []ocsf.Observable {
	var obs []ocsf.Observable

	for _, observable := range observables {
		if obsMap, ok := observable.(map[string]interface{}); ok {
			o := ocsf.Observable{}

			if name, ok := obsMap["name"].(string); ok {
				o.Name = name
			}
			if obsType, ok := obsMap["type"].(string); ok {
				o.Type = obsType
			}
			if value, ok := obsMap["value"].(string); ok {
				o.Value = value
			}
			if reputation, ok := obsMap["reputation"]; ok {
				if repInt, err := p.toInt(reputation); err == nil {
					o.Reputation = repInt
				}
			}

			obs = append(obs, o)
		}
	}

	return obs
}

// parseTime parses various time formats into time.Time
func (p *Parser) parseTime(timeField interface{}) (time.Time, error) {
	switch t := timeField.(type) {
	case string:
		// Try RFC3339 format first
		if parsed, err := time.Parse(time.RFC3339, t); err == nil {
			return parsed, nil
		}
		// Try RFC3339Nano format
		if parsed, err := time.Parse(time.RFC3339Nano, t); err == nil {
			return parsed, nil
		}
		// Try Unix timestamp as string
		if timestamp, err := strconv.ParseInt(t, 10, 64); err == nil {
			// Check if it's milliseconds (13 digits) or seconds (10 digits)
			if timestamp > 9999999999 { // More than 10 digits = milliseconds
				return time.Unix(timestamp/1000, (timestamp%1000)*1000000), nil
			}
			return time.Unix(timestamp, 0), nil
		}
		return time.Time{}, fmt.Errorf("unable to parse time string: %s", t)
	case float64:
		// Check if it's milliseconds (13 digits) or seconds (10 digits)
		if t > 9999999999 { // More than 10 digits = milliseconds
			return time.Unix(int64(t)/1000, (int64(t)%1000)*1000000), nil
		}
		return time.Unix(int64(t), 0), nil
	case int64:
		// Check if it's milliseconds (13 digits) or seconds (10 digits)
		if t > 9999999999 { // More than 10 digits = milliseconds
			return time.Unix(t/1000, (t%1000)*1000000), nil
		}
		return time.Unix(t, 0), nil
	case int:
		// Check if it's milliseconds (13 digits) or seconds (10 digits)
		if int64(t) > 9999999999 { // More than 10 digits = milliseconds
			return time.Unix(int64(t)/1000, (int64(t)%1000)*1000000), nil
		}
		return time.Unix(int64(t), 0), nil
	default:
		return time.Time{}, fmt.Errorf("unsupported time type: %T", t)
	}
}

// toInt converts various numeric types to int
func (p *Parser) toInt(value interface{}) (int, error) {
	switch v := value.(type) {
	case int:
		return v, nil
	case int64:
		return int(v), nil
	case float64:
		return int(v), nil
	case string:
		return strconv.Atoi(v)
	default:
		return 0, fmt.Errorf("cannot convert %T to int", v)
	}
}

// toInt64 converts various numeric types to int64
func (p *Parser) toInt64(value interface{}) (int64, error) {
	switch v := value.(type) {
	case int:
		return int64(v), nil
	case int64:
		return v, nil
	case float64:
		return int64(v), nil
	case string:
		return strconv.ParseInt(v, 10, 64)
	default:
		return 0, fmt.Errorf("cannot convert %T to int64", v)
	}
}