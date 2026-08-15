package ocsf

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
)

// observableTypesJSON is the vendored observable.type_id enum. type_id is the
// only required attribute of the observable object, so a reliable mapping between
// the numeric id and its caption is needed on both the read and write paths.
//
//go:embed observable_types.json
var observableTypesJSON []byte

// Common observable type IDs. These are the types Console-IR derives itself; the
// full enum lives in observable_types.json.
const (
	ObservableTypeUnknown     = 0
	ObservableTypeHostname    = 1
	ObservableTypeIPAddress   = 2
	ObservableTypeMACAddress  = 3
	ObservableTypeUserName    = 4
	ObservableTypeEmail       = 5
	ObservableTypeURLString   = 6
	ObservableTypeFileName    = 7
	ObservableTypeHash        = 8
	ObservableTypeProcessName = 9
	ObservableTypeURL         = 23
	ObservableTypeOther       = 99
)

// ObservableType pairs an observable type_id with its OCSF caption.
type ObservableType struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

type observableTypesFile struct {
	SchemaVersion string           `json:"schema_version"`
	Types         []ObservableType `json:"types"`
}

type observableTypeRegistry struct {
	types         []ObservableType
	byID          map[int]string
	byName        map[string]int
	schemaVersion string
}

var (
	obsOnce sync.Once
	obsReg  *observableTypeRegistry
)

func loadObservableTypes() *observableTypeRegistry {
	obsOnce.Do(func() {
		var f observableTypesFile
		if err := json.Unmarshal(observableTypesJSON, &f); err != nil {
			panic(fmt.Sprintf("ocsf: embedded observable_types.json is invalid: %v", err))
		}
		r := &observableTypeRegistry{
			types:         f.Types,
			byID:          make(map[int]string, len(f.Types)),
			byName:        make(map[string]int, len(f.Types)),
			schemaVersion: f.SchemaVersion,
		}
		for _, t := range f.Types {
			r.byID[t.ID] = t.Name
			r.byName[normalizeObservableName(t.Name)] = t.ID
		}
		obsReg = r
	})
	return obsReg
}

func normalizeObservableName(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

// ObservableTypeName returns the OCSF caption for an observable type_id.
func ObservableTypeName(id int) string {
	if name, ok := loadObservableTypes().byID[id]; ok {
		return name
	}
	return "Unknown"
}

// ObservableTypeIDFor resolves an observable type caption back to its type_id.
// It also accepts the short, lowercase aliases Console-IR and its enrichment
// plugins have historically used ("ip", "hash", "domain", ...), so observables
// recorded before type_id was captured can still be classified.
func ObservableTypeIDFor(name string) (int, bool) {
	n := normalizeObservableName(name)
	if n == "" {
		return ObservableTypeUnknown, false
	}
	if id, ok := loadObservableTypes().byName[n]; ok {
		return id, true
	}
	if id, ok := observableTypeAliases[n]; ok {
		return id, true
	}
	return ObservableTypeUnknown, false
}

// observableTypeAliases maps the informal type strings used elsewhere in the
// codebase (and by the threat-intel plugins) onto OCSF type IDs.
var observableTypeAliases = map[string]int{
	"ip":           ObservableTypeIPAddress,
	"ipv4":         ObservableTypeIPAddress,
	"ipv6":         ObservableTypeIPAddress,
	"ip_address":   ObservableTypeIPAddress,
	"source_ip":    ObservableTypeIPAddress,
	"src_ip":       ObservableTypeIPAddress,
	"dst_ip":       ObservableTypeIPAddress,
	"host":         ObservableTypeHostname,
	"hostname":     ObservableTypeHostname,
	"domain":       ObservableTypeHostname,
	"mac":          ObservableTypeMACAddress,
	"user":         ObservableTypeUserName,
	"username":     ObservableTypeUserName,
	"user_name":    ObservableTypeUserName,
	"email":        ObservableTypeEmail,
	"url":          ObservableTypeURLString,
	"uri":          ObservableTypeURLString,
	"file":         ObservableTypeFileName,
	"filename":     ObservableTypeFileName,
	"file_name":    ObservableTypeFileName,
	"hash":         ObservableTypeHash,
	"md5":          ObservableTypeHash,
	"sha1":         ObservableTypeHash,
	"sha256":       ObservableTypeHash,
	"sha512":       ObservableTypeHash,
	"file_hash":    ObservableTypeHash,
	"process":      ObservableTypeProcessName,
	"process_name": ObservableTypeProcessName,
}

// ObservableTypes returns the full vendored enum.
func ObservableTypes() []ObservableType {
	r := loadObservableTypes()
	out := make([]ObservableType, len(r.types))
	copy(out, r.types)
	return out
}

// ObservableSchemaVersion reports the OCSF release the embedded observable enum
// was generated from.
//
// Separate from SchemaVersion because the two files come from two endpoints and
// are refreshed by hand: they can drift, and a test says so when they do.
func ObservableSchemaVersion() string { return loadObservableTypes().schemaVersion }
