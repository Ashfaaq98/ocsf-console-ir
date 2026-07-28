package ocsf

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
)

// classesJSON is a vendored, point-in-time copy of the OCSF class registry.
// It is embedded rather than fetched so the binary keeps working offline; refresh
// it with scripts/gen-ocsf-classes.sh when adopting a new OCSF release.
//
//go:embed classes.json
var classesJSON []byte

// ClassInfo describes a single OCSF event class.
type ClassInfo struct {
	UID         int    `json:"uid"`
	Name        string `json:"name"`
	CategoryUID int    `json:"cat"`
	// Deprecated records the OCSF version that deprecated the class, if any.
	Deprecated string `json:"deprecated,omitempty"`
}

// CategoryInfo describes an OCSF category. Slug is the short, stable identifier
// persisted in events.event_type and used for coarse filtering.
type CategoryInfo struct {
	UID  int    `json:"uid"`
	Name string `json:"name"`
	Slug string `json:"slug"`
}

type registryFile struct {
	SchemaVersion string         `json:"schema_version"`
	Source        string         `json:"source"`
	Categories    []CategoryInfo `json:"categories"`
	Classes       []ClassInfo    `json:"classes"`
}

type registry struct {
	schemaVersion string
	categories    []CategoryInfo
	classes       []ClassInfo
	byClass       map[int]ClassInfo
	byCategory    map[int]CategoryInfo
}

var (
	regOnce sync.Once
	reg     *registry
)

func loadRegistry() *registry {
	regOnce.Do(func() {
		var f registryFile
		if err := json.Unmarshal(classesJSON, &f); err != nil {
			// The registry is embedded at build time, so a parse failure is a
			// programming error rather than a runtime condition.
			panic(fmt.Sprintf("ocsf: embedded classes.json is invalid: %v", err))
		}

		r := &registry{
			schemaVersion: f.SchemaVersion,
			categories:    f.Categories,
			classes:       f.Classes,
			byClass:       make(map[int]ClassInfo, len(f.Classes)),
			byCategory:    make(map[int]CategoryInfo, len(f.Categories)),
		}
		for _, c := range f.Classes {
			r.byClass[c.UID] = c
		}
		for _, c := range f.Categories {
			r.byCategory[c.UID] = c
		}
		reg = r
	})
	return reg
}

// SchemaVersion reports the OCSF release the embedded registry was generated from.
func SchemaVersion() string { return loadRegistry().schemaVersion }

// LookupClass returns the class matching uid.
func LookupClass(uid int) (ClassInfo, bool) {
	c, ok := loadRegistry().byClass[uid]
	return c, ok
}

// ClassName returns the OCSF caption for a class UID, or a readable placeholder
// for classes absent from the embedded registry (extensions, newer releases).
func ClassName(uid int) string {
	if c, ok := LookupClass(uid); ok {
		return c.Name
	}
	if uid == 0 {
		return "Unknown"
	}
	return fmt.Sprintf("Class %d", uid)
}

// LookupCategory returns the category matching uid.
func LookupCategory(uid int) (CategoryInfo, bool) {
	c, ok := loadRegistry().byCategory[uid]
	return c, ok
}

// CategoryName returns the OCSF caption for a category UID.
func CategoryName(uid int) string {
	if c, ok := LookupCategory(uid); ok {
		return c.Name
	}
	return "Unknown"
}

// CategorySlug returns the short, stable identifier for a category UID. This is
// the value persisted in events.event_type; unrecognised categories map to
// "unknown" so the column is never empty.
func CategorySlug(uid int) string {
	if c, ok := LookupCategory(uid); ok && c.Slug != "" && c.UID != 0 {
		return c.Slug
	}
	return string(EventTypeUnknown)
}

// Categories returns every known category, ordered by UID. The synthetic
// "uncategorized" entry (UID 0) is omitted since it is not user-selectable.
func Categories() []CategoryInfo {
	r := loadRegistry()
	out := make([]CategoryInfo, 0, len(r.categories))
	for _, c := range r.categories {
		if c.UID == 0 {
			continue
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UID < out[j].UID })
	return out
}

// ClassesInCategory returns every known class belonging to a category, ordered by UID.
func ClassesInCategory(categoryUID int) []ClassInfo {
	r := loadRegistry()
	out := make([]ClassInfo, 0, 16)
	for _, c := range r.classes {
		if c.CategoryUID == categoryUID {
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UID < out[j].UID })
	return out
}

// IsFinding reports whether a class UID belongs to the Findings category (2).
// Findings carry investigation semantics — status, verdict, evidence — that
// activity classes do not.
func IsFinding(classUID int) bool {
	c, ok := LookupClass(classUID)
	return ok && c.CategoryUID == CategoryFindings
}

// OCSF category UIDs.
const (
	CategoryUncategorized = 0
	CategorySystem        = 1
	CategoryFindings      = 2
	CategoryIAM           = 3
	CategoryNetwork       = 4
	CategoryDiscovery     = 5
	CategoryApplication   = 6
	CategoryRemediation   = 7
	CategoryUnmanned      = 8
)

// Notable Findings class UIDs, called out because the investigation workflow
// keys on them directly.
const (
	ClassSecurityFinding  = 2001 // deprecated in OCSF 1.1.0
	ClassDetectionFinding = 2004
	ClassIncidentFinding  = 2005
)
