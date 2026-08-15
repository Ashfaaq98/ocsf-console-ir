package ocsf

import (
	"testing"
)

// TestRegistryClassLookup pins the class UIDs that the pre-registry mapping got
// wrong. Each case here was previously mislabelled by the hardcoded ranges in
// GetEventType: Findings were reported as "file", File System Activity as
// "process", and Process Activity fell through to "unknown".
func TestRegistryClassLookup(t *testing.T) {
	cases := []struct {
		uid     int
		name    string
		cat     int
		catName string
	}{
		{1001, "File System Activity", CategorySystem, "System Activity"},
		{1007, "Process Activity", CategorySystem, "System Activity"},
		{2001, "Security Finding", CategoryFindings, "Findings"},
		{2004, "Detection Finding", CategoryFindings, "Findings"},
		{2005, "Incident Finding", CategoryFindings, "Findings"},
		{3001, "Account Change", CategoryIAM, "Identity & Access Management"},
		{3002, "Authentication", CategoryIAM, "Identity & Access Management"},
		{4001, "Network Activity", CategoryNetwork, "Network Activity"},
		{4014, "Tunnel Activity", CategoryNetwork, "Network Activity"},
		{5001, "Device Inventory Info", CategoryDiscovery, "Discovery"},
		{6003, "API Activity", CategoryApplication, "Application Activity"},
		{7001, "Remediation Activity", CategoryRemediation, "Remediation"},
		{8001, "Drone Flights Activity", CategoryUnmanned, "Unmanned Systems"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := LookupClass(tc.uid)
			if !ok {
				t.Fatalf("class_uid %d missing from embedded registry", tc.uid)
			}
			if got.Name != tc.name {
				t.Errorf("class_uid %d: name = %q, want %q", tc.uid, got.Name, tc.name)
			}
			if got.CategoryUID != tc.cat {
				t.Errorf("class_uid %d: category = %d, want %d", tc.uid, got.CategoryUID, tc.cat)
			}
			if n := CategoryName(got.CategoryUID); n != tc.catName {
				t.Errorf("class_uid %d: category name = %q, want %q", tc.uid, n, tc.catName)
			}
		})
	}
}

// TestFindingsAreNotFiles is the regression guard for the defect this change
// exists to fix: the Findings category must never be reported as file activity.
func TestFindingsAreNotFiles(t *testing.T) {
	for _, uid := range []int{2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008} {
		e := &Event{ClassUID: uid, CategoryUID: CategoryFindings}
		if got := e.GetEventType(); got != EventTypeFindings {
			t.Errorf("class_uid %d: event type = %q, want %q", uid, got, EventTypeFindings)
		}
		if !e.IsFinding() {
			t.Errorf("class_uid %d: IsFinding() = false, want true", uid)
		}
		if !IsFinding(uid) {
			t.Errorf("IsFinding(%d) = false, want true", uid)
		}
	}
}

func TestGetEventTypeFallbacks(t *testing.T) {
	tests := []struct {
		name  string
		class int
		cat   int
		want  EventType
	}{
		{"known class wins over declared category", 4001, 1, EventTypeNetwork},
		{"unknown class falls back to category", 4999, 4, EventTypeNetwork},
		{"unknown class and category is unknown", 9999, 0, EventTypeUnknown},
		{"zero class with category", 0, 2, EventTypeFindings},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := &Event{ClassUID: tc.class, CategoryUID: tc.cat}
			if got := e.GetEventType(); got != tc.want {
				t.Errorf("GetEventType() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestClassNamePlaceholder(t *testing.T) {
	if got := ClassName(2004); got != "Detection Finding" {
		t.Errorf("ClassName(2004) = %q", got)
	}
	// Classes outside the vendored registry must degrade readably rather than
	// returning an empty string.
	if got := ClassName(123456); got != "Class 123456" {
		t.Errorf("ClassName(123456) = %q, want %q", got, "Class 123456")
	}
}

func TestCategoriesCoverAllSlugs(t *testing.T) {
	cats := Categories()
	if len(cats) != 8 {
		t.Fatalf("expected 8 selectable categories, got %d", len(cats))
	}
	seen := map[string]bool{}
	for _, c := range cats {
		if c.Slug == "" {
			t.Errorf("category %d has empty slug", c.UID)
		}
		if seen[c.Slug] {
			t.Errorf("duplicate category slug %q", c.Slug)
		}
		seen[c.Slug] = true
		if CategorySlug(c.UID) != c.Slug {
			t.Errorf("CategorySlug(%d) = %q, want %q", c.UID, CategorySlug(c.UID), c.Slug)
		}
	}
	// The synthetic uncategorized entry must not be user-selectable.
	for _, c := range cats {
		if c.UID == 0 {
			t.Error("Categories() must not include the uncategorized entry")
		}
	}
}

func TestSeverityLevelCoversFullEnum(t *testing.T) {
	tests := map[int]string{
		0:   "unknown",
		1:   "informational",
		2:   "low",
		3:   "medium",
		4:   "high",
		5:   "critical",
		6:   "fatal",
		99:  "other",
		250: "unknown",
	}
	for id, want := range tests {
		e := &Event{SeverityID: id}
		if got := e.GetSeverityLevel(); got != want {
			t.Errorf("severity_id %d: got %q, want %q", id, got, want)
		}
	}
}

func TestSchemaVersionIsRecorded(t *testing.T) {
	if SchemaVersion() == "" {
		t.Error("SchemaVersion() is empty; classes.json must record the OCSF release it came from")
	}
}

// The classes an incident is actually made of are named, not numbered.
//
// A class the registry does not know still ingests and still files under its
// category, but the queue shows "Class 3007" where every other row shows a
// name. These five arrived in OCSF 1.9.0, and two of them — User Management and
// Role Management — are the identity classes an account-compromise
// investigation is entirely made of.
func TestTheRegistryKnowsTheClassesAnalystsWorkWith(t *testing.T) {
	for uid, want := range map[int]string{
		3007: "User Management",
		3008: "Role Management",
		1011: "Device Power State Activity",
		1012: "Clipboard Activity",
		5022: "Startup Item Query",
	} {
		if got := ClassName(uid); got != want {
			t.Errorf("class %d is %q, want %q — regenerate with scripts/gen-ocsf-classes.sh", uid, got, want)
		}
	}
}

// Category slugs are persisted in events.event_type, so renaming one silently
// invalidates every stored row that carries it: the filter stops matching and
// the events read as gone. Upstream renamed category 8 to "unmanned_systems"
// in 1.9.0 and this deliberately does not follow.
func TestCategorySlugsAreStableAcrossSchemaVersions(t *testing.T) {
	for uid, want := range map[int]string{
		1: "system", 2: "findings", 3: "iam", 4: "network",
		5: "discovery", 6: "application", 7: "remediation", 8: "unmanned",
	} {
		if got := CategorySlug(uid); got != want {
			t.Errorf("category %d slug is %q, want %q — a stored event_type would stop matching",
				uid, got, want)
		}
	}
}

// The observable enum tracks the schema, because it is what a pivot is keyed on.
//
// An observable whose type_id has no name still pivots — the lookup is on
// (type_id, value) and does not care — but the Indicators screen labels it
// "Unknown", which reads as "we could not work out what this is" rather than
// "this build predates the type". These two arrived with OCSF 1.9.0, alongside
// the Role Management class they describe.
func TestTheObservableEnumMatchesTheVendoredSchema(t *testing.T) {
	for id, want := range map[int]string{
		49: "IAM Role Object: name",
		50: "IAM Role Object: uid",
		99: "Other",
	} {
		if got := ObservableTypeName(id); got != want {
			t.Errorf("observable type %d is %q, want %q", id, got, want)
		}
	}
}

// Both vendored files describe the same schema release. They come from two
// endpoints and are refreshed by hand, so they can drift apart.
func TestTheVendoredFilesAgreeOnTheSchemaVersion(t *testing.T) {
	if got, want := ObservableSchemaVersion(), SchemaVersion(); got != want {
		t.Errorf("observable_types.json says %q and classes.json says %q", got, want)
	}
}
