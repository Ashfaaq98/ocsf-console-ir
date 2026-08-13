package ui

import (
	"strings"
	"testing"
	"time"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/ocsf"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/store"
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// entityRampNames label a failure.
var entityRampNames = [entityClassCount]string{"host", "user", "network", "artifact"}

// The four entity colours are told apart from one another.
//
// They are read side by side — a scope line lists hosts then users, a message
// carries an address and a filename in one sentence — so two of them in one hue
// is the whole feature failing quietly.
func TestEntityColoursAreDistinctInEveryTheme(t *testing.T) {
	for _, name := range themeNames() {
		theme := themeBuilders[name]()
		for i := 0; i < int(entityClassCount); i++ {
			for j := i + 1; j < int(entityClassCount); j++ {
				a, okA := toRGB(entityColour(entityClass(i), theme))
				b, okB := toRGB(entityColour(entityClass(j), theme))
				if !okA || !okB {
					continue
				}
				if d := distance(a, b); d < severityDistanceFloor {
					t.Errorf("%s: %s and %s are %.0f apart, want %d",
						name, entityRampNames[i], entityRampNames[j], d, severityDistanceFloor)
				}
			}
		}
	}
}

// An entity reads as coloured rather than as body text.
//
// The point is that a hostname does not look like the sentence around it. A hue
// that lands on the value colour or the label colour is decoration that costs a
// palette slot and says nothing.
func TestEntityColoursAreNotTheTextColours(t *testing.T) {
	for _, name := range themeNames() {
		theme := themeBuilders[name]()
		for i := 0; i < int(entityClassCount); i++ {
			a, ok := toRGB(entityColour(entityClass(i), theme))
			if !ok {
				continue
			}
			for _, text := range []struct {
				what  string
				color tcell.Color
			}{{"the value colour", theme.TextPrimary}, {"the label colour", theme.TextMuted}} {
				b, ok := toRGB(text.color)
				if !ok {
					continue
				}
				if d := distance(a, b); d < severityDistanceFloor {
					t.Errorf("%s: %s is %.0f from %s, want %d",
						name, entityRampNames[i], d, text.what, severityDistanceFloor)
				}
			}
		}
	}
}

// And it is legible on the surface it is drawn on.
func TestEntityColoursAreReadable(t *testing.T) {
	for _, name := range themeNames() {
		theme := themeBuilders[name]()
		for i := 0; i < int(entityClassCount); i++ {
			c := entityColour(entityClass(i), theme)
			for _, ground := range []struct {
				what  string
				color tcell.Color
			}{{"surface", theme.Surface}, {"background", theme.Bg}} {
				r := colourContrast(c, ground.color)
				if r > 0 && r < severityContrastFloor {
					t.Errorf("%s: %s reads at %.1f:1 on the %s, want %.1f",
						name, entityRampNames[i], r, ground.what, severityContrastFloor)
				}
			}
		}
	}
}

// The classes come from OCSF, so the schema's own type ids drive them.
func TestEveryDerivedObservableTypeHasAClass(t *testing.T) {
	for _, id := range []int{
		ocsf.ObservableTypeHostname, ocsf.ObservableTypeIPAddress,
		ocsf.ObservableTypeMACAddress, ocsf.ObservableTypeUserName,
		ocsf.ObservableTypeEmail, ocsf.ObservableTypeURLString,
		ocsf.ObservableTypeFileName, ocsf.ObservableTypeHash,
		ocsf.ObservableTypeProcessName, ocsf.ObservableTypeURL,
	} {
		if _, ok := entityClassOf(id); !ok {
			t.Errorf("observable type %d (%s) has no colour class", id, ocsf.ObservableTypeName(id))
		}
	}

	// And a type nobody has a colour for says so, rather than defaulting into
	// a hue that would claim a meaning.
	if _, ok := entityClassOf(ocsf.ObservableTypeOther); ok {
		t.Error("the catch-all observable type was given a colour class")
	}
}

// Entities inside a sentence are found by shape, and the sentence survives.
func TestPaintTextColoursWhatItCanRecognise(t *testing.T) {
	theme := themeGruvbox()

	for _, tc := range []struct {
		in    string
		class entityClass
		want  string
	}{
		{"Outbound session to 45.147.230.11 from the gateway", entityNetwork, "45.147.230.11"},
		{"Beaconing to cdn-metrics.example every 15 minutes", entityNetwork, "cdn-metrics.example"},
		{"Word spawned svc_update.exe", entityArtifact, "svc_update.exe"},
		{"Hash e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 seen",
			entityArtifact, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
	} {
		got := paintText(tc.in, theme)
		marked := "[" + entityTag(tc.class, theme) + "]" + tc.want + "[" + theme.TagTextPrimary + "]"
		if !strings.Contains(got, marked) {
			t.Errorf("%q did not colour %q as %s:\n%s", tc.in, tc.want, entityRampNames[tc.class], got)
		}
		if stripTags(got) != tc.in {
			t.Errorf("the sentence changed:\nwant %q\ngot  %q", tc.in, stripTags(got))
		}
	}
}

// The more specific reading wins: a filename matches the domain pattern too.
func TestAFilenameIsNotADomain(t *testing.T) {
	theme := themeGruvbox()
	got := paintText("Word spawned svc_update.exe on the host", theme)

	if !strings.Contains(got, "["+entityTag(entityArtifact, theme)+"]svc_update.exe") {
		t.Errorf("svc_update.exe was not read as an artifact:\n%s", got)
	}
	if strings.Contains(got, "["+entityTag(entityNetwork, theme)+"]svc_update.exe") {
		t.Errorf("svc_update.exe was read as a domain:\n%s", got)
	}
}

// Prose with nothing recognisable in it is left alone — a guess coloured is
// worse than nothing coloured.
func TestPaintTextLeavesOrdinaryProseAlone(t *testing.T) {
	theme := themeGruvbox()
	plain := "The analyst confirmed the alert was a true positive"

	if got := paintText(plain, theme); got != plain {
		t.Errorf("ordinary prose was marked up:\n%s", got)
	}
}

// Brackets in a message are escaped, or tview reads them as colour tags and
// swallows the text.
func TestPaintTextEscapesBrackets(t *testing.T) {
	theme := themeGruvbox()
	got := paintText("Rule [T1059] fired on 10.0.0.5", theme)

	if !strings.Contains(got, "[T1059[]") {
		t.Errorf("the bracketed rule id was not escaped: %s", got)
	}
}

// The ramp survives colour blindness.
//
// Four hues that are distinct to me and identical to a deuteranope is a feature
// that works for most of the people who would use it, which is the kind of
// claim worth failing a build over. The simulation is the same Brettel/Viénot
// approximation the severity ramp is held to.
func TestEntityColoursSurviveColourBlindness(t *testing.T) {
	// The same floor as full colour. The ramps were chosen by searching each
	// palette's hue families for the most vivid four that clear it — so this is
	// not a bar lowered to fit the colours, it is the bar the colours were
	// picked to clear.
	const floor = severityDistanceFloor

	for _, name := range themeNames() {
		theme := themeBuilders[name]()
		for _, kind := range []string{"deuteranopia", "protanopia", "tritanopia"} {
			for i := 0; i < int(entityClassCount); i++ {
				for j := i + 1; j < int(entityClassCount); j++ {
					a, okA := toRGB(entityColour(entityClass(i), theme))
					b, okB := toRGB(entityColour(entityClass(j), theme))
					if !okA || !okB {
						continue
					}
					if d := distance(simulateColourblind(a, kind), simulateColourblind(b, kind)); d < floor {
						t.Errorf("%s under %s: %s and %s collapse to %.0f apart, want %.0f",
							name, kind, entityRampNames[i], entityRampNames[j], d, float64(floor))
					}
				}
			}
		}
	}
}

// The briefing's scope colours hosts and users by what they are.
func TestTheBriefingScopeColoursItsEntities(t *testing.T) {
	th := themeGruvbox()
	base := time.Date(2026, 8, 10, 7, 21, 0, 0, time.UTC)
	d := briefingData{
		Events: []store.Event{
			{ID: "e1", Host: "workstation-14", UserName: "j.rivera", Timestamp: base},
			{ID: "e2", Host: "dc-01", UserName: "a.novak", Timestamp: base.Add(time.Hour)},
		},
	}

	lines := strings.Join(scopeLines(d, th), "\n")
	for _, want := range []string{
		"[" + entityTag(entityHost, th) + "]dc-01",
		"[" + entityTag(entityHost, th) + "]workstation-14",
		"[" + entityTag(entityUser, th) + "]a.novak",
		"[" + entityTag(entityUser, th) + "]j.rivera",
	} {
		if !strings.Contains(lines, want) {
			t.Errorf("the scope does not carry %q:\n%s", want, lines)
		}
	}

	// The labels stay quiet — the colour is on the values.
	if !strings.Contains(lines, "["+th.TagMuted+"]hosts") {
		t.Errorf("the scope labels lost their muted colour:\n%s", lines)
	}
}

// Section headings have a colour of their own.
//
// Every heading on the briefing was TagMuted — the same grey as the labels
// underneath them — so the page had no structure you could see, only structure
// you could find by reading.
func TestBriefingHeadingsAreNotTheLabelColour(t *testing.T) {
	for _, name := range themeNames() {
		th := themeBuilders[name]()
		heading := briefingHeading("SCOPE", th)

		if strings.Contains(heading, "["+th.TagMuted+"]") {
			t.Errorf("%s: a section heading is drawn in the label colour: %s", name, heading)
		}
		a, okA := toRGB(th.Header)
		b, okB := toRGB(th.TextMuted)
		if okA && okB {
			if d := distance(a, b); d < severityDistanceFloor {
				t.Errorf("%s: the heading colour is %.0f from the label colour, want %d",
					name, d, severityDistanceFloor)
			}
		}
	}
}

// The events table paints the host as a host and the message's entities inside
// it — the host column used to be the success green, which said "this is fine"
// about a row of evidence.
func TestTheEventsTableColoursItsEntities(t *testing.T) {
	ui, _ := newTestUI(t)
	ui.hasTrueColor = true
	ui.setTheme("gruvbox")
	cm := openCase(t, ui)

	cm.events = []store.Event{
		{ID: "e1", Host: "dc-01", Severity: "high", EventType: "network",
			Timestamp: time.Now(),
			Message:   "Outbound session to 45.147.230.11 carrying svc_update.exe"},
	}
	cm.updateEventsTable()

	host := cm.eventsTable.GetCell(1, 4)
	if got := host.Color; got != entityColour(entityHost, cm.theme) {
		t.Errorf("the host cell is %v, want the host colour %v",
			got, entityColour(entityHost, cm.theme))
	}
	if got := host.Color; got == cm.theme.Success {
		t.Error("the host cell is still the success green")
	}

	msg := cm.eventsTable.GetCell(1, 5).Text
	for _, want := range []struct {
		class entityClass
		value string
	}{
		{entityNetwork, "45.147.230.11"},
		{entityArtifact, "svc_update.exe"},
	} {
		if !strings.Contains(msg, "["+entityTag(want.class, cm.theme)+"]"+want.value) {
			t.Errorf("the message does not colour %q:\n%s", want.value, msg)
		}
	}
}

// An indicator is coloured by its OCSF type, which the row already carries.
func TestTheIndicatorsTableColoursByType(t *testing.T) {
	th := themeGruvbox()
	table := tview.NewTable()

	renderCaseIndicators(table, []store.CaseIndicator{
		{TypeID: ocsf.ObservableTypeIPAddress, Type: "IP Address", Value: "45.147.230.11", Sightings: 3},
		{TypeID: ocsf.ObservableTypeHostname, Type: "Hostname", Value: "dc-01", Sightings: 2},
		{TypeID: ocsf.ObservableTypeHash, Type: "Hash", Value: "abc123", Sightings: 1},
	}, th, []string{"none"})

	for row, want := range map[int]entityClass{1: entityNetwork, 2: entityHost, 3: entityArtifact} {
		cell := table.GetCell(row, 1)
		if cell == nil {
			t.Fatalf("row %d is missing", row)
		}
		if got := cell.Color; got != entityColour(want, th) {
			t.Errorf("row %d (%s) is %v, want %v", row, cell.Text, got, entityColour(want, th))
		}
	}
}

// The ramp reaches every screen that shows an entity.
//
// Applied to half the screens it is decoration: a hostname coloured on the
// events tab and plain on the findings tab teaches nothing. The value of the
// scheme is that it holds everywhere — you learn one hue once.
func TestTheEntityRampReachesEveryScreen(t *testing.T) {
	th := themeGruvbox()
	host := entityTag(entityHost, th)
	network := entityTag(entityNetwork, th)
	artifact := entityTag(entityArtifact, th)

	// The triage queue: the title is prose, the asset is a host.
	ui, st := newTestUI(t)
	ui.hasTrueColor = true
	ui.setTheme("gruvbox")
	seedTriageFinding(t, st, "a", "")
	ui.enterScreen(destTriage)
	awaitIdle(t, ui)
	if len(ui.findings) == 0 {
		t.Fatal("the queue seeded no findings")
	}
	f := ui.findings[0]
	f.Title = "Beaconing to cdn-metrics.example from the gateway"
	ui.findingAsset[f.ID] = "dc-01"
	cells := ui.triageRow(f)

	if got := cells["Title"].text; !strings.Contains(got, "["+network+"]cdn-metrics.example") {
		t.Errorf("the queue's title does not colour its domain:\n%s", got)
	}
	if got := cells["Asset"].color; got != entityColour(entityHost, ui.theme) {
		t.Errorf("the queue's asset column is %v, want the host colour", got)
	}

	// The case's findings table, and the finding window it opens.
	cm := openCase(t, ui)
	cm.caseFindings = []store.Finding{
		{ID: "f1", Title: "Word spawned svc_update.exe", Severity: "high", Status: "new"},
	}
	cm.renderCaseFindings()
	if got := cm.findingsTable.GetCell(1, 4).Text; !strings.Contains(got, "["+artifact+"]svc_update.exe") {
		t.Errorf("the case's findings table does not colour its artifact:\n%s", got)
	}

	// Notes, which analysts write host names into.
	cm.notes = []store.Note{{Content: "Isolated dc-01 and blocked 45.147.230.11", Author: "p.osei"}}
	cm.updateNotesText()
	if got := cm.notesTable.GetCell(0, 3).Text; !strings.Contains(got, "["+network+"]45.147.230.11") {
		t.Errorf("a note does not colour the address in it:\n%s", got)
	}
	_ = host
}

// The copilot's answers are coloured too — which is also a small check on the
// model: an address it invented reads as an address, and pivoting on it finds
// nothing.
func TestTheCopilotAnswersAreColoured(t *testing.T) {
	th := themeGruvbox()
	table := tview.NewTable()

	renderTranscript(table, []transcriptRow{
		{Message: -1, Text: "The host dc-01 contacted 45.147.230.11 twice."},
	}, th)

	got := table.GetCell(0, 1).Text
	if !strings.Contains(got, "["+entityTag(entityNetwork, th)+"]45.147.230.11") {
		t.Errorf("the transcript does not colour the address:\n%s", got)
	}
}
