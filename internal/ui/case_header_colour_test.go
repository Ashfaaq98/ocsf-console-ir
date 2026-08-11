package ui

import (
	"strings"
	"testing"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/store"
	"github.com/gdamore/tcell/v2"
)

// The header's colour roles, grouped by what a reader compares.
//
// Colour encodes role, so two roles read together must not share a colour. What
// counts as "read together" is a row of inline text — not two tokens at opposite
// margins, where position and form already tell them apart. The case id sits at
// column one and looks like an id; a severity badge sits at the right edge behind
// a glyph. (In gruvbox those two are 52 apart, under the floor, and it does not
// matter for exactly that reason. Every other pair is checked.)
func headerRoleGroups(t Theme) map[string][]struct {
	name  string
	color tcell.Color
} {
	type role = struct {
		name  string
		color tcell.Color
	}
	titleAndSeverity := []role{{"title (primary)", t.TextPrimary}}
	for _, sev := range severityColours(t) {
		titleAndSeverity = append(titleAndSeverity, role{"severity " + sev.name, sev.color})
	}
	return map[string][]role{
		"row 1 — title against every severity": titleAndSeverity,
		"row 1 — the id against the title": {
			{"case id (muted)", t.TextMuted},
			{"title (primary)", t.TextPrimary},
		},
		"row 2 — labels, values, gaps": {
			{"labels (muted)", t.TextMuted},
			{"values (primary)", t.TextPrimary},
			{"gap (warning)", t.Warning},
		},
		"row 3 — the next-action prompt": {
			{"marker (accent)", t.Accent},
			{"text (muted)", t.TextMuted},
		},
	}
}

// Two facts read together are never one colour.
//
// The header carried its title in the accent, and in gruvbox TagAccent and
// TagSeverityHigh are the same orange — so the case's name and its severity were
// rendered indistinguishable on a HIGH case, which is most of them.
func TestHeaderRolesAreDistinctInEveryTheme(t *testing.T) {
	for _, name := range themeNames() {
		theme := themeBuilders[name]()
		for group, roles := range headerRoleGroups(theme) {
			for i := 0; i < len(roles); i++ {
				for j := i + 1; j < len(roles); j++ {
					a, okA := toRGB(roles[i].color)
					b, okB := toRGB(roles[j].color)
					if !okA || !okB {
						continue
					}
					if d := distance(a, b); d < severityDistanceFloor {
						t.Errorf("%s, %s: %s and %s are %.0f apart, want %d",
							name, group, roles[i].name, roles[j].name, d, severityDistanceFloor)
					}
				}
			}
		}
	}
}

// The status chip is legible on its own fill.
//
// It is a filled chip rather than coloured text so that it differs from the
// severity badge beside it in shape and not only in hue — but a chip whose text
// disappears into its background is worse than the text it replaced.
func TestTheStatusChipIsReadableInEveryTheme(t *testing.T) {
	statuses := []string{"open", "investigating", "in_progress", "resolved", "archived"}

	for _, name := range themeNames() {
		theme := themeBuilders[name]()
		for _, status := range statuses {
			bg := caseStatusColour(status, theme)

			if r := colourContrast(chipFg(bg, theme), bg); r < severityContrastFloor {
				t.Errorf("%s: %s reads at %.1f:1 on its own fill, want %.1f",
					name, status, r, severityContrastFloor)
			}
		}
	}
}

// Every status the store can produce gets a colour of its own, and the two that
// mean opposite things are never the same one.
func TestOpenAndResolvedAreNeverTheSameColour(t *testing.T) {
	for _, name := range themeNames() {
		theme := themeBuilders[name]()
		a, okA := toRGB(caseStatusColour("open", theme))
		b, okB := toRGB(caseStatusColour("resolved", theme))
		if !okA || !okB {
			continue
		}
		if d := distance(a, b); d < severityDistanceFloor {
			t.Errorf("%s: open and resolved are %.0f apart, want %d", name, d, severityDistanceFloor)
		}
	}
}

// The header renders no colour tag that tview will not understand — a stray
// fragment reaches the screen as literal text.
func TestTheHeaderEmitsNoStrayTags(t *testing.T) {
	ui, _ := newTestUI(t)
	cm := openCase(t, ui)
	cm.lastWidth = 150
	cm.updateMetadataBar()

	for _, line := range renderPrimitive(t, cm.metadataBar, 150, 3) {
		if strings.Contains(line, "[-") || strings.Contains(line, "[#") {
			t.Errorf("a colour tag reached the screen: %q", line)
		}
		if w := len([]rune(strings.TrimRight(line, " "))); w > 150 {
			t.Errorf("a header row is %d columns wide: %q", w, line)
		}
	}
}

// The header carries the case id, which is what the report command wants.
//
// It was computed and thrown away: a shortID local was built on every paint and
// never used, so the one identifier that connects this screen to a ticket, a
// report or the command line appeared nowhere on it.
func TestTheHeaderCarriesTheCaseID(t *testing.T) {
	ui, _ := newTestUI(t)
	cm := openCase(t, ui)
	cm.caseData.ID = "case_a1b2c3d4-5e6f-7890-abcd-ef0123456789"
	cm.lastWidth = 150
	cm.updateMetadataBar()

	got := cm.metadataBar.GetText(true)
	if !strings.Contains(got, "case_a1b2c3d4") {
		t.Errorf("the case id is not in the header:\n%s", got)
	}

	// Long enough for ResolveCase, which matches from the start of the id and
	// wants at least four characters.
	if len(shortCaseID(cm.caseData.ID)) < 4 {
		t.Error("the shown prefix is too short for the report command to resolve")
	}
	if !strings.HasPrefix(cm.caseData.ID, shortCaseID(cm.caseData.ID)) {
		t.Error("what the header shows is not a prefix of the id")
	}
}

// The header says nothing the database cannot answer.
//
// It printed "verdict —" on every case ever opened, because nothing in the
// application sets a case verdict: UpdateCaseVerdict has no callers. And it
// carried counts from the denormalised columns while the tab strip counts the
// loaded records, so the two could disagree a row apart.
func TestTheHeaderClaimsNothingItCannotKnow(t *testing.T) {
	ui, _ := newTestUI(t)
	cm := openCase(t, ui)
	cm.caseFindings = make([]store.Finding, 3)
	cm.events = make([]store.Event, 10)
	cm.lastWidth = 150
	cm.updateMetadataBar()

	got := cm.metadataBar.GetText(true)
	for _, gone := range []string{"verdict", "findings", "evidence"} {
		if strings.Contains(strings.ToLower(got), gone) {
			t.Errorf("the header still carries %q, which it cannot source:\n%s", gone, got)
		}
	}
}

// The two halves of a row meet the two margins, and the right half is dropped
// rather than crowded when the terminal is too narrow for both.
func TestTheHeaderUsesBothMargins(t *testing.T) {
	ui, _ := newTestUI(t)
	cm := openCase(t, ui)
	cm.caseData.Severity = "high"
	cm.caseData.Status = "open"

	for _, width := range []int{190, 150, 120} {
		cm.lastWidth = width
		cm.updateMetadataBar()

		row := renderPrimitive(t, cm.metadataBar, width, 3)[0]
		trimmed := strings.TrimRight(row, " ")
		if w := len([]rune(trimmed)); w < width-3 || w > width {
			t.Errorf("at %d columns the first row ends at %d: %q", width, w, trimmed)
		}
		if !strings.HasSuffix(trimmed, "OPEN") {
			t.Errorf("at %d columns the status is not at the right margin: %q", width, trimmed)
		}
	}

	// Too narrow for both halves: the left one survives whole.
	cm.lastWidth = 40
	cm.updateMetadataBar()
	if got := cm.metadataBar.GetText(true); strings.Contains(got, "OPEN") {
		t.Errorf("the right half was kept on a terminal with no room for it:\n%s", got)
	}
}

// o takes the case, which the header has told analysts to press since the
// next-action prompt was written. Nothing handled it, and there was no other
// way to own a case: assigned_to was set once at escalation and never again.
func TestOTakesTheCase(t *testing.T) {
	ui, st := newTestUI(t)
	cm := openCase(t, ui)
	cm.caseData.AssignedTo = ""
	cm.updateMetadataBar()

	if !strings.Contains(cm.metadataBar.GetText(true), "press o to take it") {
		t.Fatal("the header does not offer the key this test is about")
	}

	cm.takeOwnership()
	awaitIdle(t, ui)

	me := cm.getCurrentAnalyst()
	if cm.caseData.AssignedTo != me {
		t.Errorf("the case is assigned to %q, want %q", cm.caseData.AssignedTo, me)
	}

	stored, err := st.GetCase(ui.ctx, cm.caseData.ID)
	if err != nil {
		t.Fatalf("GetCase: %v", err)
	}
	if stored.AssignedTo != me {
		t.Errorf("the database kept %q, want %q — ownership did not persist",
			stored.AssignedTo, me)
	}
}
