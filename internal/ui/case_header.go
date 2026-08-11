package ui

import (
	"fmt"
	"strings"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// The case header: what this case is, whose it is, and what to do next.
//
// Three rows, each answering one question, both edges of the terminal used.
// Every value is read from the case row or computed from records the screen has
// already loaded — there is nothing here that the database cannot answer.
//
//	case_a1b2c3d4   Suspected account compromise            ▲ HIGH   OPEN
//	owner a.novak · opened 02 Aug 14:22                 updated 4m ago
//	▸ NEXT  no note in 2d — press n to say where this stands
//
// What it does *not* show is as deliberate. The case's verdict, its priority,
// its impact, its suspected-breach flag and its assignee group are all columns
// in the schema that nothing in the application ever writes — UpdateCaseVerdict
// and UpdateCaseTriage have no callers. The old header printed "verdict —" on
// every case that has ever existed. A field that can only be blank is worse
// than an absent one: it reads as "this case has no verdict" rather than "this
// build cannot record one".
//
// The counts went too. They came from the denormalised event_count and
// finding_count columns while the tab strip counts the loaded records, so the
// two could disagree by a row's distance. The strip is the live number; the
// header does not repeat it.

// caseHeaderHeight is the header's height with its two rows of fact. It grows by
// one when the next-action prompt has something to say.
//
// There is no border. It cost two rows of chrome around two rows of content,
// and the tab bar below is a filled band that separates the header from the
// panel better than a box drawn around it did.
const caseHeaderHeight = 2

// staleCaseAfter is how long a case may go without activity before the header
// says so.
const staleCaseAfter = 24 * time.Hour

// caseIDWidth is how much of the case id the header shows.
//
// Enough to be a prefix `console-ir report` accepts: ResolveCase matches from
// the start of the id and wants at least four characters, and ids are
// "case_" plus a uuid. If a prefix ever matched two cases the command refuses
// and lists them, so the failure is explicit rather than silent.
const caseIDWidth = 13

// Colour roles in the header, one meaning each.
//
// Muted names the labels, the id and the separators — the scaffolding you read
// past. TextPrimary carries the values. Warning marks a gap that wants an
// analyst. Accent is the next-action marker and nothing else.
//
// The title is TextPrimary bold rather than accent, which is not a preference:
// in gruvbox TagAccent and TagSeverityHigh are the same orange, so an accent
// title beside a HIGH badge was two different facts in one colour. Severity
// keeps the colours; the title takes weight instead.
//
// Status is a filled chip rather than coloured text, so it differs from the
// severity badge beside it in *form* and not only in hue — in gruvbox again,
// OPEN's warning yellow and a MEDIUM severity are the same value. Two shapes
// cannot be confused the way two yellows can.

// caseStatusColour is a case status's colour.
//
// The one source: badge() renders the same statuses elsewhere and reads it
// through here, so a status cannot be amber in the header and grey in a list.
func caseStatusColour(status string, t Theme) tcell.Color {
	switch strings.ToUpper(strings.TrimSpace(status)) {
	case "OPEN", "NEW", "UNRESOLVED", "INVESTIGATING":
		return t.Warning
	case "CLOSED", "RESOLVED", "COMPLETED":
		return t.Success
	case "IN_PROGRESS", "TRIAGED":
		return t.Accent
	default:
		return t.TextMuted
	}
}

// chipFg is the text colour for a filled chip: whichever of the theme's two
// grounds reads better on it.
//
// Picked rather than fixed. A chip filled with a light theme's amber needs dark
// text and a dark theme's amber needs the surface behind it; hard-coding either
// makes one of the six shipped palettes unreadable.
func chipFg(bg tcell.Color, t Theme) tcell.Color {
	best, bestRatio := t.Surface, 0.0
	for _, candidate := range []tcell.Color{t.Surface, t.TextPrimary, t.Bg} {
		if r := colourContrast(candidate, bg); r > bestRatio {
			best, bestRatio = candidate, r
		}
	}
	return best
}

// colourContrast is the WCAG ratio between two widget colours, 0 when either is
// not an RGB colour the terminal named.
func colourContrast(a, b tcell.Color) float64 {
	ra, okA := toRGB(a)
	rb, okB := toRGB(b)
	if !okA || !okB {
		return 0
	}
	return contrastRatio(ra, rb)
}

// caseStatusChip is the status, filled.
func caseStatusChip(status string, t Theme) string {
	if strings.TrimSpace(status) == "" {
		status = "NEW"
	}
	bg := caseStatusColour(status, t)
	return fmt.Sprintf("[%s:%s:b] %s [-:-:-]",
		tagColor(chipFg(bg, t)), tagColor(bg), strings.ToUpper(strings.TrimSpace(status)))
}

// headerRow lays a left and a right segment on one row.
//
// The right segment is dropped rather than crowded: a header that runs its two
// halves together says less than one that shows the half that fits. Width is
// measured with tview's own tagged-width, so colour tags do not count as
// columns.
func headerRow(width int, left, right string) string {
	if right == "" {
		return left
	}
	gap := width - tview.TaggedStringWidth(left) - tview.TaggedStringWidth(right) - 1
	if gap < 2 {
		return left
	}
	return left + strings.Repeat(" ", gap) + right
}

// headerWidth is the columns the header may draw, from the same measurement the
// tab strip uses.
func (cm *CaseManagement) headerWidth() int {
	if w := cm.barWidth(); w > 0 {
		return w
	}
	return 0
}

// shortCaseID is the identifier as the header shows it.
func shortCaseID(id string) string {
	if len(id) <= caseIDWidth {
		return id
	}
	return id[:caseIDWidth]
}

// updateMetadataBar paints the header.
func (cm *CaseManagement) updateMetadataBar() {
	t := cm.theme
	muted, val := t.TagMuted, t.TagTextPrimary
	width := cm.headerWidth()

	// Row one: which case, and what state it is in.
	left := fmt.Sprintf(" [%s]%s[-]   [%s::b]%s[-:-:-]",
		muted, shortCaseID(cm.caseData.ID), val, tview.Escape(cm.caseData.Title))
	right := fmt.Sprintf("%s   %s",
		formatSeverityBadge(cm.caseData.Severity, t),
		caseStatusChip(cm.caseData.Status, t))
	row1 := headerRow(width, left, right)

	// Row two: whose it is, and since when.
	//
	// An absolute opening time as well as an age. "20h old" is not a fact you
	// can put in a report, and a case outlives the shift that opened it.
	owner, ownerColour := strings.TrimSpace(cm.caseData.AssignedTo), val
	if owner == "" {
		// A gap, not a value: the next-action prompt is about to ask for it.
		owner, ownerColour = "unassigned", t.TagWarning
	}
	left = fmt.Sprintf(" [%s]owner[-] [%s]%s[-] [%s]·[-] [%s]opened[-] [%s]%s[-]",
		muted, ownerColour, tview.Escape(owner), muted,
		muted, val, cm.caseData.CreatedAt.Format("02 Jan 15:04"))

	right = ""
	if !cm.caseData.UpdatedAt.IsZero() {
		updatedColour := val
		if time.Since(cm.caseData.UpdatedAt) > staleCaseAfter {
			updatedColour = t.TagWarning
		}
		right = fmt.Sprintf("[%s]updated[-] [%s]%s ago[-]",
			muted, updatedColour, renderRelativeTime(cm.caseData.UpdatedAt))
	}
	row2 := headerRow(width, left, right)

	rows := caseHeaderHeight
	text := row1 + "\n" + row2
	if prompt := cm.nextActionPrompt(); prompt != "" {
		text += "\n" + prompt
		rows++
	}
	cm.metadataBar.SetText(text)

	// The header grows by a row when the prompt is present. Fixed, the prompt
	// was written and then clipped — present in the widget and invisible on
	// screen.
	if cm.layout != nil {
		cm.layout.ResizeItem(cm.metadataBar, rows, 0)
	}
}

// nextActionPrompt is the one thing to do about this case, or nothing.
//
// It earns its row by being conditional: a hint that is always there is chrome,
// and the row it costs is a row of evidence.
func (cm *CaseManagement) nextActionPrompt() string {
	acc, muted := cm.theme.TagAccent, cm.theme.TagMuted

	if strings.TrimSpace(cm.caseData.AssignedTo) == "" {
		return fmt.Sprintf(" [%s]▸ NEXT[-]  [%s]no owner — press o to take it[-]", acc, muted)
	}

	var lastNote time.Time
	for _, n := range cm.notes {
		if n.CreatedAt.After(lastNote) {
			lastNote = n.CreatedAt
		}
	}
	if lastNote.IsZero() {
		return fmt.Sprintf(" [%s]▸ NEXT[-]  [%s]no note yet — press n to record where this stands[-]", acc, muted)
	}
	if time.Since(lastNote) > staleCaseAfter {
		return fmt.Sprintf(" [%s]▸ NEXT[-]  [%s]nothing recorded in %s — press n to say where this stands[-]",
			acc, muted, renderRelativeTime(lastNote))
	}
	return ""
}

// takeOwnership is `o`: put this case in the current analyst's name.
//
// The header has told analysts to press o since the next-action prompt was
// written, and there was no o. Nor any other way to own a case: assigned_to was
// set once, when the finding was escalated, and never again — so a case picked
// up by a second shift stayed in the first shift's name for good.
func (cm *CaseManagement) takeOwnership() {
	if cm.store == nil {
		cm.updateStatus("No database")
		return
	}
	me := cm.getCurrentAnalyst()
	if strings.EqualFold(strings.TrimSpace(cm.caseData.AssignedTo), me) {
		cm.updateStatus("This case is already yours")
		return
	}

	previous := cm.caseData.AssignedTo
	update := cm.caseData
	update.AssignedTo = me

	cm.updateStatus("Taking the case…")
	work := func() {
		_, err := cm.store.CreateOrUpdateCase(cm.ctx, update)
		if err == nil {
			_ = cm.store.LogCaseAction(cm.ctx, cm.caseData.ID, "case_assigned", me,
				map[string]interface{}{"from": previous, "to": me})
		}
		cm.queueUpdate(func() {
			if err != nil {
				cm.updateStatus(fmt.Sprintf("Could not take the case: %v", err))
				return
			}
			cm.caseData.AssignedTo = me
			cm.updateMetadataBar()
			cm.renderBriefing()
			cm.updateStatus("This case is now yours")
			// The audit trail carries the handover.
			cm.loadCaseData()
		})
	}

	// Tracked, so a test can wait for it and a shutdown does not race it.
	if cm.parentUI != nil {
		cm.parentUI.spawnLoad(work)
		return
	}
	go work()
}
