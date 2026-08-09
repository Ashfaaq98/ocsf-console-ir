package ui

import (
	"fmt"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/store"
)

// The dashboard's half of the finding inspector.
//
// The renderer itself is shared with Triage — see finding_inspector.go. What
// stays here is the part that is genuinely the dashboard's: which finding is
// under its cursor, how wide its panel is, and when to ask for the context.

// homeInspectorNarrativeLines is the dashboard's budget for the producer's
// description. Its panel is fifteen rows and shares them with the indicators
// and the technique, so two lines is what there is.
const homeInspectorNarrativeLines = 2

// selectionChanged is called on every cursor movement.
//
// It repaints immediately from the record — which needs no query — and only
// schedules the lookups once the cursor has settled.
func (h *homeView) selectionChanged() {
	h.renderInspector()

	f := h.selectedFinding()
	if f == nil {
		return
	}
	id := f.ID
	h.inspect.schedule(f.ID, f.CaseID, func() {
		// The cursor may have moved on while the queries ran. Repainting anyway
		// would show one finding's indicators under another's title.
		if sel := h.selectedFinding(); sel != nil && sel.ID == id {
			h.renderInspector()
		}
	})
}

// renderInspector paints the selected finding.
func (h *homeView) renderInspector() {
	_, loading := h.snapshot()
	t := h.ui.theme

	if loading[panelQueue] {
		h.inspector.SetText(" " + loadingState("", t))
		return
	}
	f := h.selectedFinding()
	if f == nil {
		h.inspector.SetText(fmt.Sprintf("\n [%s]Select a finding to see why it matters.[-:-:-]", t.TagMuted))
		return
	}

	r := findingInspector{
		theme:          t,
		width:          h.width,
		narrativeLines: homeInspectorNarrativeLines,
	}
	h.inspector.SetText(r.render(*f, h.inspect.get(f.ID)))
}

// findingByID looks a finding up in the loaded queue.
func (h *homeView) findingByID(id string) *store.Finding {
	d, _ := h.snapshot()
	for i := range d.queue {
		if d.queue[i].ID == id {
			return &d.queue[i]
		}
	}
	return nil
}

// loadFindingContext fills the inspector's context synchronously.
//
// The application goes through selectionChanged, which debounces; this is the
// same work without the wait, for callers that need the result now.
func (h *homeView) loadFindingContext(findingID string) {
	caseID := ""
	if f := h.findingByID(findingID); f != nil {
		caseID = f.CaseID
	}
	h.inspect.loadNow(findingID, caseID)
}

// inspectorWidth is the panel's inner width, kept for the layout's use.
func (h *homeView) inspectorWidth() int {
	return findingInspector{width: h.width}.innerWidth()
}
