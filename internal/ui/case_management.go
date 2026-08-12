package ui

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/llm"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/logging"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/ocsf"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/paths"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/store"
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// IOCItem represents an extracted indicator with basic aggregation.
type IOCItem struct {
	Type            string
	Value           string
	Count           int
	First           time.Time
	Last            time.Time
	RelatedEventIDs []string
	// TypeID is the OCSF observable type_id backing this indicator, used to
	// pivot on (type_id, value).
	TypeID int
	// Asserted records that the event source supplied this indicator, rather
	// than Console-IR inferring it from text. An analyst should be able to tell
	// the difference before acting on it.
	Asserted bool
}

// CaseManagement represents the Case Management TUI screen
type CaseManagement struct {
	// Core dependencies
	app    *tview.Application
	store  *store.Store
	llm    llm.ChatProvider
	logger *logging.Logger
	theme  Theme
	ctx    context.Context

	// Main case data
	caseData   store.Case
	events     []store.Event
	baseEvents []store.Event
	auditLog   []store.AuditEntry
	notes      []store.Note

	// UI Layout components
	layout      *tview.Flex
	metadataBar *tview.TextView
	eventsTable *tview.Table
	// timelineView is a table rather than a text pane: record text carries
	// brackets that a multi-line TextView cannot escape without drifting, and a
	// cluster needs a cursor on it before Enter can expand it.
	timelineView *tview.Table
	// expandedTimeline is the open cluster's label, and timelineRows maps a row
	// back to the cluster whose header sits on it.
	expandedTimeline string
	timelineRows     map[int]string
	// timelineEntries and timelineRowEntry let a key act on what the timeline
	// cursor is on, rather than on the events table's selection.
	timelineEntries  []timelineEntry
	timelineRowEntry map[int]int
	copilotPanel     *tview.Flex
	// caseBody holds the tabs and, when open, the copilot drawer beside them.
	caseBody          *tview.Flex
	copilotOpen       bool
	copilotDropdown   *tview.DropDown
	copilotTranscript *tview.Table
	// copilotPages swaps the suggestion list for the transcript once the
	// conversation starts.
	copilotPages       *tview.Pages
	copilotSuggestions *tview.Table
	copilotProvider    *tview.TextView
	suggestions        []copilotSuggestion
	// copilotFull is set when the copilot took the screen rather than sharing
	// it, so closing knows which of the two to undo.
	copilotFull bool
	// copilotStatus is what became of the most recent question, rendered in the
	// transcript so it outlives a status-bar line.
	copilotStatus copilotStatus
	// notesDraftBaseline is what the editor held when editing began — empty for
	// a blank note, the body for a template. Esc compares against it so that
	// leaving a template untouched is not treated as losing work.
	notesDraftBaseline string
	copilotEstimate    *tview.TextView
	copilotInput       *tview.InputField
	notesPanel         *tview.Flex
	notesPages         *tview.Pages
	// notesViewer is the editor; notesTable is the log. A decision log is a
	// list of decisions, not a scroll of prose.
	notesViewer   *tview.TextView
	notesTable    *tview.Table
	activityTable *tview.Table
	// caseIndicators is what the Indicators tab last drew, so a keypress can
	// resolve a row back to the indicator it stands for.
	caseIndicators []store.CaseIndicator
	// pendingWidthShift is the drawer's columns during the one frame between
	// the layout changing and tview recomputing the widget rects.
	pendingWidthShift int
	notesEditor       *tview.TextArea
	activityLog       *tview.TextView
	statusBar         *tview.TextView
	// Tabs (left column)
	tabBar *tview.TextView
	// lastWidth is the width the layout was last drawn at, so the tab strip is
	// re-rendered when it changes and not on every frame.
	lastWidth int
	tabsPages *tview.Pages
	// Additional tab views
	overviewView *tview.TextView
	iocsTable    *tview.Table

	// Manual IOC selection state and mapping (for add/delete UX)
	selectedManualIOCIDs map[string]bool // note.ID used as manual IOC id
	iocRowToManualID     map[int]string  // table row index -> note.ID (only for manual rows)

	// Findings the case is about (its OCSF members), as opposed to the events
	// attached as evidence.
	findingsTable *tview.Table
	caseFindings  []store.Finding

	// State management
	selectedEventIndex int
	pinnedEvents       map[string]bool
	chatHistory        []llm.ChatMessage
	currentPersona     string
	pendingTokens      int32 // atomic
	activeTab          int   // index into caseTabNames

	// LLM summary state (Overview)
	overviewSummary string
	isSummarizing   bool
	summaryTokens   int
	summaryCost     float64
	summaryAt       time.Time

	// Filters (Events)
	filterStart      time.Time
	filterEnd        time.Time
	filterTypes      map[string]bool
	filterSeverities map[string]bool

	// Timeline expansion state
	timelineExpanded map[int]bool

	// IOCs index: type -> aggregated list
	iocIndex map[string][]IOCItem
	// Focus management
	focusedPane int // enum below
	// Notes mode state
	isEditingNotes bool

	// Saved global input capture to allow modal-scoped navigation
	globalInputCapture func(*tcell.EventKey) *tcell.EventKey

	// Modal state flag to ensure ESC closes active modal reliably
	modalActive bool

	// Modal stack to support nested modals (e.g., LLM Settings -> Search Model)
	modalStack []tview.Primitive
	// Stack of previous input captures to restore when popping modals
	inputCaptureStack []func(*tcell.EventKey) *tcell.EventKey
	// Current root primitive (helps restore nested modal parents)
	currentRoot tview.Primitive

	// Parent UI reference for returning
	parentUI *UI
}

const (
	FocusEvents = iota
	FocusTimeline
	FocusCopilot
	FocusNotes
	FocusOverview
	FocusIOCs
	FocusActivity
	FocusFindings
)

// caseTabNames is the single source of truth for the tab strip: its order, its
// labels, its bounds and its number keys all derive from this. The bounds used
// to be a hardcoded 5 in four different places, which is what made adding a tab
// a landmine.
//
// "Briefing" rather than "Overview": the tab is what you would say to a
// colleague, and naming it for that sets the bar for its content. "Events"
// stays "Events" — OCSF already uses "evidence" for finding.evidences, which
// are artifacts, so a tab of that name would mean two things one keystroke
// apart. "Indicators" rather than "Artifacts/IOCs", because a slash is two
// names and the first half now collides with those artifacts.
var caseTabNames = []string{
	"Briefing", "Findings", "Events", "Timeline", "Indicators", "Notes", "Activity",
}

// Tab indices, named so switches read as intent rather than arithmetic.
//
// These existed already; the per-tab key handlers compared against bare numbers
// regardless, and those numbers were written for the old six-tab order. That is
// how `n` came to fire on Indicators and do nothing on the tab named Notes. Use
// the names — they move with the list.
const (
	tabBriefing = iota
	tabFindings
	tabEvents
	tabTimeline
	tabIOCs
	tabNotes
	tabActivity
)

// caseTabPages maps a tab index to its page name and focus pane.
var caseTabPages = []struct {
	page  string
	focus int
}{
	tabBriefing: {"briefing", FocusOverview},
	tabFindings: {"findings", FocusFindings},
	tabEvents:   {"events", FocusEvents},
	tabTimeline: {"timeline", FocusTimeline},
	tabIOCs:     {"iocs", FocusIOCs},
	tabNotes:    {"notes", FocusNotes},
	tabActivity: {"activity", FocusActivity},
}

// NewCaseManagement creates a new Case Management screen
func NewCaseManagement(parentUI *UI, caseData store.Case) *CaseManagement {
	// Try to cast LLM to ChatProvider, fallback to LocalStub which implements Chat
	var chatLLM llm.ChatProvider
	if cp, ok := parentUI.llm.(llm.ChatProvider); ok {
		chatLLM = cp
	} else {
		chatLLM = &llm.LocalStub{}
	}

	cm := &CaseManagement{
		app:                parentUI.app,
		store:              parentUI.store,
		llm:                chatLLM,
		logger:             parentUI.logger,
		theme:              parentUI.theme,
		ctx:                parentUI.ctx,
		caseData:           caseData,
		selectedEventIndex: -1,
		pinnedEvents:       make(map[string]bool),
		chatHistory:        []llm.ChatMessage{},
		currentPersona:     llm.PersonaSOC,
		focusedPane:        FocusEvents,
		timelineExpanded:   make(map[int]bool),
		parentUI:           parentUI,
	}

	cm.setupLayout()
	cm.setupKeybindings()
	cm.loadCaseData()
	cm.loadCaseFindings()

	return cm
}

// setupLayout creates the Case Management screen layout
func (cm *CaseManagement) setupLayout() {
	// Metadata bar (top)
	cm.metadataBar = tview.NewTextView().
		SetDynamicColors(true).
		SetTextAlign(tview.AlignLeft)
	heavyBorder(cm.metadataBar.Box, "CASE", cm.theme)
	cm.updateMetadataBar()

	// Events table (left)
	cm.eventsTable = tview.NewTable().
		SetBorders(false).
		SetSelectable(true, false).
		SetFixed(1, 0) // Fixed header row
	cm.eventsTable.SetBorder(true).SetTitle(" EVENTS ").SetTitleAlign(tview.AlignLeft)
	cm.setupEventsTable()

	// Findings the case is about
	cm.setupCaseFindingsTable()

	// Timeline view (center)
	cm.timelineView = tview.NewTable().SetSelectable(true, false)
	cm.timelineView.SetBorder(true).SetTitle(" TIMELINE ").SetTitleAlign(tview.AlignLeft)
	cm.timelineView.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch event.Key() {
		case tcell.KeyEnter:
			cm.toggleTimelineCluster()
			return nil
		case tcell.KeyTab:
			// Tab moves between the case's tabs, which is what §9 lists first
			// and what an analyst reaches for. Pane focus moved to `h`/`l`,
			// which are already the focus keys everywhere else.
			cm.switchTab(wrapTab(cm.activeTab + 1))
			return nil
		case tcell.KeyBacktab:
			cm.switchTab(wrapTab(cm.activeTab - 1))
			return nil
		case tcell.KeyRune:
			switch event.Rune() {
			case 'p', 'P':
				cm.pinTimelineEntry()
				return nil
			}
		}
		return event
	})

	// Copilot panel (right)
	cm.setupCopilotPanel()

	// Notes and activity panel (bottom)
	cm.setupNotesPanel()

	// Status bar
	cm.statusBar = tview.NewTextView().SetDynamicColors(true)
	cm.updateStatus("Case Management loaded")

	// Main layout
	// Left side: Tabbed area (Overview, Events, Timeline, Artifacts/IOCs, Notes, Activity Log)
	cm.buildTabs()
	leftTabs := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(cm.tabBar, 1, 0, true).
		AddItem(cm.tabsPages, 0, 1, false)

	// Copilot is a drawer, not a column.
	//
	// It was a permanent 50 columns, which clipped the tab bar to "Activity L"
	// and left the case around 100 columns on a 150-column terminal — on the
	// one screen that has seven tabs and two-column layouts to fit. Closed by
	// default; `]` opens it and `[` closes it.
	cm.caseBody = tview.NewFlex().SetDirection(tview.FlexColumn)
	cm.caseBody.AddItem(leftTabs, 0, 1, true)
	main := cm.caseBody

	// Two-row metadata (increase height), then main content, then status bar
	cm.layout = tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(cm.metadataBar, caseHeaderHeight, 0, false).
		AddItem(main, 0, 1, true).
		AddItem(cm.statusBar, 1, 0, false)

	// Redraw the tab strip whenever the width changes.
	//
	// It picks between the full strip and a compact form by width, and it was
	// rendered once at construction — before anything had been drawn, so it
	// asked an undrawn widget how wide it was and got a default. A resize had
	// the same effect in reverse. This is the only place that knows the answer
	// at the moment it is true.
	cm.layout.SetDrawFunc(func(screen tcell.Screen, x, y, width, height int) (int, int, int, int) {
		if width != cm.lastWidth {
			cm.lastWidth = width
			cm.renderTabBar()
			// The header lays its two halves against the same width.
			cm.updateMetadataBar()
		}
		// The layout has no border, so its inner rect is its rect. Shrinking it
		// here would inset the whole case screen by a column.
		return x, y, width, height
	})

	// Again, now that the layout exists: the header sizes itself, and the first
	// call ran before there was anything to resize.
	cm.updateMetadataBar()

	cm.applyTheme()
	cm.updateFocusStyles()
}

// setupEventsTable configures the events table
func (cm *CaseManagement) setupEventsTable() {
	// Set up headers
	headers := []string{"", "Time", "Type", "Severity", "Host", "Message"}
	for col, header := range headers {
		cell := tview.NewTableCell(header).
			SetTextColor(cm.theme.TableHeader).
			SetBackgroundColor(cm.theme.TableHeaderBg).
			SetAttributes(tcell.AttrBold).
			SetSelectable(false)
		cm.eventsTable.SetCell(0, col, cell)
	}

	// Keep selectedIndex in sync when user moves the selection cursor
	cm.eventsTable.SetSelectionChangedFunc(func(row, column int) {
		if row <= 0 {
			cm.selectedEventIndex = -1
			return
		}
		cm.selectedEventIndex = row - 1
	})

	// Event activation handler (Enter): open details modal
	cm.eventsTable.SetSelectedFunc(func(row, col int) {
		cm.onEventSelected(row)
		if row > 0 && row-1 < len(cm.events) {
			cm.showEventDetailsModal(cm.events[row-1])
		}
	})

	cm.eventsTable.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		return cm.handleEventsInput(event)
	})
}

// setupCopilotPanel creates the Copilot chat interface
func (cm *CaseManagement) setupCopilotPanel() {
	// Persona dropdown
	cm.copilotDropdown = tview.NewDropDown().
		SetLabel("Persona: ").
		SetOptions([]string{llm.PersonaSOC, llm.PersonaForensics, llm.PersonaHunter}, nil).
		SetCurrentOption(0)
	// Update persona immediately when selection changes
	cm.copilotDropdown.SetSelectedFunc(func(text string, index int) {
		cm.currentPersona = text
		cm.updateStatus(fmt.Sprintf("Persona: %s", text))
	})

	// The provider is named rather than assumed.
	cm.copilotProvider = tview.NewTextView().SetDynamicColors(true)
	cm.copilotProvider.SetText(fmt.Sprintf("[%s]%s[-]",
		cm.theme.TagMuted, copilotProviderLine(activeLLMProvider(), true)))

	// Chat transcript. A table, not a text pane: a model's answer carries
	// brackets, and escaping those in one multi-line TextView drifts the tag
	// state across every following line.
	cm.copilotTranscript = tview.NewTable().SetSelectable(true, false)
	cm.copilotTranscript.SetBackgroundColor(cm.theme.Bg)
	cm.copilotTranscript.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch event.Key() {
		case tcell.KeyEsc:
			cm.toggleCaseCopilot()
			return nil
		case tcell.KeyRune:
			switch event.Rune() {
			case ']':
				cm.app.SetFocus(cm.copilotInput)
				cm.updateStatus("Copilot focus: Input")
				return nil
			case '[':
				cm.toggleCaseCopilot()
				return nil
			case 'a', 'A':
				cm.acceptCopilotAnswer()
				return nil
			case 'r', 'R':
				cm.regenerateCopilotAnswer()
				return nil
			}
		}
		return event
	})

	// The opening suggestions, replaced by the transcript once asked.
	cm.copilotSuggestions = tview.NewTable().SetSelectable(true, false)
	cm.copilotSuggestions.SetBackgroundColor(cm.theme.Bg)
	cm.copilotSuggestions.SetSelectedFunc(func(row, _ int) { cm.askSuggestion(row) })
	cm.copilotSuggestions.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyEsc {
			cm.toggleCaseCopilot()
			return nil
		}
		if event.Key() != tcell.KeyRune {
			return event
		}
		// The brackets belong to the drawer wherever they are pressed, so they
		// are never typed through. Without this, `[` on the suggestion list put
		// a bracket in the input instead of closing the copilot.
		switch event.Rune() {
		case '[':
			cm.toggleCaseCopilot()
			return nil
		case ']', ' ':
			return event
		}
		// Anything else goes to the input, so the list never blocks a direct
		// question. The keystroke is placed by hand: tview delivers an event to
		// whoever held focus when it was dispatched, so moving focus drops it.
		cm.copilotInput.SetText(cm.copilotInput.GetText() + string(event.Rune()))
		cm.app.SetFocus(cm.copilotInput)
		return nil
	})

	cm.copilotPages = tview.NewPages()
	cm.copilotPages.AddPage("suggestions", cm.copilotSuggestions, true, true)
	cm.copilotPages.AddPage("transcript", cm.copilotTranscript, true, false)

	// Inline token estimate (one-line)
	cm.copilotEstimate = tview.NewTextView().
		SetDynamicColors(true)
	cm.copilotEstimate.SetText(fmt.Sprintf("[%s]Est:[-] 0 tok  ~$0.0000", cm.theme.TagMuted))

	// Input field
	cm.copilotInput = tview.NewInputField().
		SetLabel("Ask: ").
		SetFieldWidth(0)

	// Update token estimate as the user types
	cm.copilotInput.SetChangedFunc(func(text string) {
		cm.updateTokenEstimate(text)
	})

	cm.copilotInput.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		return cm.handleCopilotInput(event)
	})

	// Assemble copilot panel
	controlsPanel := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(cm.copilotDropdown, 1, 0, false)

	cm.copilotPanel = tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(controlsPanel, 1, 0, false).
		AddItem(cm.copilotProvider, 1, 0, false).
		AddItem(cm.copilotPages, 0, 1, false).
		AddItem(cm.copilotEstimate, 1, 0, false).
		AddItem(cm.copilotInput, 1, 0, false)

	cm.copilotPanel.SetBorder(true).SetTitle(" COPILOT ").SetTitleAlign(tview.AlignLeft)
}

// setupNotesPanel creates a two-mode Notes panel (View/TextView vs Edit/TextArea) within a Pages container.
func (cm *CaseManagement) setupNotesPanel() {
	// Viewer (read-only, scrollable)
	cm.notesTable = tview.NewTable().SetSelectable(true, false)
	cm.notesTable.SetBorder(true).SetTitle(" NOTES ").SetTitleAlign(tview.AlignLeft)
	cm.notesTable.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch event.Key() {
		case tcell.KeyTab:
			// Tab moves between the case's tabs, which is what §9 lists first
			// and what an analyst reaches for. Pane focus moved to `h`/`l`,
			// which are already the focus keys everywhere else.
			cm.switchTab(wrapTab(cm.activeTab + 1))
			return nil
		case tcell.KeyBacktab:
			cm.switchTab(wrapTab(cm.activeTab - 1))
			return nil
		case tcell.KeyRune:
			switch event.Rune() {
			case 'n', 'N':
				// Start a new note (switch to editor)
				cm.switchToNotesEdit()
				return nil
			case 'T':
				// Shift, because lowercase t is the theme key and the screen's
				// own capture claims it before any widget sees it — the
				// lowercase branch here could never fire.
				cm.showNoteTemplates()
				return nil
			}
		}
		return event
	})

	// Editor (TextArea)
	cm.notesEditor = tview.NewTextArea().
		SetPlaceholder("What you did, and why. Ctrl+S saves.")
	// Minimal hint in title while editing
	cm.notesEditor.SetBorder(true).SetTitle(" NOTE  ·  Ctrl+S saves  ·  Esc cancels ").SetTitleAlign(tview.AlignLeft)
	cm.notesEditor.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		return cm.handleNotesInput(event)
	})

	// Pages container
	cm.notesPages = tview.NewPages()
	cm.notesPages.AddPage("view", cm.notesTable, true, true)
	cm.notesPages.AddPage("edit", cm.notesEditor, true, false)
}

// setupKeybindings configures keyboard shortcuts for the Case Management root
func (cm *CaseManagement) setupKeybindings() {
	handler := func(event *tcell.EventKey) *tcell.EventKey {
		switch event.Key() {
		case tcell.KeyEsc:
			// If a modal is active, close it; otherwise exit CM screen.
			if cm.modalActive {
				cm.popModalRoot()
				return nil
			}
			// An unsaved note is asked about here rather than in the editor's
			// own handler: this global capture runs first, so Esc while writing
			// was closing the entire case screen and taking the draft with it.
			if cm.isEditingNotes {
				cm.discardNoteDraft()
				return nil
			}
			cm.close()
			return nil
		case tcell.KeyTab:
			// Tab moves between the case's tabs, which is what §9 lists first
			// and what an analyst reaches for. Pane focus moved to `h`/`l`,
			// which are already the focus keys everywhere else.
			cm.switchTab(wrapTab(cm.activeTab + 1))
			return nil
		case tcell.KeyBacktab:
			cm.switchTab(wrapTab(cm.activeTab - 1))
			return nil
		case tcell.KeyRune:
			// Do not process global letter shortcuts when typing in inputs (Copilot/Notes)
			if f := cm.app.GetFocus(); f != nil {
				switch f.(type) {
				case *tview.InputField, *tview.TextArea:
					return event
				}
			}
			switch event.Rune() {
			case 'q', 'Q':
				if cm.modalActive {
					cm.popModalRoot()
					return nil
				}
			case 't':
				// The theme, as everywhere else.
				//
				// Show installs this handler as the application-wide capture,
				// so the parent's global keys are not reachable while a case is
				// open — t did nothing here, and the case screen was the one
				// place the theme could not be changed.
				if cm.parentUI != nil {
					cm.parentUI.cycleTheme()
				}
				return nil
			case 'E':
				// The report, not the bundle. An analyst pressing export at the
				// end of a case wants something they can send; the JSON is for
				// a machine and is on Shift+J.
				cm.writeCaseReport()
				return nil
			case 'J':
				cm.exportCase()
				return nil
			case 's':
				cm.showStatusChangeModal()
				return nil
			case 'S':
				cm.quickCycleStatus()
				return nil
			case 'o':
				// The header's next-action prompt has named this key since it
				// was written, and nothing handled it.
				cm.takeOwnership()
				return nil
			case 'L':
				// Global hotkey: Shift+L opens LLM Settings anywhere in Case Management
				cm.showLLMSettingsModal()
				return nil
			case 'h':
				cm.focusTabContent()
				return nil
			case 'l':
				cm.focusCopilot()
				return nil
			case ']':
				if !cm.copilotOpen {
					cm.toggleCaseCopilot()
				}
				return nil
			case '[':
				if cm.copilotOpen {
					cm.toggleCaseCopilot()
				}
				return nil
			case 'd', 'D':
				// A finding is what the case is about, so detaching one is a
				// statement about the case rather than a tidy-up. Confirmed.
				if cm.activeTab == tabFindings {
					cm.detachSelectedFinding()
					return nil
				}
			case 'p', 'P':
				if cm.activeTab == tabEvents {
					cm.pinCurrentEvent()
					return nil
				}
			case 'n', 'N':
				// These indices were written against the old six-tab order and
				// never moved: this read `== 4`, which is now Indicators, so `n`
				// opened a new note from the indicator list and did nothing on
				// the tab named Notes.
				if cm.activeTab == tabNotes {
					cm.addNewNote()
					return nil
				}
			case '?':
				cm.showCaseHelp()
				return nil
			case 'r', 'R':
				cm.refreshCaseData()
				return nil
			}
		}
		return event
	}
	cm.globalInputCapture = handler
	cm.app.SetInputCapture(handler)
}

// Event handlers

func (cm *CaseManagement) handleEventsInput(event *tcell.EventKey) *tcell.EventKey {
	switch event.Key() {
	case tcell.KeyRune:
		switch event.Rune() {
		case ' ':
			cm.togglePinnedEvent()
			return nil
		case 'e':
			cm.exportSelectedEvents()
			return nil
		case 'f':
			cm.showEventsFilterModal()
			return nil
		case 'F':
			cm.clearEventFilters()
			return nil
		}
	case tcell.KeyEnter:
		// Let tview's SetSelectedFunc handle activation/opening.
		return event
	}
	return event
}

func (cm *CaseManagement) handleCopilotInput(event *tcell.EventKey) *tcell.EventKey {
	switch event.Key() {
	case tcell.KeyEnter:
		cm.sendCopilotMessage()
		return nil
	case tcell.KeyTab:
		cm.toggleLeftRightFocus()
		return nil
	case tcell.KeyCtrlC:
		cm.copilotInput.SetText("")
		return nil
	case tcell.KeyBacktab:
		// Persona lives one step back from the input. It used to be on '[',
		// which now closes the drawer from everywhere in the case — a key that
		// closes a panel in one pane and moves focus in another is two keys.
		if cm.copilotDropdown != nil {
			cm.app.SetFocus(cm.copilotDropdown)
			cm.updateStatus("Copilot focus: Persona")
		}
		return nil
	case tcell.KeyRune:
		switch event.Rune() {
		case '[':
			// Closes the drawer from inside it too, so the key means one thing.
			cm.toggleCaseCopilot()
			return nil
		// Focus Copilot transcript (non-alphanumeric key). Use Up/Down/PgUp/PgDn to scroll.
		case '\\':
			if cm.copilotTranscript != nil {
				cm.app.SetFocus(cm.copilotTranscript)
				cm.updateStatus("Copilot focus: Transcript (Up/Down/PgUp/PgDn to scroll, ] to return)")
			}
			return nil
		}
	}
	return event
}

func (cm *CaseManagement) handleNotesInput(event *tcell.EventKey) *tcell.EventKey {
	// Editor-mode input handling
	switch event.Key() {
	case tcell.KeyCtrlS:
		cm.saveNotes()
		return nil
	case tcell.KeyTab:
		// Move focus to Copilot
		cm.toggleLeftRightFocus()
		return nil
	case tcell.KeyBacktab:
		// Shift+Tab: return focus to left tab area (Overview pane as entry)
		cm.setFocusPane(FocusOverview)
		return nil
	case tcell.KeyEsc:
		cm.discardNoteDraft()
		return nil
	}
	return event
}

// discardNoteDraft leaves the editor, asking first if there is work to lose.
//
// Esc used to discard silently, which is the wrong default for the one screen
// whose entire purpose is recording a decision — a mistyped Esc threw away a
// containment note with no way back. It only asks when there is a change to
// lose, so backing out of an untouched editor stays a single keystroke.
func (cm *CaseManagement) discardNoteDraft() {
	if cm.notesEditor == nil {
		cm.switchToNotesView()
		return
	}
	current := strings.TrimSpace(cm.notesEditor.GetText())
	if current == "" || current == strings.TrimSpace(cm.notesDraftBaseline) {
		cm.switchToNotesView()
		return
	}

	modal := tview.NewModal().
		SetText("Discard this note?\n\nIt has not been saved.").
		AddButtons([]string{"Keep editing", "Discard"}).
		SetDoneFunc(func(_ int, label string) {
			cm.popModalRoot()
			if label == "Discard" {
				cm.switchToNotesView()
				return
			}
			cm.app.SetFocus(cm.notesEditor)
		})
	cm.pushModalRoot(modal)
}

// Data loading and management

func (cm *CaseManagement) loadCaseData() {
	// Through the parent's tracked spawn where there is one, so a caller that
	// is about to close the database — which in practice means a test — can
	// wait for the read to finish. A bare goroutine is unobservable.
	// The id is read here, on the UI goroutine, and the load works from the
	// copy. Reading cm.caseData from inside the goroutine raced every render —
	// and raced the constructor, which starts this load and then reads the same
	// field to start the findings load.
	caseID := cm.caseData.ID

	work := func() {
		if cm.ctx.Err() != nil {
			return
		}
		// Ensure audit/notes tables are available
		_ = cm.store.SetupAuditTables()

		// Load events for this case
		cm.reloadCaseRow(caseID)
		events, err := cm.store.GetEventsByCase(cm.ctx, caseID)
		if err != nil {
			if strings.Contains(err.Error(), "database is closed") || cm.ctx.Err() != nil {
				return
			}
			if cm.logger != nil {
				cm.logger.Printf("Error loading events for case %s: %v", caseID, err)
			}
		}

		// Load notes
		notes, err := cm.store.GetNotes(cm.ctx, caseID)
		if err != nil {
			if strings.Contains(err.Error(), "database is closed") || cm.ctx.Err() != nil {
				return
			}
			if cm.logger != nil {
				cm.logger.Printf("Error loading notes for case %s: %v", caseID, err)
			}
		}

		// Load activity log (audit entries)
		audits, err := cm.store.GetAuditEntries(cm.ctx, caseID, 0)
		if err != nil {
			if strings.Contains(err.Error(), "database is closed") || cm.ctx.Err() != nil {
				return
			}
			if cm.logger != nil {
				cm.logger.Printf("Error loading audit entries for case %s: %v", caseID, err)
			}
		}

		// Which of those events the analyst starred. Loaded here so the
		// briefing and the evidence tab agree without either querying again.
		pinned, err := cm.store.GetPinnedMemberIDs(cm.ctx, caseID, store.MemberTypeEvent)
		if err != nil {
			if cm.logger != nil {
				cm.logger.Warn("could not read pinned evidence for case %s: %v", caseID, err)
			}
			pinned = map[string]bool{}
		}

		// Update UI on main thread
		cm.queueUpdate(func() {
			cm.baseEvents = events
			cm.events = events
			cm.pinnedEvents = pinned
			cm.notes = notes
			cm.auditLog = audits

			// Render tabs
			cm.updateEventsTable()
			cm.updateTimelineView()
			cm.updateNotesText()
			cm.renderBriefing()
			cm.renderActivityLog()
			cm.renderIOCs()
			// The header's prompt reads the notes, which have only just
			// arrived; without this it reports "no note yet" on a case with
			// notes.
			cm.updateMetadataBar()
			// The strip carries each tab's count, so it is stale until the
			// data it counts has landed.
			cm.renderTabBar()

			// What was read, not one of the six things. This line was written
			// from the events tab's point of view and printed on every tab, so
			// pressing r on Activity reported a number of events.
			cm.updateStatus(fmt.Sprintf("Case refreshed · %s · %s · %s",
				plural(len(events), "event"), plural(len(notes), "note"),
				plural(len(audits), "activity entry")))
		})
	}

	if cm.parentUI != nil {
		cm.parentUI.spawnLoad(work)
		return
	}
	go work()
}

// reloadCaseRow re-reads the case so its analyst and status fields stay
// accurate after a change, and applies the result on the UI goroutine.
//
// The query runs where it is called — a load goroutine — but the write does
// not: cm.caseData is read by every render on this screen, and assigning it
// from the loader raced the constructor, which starts this load and then reads
// the same field to start the next one.
func (cm *CaseManagement) reloadCaseRow(id string) {
	if cm.store == nil || id == "" {
		return
	}
	c, err := cm.store.GetCase(cm.ctx, id)
	if err != nil || c == nil {
		return
	}
	fresh := *c
	cm.queueUpdate(func() { cm.caseData = fresh })
}

func (cm *CaseManagement) refreshCaseData() {
	cm.updateStatus("Refreshing case data...")
	cm.loadCaseData()
}

// UI update methods

func (cm *CaseManagement) updateEventsTable() {
	// Clear existing rows (keep header)
	for row := cm.eventsTable.GetRowCount() - 1; row > 0; row-- {
		cm.eventsTable.RemoveRow(row)
	}
	setTableCursor(cm.eventsTable, len(cm.events) > 0)

	// Sort events by timestamp (newest first)
	sort.Slice(cm.events, func(i, j int) bool {
		return cm.events[i].Timestamp.After(cm.events[j].Timestamp)
	})

	// Add event rows
	for i, event := range cm.events {
		row := i + 1

		// Selection indicator
		// ★ is the analyst's judgement about which of these events actually
		// prove the case. It surfaces on the briefing and in exports, which is
		// why it is stored rather than kept in the widget.
		selected := cm.pinnedEvents[event.ID]
		indicator := " "
		if selected {
			indicator = "★"
		}

		// Row cells
		// The host is a host wherever it appears, and the message carries the
		// addresses and filenames it mentions. The host column used to be the
		// success green, which said "this is fine" about a row of evidence.
		cells := []struct {
			text  string
			color tcell.Color
		}{
			{indicator, cm.theme.Accent},
			{event.Timestamp.Format("15:04:05"), cm.theme.TextMuted},
			{event.EventType, cm.theme.Accent},
			{strings.ToUpper(event.Severity), cm.getSeverityTcell(event.Severity)},
			{event.Host, entityColour(entityHost, cm.theme)},
			{truncate(event.Message, 80), cm.theme.TextPrimary},
		}

		for col, cell := range cells {
			text := cell.text
			if col == 5 {
				// The message column is prose; the entities inside it are
				// coloured where they can be recognised from their shape.
				text = paintTextOn(cell.text, tagColor(cm.theme.TextPrimary), cm.theme)
			}
			tableCell := tview.NewTableCell(text).
				SetTextColor(cell.color)

			// Highlight selected rows
			if selected {
				tableCell.SetBackgroundColor(cm.theme.SelectionBg)
			} else {
				// zebra striping
				zebra := cm.theme.TableZebra1
				if i%2 == 1 {
					zebra = cm.theme.TableZebra2
				}
				tableCell.SetBackgroundColor(zebra)
			}

			cm.eventsTable.SetCell(row, col, tableCell)
		}
	}
	// Ensure a data row is selected so Enter works immediately.
	if cm.eventsTable.GetRowCount() > 1 {
		if curRow, _ := cm.eventsTable.GetSelection(); curRow <= 0 {
			cm.eventsTable.Select(1, 0)
			cm.selectedEventIndex = 0
		}
	}
}

// Events filter modal and filtering logic (time, type, severity).
func (cm *CaseManagement) showEventsFilterModal() {
	form := tview.NewForm()
	form.SetTitle(" Events Filter ")
	form.SetBorder(true)
	cm.applyModalTheme(form)

	var startStr, endStr, typesStr, sevsStr string

	form.AddInputField("Start (YYYY-01-02 15:04)", "", 20, nil, func(text string) { startStr = text })
	form.AddInputField("End   (YYYY-01-02 15:04)", "", 20, nil, func(text string) { endStr = text })
	form.AddInputField("Types (comma-separated)", "", 40, nil, func(text string) { typesStr = text })
	form.AddInputField("Severities (comma-separated)", "", 40, nil, func(text string) { sevsStr = text })

	form.AddButton("Apply", func() {
		layout := "2006-01-02 15:04"

		var start, end time.Time
		var err error
		if strings.TrimSpace(startStr) != "" {
			start, err = time.Parse(layout, strings.TrimSpace(startStr))
			if err != nil {
				cm.updateStatus("Invalid start time")
				return
			}
		}
		if strings.TrimSpace(endStr) != "" {
			end, err = time.Parse(layout, strings.TrimSpace(endStr))
			if err != nil {
				cm.updateStatus("Invalid end time")
				return
			}
		}

		typeMap := map[string]bool{}
		for _, t := range strings.Split(typesStr, ",") {
			t = strings.TrimSpace(t)
			if t != "" {
				typeMap[strings.ToLower(t)] = true
			}
		}
		sevMap := map[string]bool{}
		for _, s := range strings.Split(sevsStr, ",") {
			s = strings.TrimSpace(s)
			if s != "" {
				sevMap[strings.ToLower(s)] = true
			}
		}

		cm.filterStart = start
		cm.filterEnd = end
		cm.filterTypes = typeMap
		cm.filterSeverities = sevMap

		cm.applyEventFilters()
		cm.popModalRoot()
	})
	form.AddButton("Cancel", func() {
		cm.popModalRoot()
	})

	cm.pushModalRoot(form)
}

func (cm *CaseManagement) applyEventFilters() {
	if len(cm.baseEvents) == 0 {
		return
	}
	filtered := make([]store.Event, 0, len(cm.baseEvents))
	for _, ev := range cm.baseEvents {
		if !cm.filterStart.IsZero() && ev.Timestamp.Before(cm.filterStart) {
			continue
		}
		if !cm.filterEnd.IsZero() && ev.Timestamp.After(cm.filterEnd) {
			continue
		}
		if len(cm.filterTypes) > 0 && !cm.filterTypes[strings.ToLower(ev.EventType)] {
			continue
		}
		if len(cm.filterSeverities) > 0 && !cm.filterSeverities[strings.ToLower(ev.Severity)] {
			continue
		}
		filtered = append(filtered, ev)
	}
	cm.events = filtered
	cm.updateEventsTable()
	cm.updateTimelineView()
	cm.updateStatus(fmt.Sprintf("Applied filters: %d events", len(filtered)))
}

func (cm *CaseManagement) clearEventFilters() {
	cm.filterStart = time.Time{}
	cm.filterEnd = time.Time{}
	cm.filterTypes = nil
	cm.filterSeverities = nil
	if cm.baseEvents != nil {
		cm.events = cm.baseEvents
	}
	cm.updateEventsTable()
	cm.updateTimelineView()
	cm.updateStatus("Cleared event filters")
}

// showEventDetailsModal displays plugin-wise enrichments for the given event in a themable, scrollable modal.
func (cm *CaseManagement) showEventDetailsModal(ev store.Event) {
	// Single scrollable TextView modal (no actions bar) and Esc to close.
	body := tview.NewTextView().
		SetDynamicColors(true).
		SetScrollable(true).
		SetWrap(true)
	body.SetBorder(true).SetTitle(" Event Details ").SetTitleAlign(tview.AlignLeft)
	body.SetBackgroundColor(cm.theme.Surface)
	body.SetTextColor(cm.theme.TextPrimary)

	// Allow Esc (and 'q') to close the modal
	body.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch event.Key() {
		case tcell.KeyEsc:
			cm.popModalRoot()
			return nil
		case tcell.KeyRune:
			if event.Rune() == 'q' || event.Rune() == 'Q' {
				cm.popModalRoot()
				return nil
			}
		}
		return event
	})
	// Also register DoneFunc as an additional reliable close path for Esc
	body.SetDoneFunc(func(key tcell.Key) {
		if key == tcell.KeyEsc {
			cm.popModalRoot()
		}
	})

	// Initial content
	render := func(text string) {
		body.SetText(text)
	}

	lbl := cm.theme.TagWarning
	val := cm.theme.TagTextPrimary
	acc := cm.theme.TagAccent

	header := fmt.Sprintf("[%s]Event[-] [%s]%s[-]  [%s]%s[-]  [%s]%s[-]\n\n",
		lbl, val, ev.Timestamp.Format("2006-01-02 15:04:05"),
		cm.severityTag(ev.Severity), strings.ToUpper(ev.EventType),
		acc, ev.ID,
	)
	// Render initial placeholder and include a visible hint so users know how to close immediately.
	render(fmt.Sprintf("%sLoading enrichments...\n\n[%s][Esc or q] close[-]", header, cm.theme.TagMuted))

	// Mount modal (body only)
	cm.pushModalRoot(body)

	// Fetch enrichments asynchronously
	go func() {
		enrichments, err := cm.store.GetEnrichmentsByEvent(cm.ctx, ev.ID)
		var observables []store.Observable
		if err == nil && len(enrichments) > 0 {
			if byEvent, obsErr := cm.store.GetObservablesForEvents(cm.ctx, []string{ev.ID}); obsErr == nil {
				observables = byEvent[ev.ID]
			}
		}
		cm.app.QueueUpdateDraw(func() {
			if err != nil {
				render(header + fmt.Sprintf("[%s]Failed to load enrichments:[-] %v", cm.theme.TagWarning, err))
				return
			}
			var sb strings.Builder
			sb.WriteString(header)
			// Base fields
			if ev.Host != "" {
				sb.WriteString(fmt.Sprintf("[%s]Host:[-] [%s]%s[-]\n", lbl, val, ev.Host))
			}
			if ev.Message != "" {
				sb.WriteString(fmt.Sprintf("[%s]Message:[-] [%s]%s[-]\n", lbl, val, ev.Message))
			}
			if ev.SrcIP != "" || ev.DstIP != "" {
				if ev.SrcIP != "" {
					sb.WriteString(fmt.Sprintf("[%s]Src:[-] [%s]%s:%d[-]  ", lbl, acc, ev.SrcIP, ev.SrcPort))
				}
				if ev.DstIP != "" {
					sb.WriteString(fmt.Sprintf("[%s]Dst:[-] [%s]%s:%d[-]", lbl, acc, ev.DstIP, ev.DstPort))
				}
				sb.WriteString("\n")
			}
			if ev.ProcessName != "" {
				sb.WriteString(fmt.Sprintf("[%s]Process:[-] [%s]%s[-]\n", lbl, val, ev.ProcessName))
			}
			if ev.FileName != "" {
				sb.WriteString(fmt.Sprintf("[%s]File:[-] [%s]%s[-]\n", lbl, val, ev.FileName))
			}
			sb.WriteString("\n")

			// Enrichments, grouped into one card per indicator — the same
			// rendering the main detail pane uses.
			sb.WriteString(fmt.Sprintf("[%s]Enrichments[-]\n", lbl))
			if len(enrichments) == 0 {
				sb.WriteString("  (none)\n")
			} else {
				cards := groupEnrichments(enrichments, eventIndicatorValues(observables, &ev))
				renderEnrichmentCards(&sb, cm.theme, cards, enrichmentRenderOptions{
					Indent:      "  ",
					MaxFields:   12,
					MaxValueLen: 120,
				})
			}
			// Append a persistent hint at the bottom after enrichments load
			sb.WriteString(fmt.Sprintf("\n\n[%s][Esc or q] close[-]", cm.theme.TagMuted))
			render(sb.String())
		})
	}()
}

// Overview rendering (metadata, quick stats, pinned highlights)
// briefingWidth is the room the briefing has to lay out in.
//
// The widget's own rect is one frame stale immediately after the drawer opens
// or closes — tview recomputes it during Draw — so the pending change is
// applied here. Without it the two-column layout is chosen for a width the
// briefing no longer has, and every right-hand column is clipped mid-word.
func (cm *CaseManagement) briefingWidth() int {
	_, _, width, _ := cm.overviewView.GetInnerRect()
	if width <= 0 {
		return briefingTwoColumnWidth
	}
	return width + cm.pendingWidthShift
}

// renderBriefing paints the Briefing tab.
//
// The same renderer the Cases screen uses, so the two cannot disagree about a
// case. It replaced renderOverview, which listed the title, description, status
// and time span — facts the analyst already had, since they opened this case.
func (cm *CaseManagement) renderBriefing() {
	if cm.overviewView == nil {
		return
	}
	d := briefingData{Case: cm.caseData, Findings: cm.caseFindings,
		Events: cm.events, Pinned: cm.pinnedEvents}
	if d.Pinned == nil {
		d.Pinned = map[string]bool{}
	}

	brief, err := cm.store.GetBriefing(cm.ctx, cm.caseData.ID)
	if err != nil {
		cm.overviewView.SetText(fmt.Sprintf("\n [%s]Could not load the briefing.[-]\n [%s]%s[-]\n\n [%s]%s[-]",
			cm.theme.TagError, cm.theme.TagMuted, tview.Escape(err.Error()),
			cm.theme.TagAccent, tview.Escape("[r] Retry")))
		return
	}
	d.Brief = brief

	cm.overviewView.SetText(renderBriefing(d, cm.theme, cm.briefingWidth()))
}

// IOC table rendering with extraction and grouping

// iocBuckets is the display order of indicator groups in the IOCs tab.
var iocBuckets = []string{"ip", "domain", "url", "hash", "file", "process", "user", "email"}

// iocBucketFor maps an OCSF observable type_id onto a display bucket. Types that
// are not useful as pivot indicators (ports, countries, ...) are skipped.
func iocBucketFor(typeID int) (string, bool) {
	switch typeID {
	case ocsf.ObservableTypeIPAddress:
		return "ip", true
	case ocsf.ObservableTypeHostname:
		return "domain", true
	case ocsf.ObservableTypeURLString, ocsf.ObservableTypeURL:
		return "url", true
	case ocsf.ObservableTypeHash:
		return "hash", true
	case ocsf.ObservableTypeFileName:
		return "file", true
	case ocsf.ObservableTypeProcessName:
		return "process", true
	case ocsf.ObservableTypeUserName:
		return "user", true
	case ocsf.ObservableTypeEmail:
		return "email", true
	}
	return "", false
}

// extractIOCs builds the case's indicator index.
//
// Indicators come from the observables table, which OCSF describes as "an
// optional query optimization" existing precisely so consumers do not have to
// rediscover indicators by scanning text. Regex scraping remains only as a
// fallback for events that arrived without observables, and anything found that
// way is marked as derived so it is distinguishable in the UI.
func (cm *CaseManagement) extractIOCs() {
	// Choose source: use full corpus if available
	source := cm.baseEvents
	if len(source) == 0 {
		source = cm.events
	}

	index := map[string]map[string]*IOCItem{}
	for _, b := range iocBuckets {
		index[b] = map[string]*IOCItem{}
	}

	add := func(typ, val, evID string, ts time.Time, typeID int, asserted bool) {
		val = strings.TrimSpace(val)
		if val == "" {
			return
		}
		m, ok := index[typ]
		if !ok {
			return
		}
		item, exists := m[val]
		if !exists {
			item = &IOCItem{
				Type:            typ,
				Value:           val,
				First:           ts,
				Last:            ts,
				RelatedEventIDs: []string{},
				TypeID:          typeID,
			}
			m[val] = item
		}
		item.Count++
		// An indicator the source vouched for stays marked as such even if the
		// same value is also derived elsewhere.
		if asserted {
			item.Asserted = true
		}
		if typeID != ocsf.ObservableTypeUnknown && item.TypeID == ocsf.ObservableTypeUnknown {
			item.TypeID = typeID
		}
		if ts.Before(item.First) {
			item.First = ts
		}
		if ts.After(item.Last) {
			item.Last = ts
		}
		if len(item.RelatedEventIDs) == 0 || item.RelatedEventIDs[len(item.RelatedEventIDs)-1] != evID {
			item.RelatedEventIDs = append(item.RelatedEventIDs, evID)
		}
	}

	// One indexed query for the whole case rather than a query per event.
	obsByEvent := map[string][]store.Observable{}
	if cm.store != nil && len(source) > 0 {
		ids := make([]string, 0, len(source))
		for _, ev := range source {
			ids = append(ids, ev.ID)
		}
		loaded, err := cm.store.GetObservablesForEvents(cm.ctx, ids)
		if err != nil {
			if cm.logger != nil {
				cm.logger.Printf("extractIOCs: observable lookup failed, falling back to text scan: %v", err)
			}
		} else {
			obsByEvent = loaded
		}
	}

	for _, ev := range source {
		if obs := obsByEvent[ev.ID]; len(obs) > 0 {
			for _, o := range obs {
				bucket, ok := iocBucketFor(o.TypeID)
				if !ok {
					continue
				}
				add(bucket, o.Value, ev.ID, ev.Timestamp, o.TypeID, o.IsAsserted())
			}
			continue
		}
		// No observables recorded for this event — fall back to scraping text.
		cm.scrapeIOCs(ev, add)
	}

	out := make(map[string][]IOCItem, len(index))
	for typ, m := range index {
		list := make([]IOCItem, 0, len(m))
		for _, v := range m {
			list = append(list, *v)
		}
		out[typ] = list
	}
	cm.iocIndex = out
}

// Fallback matchers, used only for events with no recorded observables.
var (
	iocIPRe     = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b`)
	iocURLRe    = regexp.MustCompile(`https?://[^\s]+`)
	iocDomainRe = regexp.MustCompile(`\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b`)
	iocMD5Re    = regexp.MustCompile(`\b[a-fA-F0-9]{32}\b`)
	iocSHA1Re   = regexp.MustCompile(`\b[a-fA-F0-9]{40}\b`)
	iocSHA256Re = regexp.MustCompile(`\b[a-fA-F0-9]{64}\b`)
)

// scrapeIOCs recovers indicators from an event's text for sources that supply no
// observables. Everything it finds is reported as derived, never asserted.
func (cm *CaseManagement) scrapeIOCs(ev store.Event, add func(typ, val, evID string, ts time.Time, typeID int, asserted bool)) {
	ts := ev.Timestamp
	evID := ev.ID
	msg := ev.Message

	if ip := strings.TrimSpace(ev.SrcIP); ip != "" {
		add("ip", ip, evID, ts, ocsf.ObservableTypeIPAddress, false)
	}
	if ip := strings.TrimSpace(ev.DstIP); ip != "" {
		add("ip", ip, evID, ts, ocsf.ObservableTypeIPAddress, false)
	}

	for _, u := range iocURLRe.FindAllString(msg, -1) {
		add("url", u, evID, ts, ocsf.ObservableTypeURLString, false)
		if m := iocDomainRe.FindString(u); m != "" && !iocIPRe.MatchString(m) {
			add("domain", m, evID, ts, ocsf.ObservableTypeHostname, false)
		}
	}
	for _, ip := range iocIPRe.FindAllString(msg, -1) {
		add("ip", ip, evID, ts, ocsf.ObservableTypeIPAddress, false)
	}
	for _, d := range iocDomainRe.FindAllString(msg, -1) {
		if !iocIPRe.MatchString(d) {
			add("domain", d, evID, ts, ocsf.ObservableTypeHostname, false)
		}
	}
	for _, h := range iocSHA256Re.FindAllString(msg, -1) {
		add("hash", strings.ToLower(h), evID, ts, ocsf.ObservableTypeHash, false)
	}
	for _, h := range iocSHA1Re.FindAllString(msg, -1) {
		add("hash", strings.ToLower(h), evID, ts, ocsf.ObservableTypeHash, false)
	}
	for _, h := range iocMD5Re.FindAllString(msg, -1) {
		add("hash", strings.ToLower(h), evID, ts, ocsf.ObservableTypeHash, false)
	}

	if ev.Host != "" && iocDomainRe.MatchString(ev.Host) && !iocIPRe.MatchString(ev.Host) {
		add("domain", ev.Host, evID, ts, ocsf.ObservableTypeHostname, false)
	}
	if ev.FileName != "" {
		for _, re := range []*regexp.Regexp{iocSHA256Re, iocSHA1Re, iocMD5Re} {
			for _, h := range re.FindAllString(ev.FileName, -1) {
				add("hash", strings.ToLower(h), evID, ts, ocsf.ObservableTypeHash, false)
			}
		}
	}
}

// Activity Log rendering

// formatActionDescription provides human-readable descriptions for audit actions
func (cm *CaseManagement) formatActionDescription(action string, details map[string]interface{}) string {
	switch action {
	case "note_added":
		return "📝 Added note"
	case "ioc_added":
		if typ, ok := details["type"].(string); ok {
			if val, ok2 := details["value"].(string); ok2 {
				return fmt.Sprintf("🎯 Added %s IOC: %s", strings.ToUpper(typ), truncate(val, 20))
			}
		}
		return "🎯 Added IOC"
	case "iocs_deleted":
		if count, ok := details["count"].(int); ok {
			return fmt.Sprintf("🗑️ Deleted %d IOCs", count)
		}
		return "🗑️ Deleted IOCs"
	case "status_quick_cycle":
		if from, ok := details["from"].(string); ok {
			if to, ok2 := details["to"].(string); ok2 {
				return fmt.Sprintf("📊 Status: %s → %s", strings.ToUpper(from), strings.ToUpper(to))
			}
		}
		return "📊 Changed status"
	case "case_export":
		return "📤 Exported case"
	case "events_export":
		if count, ok := details["events"].(int); ok {
			return fmt.Sprintf("📤 Exported %d events", count)
		}
		return "📤 Exported events"
	case "copilot_query":
		return "🤖 Copilot query"
	case "case_summary":
		return "🧾 Case summary generated"
	default:
		return strings.ReplaceAll(action, "_", " ")
	}
}

// Tabs: build tab bar and pages, render, switch, and toggle focus.

func (cm *CaseManagement) buildTabs() {
	// Create tab bar
	cm.tabBar = tview.NewTextView().
		SetDynamicColors(true)
	cm.tabBar.SetBorder(false)
	cm.tabBar.SetWrap(false)

	// Create pages container
	cm.tabsPages = tview.NewPages()

	// Build additional views
	cm.overviewView = tview.NewTextView().SetDynamicColors(true).SetScrollable(true)
	cm.overviewView.SetBorder(true).SetTitle(" BRIEFING ").SetTitleAlign(tview.AlignLeft)
	// Overview tab input capture: l to generate case summary, Tab to toggle focus
	cm.overviewView.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch event.Key() {
		case tcell.KeyTab:
			// Tab moves between the case's tabs, which is what §9 lists first
			// and what an analyst reaches for. Pane focus moved to `h`/`l`,
			// which are already the focus keys everywhere else.
			cm.switchTab(wrapTab(cm.activeTab + 1))
			return nil
		case tcell.KeyBacktab:
			cm.switchTab(wrapTab(cm.activeTab - 1))
			return nil
		case tcell.KeyRune:
			switch event.Rune() {
			case 'l':
				cm.runCaseSummary()
				return nil
			}
		}
		return event
	})

	cm.iocsTable = tview.NewTable().
		SetBorders(false).
		SetSelectable(true, false).
		SetFixed(1, 0)
	cm.iocsTable.SetBorder(true).SetTitle(" INDICATORS ").SetTitleAlign(tview.AlignLeft)
	// IOC tab input capture: add ( + ), delete ( d ), toggle select (space), Tab to switch panes.
	cm.iocsTable.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch event.Key() {
		case tcell.KeyTab:
			// Tab moves between the case's tabs, which is what §9 lists first
			// and what an analyst reaches for. Pane focus moved to `h`/`l`,
			// which are already the focus keys everywhere else.
			cm.switchTab(wrapTab(cm.activeTab + 1))
			return nil
		case tcell.KeyBacktab:
			cm.switchTab(wrapTab(cm.activeTab - 1))
			return nil
		case tcell.KeyRune:
			switch event.Rune() {
			case '+':
				cm.showAddIOCModal()
				return nil
			case 'p', 'P':
				cm.pivotSelectedIndicator()
				return nil
			case 'd':
				cm.deleteSelectedManualIOCs()
				return nil
			case ' ':
				cm.toggleManualIOC()
				return nil
			}
		}
		return event
	})
	// Enter pivots, as it does on Events: "where else has this appeared?" is
	// answered the same way wherever it is asked.
	cm.iocsTable.SetSelectedFunc(func(row, col int) { cm.pivotSelectedIndicator() })

	cm.activityTable = tview.NewTable().SetSelectable(true, false).SetFixed(1, 0)
	cm.activityTable.SetBorder(true).SetTitle(" ACTIVITY ").SetTitleAlign(tview.AlignLeft)

	// Add pages in required order: overview, events, timeline, iocs, notes, activity
	cm.tabsPages.AddPage("briefing", cm.overviewView, true, true)
	cm.tabsPages.AddPage("findings", cm.findingsTable, true, false)
	cm.tabsPages.AddPage("events", cm.eventsTable, true, false)
	cm.tabsPages.AddPage("timeline", cm.timelineView, true, false)
	cm.tabsPages.AddPage("iocs", cm.iocsTable, true, false)
	cm.tabsPages.AddPage("notes", cm.notesPages, true, false)
	cm.tabsPages.AddPage("activity", cm.activityTable, true, false)

	// Ensure a valid active tab, default to Overview
	if cm.activeTab < 0 || cm.activeTab >= len(caseTabNames) {
		cm.activeTab = tabBriefing
	}
	cm.tabsPages.SwitchToPage(caseTabPages[cm.activeTab].page)

	// Initial renders. The findings query is started by the constructor, once
	// the layout exists — reading into widgets that are still being built is
	// safe only by accident.
	cm.renderBriefing()
	cm.renderCaseFindings()
	cm.renderIOCs()
	cm.renderActivityLog()

	cm.renderTabBar()
}

// Spacing inside the bar. Two columns either side of a label give each segment
// room to be its own thing; the separator between them takes one more.
const (
	caseTabIndent = 1
	caseTabPad    = 2
	caseTabRuleW  = 1
)

// caseTabStripWidth is the columns the full strip needs for these labels.
func caseTabStripWidth(labels []string) int {
	w := caseTabIndent
	for i, label := range labels {
		if i > 0 {
			w += caseTabRuleW
		}
		w += len([]rune(label)) + 2*caseTabPad
	}
	return w
}

// barWidth is how wide the tab bar may draw.
//
// From the terminal the application already measured every frame, falling back
// to the widget's own rect only once it has been drawn at least once — an
// undrawn one answers with a default that has nothing to do with this screen.
func (cm *CaseManagement) barWidth() int {
	// What the layout was last drawn at, recorded by its draw function, which
	// is handed the true width every frame.
	if cm.lastWidth > 0 {
		return cm.lastWidth
	}
	// Before the first draw: what the application measured for the terminal.
	if cm.parentUI != nil && cm.parentUI.termWidth > 0 {
		return cm.parentUI.termWidth
	}
	// Last resort, and only once the widget has been drawn at least once: an
	// undrawn TextView answers with a default that has nothing to do with this
	// screen.
	// The header measures itself against this too, and it is painted while the
	// layout is still being built — before the tab bar exists.
	if cm.tabBar == nil {
		return 0
	}
	if _, _, w, _ := cm.tabBar.GetInnerRect(); w > caseTabBarMinRect {
		return w
	}
	return 0
}

// caseTabBarMinRect is the width below which a tab bar's reported rect is
// tview's default rather than a measurement. A real terminal is never this
// narrow, and an undrawn TextView reports 15.
const caseTabBarMinRect = 20

// caseTabCount is how many records a tab holds, or -1 where a count says
// nothing.
//
// Briefing is one document, so a number beside it would be noise. The rest are
// lists, and how full they are is exactly what an analyst wants to know before
// deciding where to look — "Findings 3 · Events 128 · Notes 0" is a shape of the
// case, readable without pressing Tab seven times.
func (cm *CaseManagement) caseTabCount(idx int) int {
	switch idx {
	case tabFindings:
		return len(cm.caseFindings)
	case tabEvents:
		return len(cm.events)
	case tabTimeline:
		return len(cm.timelineEntries)
	case tabIOCs:
		return len(cm.caseIndicators)
	case tabNotes:
		// What the tab shows, not what the case holds: the briefing and the
		// hand-added indicators are notes too, and they belong to their tabs.
		return len(caseLogNotes(cm.notes))
	case tabActivity:
		return len(cm.auditLog)
	}
	return -1
}

// caseTabParts is a tab's name and its count, kept apart so each can be drawn
// in its own weight — "Findings 3" in one colour reads as a two-word name.
func (cm *CaseManagement) caseTabParts(idx int) (name, count string) {
	name = caseTabNames[idx]
	if n := cm.caseTabCount(idx); n >= 0 {
		count = strconv.Itoa(n)
	}
	return name, count
}

// caseTabLabel is a tab's text, for measuring the strip against the terminal.
func (cm *CaseManagement) caseTabLabel(idx int) string {
	name, count := cm.caseTabParts(idx)
	if count == "" {
		return name
	}
	return name + " " + count
}

// renderTabBar draws the tab strip.
//
// A bar, not a line of words. The strip is one row of raised surface running
// the full width, each tab a segment on it, separated by a hairline, with the
// tab you are on filled in the accent. The bar is the element; the tabs are
// parts of it — which is what makes six inactive tabs read as six things you
// can go to rather than as a sentence.
//
// It has been through two worse forms. The first drew a little box around each
// tab, " ┌ Events ┐ ": seven boxes read as seven separate widgets, the corner
// glyphs cost four columns each and carried nothing, and the active tab was
// marked only by the shape of its corners. The second dropped the boxes for
// plain text and an accent rule on a second row — but text floating on the app
// background has no edges, so the tabs ran together, and the rule row was a
// dozen columns of ink and a hundred and eighty of nothing. This form spends
// one row instead of two and gives every tab an edge.
func (cm *CaseManagement) renderTabBar() {
	names := caseTabNames
	active := cm.activeTab
	if active < 0 || active >= len(names) {
		active = 0
	}

	labels := make([]string, len(names))
	for i := range names {
		labels[i] = cm.caseTabLabel(i)
	}

	// The width comes from the terminal, not from the widget. tview reports a
	// primitive's rect a frame late, and an undrawn TextView answers 15 — so
	// every case opened on the compact form, on a screen with room for the
	// whole strip, and only corrected itself once something re-rendered the
	// bar. Which is why the tabs appeared the first time you pressed Tab.
	barWidth := cm.barWidth()

	// Below the width the strip needs it would truncate mid-word and drop the
	// last tabs off the end entirely — a bar that hides where you can go is
	// worse than one that admits it does not fit. The narrow form states
	// position and how to move instead.
	if barWidth > 0 && barWidth < caseTabStripWidth(labels) {
		cm.tabBar.SetText(fmt.Sprintf(
			" [::b]%s[-]  [%s]%d/%d · Tab next · Shift+Tab back[-]",
			labels[active], cm.theme.TagMuted, active+1, len(names)))
		return
	}

	raised := tagColor(cm.theme.SurfaceRaised)
	rule := "│"
	if !supportsUnicode() {
		rule = "|"
	}

	var strip strings.Builder
	strip.WriteString(fmt.Sprintf("[:%s]%s", raised, strings.Repeat(" ", caseTabIndent)))

	for i := range labels {
		if i > 0 {
			// No hairline against the filled segment: the fill is already an
			// edge, and a rule beside it reads as a seam.
			if i == active || i-1 == active {
				strip.WriteString(fmt.Sprintf("[:%s] ", raised))
			} else {
				strip.WriteString(fmt.Sprintf("[%s:%s]%s",
					tagColor(cm.theme.Border), raised, rule))
			}
		}

		name, count := cm.caseTabParts(i)
		if i == active {
			// Foreground taken from the surface behind the strip, so the label
			// sits *in* the accent rather than on top of it. The count drops
			// the bold rather than the colour: on a filled segment anything
			// quieter than the label stops being legible.
			strip.WriteString(caseTabSegment(
				tagColor(cm.theme.Surface), tagColor(cm.theme.Accent), "b", "", name, count))
			continue
		}
		strip.WriteString(caseTabSegment(cm.theme.TagMuted, raised, "", "d", name, count))
	}

	// The rest of the row is bar, not background: the strip ends where the
	// terminal does.
	strip.WriteString(fmt.Sprintf("[:%s]", raised))
	cm.tabBar.SetText(strip.String())
}

// caseTabSegment draws one segment of the bar: padding, the tab's name, and its
// count in a quieter weight.
func caseTabSegment(fg, bg, attrs, countAttrs, name, count string) string {
	pad := strings.Repeat(" ", caseTabPad)
	label := fmt.Sprintf("[%s:%s:%s]%s%s", fg, bg, attrs, pad, name)
	if count != "" {
		label += fmt.Sprintf(" [%s:%s:%s]%s", fg, bg, countAttrs, count)
	}
	return label + fmt.Sprintf("[%s:%s:%s]%s[-:-:-]", fg, bg, attrs, pad)
}

// wrapTab keeps a tab index inside the tab list, wrapping at both ends.
func wrapTab(idx int) int {
	n := len(caseTabNames)
	if n == 0 {
		return 0
	}
	return ((idx % n) + n) % n
}

func (cm *CaseManagement) switchTab(idx int) {
	if idx < 0 || idx >= len(caseTabNames) {
		return
	}
	cm.activeTab = idx
	cm.tabsPages.SwitchToPage(caseTabPages[idx].page)
	cm.setFocusPane(caseTabPages[idx].focus)
	if idx == tabFindings {
		// Refresh on entry: a finding may have been escalated into this case
		// since the screen was opened.
		cm.loadCaseFindings()
	}
	cm.renderTabBar()
}

// focusTabContent is `h`: move left, to the tab you are on.
//
// h and l both toggled, so h — which means "left" to everyone who has used vi —
// jumped right into the copilot, and pressing it again to undo that only worked
// because the toggle happened to be symmetric. They are directions now.
func (cm *CaseManagement) focusTabContent() {
	if cm.activeTab >= 0 && cm.activeTab < len(caseTabPages) {
		cm.setFocusPane(caseTabPages[cm.activeTab].focus)
		return
	}
	cm.setFocusPane(FocusEvents)
}

// focusCopilot is `l`: move right, to the copilot — if it is open.
//
// With the panel closed there is nothing to the right, so the key says so
// rather than focusing a hidden widget and reporting "Focus: Copilot" over a
// pane that is not on screen.
func (cm *CaseManagement) focusCopilot() {
	if !cm.copilotOpen {
		cm.updateStatus("The copilot is closed — ] opens it")
		return
	}
	cm.setFocusPane(FocusCopilot)
}

func (cm *CaseManagement) toggleLeftRightFocus() {
	if cm.focusedPane == FocusCopilot {
		// Return to active left tab
		if cm.activeTab >= 0 && cm.activeTab < len(caseTabPages) {
			cm.setFocusPane(caseTabPages[cm.activeTab].focus)
		} else {
			cm.setFocusPane(FocusEvents)
		}
	} else {
		// Go to Copilot
		cm.setFocusPane(FocusCopilot)
	}
}

// OnThemeChanged updates the Case Management theme live when the parent UI changes theme.
func (cm *CaseManagement) OnThemeChanged(theme Theme) {
	cm.theme = theme
	cm.applyTheme()
	cm.updateMetadataBar()
	cm.updateEventsTable()
	cm.updateTimelineView()
	cm.renderBriefing()
	cm.renderIOCs()
	cm.renderActivityLog()
	cm.renderTabBar()
}

func (cm *CaseManagement) updateStatus(message string) {
	timestamp := time.Now().Format("15:04:05")

	mut := cm.theme.TagMuted
	acc := cm.theme.TagAccent

	sep := fmt.Sprintf(" [%s]|[-] ", mut)
	analyst := cm.getCurrentAnalyst()

	// Base line with consistent theming (no selection count by default)
	statusText := fmt.Sprintf(
		"[%s]%s[-]%s[%s]Analyst[-]: %s%s%s",
		mut, timestamp,
		sep, acc, analyst,
		sep, message,
	)

	// The pinned count, which is this screen's selection: it is what the
	// briefing lists, what the report quotes and what `e` exports. The badge
	// used to count a selection map nothing wrote, so it never appeared.
	if n := len(cm.pinnedEvents); n > 0 {
		statusText = fmt.Sprintf("%s%s[%s]%d[-] pinned", statusText, sep, acc, n)
	}

	// Standard navigation hints
	// The same words the tab strip uses. Two names for one key — "Tab next" on
	// the strip and "Tab-left/right" here — reads as two different keys.
	statusText = fmt.Sprintf("%s%s[%s]Tab[-] next · [%s]Shift+Tab[-] back · [%s]Esc[-] leaves · [%s]?[-] help",
		statusText, sep, acc, acc, acc, acc)

	cm.statusBar.SetText(statusText)
}

// setStatusDirect bypasses the default patterned status format and sets the status bar verbatim.
func (cm *CaseManagement) setStatusDirect(text string) {
	if cm.statusBar != nil {
		cm.statusBar.SetText(text)
	}
}

// notesViewStatusText renders a Notes status line (view mode) using the global color theme.
func (cm *CaseManagement) notesViewStatusText() string {
	ts := time.Now().Format("15:04:05")
	mut := cm.theme.TagMuted
	acc := cm.theme.TagAccent
	sep := fmt.Sprintf(" [%s]|[-] ", mut)
	analyst := cm.getCurrentAnalyst()
	return fmt.Sprintf(
		"[%s]%s[-]%s[%s]Analyst[-]: %s%s[%s]Focus[-]: Notes%s n new · T template · Tab next tab%s[%s]Esc[-] leaves",
		mut, ts,
		sep, acc, analyst,
		sep, acc,
		sep, sep, acc,
	)
}

// notesEditStatusText renders a Notes status line (edit mode) using the global color theme (no selection count).
func (cm *CaseManagement) notesEditStatusText() string {
	ts := time.Now().Format("15:04:05")
	mut := cm.theme.TagMuted
	acc := cm.theme.TagAccent
	sep := fmt.Sprintf(" [%s]|[-] ", mut)
	analyst := cm.getCurrentAnalyst()
	return fmt.Sprintf(
		"[%s]%s[-]%s[%s]Analyst[-]: %s%s[%s]Focus[-]: Notes (editing)%s Ctrl+S saves · Esc cancels · Tab opens the copilot",
		mut, ts,
		sep, acc, analyst,
		sep, acc,
		sep,
	)
}

// switchToNotesView switches Notes to view mode, focuses viewer, and sets the exact status hint.
func (cm *CaseManagement) switchToNotesView() {
	cm.isEditingNotes = false
	if cm.notesPages != nil {
		cm.notesPages.SwitchToPage("view")
	}
	if cm.notesTable != nil {
		cm.app.SetFocus(cm.notesTable)
	}
	cm.setStatusDirect(cm.notesViewStatusText())
	cm.updateFocusStyles()
}

// switchToNotesEdit switches Notes to edit mode, focuses editor, and shows an edit-oriented status line.
func (cm *CaseManagement) switchToNotesEdit() {
	cm.isEditingNotes = true
	if cm.notesEditor != nil {
		// Start with an empty draft
		cm.notesEditor.SetText("", true)
		cm.notesDraftBaseline = ""
	}
	if cm.notesPages != nil {
		cm.notesPages.SwitchToPage("edit")
	}
	if cm.notesEditor != nil {
		cm.app.SetFocus(cm.notesEditor)
	}
	// Edit-mode status (kept concise; themed like other tabs)
	cm.setStatusDirect(cm.notesEditStatusText())
	cm.updateFocusStyles()
}

// Action handlers

func (cm *CaseManagement) onEventSelected(row int) {
	if row <= 0 || row-1 >= len(cm.events) {
		return
	}

	cm.selectedEventIndex = row - 1
	event := cm.events[cm.selectedEventIndex]

	// Update timeline to highlight this event (no special highlight yet)
	_ = event
	cm.updateTimelineView()
	cm.updateStatus(fmt.Sprintf("Selected event: %s", truncate(event.Message, 80)))
}

func (cm *CaseManagement) pinCurrentEvent() {
	if cm.selectedEventIndex < 0 || cm.selectedEventIndex >= len(cm.events) {
		return
	}

	event := cm.events[cm.selectedEventIndex]
	if cm.pinnedEvents[event.ID] {
		delete(cm.pinnedEvents, event.ID)
		cm.updateStatus("Event unpinned from timeline")
	} else {
		cm.pinnedEvents[event.ID] = true
		cm.updateStatus("Event pinned to timeline")
	}

	cm.updateTimelineView()
}

func (cm *CaseManagement) sendCopilotMessage() {
	message := cm.copilotInput.GetText()
	if strings.TrimSpace(message) == "" {
		return
	}

	// Update persona from dropdown selection
	if opt, _ := cm.copilotDropdown.GetCurrentOption(); opt >= 0 {
		opts := []string{llm.PersonaSOC, llm.PersonaForensics, llm.PersonaHunter}
		if opt < len(opts) {
			cm.currentPersona = opts[opt]
		}
	}

	// Estimate tokens and confirm if over threshold
	tokensEst := cm.llm.EstimateTokens(message)
	if tokensEst > 1000 {
		cm.showTokenConfirmation(message, tokensEst)
		return
	}

	cm.processCopilotMessage(message)
}

func (cm *CaseManagement) showTokenConfirmation(message string, tokens int) {
	cost := float64(tokens) * 0.002 / 1000 // Rough estimate

	modal := tview.NewModal().
		SetText(fmt.Sprintf("This request will use approximately %d tokens (~$%.4f).\n\nProceed?", tokens, cost)).
		AddButtons([]string{"Send", "Cancel"}).
		SetDoneFunc(func(buttonIndex int, buttonLabel string) {
			if buttonLabel == "Send" {
				cm.processCopilotMessage(message)
			}
			cm.popModalRoot()
			cm.app.SetFocus(cm.copilotInput)
		})

	modal.SetBackgroundColor(cm.theme.Surface)
	modal.SetTextColor(cm.theme.TextPrimary)
	modal.SetBorderColor(cm.theme.FocusBorder)

	cm.pushModalRoot(modal)
}

func (cm *CaseManagement) processCopilotMessage(message string) {
	atomic.AddInt32(&cm.pendingTokens, 1)

	// Add user message to transcript immediately
	userMsg := llm.ChatMessage{
		Role:      "user",
		Content:   message,
		Timestamp: time.Now(),
		Persona:   cm.currentPersona,
	}
	cm.chatHistory = append(cm.chatHistory, userMsg)
	cm.updateCopilotTranscript()

	// Clear input
	cm.copilotInput.SetText("")

	cm.copilotStatus = copilotStatus{Pending: true}
	cm.updateCopilotTranscript()
	if cm.copilotTranscript != nil {
		cm.app.SetFocus(cm.copilotTranscript)
	}
	cm.updateStatus("Copilot thinking...")

	// Process in background
	go func() {
		// Build a non-persisted Case Context and prepend it to outgoing messages.
		msgs := make([]llm.ChatMessage, 0, len(cm.chatHistory)+1)
		if ctx := strings.TrimSpace(cm.buildCaseChatContext()); ctx != "" {
			msgs = append(msgs, llm.ChatMessage{
				Role:      "user",
				Content:   "Case Context:\n" + ctx,
				Timestamp: time.Now(),
				Persona:   cm.currentPersona,
			})
		}
		// Append the actual chat history (already includes the latest user message)
		msgs = append(msgs, cm.chatHistory...)

		req := llm.ChatRequest{
			Messages:  msgs,
			Persona:   cm.currentPersona,
			MaxTokens: 500,
		}

		resp, err := cm.llm.Chat(cm.ctx, req)
		atomic.AddInt32(&cm.pendingTokens, -1)

		cm.app.QueueUpdateDraw(func() {
			if err != nil {
				cm.copilotStatus = copilotStatus{Failure: err.Error()}
				cm.updateCopilotTranscript()
				cm.updateStatus(fmt.Sprintf("Copilot error: %v", err))
				return
			}

			if resp == nil || resp.Error != "" {
				errMsg := "unknown"
				if resp != nil {
					errMsg = resp.Error
				}
				cm.copilotStatus = copilotStatus{Failure: errMsg}
				cm.updateCopilotTranscript()
				cm.updateStatus(fmt.Sprintf("Copilot error: %s", errMsg))
				return
			}

			// Add response to transcript
			cm.copilotStatus = copilotStatus{}
			cm.chatHistory = append(cm.chatHistory, resp.Message)
			cm.updateCopilotTranscript()

			// Log the interaction (non-blocking)
			go cm.store.LogCopilotQuery(cm.ctx, cm.caseData.ID, cm.getCurrentAnalyst(),
				message, resp.Message.Content, resp.TokensUsed, resp.Cost)

			cm.updateStatus(fmt.Sprintf("Copilot response received (%d tokens, $%.4f)",
				resp.TokensUsed, resp.Cost))
		})
	}()
}

func (cm *CaseManagement) updateCopilotTranscript() {
	if cm.copilotTranscript == nil {
		return
	}
	if len(cm.chatHistory) == 0 {
		cm.showCopilotSuggestions()
		return
	}
	renderTranscript(cm.copilotTranscript,
		buildTranscript(cm.chatHistory, cm.copilotTextWidth(), cm.copilotStatus), cm.theme)
	cm.copilotPages.SwitchToPage("transcript")
}

// updateTokenEstimate updates the inline token/cost estimate below the chat transcript.
func (cm *CaseManagement) updateTokenEstimate(text string) {
	if cm.copilotEstimate == nil || cm.llm == nil {
		return
	}
	tokens := cm.llm.EstimateTokens(text)
	cost := float64(tokens) * 0.002 / 1000.0
	cm.copilotEstimate.SetText(fmt.Sprintf("[%s]Est:[-] %d tok  ~$%.4f",
		cm.theme.TagMuted, tokens, cost))
}

// runCaseSummary assembles a prompt from case metadata, events, and enrichments,
// applies a 2000-token confirmation threshold, and renders the summary in Overview.
func (cm *CaseManagement) runCaseSummary() {
	if cm.isSummarizing {
		cm.updateStatus("Case summary already in progress")
		return
	}

	// Gather source events: prefer full corpus if available
	source := cm.baseEvents
	if len(source) == 0 {
		source = cm.events
	}
	events := make([]store.Event, len(source))
	copy(events, source)

	// Sort chronologically and cap to the latest 200 events for token control
	sort.Slice(events, func(i, j int) bool { return events[i].Timestamp.Before(events[j].Timestamp) })
	if len(events) > 200 {
		events = events[len(events)-200:]
	}

	// Build prompt (include enrichments for the tail subset)
	prompt := cm.buildCaseSummaryPrompt(events, 50, 5, 8)

	// Estimate tokens and optionally confirm when large
	tokens := cm.llm.EstimateTokens(prompt)
	if tokens > 2000 {
		cost := float64(tokens) * 0.002 / 1000.0
		cm.showSummaryConfirmation(tokens, cost, func() {
			cm.executeCaseSummary(prompt, events, tokens)
		})
		return
	}

	cm.executeCaseSummary(prompt, events, tokens)
}

// buildCaseSummaryPrompt composes a compact text context for the LLM.
func (cm *CaseManagement) buildCaseSummaryPrompt(events []store.Event, maxEventsWithEnr int, maxEnrPerEvent int, maxKeysPerEnr int) string {
	var sb strings.Builder
	sb.WriteString("You are an incident response analyst. Produce a concise, structured case summary with sections: Executive Summary, Key Findings, Notable IOCs, Affected Assets, Recommended Actions, Open Questions.\n\n")

	// Case header and quick stats
	byType := map[string]int{}
	bySev := map[string]int{}
	var minT, maxT time.Time
	for _, ev := range events {
		byType[ev.EventType]++
		sev := strings.ToLower(ev.Severity)
		bySev[sev]++
		if minT.IsZero() || ev.Timestamp.Before(minT) {
			minT = ev.Timestamp
		}
		if maxT.IsZero() || ev.Timestamp.After(maxT) {
			maxT = ev.Timestamp
		}
	}
	sb.WriteString(fmt.Sprintf(
		"Case: %s | Title: %s | Severity: %s | Status: %s | Owner: %s | Events: %d\n",
		cm.caseData.ID, cm.caseData.Title, cm.caseData.Severity, cm.caseData.Status, cm.caseData.AssignedTo, len(events),
	))
	if !minT.IsZero() && !maxT.IsZero() {
		sb.WriteString(fmt.Sprintf("Time span: %s -> %s\n", minT.Format(time.RFC3339), maxT.Format(time.RFC3339)))
	}
	if len(byType) > 0 {
		sb.WriteString("Events by type: ")
		types := make([]string, 0, len(byType))
		for t := range byType {
			types = append(types, t)
		}
		sort.Strings(types)
		for i, t := range types {
			if i > 0 {
				sb.WriteString(", ")
			}
			sb.WriteString(fmt.Sprintf("%s=%d", t, byType[t]))
		}
		sb.WriteString("\n")
	}
	if len(bySev) > 0 {
		sb.WriteString("Events by severity: ")
		sevs := []string{"critical", "high", "medium", "low", "informational"}
		first := true
		for _, s := range sevs {
			if c := bySev[s]; c > 0 {
				if !first {
					sb.WriteString(", ")
				}
				first = false
				sb.WriteString(fmt.Sprintf("%s=%d", s, c))
			}
		}
		sb.WriteString("\n")
	}

	// Events (compact)
	sb.WriteString("\nEvents:\n")
	for _, ev := range events {
		sb.WriteString(fmt.Sprintf("- %s | %s | sev=%s | host=%s | %s\n",
			ev.Timestamp.Format("2006-01-02 15:04:05"),
			ev.EventType,
			strings.ToUpper(ev.Severity),
			ev.Host,
			truncate(ev.Message, 160),
		))
	}

	// Enrichments for the most recent subset
	if maxEventsWithEnr > 0 && maxEnrPerEvent > 0 {
		sb.WriteString("\nEnrichments (subset):\n")
		start := 0
		if len(events) > maxEventsWithEnr {
			start = len(events) - maxEventsWithEnr
		}
		for i := start; i < len(events); i++ {
			ev := events[i]
			enrs, err := cm.store.GetEnrichmentsByEvent(cm.ctx, ev.ID)
			if err != nil || len(enrs) == 0 {
				continue
			}
			sb.WriteString(fmt.Sprintf("  - Event %s %s %s:\n", ev.Timestamp.Format("2006-01-02 15:04:05"), ev.EventType, ev.ID))
			limit := maxEnrPerEvent
			if len(enrs) < limit {
				limit = len(enrs)
			}
			for j := 0; j < limit; j++ {
				enr := enrs[j]
				sb.WriteString(fmt.Sprintf("    • %s/%s: ", strings.ToUpper(enr.Source), enr.Type))
				keys := make([]string, 0, len(enr.Data))
				for k := range enr.Data {
					keys = append(keys, k)
				}
				sort.Strings(keys)
				n := maxKeysPerEnr
				if len(keys) < n {
					n = len(keys)
				}
				for k := 0; k < n; k++ {
					key := keys[k]
					val := enr.Data[key]
					jb, _ := json.Marshal(val)
					txt := string(jb)
					if len(txt) > 100 {
						txt = txt[:97] + "..."
					}
					if k > 0 {
						sb.WriteString("; ")
					}
					sb.WriteString(fmt.Sprintf("%s=%s", key, txt))
				}
				if len(keys) > n {
					sb.WriteString("; ...")
				}
				sb.WriteString("\n")
			}
		}
	}

	sb.WriteString("\nPlease provide a concise, structured summary based on the above.")
	return sb.String()
}

// buildCaseChatContext constructs a compact context containing only Overview and Analyst Notes.
// It intentionally excludes Events, Enrichments, and IOC details to control token usage.
func (cm *CaseManagement) buildCaseChatContext() string {
	var sb strings.Builder

	// Overview header
	title := strings.TrimSpace(cm.caseData.Title)
	if title == "" {
		title = "(untitled case)"
	}
	owner := strings.TrimSpace(cm.caseData.AssignedTo)
	if owner == "" {
		owner = "Unassigned"
	}
	status := strings.ToUpper(strings.TrimSpace(cm.caseData.Status))
	if status == "" {
		status = "OPEN"
	}
	sev := strings.ToLower(strings.TrimSpace(cm.caseData.Severity))
	if sev == "" {
		sev = "medium"
	}

	// Time span from events if available
	var minT, maxT time.Time
	if len(cm.events) > 0 {
		for _, ev := range cm.events {
			if minT.IsZero() || ev.Timestamp.Before(minT) {
				minT = ev.Timestamp
			}
			if maxT.IsZero() || ev.Timestamp.After(maxT) {
				maxT = ev.Timestamp
			}
		}
	}

	sb.WriteString("Overview:\n")
	sb.WriteString(fmt.Sprintf("- Title: %s\n", title))
	sb.WriteString(fmt.Sprintf("- Status: %s | Severity: %s | Events: %d | Owner: %s\n", status, sev, len(cm.events), owner))
	if !minT.IsZero() && !maxT.IsZero() {
		sb.WriteString(fmt.Sprintf("- Time span: %s → %s\n", minT.Format("2006-01-02 15:04"), maxT.Format("2006-01-02 15:04")))
	}

	// Use existing Overview summary if present; else fallback to a short hint
	if s := strings.TrimSpace(cm.overviewSummary); s != "" {
		sb.WriteString("- Summary: " + s + "\n")
	} else {
		sb.WriteString("- Summary: (no stored overview; use metadata and notes below)\n")
	}

	// Analyst Notes (exclude LinkedType=="summary"), latest first
	type noteView struct {
		when   time.Time
		author string
		text   string
	}
	var notes []noteView
	for _, n := range cm.notes {
		if strings.EqualFold(n.LinkedType, "summary") {
			continue
		}
		notes = append(notes, noteView{
			when:   n.CreatedAt,
			author: n.Author,
			text:   n.Content,
		})
	}
	// Sort newest first
	if len(notes) > 1 {
		sort.Slice(notes, func(i, j int) bool { return notes[i].when.After(notes[j].when) })
	}

	// Initial caps
	maxNotes := 5
	if len(notes) < maxNotes {
		maxNotes = len(notes)
	}
	truncLen := 300

	renderNotes := func(limit int, maxChars int) string {
		var nb strings.Builder
		if limit <= 0 {
			return ""
		}
		nb.WriteString("\nAnalyst Notes:\n")
		for i := 0; i < limit; i++ {
			n := notes[i]
			content := strings.TrimSpace(n.text)
			if content == "" {
				continue
			}
			if len(content) > maxChars {
				content = content[:maxChars] + "..."
			}
			nb.WriteString(fmt.Sprintf("- %s — %s\n", n.when.Format("2006-01-02 15:04"), content))
		}
		return nb.String()
	}

	sb.WriteString(renderNotes(maxNotes, truncLen))

	// Token budget control: try to stay within ~600 tokens
	context := sb.String()
	if llm.EstimateTokens(context) > 600 {
		sb.Reset()
		// Rebuild with tighter limits
		sb.WriteString("Overview:\n")
		sb.WriteString(fmt.Sprintf("- Title: %s\n", title))
		sb.WriteString(fmt.Sprintf("- Status: %s | Severity: %s | Events: %d | Owner: %s\n", status, sev, len(cm.events), owner))
		if !minT.IsZero() && !maxT.IsZero() {
			sb.WriteString(fmt.Sprintf("- Time span: %s → %s\n", minT.Format("2006-01-02 15:04"), maxT.Format("2006-01-02 15:04")))
		}
		if s := strings.TrimSpace(cm.overviewSummary); s != "" {
			short := s
			if len(short) > 400 {
				short = short[:400] + "..."
			}
			sb.WriteString("- Summary: " + short + "\n")
		} else {
			sb.WriteString("- Summary: (no stored overview; use metadata and notes below)\n")
		}
		tightNotes := 3
		if len(notes) < tightNotes {
			tightNotes = len(notes)
		}
		sb.WriteString(renderNotes(tightNotes, 220))
		context = sb.String()
	}

	// If still large, one more reduction
	if llm.EstimateTokens(context) > 700 {
		sb.Reset()
		sb.WriteString("Overview:\n")
		sb.WriteString(fmt.Sprintf("- Title: %s\n", title))
		sb.WriteString(fmt.Sprintf("- Status: %s | Severity: %s | Events: %d | Owner: %s\n", status, sev, len(cm.events), owner))
		if s := strings.TrimSpace(cm.overviewSummary); s != "" {
			short := s
			if len(short) > 300 {
				short = short[:300] + "..."
			}
			sb.WriteString("- Summary: " + short + "\n")
		} else {
			sb.WriteString("- Summary: (no stored overview; notes trimmed)\n")
		}
		tighterNotes := 2
		if len(notes) < tighterNotes {
			tighterNotes = len(notes)
		}
		sb.WriteString(renderNotes(tighterNotes, 150))
	}

	return strings.TrimSpace(sb.String())
}

// executeCaseSummary performs the LLM call and updates UI state.
func (cm *CaseManagement) executeCaseSummary(prompt string, events []store.Event, estTokens int) {
	cm.isSummarizing = true
	cm.updateStatus("Generating case summary...")
	cm.renderBriefing()

	go func() {
		var (
			summary string
			tokens  int
			cost    float64
		)

		// Prefer Chat (persona-aware) over the plain completion path
		req := llm.ChatRequest{
			Messages: []llm.ChatMessage{{
				Role:      "user",
				Content:   prompt,
				Timestamp: time.Now(),
				Persona:   cm.currentPersona,
			}},
			Persona:   cm.currentPersona,
			MaxTokens: 700,
		}
		resp, err := cm.llm.Chat(cm.ctx, req)
		if err == nil && resp != nil && resp.Error == "" {
			summary = resp.Message.Content
			tokens = resp.TokensUsed
			cost = resp.Cost
		} else {
			// Fallback to SummarizeCase
			if s, ferr := cm.llm.SummarizeCase(cm.ctx, cm.caseData, events); ferr == nil {
				summary = s
				tokens = estTokens
				cost = float64(tokens) * 0.002 / 1000.0
			} else {
				cm.app.QueueUpdateDraw(func() {
					cm.isSummarizing = false
					cm.updateStatus(fmt.Sprintf("Summary error: %v", ferr))
					cm.renderBriefing()
				})
				return
			}
		}

		cm.app.QueueUpdateDraw(func() {
			cm.overviewSummary = summary
			cm.summaryTokens = tokens
			cm.summaryCost = cost
			cm.summaryAt = time.Now()
			cm.isSummarizing = false

			// Persist summary as a linked Note so it is available on reopen
			go func(s string) {
				n := store.Note{
					CaseID:     cm.caseData.ID,
					Content:    s,
					Author:     cm.getCurrentAnalyst(),
					Color:      "#ffd166",
					LinkedType: "summary",
					LinkedID:   "overview",
				}
				_, _ = cm.store.AddNote(cm.ctx, n)
			}(summary)

			// Log audit entry (non-blocking)
			go cm.store.LogCaseAction(cm.ctx, cm.caseData.ID, "case_summary", cm.getCurrentAnalyst(),
				map[string]interface{}{"tokens": tokens, "cost": cost})

			cm.renderBriefing()
			cm.renderActivityLog()
			cm.updateStatus("Case summary generated")
		})
	}()
}

// showSummaryConfirmation shows a token/cost confirmation modal for summaries.
func (cm *CaseManagement) showSummaryConfirmation(tokens int, cost float64, onConfirm func()) {
	modal := tview.NewModal().
		SetText(fmt.Sprintf("This summary will use approximately %d tokens (~$%.4f).\n\nProceed?", tokens, cost)).
		AddButtons([]string{"Generate", "Cancel"}).
		SetDoneFunc(func(buttonIndex int, buttonLabel string) {
			if buttonLabel == "Generate" {
				onConfirm()
			} else {
				cm.isSummarizing = false
			}
			cm.popModalRoot()
		})

	modal.SetBackgroundColor(cm.theme.Surface)
	modal.SetTextColor(cm.theme.TextPrimary)
	modal.SetBorderColor(cm.theme.FocusBorder)
	modal.SetButtonBackgroundColor(cm.theme.SelectionBg)
	modal.SetButtonTextColor(cm.theme.SelectionFg)

	cm.pushModalRoot(modal)
}

func (cm *CaseManagement) saveNotes() {
	content := ""
	if cm.notesEditor != nil {
		content = cm.notesEditor.GetText()
	}
	if strings.TrimSpace(content) == "" {
		cm.updateStatus("No notes to save")
		return
	}

	note := store.Note{
		CaseID:  cm.caseData.ID,
		Content: content,
		Author:  cm.getCurrentAnalyst(),
	}

	go func() {
		_, err := cm.store.AddNote(cm.ctx, note)
		cm.app.QueueUpdate(func() {
			if err != nil {
				cm.updateStatus(fmt.Sprintf("Error saving notes: %v", err))
				return
			}

			cm.updateStatus("Notes saved successfully")
			// Log the action
			go cm.store.LogCaseAction(cm.ctx, cm.caseData.ID, "note_added", cm.getCurrentAnalyst(),
				map[string]interface{}{"content_length": len(content)})

			// Return to view mode and refresh notes
			cm.switchToNotesView()
			cm.refreshCaseData()
		})
	}()
}

func (cm *CaseManagement) addNewNote() {
	cm.switchToNotesEdit()
}

// Focus management

func (cm *CaseManagement) cycleFocus() {
	// In tabbed layout, use Tab to toggle focus between Left Tabs and Copilot.
	cm.toggleLeftRightFocus()
}

// paneWidget is the widget that owns the keyboard for a pane.
//
// One table, because the answer was written out twice: setFocusPane knew about
// the Findings tab and popModalRoot's copy did not, so closing a finding left
// the focus on a primitive that was no longer in the tree and the arrow keys
// stopped working until you changed tabs. A pane added later cannot go missing
// from one of two lists any more.
func (cm *CaseManagement) paneWidget(pane int) tview.Primitive {
	if w := cm.paneWidgetStrict(pane); w != nil {
		return w
	}
	// The events table is always built, so the keyboard always lands somewhere.
	if cm.eventsTable != nil {
		return cm.eventsTable
	}
	return nil
}

// paneWidgetStrict is the same answer without the fallback: nil means this pane
// has no widget, which a styling pass needs to know and a focus move does not.
func (cm *CaseManagement) paneWidgetStrict(pane int) tview.Primitive {
	switch pane {
	case FocusEvents:
		if cm.eventsTable != nil {
			return cm.eventsTable
		}
	case FocusOverview:
		if cm.overviewView != nil {
			return cm.overviewView
		}
	case FocusFindings:
		if cm.findingsTable != nil {
			return cm.findingsTable
		}
	case FocusTimeline:
		if cm.timelineView != nil {
			return cm.timelineView
		}
	case FocusIOCs:
		if cm.iocsTable != nil {
			return cm.iocsTable
		}
	case FocusNotes:
		if cm.isEditingNotes && cm.notesEditor != nil {
			return cm.notesEditor
		}
		if cm.notesTable != nil {
			return cm.notesTable
		}
	case FocusActivity:
		if cm.activityTable != nil {
			return cm.activityTable
		}
	case FocusCopilot:
		if cm.copilotInput != nil {
			return cm.copilotInput
		}
	}
	return nil
}

// focusCurrentPane puts the keyboard back where it was, without touching the
// status line — used when returning from a modal, which should not narrate.
func (cm *CaseManagement) focusCurrentPane() {
	if w := cm.paneWidget(cm.focusedPane); w != nil {
		cm.app.SetFocus(w)
	}
}

func (cm *CaseManagement) setFocusPane(pane int) {
	cm.focusedPane = pane
	if w := cm.paneWidget(pane); w != nil {
		cm.app.SetFocus(w)
	}
	switch pane {
	case FocusOverview:
		cm.updateStatus("Focus: Overview")
	case FocusFindings:
		cm.updateStatus("Focus: Findings - Enter=open, the findings this case is about")
	case FocusEvents:
		cm.updateStatus("Focus: Events · Space pin as evidence · e export · f/F filter/clear")
	case FocusTimeline:
		cm.updateStatus("Focus: Timeline - p=pin")
	case FocusIOCs:
		// Arrow keys move in every table; saying so spends the line that should
		// name the keys nobody could guess. And d only removes what you added.
		cm.updateStatus("Focus: Indicators · + add · Space select your own · d delete selected · p pivot (leaves the case)")
	case FocusNotes:
		if cm.isEditingNotes {
			cm.setStatusDirect(cm.notesEditStatusText())
		} else {
			cm.setStatusDirect(cm.notesViewStatusText())
		}
	case FocusActivity:
		cm.updateStatus("Focus: Activity - r=refresh")
	case FocusCopilot:
		cm.updateStatus("Focus: Copilot - Type message, Enter=send, [ / ] persona")
	}
	cm.updateFocusStyles()
}

// Utility methods

func (cm *CaseManagement) getSeverityTcell(severity string) tcell.Color {
	switch strings.ToLower(severity) {
	case "critical":
		return cm.theme.SeverityCritical
	case "high":
		return cm.theme.SeverityHigh
	case "medium":
		return cm.theme.SeverityMedium
	case "low":
		return cm.theme.SeverityLow
	default:
		return cm.theme.SeverityInfo
	}
}

func (cm *CaseManagement) severityTag(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return cm.theme.TagSeverityCritical
	case "high":
		return cm.theme.TagSeverityHigh
	case "medium":
		return cm.theme.TagSeverityMedium
	case "low":
		return cm.theme.TagSeverityLow
	default:
		return cm.theme.TagSeverityInfo
	}
}

func (cm *CaseManagement) applyTheme() {
	// Apply theme colors to all components
	cm.metadataBar.SetBackgroundColor(cm.theme.Surface)
	// The border draws itself, so it holds the theme it was installed with.
	heavyBorder(cm.metadataBar.Box, "CASE", cm.theme)
	cm.metadataBar.SetTextColor(cm.theme.TextPrimary)

	cm.eventsTable.SetBackgroundColor(cm.theme.Surface)
	if cm.findingsTable != nil {
		cm.findingsTable.SetBackgroundColor(cm.theme.Surface)
	}
	if cm.iocsTable != nil {
		cm.iocsTable.SetBackgroundColor(cm.theme.Surface)
	}

	cm.timelineView.SetBackgroundColor(cm.theme.Surface)
	cm.timelineView.SetSelectedStyle(tcell.StyleDefault.
		Background(cm.theme.SelectionBg).Foreground(cm.theme.SelectionFg))

	cm.copilotPanel.SetBackgroundColor(cm.theme.Surface)

	// The copilot's own widgets, all of them.
	//
	// The drawer is built once and coloured from this one pass, and three of
	// its parts were never in it: the provider line, the page container that
	// holds the suggestions and the transcript, and the dropdown's own box. A
	// widget with no background falls back to tview's global default, which is
	// black — which is why the panel had dark bands across it on every palette
	// whose surface is not black.
	if cm.copilotDropdown != nil {
		cm.copilotDropdown.SetBackgroundColor(cm.theme.Surface)
		cm.copilotDropdown.SetFieldBackgroundColor(cm.theme.Surface)
		cm.copilotDropdown.SetFieldTextColor(cm.theme.TextPrimary)
		cm.copilotDropdown.SetLabelColor(cm.theme.TextMuted)
		// The list that drops down is a widget of its own, and tview styles it
		// its own blue unless told otherwise.
		cm.copilotDropdown.SetListStyles(
			tcell.StyleDefault.Background(cm.theme.SurfaceRaised).Foreground(cm.theme.TextPrimary),
			tcell.StyleDefault.Background(cm.theme.SelectionBg).Foreground(cm.theme.SelectionFg))
	}
	if cm.copilotProvider != nil {
		cm.copilotProvider.SetBackgroundColor(cm.theme.Surface)
		cm.copilotProvider.SetTextColor(cm.theme.TextMuted)
		// The text carries its own colour tag, written when the panel was
		// built under whichever theme was then in force.
		cm.copilotProvider.SetText(fmt.Sprintf("[%s]%s[-]",
			cm.theme.TagMuted, copilotProviderLine(activeLLMProvider(), true)))
	}
	if cm.copilotPages != nil {
		cm.copilotPages.SetBackgroundColor(cm.theme.Surface)
	}

	cm.copilotTranscript.SetBackgroundColor(cm.theme.Surface)
	cm.copilotTranscript.SetSelectedStyle(tcell.StyleDefault.
		Background(cm.theme.SelectionBg).Foreground(cm.theme.SelectionFg))
	if cm.copilotSuggestions != nil {
		cm.copilotSuggestions.SetBackgroundColor(cm.theme.Surface)
		cm.copilotSuggestions.SetSelectedStyle(tcell.StyleDefault.
			Background(cm.theme.SelectionBg).Foreground(cm.theme.SelectionFg))
	}

	if cm.copilotEstimate != nil {
		cm.copilotEstimate.SetBackgroundColor(cm.theme.Surface)
		cm.copilotEstimate.SetTextColor(cm.theme.TextPrimary)
		if cm.copilotInput != nil {
			// Repaint the line so its tag picks up the new palette.
			cm.updateTokenEstimate(cm.copilotInput.GetText())
		}
	}

	if cm.notesTable != nil {
		cm.notesTable.SetBackgroundColor(cm.theme.Surface)
		cm.notesTable.SetSelectedStyle(tcell.StyleDefault.
			Background(cm.theme.SelectionBg).Foreground(cm.theme.SelectionFg))
	}
	if cm.notesEditor != nil {
		cm.notesEditor.SetBackgroundColor(cm.theme.Surface)
	}

	// Tab bar styling
	if cm.tabBar != nil {
		// Raised, so the strip reads as a bar across the screen rather than as
		// text floating on the same ground as everything else.
		cm.tabBar.SetBackgroundColor(cm.theme.SurfaceRaised)
		cm.tabBar.SetTextColor(cm.theme.TextPrimary)
	}

	// The containers, and the four widgets nothing ever coloured.
	//
	// A widget with no background falls back to tview's global default, which
	// is black — so three quarters of this screen painted black while every
	// other screen painted the theme's own background. On gruvbox that is
	// #282828 against #000000: the case screen read as a slightly different,
	// darker application.
	for _, box := range []*tview.Box{
		boxOf(cm.layout), boxOf(cm.caseBody), boxOf(cm.tabsPages),
		boxOf(cm.overviewView), boxOf(cm.activityTable),
		boxOf(cm.notesViewer),
	} {
		if box != nil {
			box.SetBackgroundColor(cm.theme.Bg)
		}
	}
	// The panes themselves sit on the raised surface, as they do elsewhere.
	if cm.overviewView != nil {
		cm.overviewView.SetBackgroundColor(cm.theme.Surface)
		cm.overviewView.SetTextColor(cm.theme.TextPrimary)
	}
	if cm.activityTable != nil {
		cm.activityTable.SetBackgroundColor(cm.theme.Surface)
	}
	if cm.notesViewer != nil {
		cm.notesViewer.SetBackgroundColor(cm.theme.Surface)
	}
	if cm.copilotInput != nil {
		// On the panel's own surface. It was set to Bg inside a Surface drawer,
		// so the ask line drew as a darker band across the bottom of the panel.
		cm.copilotInput.SetFieldBackgroundColor(cm.theme.Surface)
		cm.copilotInput.SetFieldTextColor(cm.theme.TextPrimary)
		cm.copilotInput.SetLabelColor(cm.theme.TextMuted)
		cm.copilotInput.SetBackgroundColor(cm.theme.Surface)
	}

	cm.statusBar.SetBackgroundColor(cm.theme.Surface)
	cm.statusBar.SetTextColor(cm.theme.TextPrimary)

	if cm.activityTable != nil {
		cm.activityTable.SetSelectedStyle(tcell.StyleDefault.
			Background(cm.theme.SelectionBg).Foreground(cm.theme.SelectionFg))
	}
	// Borders and titles are updateFocusStyles', below: one pass over the panes
	// rather than a second list here that has to be kept in step with it.

	// Re-render the findings table so its cell colours follow the theme; the
	// widget-level calls above only restyle the frame.
	cm.renderCaseFindings()

	// Re-render tab bar to reflect theme changes
	if cm.tabBar != nil {
		cm.renderTabBar()
	}

	// Re-apply focus highlight after theming
	cm.updateFocusStyles()
}

// Modal and action handlers

// The events tab once had a second selection model — a selectedEventIDs map fed
// by Space, with "add these to another case", "create a case from these" and an
// export hanging off it. Space became pin, nothing wrote the map again, and
// every one of those actions could only report "No events selected". They are
// gone rather than rewired: a case screen is for working one case, moving events
// between cases belongs on the Events screen, and pinning is the selection that
// the briefing, the timeline and the report already read.

func (cm *CaseManagement) exportCase() {
	cm.updateStatus("Exporting case...")
	go func() {
		payload := struct {
			Case        store.Case    `json:"case"`
			Events      []store.Event `json:"events"`
			GeneratedAt time.Time     `json:"generated_at"`
		}{
			Case:        cm.caseData,
			Events:      cm.events,
			GeneratedAt: time.Now(),
		}

		data, err := json.MarshalIndent(payload, "", "  ")
		if err != nil {
			cm.app.QueueUpdate(func() {
				cm.updateStatus(fmt.Sprintf("Export error: %v", err))
			})
			return
		}

		// The directory the analyst launched from, not an "exports" folder
		// resolved against whatever it happens to be: from home that wrote to
		// ~/exports and from /tmp somewhere else, and nobody could predict
		// which.
		dir, err := os.Getwd()
		if err != nil {
			dir = paths.Current().Data
		}
		path := filepath.Join(dir, fmt.Sprintf("console-ir-%s-%s.json",
			slugify(cm.caseData.Title), time.Now().Format("2006-01-02-1504")))

		if err := os.WriteFile(path, data, 0o644); err != nil {
			cm.app.QueueUpdate(func() {
				cm.updateStatus(fmt.Sprintf("Export error: %v", err))
			})
			return
		}

		// Log audit entry (non-blocking)
		go cm.store.LogCaseAction(cm.ctx, cm.caseData.ID, "case_export", cm.getCurrentAnalyst(),
			map[string]interface{}{"file": path, "events": len(cm.events)})

		cm.app.QueueUpdate(func() {
			cm.updateStatus(fmt.Sprintf("Case exported to %s", path))
		})
	}()
}

// exportSelectedEvents is `e` on the Events tab: the pinned evidence as JSON.
//
// Three exports, three audiences. `E` writes the report — the narrative a human
// reads. `J` writes the whole case — every event it holds, for an archive or a
// handover. `e` writes only what is pinned: the handful of events that prove the
// case, for a ticket, a script or a colleague who does not run Console-IR.
//
// It read selectedEventIDs, a second selection map that nothing on this screen
// has written since Space became pin, so it could only ever answer "No events
// selected for export". Pinned evidence is the subset an analyst has actually
// marked, and it is the one the briefing, the timeline and the report already
// use.
func (cm *CaseManagement) exportSelectedEvents() {
	pinned := make([]store.Event, 0, len(cm.pinnedEvents))
	for _, ev := range cm.events {
		if cm.pinnedEvents[ev.ID] {
			pinned = append(pinned, ev)
		}
	}
	if len(pinned) == 0 {
		cm.updateStatus("Nothing pinned — Space pins the evidence to export, or J exports the whole case")
		return
	}

	caseID, title := cm.caseData.ID, cm.caseData.Title
	cm.updateStatus(fmt.Sprintf("Exporting %s…", plural(len(pinned), "pinned event")))

	go func() {
		payload := struct {
			CaseID      string        `json:"case_id"`
			CaseTitle   string        `json:"case_title"`
			Events      []store.Event `json:"events"`
			GeneratedAt time.Time     `json:"generated_at"`
			Count       int           `json:"count"`
		}{
			CaseID:      caseID,
			CaseTitle:   title,
			Events:      pinned,
			GeneratedAt: time.Now(),
			Count:       len(pinned),
		}

		data, err := json.MarshalIndent(payload, "", "  ")
		if err != nil {
			cm.queueUpdate(func() { cm.updateStatus(fmt.Sprintf("Export error: %v", err)) })
			return
		}

		// Beside the report and the case bundle: the directory the analyst
		// launched from. "exports/" was resolved against the working directory,
		// so nobody could predict where the file went.
		dir, err := os.Getwd()
		if err != nil {
			dir = paths.Current().Data
		}
		path := filepath.Join(dir, fmt.Sprintf("console-ir-%s-evidence-%s.json",
			slugify(title), time.Now().Format("2006-01-02-1504")))

		if err := os.WriteFile(path, data, 0o644); err != nil {
			cm.queueUpdate(func() { cm.updateStatus(fmt.Sprintf("Export error: %v", err)) })
			return
		}

		go cm.store.LogCaseAction(cm.ctx, caseID, "events_export", cm.getCurrentAnalyst(),
			map[string]interface{}{"file": path, "events": len(pinned)})

		cm.queueUpdate(func() {
			cm.updateStatus(fmt.Sprintf("%s exported to %s", plural(len(pinned), "pinned event"), path))
		})
	}()
}

// paneFrame is the box that carries a pane's border and title.
//
// Usually the widget itself, but the copilot's keyboard lives in its input
// field while its frame belongs to the drawer around it — so styling the widget
// would set a border on something that has none and leave the panel grey while
// focused.
func (cm *CaseManagement) paneFrame(pane int) *tview.Box {
	if pane == FocusCopilot {
		return boxOf(cm.copilotPanel)
	}
	return boxOf(cm.paneWidgetStrict(pane))
}

// casePanes is every pane the tab strip can reach, in tab order.
var casePanes = []int{
	FocusOverview, FocusFindings, FocusEvents, FocusTimeline,
	FocusIOCs, FocusNotes, FocusActivity, FocusCopilot,
}

// updateFocusStyles marks which pane has the keyboard.
//
// Over the panes, not through a list of them. This was a reset written out pane
// by pane and then a switch that repeated the same list — and the Findings tab
// was in neither, so its frame stayed the resting grey while every other pane
// went blue on focus, and its title never took a theme colour at all. That is
// the third list of panes in this file to have gone out of step with the tabs;
// paneWidget is the only one now.
func (cm *CaseManagement) updateFocusStyles() {
	for _, pane := range casePanes {
		box := cm.paneFrame(pane)
		if box == nil {
			continue
		}
		border, title := cm.theme.Border, cm.theme.TextPrimary
		if pane == cm.focusedPane {
			border, title = cm.theme.FocusBorder, cm.theme.FocusBorder
		}
		box.SetBorderColor(border)
		box.SetTitleColor(title)
	}

	// The notes editor replaces the notes table in place and carries no title;
	// tview's TextArea has no SetTitleColor.
	if cm.notesEditor != nil {
		border := cm.theme.Border
		if cm.focusedPane == FocusNotes && cm.isEditingNotes {
			border = cm.theme.FocusBorder
		}
		cm.notesEditor.SetBorderColor(border)
	}
}

func (cm *CaseManagement) showStatusChangeModal() {
	form := tview.NewForm()
	form.SetTitle(" Change Case Status ")
	form.SetBorder(true)
	cm.applyModalTheme(form)

	statuses := store.CaseStatuses()
	current := 0
	for i, s := range statuses {
		if strings.EqualFold(s, cm.caseData.Status) {
			current = i
			break
		}
	}

	selectedIdx := current
	form.AddDropDown("Status", statuses, current, func(option string, idx int) {
		selectedIdx = idx
	})

	form.AddButton("Save", func() {
		if selectedIdx < 0 || selectedIdx >= len(statuses) {
			cm.popModalRoot()
			return
		}
		newStatus := statuses[selectedIdx]
		// Persist via store
		go func() {
			update := cm.caseData
			update.Status = newStatus
			if _, err := cm.store.CreateOrUpdateCase(cm.ctx, update); err != nil {
				cm.app.QueueUpdate(func() {
					cm.updateStatus(fmt.Sprintf("Failed to update status: %v", err))
					cm.popModalRoot()
				})
				return
			}
			cm.app.QueueUpdateDraw(func() {
				cm.caseData.Status = newStatus
				cm.updateMetadataBar()
				cm.updateStatus(fmt.Sprintf("Case status changed to %s", strings.ToUpper(newStatus)))
				// Refresh main UI cases list so sidebar reflects updated status
				if cm.parentUI != nil {
					go cm.parentUI.refreshCases()
				}
				cm.popModalRoot()
			})
		}()
	})

	form.AddButton("Cancel", func() {
		cm.popModalRoot()
	})

	cm.pushModalRoot(form)
}

func (cm *CaseManagement) quickCycleStatus() {
	statuses := store.CaseStatuses()
	current := 0
	for i, s := range statuses {
		if strings.EqualFold(s, cm.caseData.Status) {
			current = i
			break
		}
	}
	next := statuses[(current+1)%len(statuses)]
	cm.updateStatus(fmt.Sprintf("Updating status to %s...", strings.ToUpper(next)))

	go func() {
		update := cm.caseData
		update.Status = next
		if _, err := cm.store.CreateOrUpdateCase(cm.ctx, update); err != nil {
			cm.app.QueueUpdate(func() {
				cm.updateStatus(fmt.Sprintf("Failed to update status: %v", err))
			})
			return
		}
		// Log action non-blocking
		go cm.store.LogCaseAction(cm.ctx, cm.caseData.ID, "status_quick_cycle", cm.getCurrentAnalyst(),
			map[string]interface{}{"from": cm.caseData.Status, "to": next})

		cm.app.QueueUpdateDraw(func() {
			cm.caseData.Status = next
			cm.updateMetadataBar()
			cm.updateStatus(fmt.Sprintf("Case status changed to %s", strings.ToUpper(next)))
			// Refresh main UI cases list so sidebar reflects updated status
			if cm.parentUI != nil {
				go cm.parentUI.refreshCases()
			}
		})
	}()
}

// Show mounts the Case Management screen as the current root and focuses the Events pane.
func (cm *CaseManagement) Show() {
	cm.app.SetRoot(cm.layout, true)
	// The strip is drawn for the width the screen actually has, which is not
	// known until something has been drawn in it.
	cm.renderTabBar()
	// Ensure our input capture is active (parent UI capture may still be installed)
	if cm.globalInputCapture != nil {
		cm.app.SetInputCapture(cm.globalInputCapture)
	}
	cm.app.SetFocus(cm.eventsTable)
	cm.updateStatus("Focus: Events · Space pin as evidence · e export · f/F filter/clear")
}

// close returns back to the parent UI main layout.
func (cm *CaseManagement) close() {
	if cm.parentUI != nil {
		// Ensure the left sidebar shows latest case status when returning
		go cm.parentUI.refreshCases()
		cm.parentUI.restoreMainLayout()
		return
	}
	// Fallback: just remount our layout if parent is missing (should not happen).
	cm.app.SetRoot(cm.layout, true)
}

// applyModalTheme applies the current theme to a tview.Form used as a modal.
func (cm *CaseManagement) applyModalTheme(form *tview.Form) {
	form.SetBackgroundColor(cm.theme.Surface)
	form.SetFieldBackgroundColor(cm.theme.Surface)
	form.SetFieldTextColor(cm.theme.TextPrimary)
	form.SetLabelColor(cm.theme.TextPrimary)
	form.SetButtonBackgroundColor(cm.theme.SelectionBg)
	form.SetButtonTextColor(cm.theme.SelectionFg)
	form.SetBorderColor(cm.theme.FocusBorder)
}

// showLLMSettingsModal opens a provider selection dialog (Shift+L) to configure the LLM used by Copilot and Overview summary.
// Settings are persisted to the per-user config directory and applied live.
func (cm *CaseManagement) showLLMSettingsModal() {
	cfgPath := paths.Current().ConfigFile(paths.LLMSettingsName)

	// Load current settings (defaults to Ollama localhost qwen3:0.6b)
	settings, _ := llm.LoadSettings(cfgPath)
	provider := settings.Active.Provider
	// UI default: if unset OR OpenRouter has no API key (and no env override), fall back to ollama
	if strings.TrimSpace(provider) == "" {
		provider = "ollama"
	} else if strings.EqualFold(strings.TrimSpace(provider), "openrouter") {
		if strings.TrimSpace(settings.Active.APIKey) == "" && strings.TrimSpace(os.Getenv("OPENROUTER_API_KEY")) == "" {
			// Do not modify persisted settings here; only change the UI selection default.
			provider = "ollama"
		}
	}
	endpoint := settings.Active.Endpoint
	model := settings.Active.Model

	form := tview.NewForm()
	form.SetTitle(" LLM Settings ")
	form.SetBorder(true)
	cm.applyModalTheme(form)
	// Predeclare form fields so callbacks can reference them safely
	var endpointIF *tview.InputField
	var modelDD *tview.DropDown
	var apiKeyIF *tview.InputField
	var modelOptions []string
	// Predeclare model discovery so provider callback can invoke it
	var refreshModels func()
	// Guard to prevent concurrent refreshes that can lock up the UI
	var refreshing int32

	// Provider dropdown
	provOptions := []string{"ollama", "openrouter", "groq", "synthetic"}
	provIdx := 0
	switch strings.ToLower(provider) {
	case "openrouter":
		provIdx = 1
	case "groq":
		provIdx = 2
	case "synthetic":
		provIdx = 3
	default:
		provIdx = 0
	}
	form.AddDropDown("Provider", provOptions, provIdx, func(option string, index int) {
		// Normalize and clear any previously selected model
		provider = strings.ToLower(strings.TrimSpace(option))
		model = ""

		// Defer UI updates slightly to avoid re-entrancy while the provider dropdown popup is still open.
		go func() {
			time.Sleep(10 * time.Millisecond)
			cm.app.QueueUpdate(func() {
				// Endpoint defaults per provider
				if endpointIF != nil {
					switch provider {
					case "openrouter":
						endpointIF.SetText("https://openrouter.ai/api/v1")
					case "groq":
						endpointIF.SetText("https://api.groq.com/openai/v1")
					case "synthetic":
						endpointIF.SetText("https://api.synthetic.new/openai/v1")
					case "ollama":
						endpointIF.SetText("http://localhost:11434")
					default:
						endpointIF.SetText("")
					}
				}

				// Reset model dropdown options; we auto-load models (no refresh button).
				if modelDD != nil {
					switch provider {
					case "openrouter":
						if strings.TrimSpace(apiKeyIF.GetText()) == "" && strings.TrimSpace(os.Getenv("OPENROUTER_API_KEY")) == "" {
							modelOptions = []string{"(requires api key)"}
						} else {
							modelOptions = []string{"(loading...)"}
						}
					case "groq":
						if strings.TrimSpace(apiKeyIF.GetText()) == "" && strings.TrimSpace(os.Getenv("GROQ_API_KEY")) == "" {
							modelOptions = []string{"(requires api key)"}
						} else {
							modelOptions = []string{"(loading...)"}
						}
					case "synthetic":
						if strings.TrimSpace(apiKeyIF.GetText()) == "" && strings.TrimSpace(os.Getenv("SYNTHETIC_API_KEY")) == "" {
							modelOptions = []string{"(requires api key)"}
						} else {
							modelOptions = []string{"(loading...)"}
						}
					default:
						modelOptions = []string{"(loading...)"}
					}
					modelDD.SetOptions(modelOptions, nil)
					modelDD.SetCurrentOption(0)
				}

				// Helpful status hint
				if provider == "openrouter" && strings.TrimSpace(apiKeyIF.GetText()) == "" && strings.TrimSpace(os.Getenv("OPENROUTER_API_KEY")) == "" {
					cm.updateStatus("Provider set to OpenRouter. Enter API key to load models.")
				} else if provider == "groq" && strings.TrimSpace(apiKeyIF.GetText()) == "" && strings.TrimSpace(os.Getenv("GROQ_API_KEY")) == "" {
					cm.updateStatus("Provider set to Groq. Enter API key to load models.")
				} else if provider == "synthetic" && strings.TrimSpace(apiKeyIF.GetText()) == "" && strings.TrimSpace(os.Getenv("SYNTHETIC_API_KEY")) == "" {
					cm.updateStatus("Provider set to Synthetic. Enter API key to load models.")
				} else {
					cm.updateStatus(fmt.Sprintf("Provider set to %s", provider))
				}
			})

			// Auto-refresh models after provider change (no button interaction needed).
			if !((strings.EqualFold(provider, "openrouter") &&
				strings.TrimSpace(apiKeyIF.GetText()) == "" &&
				strings.TrimSpace(os.Getenv("OPENROUTER_API_KEY")) == "") ||
				(strings.EqualFold(provider, "groq") &&
					strings.TrimSpace(apiKeyIF.GetText()) == "" &&
					strings.TrimSpace(os.Getenv("GROQ_API_KEY")) == "") ||
				(strings.EqualFold(provider, "synthetic") &&
					strings.TrimSpace(apiKeyIF.GetText()) == "" &&
					strings.TrimSpace(os.Getenv("SYNTHETIC_API_KEY")) == "")) {
				refreshModels()
			}
		}()
	})

	// Endpoint (used when provider=ollama/openrouter)
	endpointIF = tview.NewInputField().SetLabel("Endpoint").SetText(endpoint)
	// If no endpoint is present for the currently selected provider, set a sensible default now
	if strings.TrimSpace(endpointIF.GetText()) == "" {
		if strings.EqualFold(provider, "openrouter") {
			endpointIF.SetText("https://openrouter.ai/api/v1")
		} else if strings.EqualFold(provider, "groq") {
			endpointIF.SetText("https://api.groq.com/openai/v1")
		} else if strings.EqualFold(provider, "synthetic") {
			endpointIF.SetText("https://api.synthetic.new/openai/v1")
		} else if strings.EqualFold(provider, "ollama") {
			endpointIF.SetText("http://localhost:11434")
		}
	}
	endpointIF.SetFieldBackgroundColor(cm.theme.Surface).SetFieldTextColor(cm.theme.TextPrimary).SetLabelColor(cm.theme.TextPrimary)
	form.AddFormItem(endpointIF)

	// Model dropdown (single control). Start with persisted model or placeholder; options updated by discovery.
	initialModel := strings.TrimSpace(model)
	if initialModel == "" {
		modelOptions = []string{"(refresh to load)"}
	} else {
		modelOptions = []string{initialModel}
	}
	modelDD = tview.NewDropDown().
		SetLabel("Model").
		SetOptions(modelOptions, func(text string, idx int) {
			// selection handled on Save
		})
	modelDD.SetFieldBackgroundColor(cm.theme.Surface).SetFieldTextColor(cm.theme.TextPrimary).SetLabelColor(cm.theme.TextPrimary)
	form.AddFormItem(modelDD)

	// API Key (for OpenRouter)
	apiKey := settings.Active.APIKey
	apiKeyIF = tview.NewInputField().SetLabel("API Key (OpenRouter/Groq)").SetText(apiKey)
	apiKeyIF.SetMaskCharacter('*')
	apiKeyIF.SetFieldBackgroundColor(cm.theme.Surface).SetFieldTextColor(cm.theme.TextPrimary).SetLabelColor(cm.theme.TextPrimary)
	form.AddFormItem(apiKeyIF)

	// (Removed) separate discovered models dropdown — using single Model dropdown above.

	// Helper to refresh model list from current Provider/Endpoint
	refreshModels = func() {
		// Concurrency guard: prevent overlapping refreshes which can deadlock the UI.
		if !atomic.CompareAndSwapInt32(&refreshing, 0, 1) {
			// Use non-blocking QueueUpdate from UI goroutine to avoid draw re-entrancy
			cm.app.QueueUpdate(func() {
				cm.updateStatus("Model refresh already in progress")
			})
			return
		}

		// Show immediate loading placeholder in the Model dropdown (non-blocking UI update)
		cm.app.QueueUpdate(func() {
			modelOptions = []string{"(refreshing...)"}
			if modelDD != nil {
				modelDD.SetOptions(modelOptions, nil)
				modelDD.SetCurrentOption(0)
			}
		})

		// Snapshot current provider/endpoint/key at click time (on UI goroutine)
		prov := strings.ToLower(strings.TrimSpace(provider))
		ep := strings.TrimSpace(endpointIF.GetText())
		key := strings.TrimSpace(apiKeyIF.GetText())

		if cm.logger != nil {
			cm.logger.Printf("LLM Settings: refreshModels start provider=%s endpoint=%s key_len=%d", prov, ep, len(key))
		}

		// If OpenRouter selected without an API key, don't attempt network calls; show helpful placeholder.
		if (prov == "openrouter" && key == "" && strings.TrimSpace(os.Getenv("OPENROUTER_API_KEY")) == "") ||
			(prov == "groq" && key == "" && strings.TrimSpace(os.Getenv("GROQ_API_KEY")) == "") ||
			(prov == "synthetic" && key == "" && strings.TrimSpace(os.Getenv("SYNTHETIC_API_KEY")) == "") {
			// Non-blocking UI update to avoid deadlock in button callback path
			cm.app.QueueUpdate(func() {
				modelOptions = []string{"(requires api key)"}
				if modelDD != nil {
					modelDD.SetOptions(modelOptions, nil)
					modelDD.SetCurrentOption(0)
				}
				if prov == "groq" {
					cm.updateStatus("Groq requires an API key to list models")
				} else if prov == "synthetic" {
					cm.updateStatus("Synthetic requires an API key to list models")
				} else {
					cm.updateStatus("OpenRouter requires an API key to list models")
				}
				atomic.StoreInt32(&refreshing, 0)
			})
			return
		}

		// Determine current model selection (if any)
		curModel := ""
		if modelDD != nil && len(modelOptions) > 0 {
			if idx, _ := modelDD.GetCurrentOption(); idx >= 0 && idx < len(modelOptions) {
				curModel = strings.TrimSpace(modelOptions[idx])
			}
		}

		// Build a provider (model not required for discovery)
		cfg := llm.ProviderConfig{
			Provider: prov,
			Endpoint: ep,
			Model:    curModel,
			APIKey:   key,
		}

		go func() {
			start := time.Now()
			// Use a short, per-refresh timeout when building the provider to avoid
			// blocking indefinitely on network or DNS during provider init.
			buildTimeout := 3 * time.Second
			if strings.EqualFold(prov, "openrouter") {
				buildTimeout = 8 * time.Second
			}
			buildCtx, buildCancel := context.WithTimeout(cm.ctx, buildTimeout)
			defer buildCancel()

			p, err := llm.Build(buildCtx, cfg, cm.logger)
			if err != nil {
				if cm.logger != nil {
					cm.logger.Printf("LLM Settings: provider build failed provider=%s err=%v", prov, err)
				}
				// Use QueueUpdate from background goroutine to avoid potential QueueUpdateDraw deadlocks.
				cm.app.QueueUpdate(func() {
					modelOptions = []string{"(error)"}
					if modelDD != nil {
						modelDD.SetOptions(modelOptions, nil)
					}
					cm.updateStatus(fmt.Sprintf("Model list error: %v", err))
					atomic.StoreInt32(&refreshing, 0)
				})
				return
			}

			timeout := 3 * time.Second
			if strings.EqualFold(prov, "openrouter") {
				timeout = 8 * time.Second
			}
			ctx, cancel := context.WithTimeout(cm.ctx, timeout)
			defer cancel()
			list, err := llm.TryListModels(ctx, p)
			duration := time.Since(start)

			// Use QueueUpdate (not QueueUpdateDraw) from background goroutine to avoid blocking the UI draw thread.
			cm.app.QueueUpdate(func() {
				if err != nil {
					// Detect context timeout
					timedOut := ctx.Err() == context.DeadlineExceeded
					if timedOut {
						modelOptions = []string{"(timeout)"}
						cm.updateStatus(fmt.Sprintf("Model discovery timed out after %s", timeout))
					} else {
						modelOptions = []string{"(error)"}
						cm.updateStatus(fmt.Sprintf("Model list error: %v", err))
					}
					if modelDD != nil {
						modelDD.SetOptions(modelOptions, nil)
					}
					if cm.logger != nil {
						cm.logger.Printf("LLM Settings: list models failed provider=%s duration=%s err=%v", prov, duration, err)
					}
					atomic.StoreInt32(&refreshing, 0)
					return
				}
				if len(list) == 0 {
					modelOptions = []string{"(none found)"}
					if modelDD != nil {
						modelDD.SetOptions(modelOptions, nil)
					}
					cm.updateStatus("No models discovered")
					if cm.logger != nil {
						cm.logger.Printf("LLM Settings: list models returned 0 models provider=%s duration=%s", prov, duration)
					}
					atomic.StoreInt32(&refreshing, 0)
					return
				}
				sort.Strings(list)
				modelOptions = list
				// Rebind with selection callback
				if modelDD != nil {
					modelDD.SetOptions(modelOptions, func(text string, idx int) {
						// selection handled on Save
					})
					// Select current model if present
					sel := 0
					cur := strings.TrimSpace(curModel)
					for i, m := range modelOptions {
						if strings.EqualFold(strings.TrimSpace(m), cur) {
							sel = i
							break
						}
					}
					modelDD.SetCurrentOption(sel)
				}
				cm.updateStatus(fmt.Sprintf("Discovered %d models in %s", len(list), duration.Truncate(time.Millisecond)))
				if cm.logger != nil {
					cm.logger.Printf("LLM Settings: discovered %d models provider=%s duration=%s", len(list), prov, duration)
				}
				atomic.StoreInt32(&refreshing, 0)
			})
		}()
	}

	// Removed Refresh Models button; models load automatically on provider change.

	// Kick off initial discovery shortly after modal opens (non-blocking), when feasible.
	// Skip auto-discovery for OpenRouter/Groq without an API key to avoid the "(requires api key)" churn.
	go func() {
		time.Sleep(150 * time.Millisecond)
		if !((strings.EqualFold(provider, "openrouter") &&
			strings.TrimSpace(apiKeyIF.GetText()) == "" &&
			strings.TrimSpace(os.Getenv("OPENROUTER_API_KEY")) == "") ||
			(strings.EqualFold(provider, "groq") &&
				strings.TrimSpace(apiKeyIF.GetText()) == "" &&
				strings.TrimSpace(os.Getenv("GROQ_API_KEY")) == "") ||
			(strings.EqualFold(provider, "synthetic") &&
				strings.TrimSpace(apiKeyIF.GetText()) == "" &&
				strings.TrimSpace(os.Getenv("SYNTHETIC_API_KEY")) == "")) {
			refreshModels()
		}
	}()

	// Buttons

	form.AddButton("Search Model", func() {
		// Open a searchable modal over the current modelOptions. The selection will be applied to the Model dropdown.
		opts := make([]string, len(modelOptions))
		copy(opts, modelOptions)
		cm.showModelSearchModal(opts, func(sel string) {
			// Apply selection directly (caller ensures we are on the UI goroutine).
			// Ensure the chosen model is present in options
			found := false
			for _, m := range modelOptions {
				if strings.EqualFold(strings.TrimSpace(m), strings.TrimSpace(sel)) {
					found = true
					break
				}
			}
			if !found {
				modelOptions = append(modelOptions, sel)
				sort.Strings(modelOptions)
				if modelDD != nil {
					modelDD.SetOptions(modelOptions, nil)
				}
			}
			// Select it in the dropdown
			if modelDD != nil {
				idx := 0
				for i, m := range modelOptions {
					if strings.EqualFold(strings.TrimSpace(m), strings.TrimSpace(sel)) {
						idx = i
						break
					}
				}
				modelDD.SetCurrentOption(idx)
				// Focus the dropdown to give immediate feedback
				cm.app.SetFocus(modelDD)
			}
			// Track in local variable; persisted on Save
			model = sel
			cm.updateStatus(fmt.Sprintf("Model set to %s", sel))
		})
	})
	form.AddButton("Save", func() {
		// Determine selected model from dropdown
		selectedModel := ""
		if modelDD != nil && len(modelOptions) > 0 {
			if idx, _ := modelDD.GetCurrentOption(); idx >= 0 && idx < len(modelOptions) {
				v := strings.TrimSpace(modelOptions[idx])
				// Ignore placeholder entries
				if v != "(refresh to load)" && v != "(none found)" && v != "(error)" && v != "(refreshing...)" && v != "(not required)" && v != "(requires api key)" && v != "(timeout)" {
					selectedModel = v
				}
			}
		}
		// Fallback to persisted model value if dropdown is empty/unset
		if selectedModel == "" {
			selectedModel = strings.TrimSpace(model)
		}

		// Update and persist settings
		settings.Active.Provider = strings.ToLower(strings.TrimSpace(provider))
		settings.Active.Endpoint = strings.TrimSpace(endpointIF.GetText())
		settings.Active.Model = selectedModel
		settings.Active.APIKey = strings.TrimSpace(apiKeyIF.GetText())
		if settings.Active.Extra == nil {
			settings.Active.Extra = map[string]string{}
		}
		if err := llm.SaveSettings(cfgPath, settings); err != nil {
			cm.updateStatus(fmt.Sprintf("Save failed: %v", err))
			return
		}
		// Build provider and apply to UI + current CM
		p, err := llm.Build(cm.ctx, settings.Active, cm.logger)
		if err != nil {
			cm.updateStatus(fmt.Sprintf("Provider build failed: %v", err))
			return
		}
		// Apply to parent UI (propagates to active CM)
		if cm.parentUI != nil {
			cm.parentUI.ApplyLLMProvider(p)
		}
		// Ensure cm.llm reflects the new provider immediately
		if cp, ok := p.(llm.ChatProvider); ok {
			cm.llm = cp
		} else {
			cm.llm = &llm.LocalStub{}
		}
		cm.updateStatus("LLM settings saved and applied")
		cm.popModalRoot()
	})

	form.AddButton("Cancel", func() {
		cm.popModalRoot()
	})

	// Esc to close
	form.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
		if ev.Key() == tcell.KeyEsc {
			cm.popModalRoot()
			return nil
		}
		return ev
	})

	cm.pushModalRoot(form)
}

// getCurrentAnalyst returns case owner if present, else env var CONSOLE_IR_ANALYST, else "analyst".
func (cm *CaseManagement) getCurrentAnalyst() string {
	if strings.TrimSpace(cm.caseData.AssignedTo) != "" {
		return cm.caseData.AssignedTo
	}
	if v := strings.TrimSpace(os.Getenv("CONSOLE_IR_ANALYST")); v != "" {
		return v
	}
	return "analyst"
}

// showAddIOCModal opens a modal to add a manual IOC (persisted as a linked note).
func (cm *CaseManagement) showAddIOCModal() {
	form := tview.NewForm()
	form.SetTitle(" Add IOC ")
	form.SetBorder(true)
	cm.applyModalTheme(form)

	types := []string{"ip", "domain", "url", "hash", "email", "file", "custom"}
	iocType := "ip"
	value := ""

	form.AddDropDown("Type", types, 0, func(option string, idx int) {
		iocType = strings.ToLower(strings.TrimSpace(option))
	})
	form.AddInputField("Value", "", 60, nil, func(text string) {
		value = strings.TrimSpace(text)
	})

	// Add Esc handling to the form itself
	form.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyEsc {
			cm.popModalRoot()
			return nil
		}
		return event
	})

	form.AddButton("Add", func() {
		if value == "" {
			cm.updateStatus("IOC value required")
			return
		}
		// Create a note representing manual IOC
		n := store.Note{
			CaseID:     cm.caseData.ID,
			Content:    "ioc_type:" + iocType,
			Author:     cm.getCurrentAnalyst(),
			Color:      "#80b1d3", // neutral blue
			LinkedType: "ioc",
			LinkedID:   value,
		}
		go func() {
			_, err := cm.store.AddNote(cm.ctx, n)
			cm.app.QueueUpdateDraw(func() {
				if err != nil {
					cm.updateStatus(fmt.Sprintf("Failed to add IOC: %v", err))
				} else {
					cm.updateStatus("IOC added")
					// Log the action
					go cm.store.LogCaseAction(cm.ctx, cm.caseData.ID, "ioc_added", cm.getCurrentAnalyst(),
						map[string]interface{}{"type": iocType, "value": value})
					// refresh notes + iocs view
					cm.refreshCaseData()
				}
				cm.popModalRoot()
			})
		}()
	})
	form.AddButton("Cancel", func() {
		cm.popModalRoot()
	})

	cm.pushModalRoot(form)
}

// deleteSelectedManualIOCs removes selected manual IOCs (linked notes with LinkedType=ioc).
func (cm *CaseManagement) deleteSelectedManualIOCs() {
	if len(cm.selectedManualIOCIDs) == 0 {
		// Naming the key, because the reason nothing is selected is usually
		// that Space was pressed on a row it does not apply to.
		cm.updateStatus("Nothing selected — Space marks an indicator you added")
		return
	}
	ids := make([]string, 0, len(cm.selectedManualIOCIDs))
	for id := range cm.selectedManualIOCIDs {
		ids = append(ids, id)
	}
	// Confirm deletion
	modal := tview.NewModal().
		SetText(fmt.Sprintf("Delete %s you added?\n\nIndicators extracted from the evidence are not affected.", plural(len(ids), "indicator"))).
		AddButtons([]string{"Delete", "Cancel"}).
		SetDoneFunc(func(buttonIndex int, buttonLabel string) {
			if buttonLabel != "Delete" {
				cm.popModalRoot()
				return
			}
			go func(toDel []string) {
				var errFirst error
				for _, id := range toDel {
					if err := cm.store.DeleteNote(cm.ctx, id); err != nil && errFirst == nil {
						errFirst = err
					}
				}
				cm.app.QueueUpdateDraw(func() {
					if errFirst != nil {
						cm.updateStatus(fmt.Sprintf("Failed to delete some IOCs: %v", errFirst))
					} else {
						cm.updateStatus("Manual IOCs deleted")
						// Log the action
						go cm.store.LogCaseAction(cm.ctx, cm.caseData.ID, "iocs_deleted", cm.getCurrentAnalyst(),
							map[string]interface{}{"count": len(toDel)})
					}
					// Clear selection and refresh
					cm.selectedManualIOCIDs = map[string]bool{}
					cm.refreshCaseData()
					cm.popModalRoot()
				})
			}(append([]string(nil), ids...))
		})
	modal.SetBackgroundColor(cm.theme.Surface)
	modal.SetTextColor(cm.theme.TextPrimary)
	modal.SetBorderColor(cm.theme.FocusBorder)
	modal.SetButtonBackgroundColor(cm.theme.SelectionBg)
	modal.SetButtonTextColor(cm.theme.SelectionFg)
	cm.pushModalRoot(modal)
}

// pushModalRoot mounts a modal and relaxes the global input capture so Tab/Enter work inside forms.
func (cm *CaseManagement) pushModalRoot(p tview.Primitive) {
	// Mark modal active; rely on modal widget capture and global handler for Esc/q.
	cm.modalActive = true

	// Push current state onto stacks so we can restore on pop.
	// If currentRoot is nil, treat cm.layout as the base root.
	prevRoot := cm.currentRoot
	if prevRoot == nil {
		prevRoot = cm.layout
	}
	cm.modalStack = append(cm.modalStack, prevRoot)
	cm.inputCaptureStack = append(cm.inputCaptureStack, cm.globalInputCapture)

	// Temporarily disable the global application input capture so modal widgets
	// receive Tab/Enter keys and navigation works as expected.
	if cm.globalInputCapture != nil {
		cm.app.SetInputCapture(nil)
	}

	// Mount the modal root and focus it.
	cm.app.SetRoot(p, true)
	cm.app.SetFocus(p)

	// Track current root
	cm.currentRoot = p
}

// popModalRoot restores the CM layout and re-applies the global input capture.
func (cm *CaseManagement) popModalRoot() {
	// Restore the previous root if stacked; otherwise fall back to the main layout.
	if len(cm.modalStack) > 0 {
		// Pop previous root and input capture snapshot
		lastIdx := len(cm.modalStack) - 1
		prev := cm.modalStack[lastIdx]
		cm.modalStack = cm.modalStack[:lastIdx]

		var prevIC func(*tcell.EventKey) *tcell.EventKey
		if len(cm.inputCaptureStack) > 0 {
			icIdx := len(cm.inputCaptureStack) - 1
			prevIC = cm.inputCaptureStack[icIdx]
			cm.inputCaptureStack = cm.inputCaptureStack[:icIdx]
		}

		// Set the previous root
		cm.app.SetRoot(prev, true)
		cm.currentRoot = prev

		// If we restored to the main layout, we are exiting modal mode.
		if prev == cm.layout {
			cm.modalActive = false
			// Restore global input capture and pane focus
			// Prefer the popped snapshot if present, else keep existing globalInputCapture.
			if prevIC != nil {
				cm.globalInputCapture = prevIC
			}
			if cm.globalInputCapture != nil {
				cm.app.SetInputCapture(cm.globalInputCapture)
			}
			// Re-render header and focus visuals
			cm.renderTabBar()
			cm.updateFocusStyles()
			// Restore focus to the last focused pane.
			cm.focusCurrentPane()
		} else {
			// Still inside nested modal stack (e.g., back to LLM Settings form)
			cm.modalActive = true
			// Keep application input capture nil so the form receives Tab/Enter
			cm.app.SetInputCapture(nil)
			// Focus the restored modal primitive
			cm.app.SetFocus(prev)
		}
		return
	}

	// No stacked root: restore main layout as a safety fallback
	cm.modalActive = false
	cm.app.SetRoot(cm.layout, true)
	cm.currentRoot = cm.layout
	if cm.globalInputCapture != nil {
		cm.app.SetInputCapture(cm.globalInputCapture)
	}
	// Re-render header and focus visuals
	cm.renderTabBar()
	cm.updateFocusStyles()
	// Restore focus to the last focused pane
	switch cm.focusedPane {
	case FocusEvents:
		cm.app.SetFocus(cm.eventsTable)
	case FocusTimeline:
		cm.app.SetFocus(cm.timelineView)
	case FocusIOCs:
		if cm.iocsTable != nil {
			cm.app.SetFocus(cm.iocsTable)
		}
	case FocusNotes:
		if cm.isEditingNotes && cm.notesEditor != nil {
			cm.app.SetFocus(cm.notesEditor)
		} else if cm.notesTable != nil {
			cm.app.SetFocus(cm.notesTable)
		}
	case FocusCopilot:
		cm.app.SetFocus(cm.copilotInput)
	case FocusOverview:
		if cm.overviewView != nil {
			cm.app.SetFocus(cm.overviewView)
		}
	case FocusActivity:
		if cm.activityTable != nil {
			cm.app.SetFocus(cm.activityTable)
		}
	}
}

// truncate returns a shortened string with ellipsis when len(s) > max.
func truncate(s string, max int) string {
	if max <= 0 {
		return ""
	}
	if len(s) <= max {
		return s
	}
	if max <= 3 {
		return s[:max]
	}
	return s[:max-3] + "..."
}

// Searchable modal for selecting a model from the discovered list.
// Opens an Input + List filter UI, and invokes onSelect with the chosen model.
func (cm *CaseManagement) showModelSearchModal(options []string, onSelect func(string)) {
	// Normalize and filter out placeholder entries
	placeholderSet := map[string]bool{
		"(refresh to load)":  true,
		"(none found)":       true,
		"(error)":            true,
		"(refreshing...)":    true,
		"(not required)":     true,
		"(requires api key)": true,
		"(timeout)":          true,
	}
	cleaned := make([]string, 0, len(options))
	seen := make(map[string]bool)
	for _, opt := range options {
		o := strings.TrimSpace(opt)
		if o == "" {
			continue
		}
		lo := strings.ToLower(o)
		if placeholderSet[lo] || (strings.HasPrefix(o, "(") && strings.HasSuffix(o, ")")) {
			continue
		}
		if !seen[o] {
			seen[o] = true
			cleaned = append(cleaned, o)
		}
	}
	// If nothing usable, show a status hint and return
	if len(cleaned) == 0 {
		cm.updateStatus("No models available to search")
		return
	}
	sort.Strings(cleaned)

	// Build UI: InputField + List inside a bordered container
	input := tview.NewInputField().
		SetLabel("Search ").
		SetFieldWidth(40)
	list := tview.NewList().
		ShowSecondaryText(false)

	// Apply theme styling
	input.SetFieldBackgroundColor(cm.theme.Surface).
		SetFieldTextColor(cm.theme.TextPrimary).
		SetLabelColor(cm.theme.TextPrimary)
	list.SetBackgroundColor(cm.theme.Surface)
	list.SetMainTextColor(cm.theme.TextPrimary)
	list.SetSelectedBackgroundColor(cm.theme.SelectionBg)
	list.SetSelectedTextColor(cm.theme.SelectionFg)

	container := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(input, 1, 0, true).
		AddItem(list, 0, 1, false)
	container.SetBorder(true).SetTitle(" Search Models ").SetTitleAlign(tview.AlignLeft)
	container.SetBackgroundColor(cm.theme.Surface)

	// Guard to prevent double activation (double-Enter) in the search list
	var selecting int32
	// Track the last rendered matches so Enter from the Input can commit the highlighted item in one keypress.
	var lastMatches []string

	// Commit selection helper: restores the parent modal root first, then applies the selection
	commitSelection := func(sel string) {
		if strings.TrimSpace(sel) == "" || strings.HasPrefix(sel, "(") {
			return
		}
		// Prevent re-entrancy
		if !atomic.CompareAndSwapInt32(&selecting, 0, 1) {
			return
		}
		// Execute in two UI ticks to avoid tview re-entrancy
		go func(s string) {
			done := make(chan struct{}, 1)
			// Phase 1: restore previous modal (LLM Settings form)
			cm.app.QueueUpdate(func() {
				cm.popModalRoot()
				close(done)
			})
			<-done
			// Phase 2: apply the selection to the restored form widgets
			cm.app.QueueUpdate(func() {
				if onSelect != nil {
					onSelect(s)
				}
				cm.updateStatus(fmt.Sprintf("Model selected: %s", s))
				atomic.StoreInt32(&selecting, 0)
			})
		}(sel)
	}

	// Populate list based on query
	updateList := func(query string) {
		q := strings.ToLower(strings.TrimSpace(query))
		list.Clear()
		matches := make([]string, 0, len(cleaned))
		for _, m := range cleaned {
			if q == "" || strings.Contains(strings.ToLower(m), q) {
				matches = append(matches, m)
			}
		}
		// Persist current matches so Enter from the Input can commit immediately.
		lastMatches = matches

		if len(matches) == 0 {
			list.AddItem("(no matches)", "", 0, nil)
			return
		}
		for _, m := range matches {
			model := m
			list.AddItem(model, "", 0, nil)
		}
		// Ensure a selection exists
		if list.GetItemCount() > 0 {
			list.SetCurrentItem(0)
		}
	}

	// Handlers
	input.SetChangedFunc(func(text string) {
		updateList(text)
	})
	input.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
		switch ev.Key() {
		case tcell.KeyEsc:
			cm.popModalRoot()
			return nil
		case tcell.KeyEnter:
			// Single-Enter selection from the Input: commit the currently highlighted item (or first match).
			if len(lastMatches) == 0 {
				return nil
			}
			idx := list.GetCurrentItem()
			if idx < 0 || idx >= len(lastMatches) {
				idx = 0
			}
			commitSelection(lastMatches[idx])
			return nil
		case tcell.KeyDown:
			// Allow arrowing into the list if the user prefers
			cm.app.SetFocus(list)
			return nil
		}
		return ev
	})

	list.SetSelectedFunc(func(index int, mainText, secondaryText string, shortcut rune) {
		if strings.TrimSpace(mainText) == "" || strings.HasPrefix(mainText, "(") {
			return
		}
		commitSelection(mainText)
	})
	list.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
		if ev.Key() == tcell.KeyEsc {
			cm.popModalRoot()
			return nil
		}
		return ev
	})

	// Mount modal and prime list
	cm.pushModalRoot(container)
	updateList("")
	cm.app.SetFocus(input)
}

// iocSourceLabel distinguishes indicators the event source asserted from those
// Console-IR inferred, so an analyst knows how much to trust one at a glance.
func iocSourceLabel(it IOCItem) string {
	if it.Asserted {
		return "asserted"
	}
	return "derived"
}

func iocSourceColor(theme Theme, it IOCItem) tcell.Color {
	if it.Asserted {
		return theme.Accent
	}
	return theme.TableRowMuted
}

// copilotDrawerWidth is the drawer's width when open. Narrower than the column
// it replaces: it is a conversation, not a second screen.
const copilotDrawerWidth = 44

// caseMinWidth is the narrowest the case may be squeezed to.
//
// 80 columns is the standard minimum terminal, and the case is the screen the
// analyst is actually working on — the copilot is not entitled to push it below
// what the case itself would get on the smallest supported terminal.
const caseMinWidth = 80

// copilotFullScreen reports whether the drawer must take the screen instead of
// sharing it. At 100 columns a 44-column drawer would leave the case 56.
func copilotFullScreen(totalWidth int) bool {
	return totalWidth-copilotDrawerWidth < caseMinWidth
}

// toggleCaseCopilot opens or closes the copilot.
//
// Wide enough, it is a drawer beside the case. Too narrow to share, it takes
// the screen — a 36-column case behind a drawer is neither one thing nor the
// other.
func (cm *CaseManagement) toggleCaseCopilot() {
	if cm.caseBody == nil || cm.copilotPanel == nil {
		return
	}
	if cm.copilotOpen {
		if cm.copilotFull {
			cm.popModalRoot()
			cm.copilotFull = false
		} else {
			cm.caseBody.RemoveItem(cm.copilotPanel)
			// The drawer's columns come back to the case on the next frame.
			cm.pendingWidthShift = copilotDrawerWidth
			cm.renderBriefing()
			cm.pendingWidthShift = 0
		}
		cm.copilotOpen = false
		cm.setFocusPane(caseTabPages[cm.activeTab].focus)
		cm.updateStatus("Copilot closed")
		return
	}

	cm.copilotOpen = true
	cm.showCopilotSuggestions()

	_, _, width, _ := cm.layout.GetInnerRect()
	if copilotFullScreen(width) {
		cm.copilotFull = true
		cm.pushModalRoot(cm.copilotPanel)
		cm.focusCopilotEntry()
		cm.updateStatus("Copilot — Esc or [ returns to the case")
		return
	}

	cm.caseBody.AddItem(cm.copilotPanel, copilotDrawerWidth, 0, false)
	cm.pendingWidthShift = -copilotDrawerWidth
	cm.renderBriefing()
	cm.pendingWidthShift = 0
	cm.focusCopilotEntry()
	cm.updateStatus("Copilot open — [ closes it")
}

// togglePinnedEvent stars or unstars the evidence under the cursor.
//
// Persisted immediately rather than on some later save: a star is a judgement,
// and a judgement that survives only until the screen closes is not one.
func (cm *CaseManagement) togglePinnedEvent() {
	row, _ := cm.eventsTable.GetSelection()
	if row <= 0 || row-1 >= len(cm.events) {
		return
	}
	ev := cm.events[row-1]

	if cm.pinnedEvents == nil {
		cm.pinnedEvents = map[string]bool{}
	}
	pin := !cm.pinnedEvents[ev.ID]

	if err := cm.store.SetMemberPinned(cm.ctx, cm.caseData.ID, store.MemberTypeEvent, ev.ID, pin); err != nil {
		cm.updateStatus(fmt.Sprintf("Could not pin: %v", err))
		return
	}
	if pin {
		cm.pinnedEvents[ev.ID] = true
	} else {
		delete(cm.pinnedEvents, ev.ID)
	}

	cm.updateEventsTable()
	// The briefing lists pinned evidence, so it changes too.
	cm.renderBriefing()

	n := len(cm.pinnedEvents)
	if pin {
		cm.updateStatus(fmt.Sprintf("Pinned · %s pinned", plural(n, "event")))
	} else {
		cm.updateStatus(fmt.Sprintf("Unpinned · %s pinned", plural(n, "event")))
	}
}

// boxOf reaches the Box inside a primitive, so a list of widgets of different
// types can be given a background in one pass. A nil primitive yields nil.
func boxOf(p tview.Primitive) *tview.Box {
	switch v := p.(type) {
	case *tview.Flex:
		if v == nil {
			return nil
		}
		return v.Box
	case *tview.Pages:
		if v == nil {
			return nil
		}
		return v.Box
	case *tview.TextView:
		if v == nil {
			return nil
		}
		return v.Box
	case *tview.Table:
		if v == nil {
			return nil
		}
		return v.Box
	case *tview.TextArea:
		if v == nil {
			return nil
		}
		return v.Box
	case *tview.InputField:
		if v == nil {
			return nil
		}
		return v.Box
	}
	return nil
}

// showCaseHelp opens the key reference over the case.
//
// On the case's own modal stack rather than the parent's: the case screen
// installs its own application-wide input capture, so the parent's ? never runs
// here — help was unreachable from the one screen whose keys it documents — and
// closing the parent's help returns to the main layout, which would eject the
// analyst from the case they were reading about.
func (cm *CaseManagement) showCaseHelp() {
	if cm.parentUI == nil {
		return
	}
	ui := cm.parentUI
	ui.helpActive = true

	card, focus := ui.buildHelpCard(func() {
		ui.helpActive = false
		cm.popModalRoot()
	})
	cm.pushModalRoot(card)
	cm.app.SetFocus(focus)
}

// queueUpdate runs fn on the UI goroutine.
//
// Through the parent's guarded helper, which runs fn inline when there is no
// event loop to post to. QueueUpdateDraw blocks until the loop drains it, so
// the raw call deadlocks anything running before the application starts — and
// makes this load unobservable from a test. There are thirty-odd raw calls left
// in this file; converting them is the sweep the roadmap already carries.
func (cm *CaseManagement) queueUpdate(fn func()) {
	if cm.parentUI != nil {
		cm.parentUI.queueUpdate(fn)
		return
	}
	cm.app.QueueUpdateDraw(fn)
}

// toggleManualIOC marks one of the analyst's own entries for deletion.
//
// Only their own. The rest of this list is observables pulled out of the case's
// evidence — deleting one would mean deleting a fact the data carries, which is
// not something a case screen should offer. Space did nothing at all on those
// rows while the status line advertised it for every row, so the key read as
// broken rather than as inapplicable.
func (cm *CaseManagement) toggleManualIOC() {
	row, _ := cm.iocsTable.GetSelection()
	if row <= 0 {
		return
	}

	id := ""
	if cm.iocRowToManualID != nil {
		id = cm.iocRowToManualID[row]
	}
	if id == "" {
		cm.updateStatus("Only indicators you added can be selected — this one came from the evidence")
		return
	}

	if cm.selectedManualIOCIDs == nil {
		cm.selectedManualIOCIDs = map[string]bool{}
	}
	if cm.selectedManualIOCIDs[id] {
		delete(cm.selectedManualIOCIDs, id)
	} else {
		cm.selectedManualIOCIDs[id] = true
	}

	cm.renderIOCs()
	cm.updateStatus(fmt.Sprintf("%s selected for deletion",
		plural(len(cm.selectedManualIOCIDs), "indicator")))
}
