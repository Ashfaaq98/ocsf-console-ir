package ui

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/llm"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/store"
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
}

// CaseManagement represents the Case Management TUI screen
type CaseManagement struct {
	// Core dependencies
	app    *tview.Application
	store  *store.Store
	llm    llm.ChatProvider
	logger *log.Logger
	theme  Theme
	ctx    context.Context

	// Main case data
	caseData    store.Case
	events      []store.Event
	baseEvents  []store.Event
	auditLog    []store.AuditEntry
	notes       []store.Note

	// UI Layout components
	layout            *tview.Flex
	metadataBar       *tview.TextView
	eventsTable       *tview.Table
	timelineView      *tview.TextView
	copilotPanel      *tview.Flex
	copilotDropdown   *tview.DropDown
	copilotTranscript *tview.TextView
	copilotEstimate   *tview.TextView
	copilotInput      *tview.InputField
	notesPanel        *tview.Flex
	notesPages        *tview.Pages
	notesViewer       *tview.TextView
	notesEditor       *tview.TextArea
	activityLog       *tview.TextView
	statusBar         *tview.TextView
	// Tabs (left column)
	tabBar    *tview.TextView
	tabsPages *tview.Pages
	// Additional tab views
	overviewView *tview.TextView
	iocsTable    *tview.Table
	activityView *tview.TextView

	// Manual IOC selection state and mapping (for add/delete UX)
	selectedManualIOCIDs map[string]bool // note.ID used as manual IOC id
	iocRowToManualID     map[int]string  // table row index -> note.ID (only for manual rows)

	// State management
	selectedEventIDs   map[string]bool
	selectedEventIndex int
	pinnedEvents       map[string]bool
	chatHistory        []llm.ChatMessage
	currentPersona     string
	pendingTokens      int32 // atomic
	activeTab          int   // 0=Overview, 1=Events, 2=Timeline, 3=IOCs, 4=Notes, 5=Activity

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
)

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
		app:                 parentUI.app,
		store:               parentUI.store,
		llm:                 chatLLM,
		logger:              parentUI.logger,
		theme:               parentUI.theme,
		ctx:                 parentUI.ctx,
		caseData:            caseData,
		selectedEventIDs:    make(map[string]bool),
		selectedEventIndex:  -1,
		pinnedEvents:        make(map[string]bool),
		chatHistory:         []llm.ChatMessage{},
		currentPersona:      llm.PersonaSOC,
		focusedPane:         FocusEvents,
		timelineExpanded:    make(map[int]bool),
		parentUI:            parentUI,
	}

	cm.setupLayout()
	cm.setupKeybindings()
	cm.loadCaseData()

	return cm
}

// setupLayout creates the Case Management screen layout
func (cm *CaseManagement) setupLayout() {
	// Metadata bar (top)
	cm.metadataBar = tview.NewTextView().
		SetDynamicColors(true).
		SetTextAlign(tview.AlignLeft)
	cm.metadataBar.SetBorder(true).SetTitle(" Case Details ").SetTitleAlign(tview.AlignLeft)
	cm.updateMetadataBar()

	// Events table (left)
	cm.eventsTable = tview.NewTable().
		SetBorders(false).
		SetSelectable(true, false).
		SetFixed(1, 0) // Fixed header row
	cm.eventsTable.SetBorder(true).SetTitle(" Events ").SetTitleAlign(tview.AlignLeft)
	cm.setupEventsTable()

	// Timeline view (center)
	cm.timelineView = tview.NewTextView().
		SetDynamicColors(true).
		SetScrollable(true).
		SetWrap(true)
	cm.timelineView.SetBorder(true).SetTitle(" Timeline & Evidence ").SetTitleAlign(tview.AlignLeft)
	cm.timelineView.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch event.Key() {
		case tcell.KeyEnter:
			cm.toggleTimelineCard(cm.selectedEventIndex)
			return nil
		case tcell.KeyTab:
			cm.toggleLeftRightFocus()
			return nil
		case tcell.KeyRune:
			switch event.Rune() {
			case 'p', 'P':
				cm.pinCurrentEvent()
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
		AddItem(cm.tabBar, 2, 0, true).
		AddItem(cm.tabsPages, 0, 1, false)

	// Right side: Copilot full-height column
	main := tview.NewFlex().SetDirection(tview.FlexColumn).
		AddItem(leftTabs, 0, 2, true).
		AddItem(cm.copilotPanel, 50, 0, false) // Fixed width for copilot

	// Two-row metadata (increase height), then main content, then status bar
	cm.layout = tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(cm.metadataBar, 4, 0, false).
		AddItem(main, 0, 1, true).
		AddItem(cm.statusBar, 1, 0, false)

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


	// Chat transcript
	cm.copilotTranscript = tview.NewTextView().
		SetDynamicColors(true).
		SetScrollable(true).
		SetWrap(true)
	cm.copilotTranscript.SetBorder(true).SetTitle(" Chat ").SetTitleAlign(tview.AlignLeft)
	// Allow returning focus to input with a non-alphanumeric key
	cm.copilotTranscript.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch event.Key() {
		case tcell.KeyRune:
			if event.Rune() == ']' {
				cm.app.SetFocus(cm.copilotInput)
				cm.updateStatus("Copilot focus: Input")
				return nil
			}
		}
		return event
	})

	// Inline token estimate (one-line)
	cm.copilotEstimate = tview.NewTextView().
		SetDynamicColors(true)
	cm.copilotEstimate.SetText("[gray]Est:[-] 0 tok  ~$0.0000")

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
		AddItem(cm.copilotTranscript, 0, 1, false).
		AddItem(cm.copilotEstimate, 1, 0, false).
		AddItem(cm.copilotInput, 1, 0, false)

	cm.copilotPanel.SetBorder(true).SetTitle(" Copilot ").SetTitleAlign(tview.AlignLeft)
}

// setupNotesPanel creates a two-mode Notes panel (View/TextView vs Edit/TextArea) within a Pages container.
func (cm *CaseManagement) setupNotesPanel() {
	// Viewer (read-only, scrollable)
	cm.notesViewer = tview.NewTextView().
		SetDynamicColors(true).
		SetScrollable(true).
		SetWrap(true)
	cm.notesViewer.SetBorder(true).SetTitle(" Notes ").SetTitleAlign(tview.AlignLeft)
	cm.notesViewer.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch event.Key() {
		case tcell.KeyTab:
			cm.toggleLeftRightFocus()
			return nil
		case tcell.KeyRune:
			switch event.Rune() {
			case 'n', 'N':
				// Start a new note (switch to editor)
				cm.switchToNotesEdit()
				return nil
			}
		}
		return event
	})

	// Editor (TextArea)
	cm.notesEditor = tview.NewTextArea().
		SetPlaceholder("Add case notes here... (Ctrl+S to save)")
	// Minimal hint in title while editing
	cm.notesEditor.SetBorder(true).SetTitle(" Notes (Esc cancel, Ctrl+S save) ").SetTitleAlign(tview.AlignLeft)
	cm.notesEditor.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		return cm.handleNotesInput(event)
	})

	// Pages container
	cm.notesPages = tview.NewPages()
	cm.notesPages.AddPage("view", cm.notesViewer, true, true)
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
			} else {
				cm.close()
			}
			return nil
		case tcell.KeyTab:
			cm.toggleLeftRightFocus()
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
			case 'E':
				cm.exportCase()
				return nil
			case 's':
				cm.showStatusChangeModal()
				return nil
			case 'S':
				cm.quickCycleStatus()
				return nil
			case 'L':
				// Global hotkey: Shift+L opens LLM Settings anywhere in Case Management
				cm.showLLMSettingsModal()
				return nil
			case '1':
				cm.switchTab(0) // Overview
				return nil
			case '2':
				cm.switchTab(1) // Events
				return nil
			case '3':
				cm.switchTab(2) // Timeline
				return nil
			case '4':
				cm.switchTab(3) // IOCs
				return nil
			case '5':
				cm.switchTab(4) // Notes
				return nil
			case '6':
				cm.switchTab(5) // Activity
				return nil
			case 'p', 'P':
				// Allow pin on Timeline tab
				if cm.activeTab == 2 {
					cm.pinCurrentEvent()
					return nil
				}
			case 'n', 'N':
				// Allow new note on Notes tab
				if cm.activeTab == 4 {
					cm.addNewNote()
					return nil
				}
			case 'r', 'R':
				// Global refresh
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
			cm.toggleEventSelection()
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
	case tcell.KeyRune:
		switch event.Rune() {
		// Toggle MCP radio via keyboard: 'm' switches local/remote text indicator
		// Copilot sub-focus navigation: '[' to persona dropdown, ']' back to input
		case '[':
			cm.app.SetFocus(cm.copilotDropdown)
			cm.updateStatus("Copilot focus: Persona")
			return nil
		case ']':
			cm.app.SetFocus(cm.copilotInput)
			cm.updateStatus("Copilot focus: Input")
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
		// Cancel edit and return to view mode
		cm.switchToNotesView()
		return nil
	}
	return event
}

// Data loading and management

func (cm *CaseManagement) loadCaseData() {
	go func() {
		// Ensure audit/notes tables are available
		_ = cm.store.SetupAuditTables()

		// Load events for this case
		events, err := cm.store.GetEventsByCase(cm.ctx, cm.caseData.ID)
		if err != nil && cm.logger != nil {
			cm.logger.Printf("Error loading events for case %s: %v", cm.caseData.ID, err)
		}

		// Load notes
		notes, err := cm.store.GetNotes(cm.ctx, cm.caseData.ID)
		if err != nil && cm.logger != nil {
			cm.logger.Printf("Error loading notes for case %s: %v", cm.caseData.ID, err)
		}

		// Load activity log (audit entries)
		audits, err := cm.store.GetAuditEntries(cm.ctx, cm.caseData.ID, 0)
		if err != nil && cm.logger != nil {
			cm.logger.Printf("Error loading audit entries for case %s: %v", cm.caseData.ID, err)
		}

		// Update UI on main thread
		cm.app.QueueUpdateDraw(func() {
			cm.baseEvents = events
			cm.events = events
			cm.notes = notes
			cm.auditLog = audits

			// Render tabs
			cm.updateEventsTable()
			cm.updateTimelineView()
			cm.updateNotesText()
			cm.renderOverview()
			cm.renderActivityLog()
			// IOCs render will be computed lazily/placeholder
			cm.renderIOCs()

			cm.updateStatus(fmt.Sprintf("Loaded %d events for case %s", len(events), cm.caseData.Title))
		})
	}()
}

func (cm *CaseManagement) refreshCaseData() {
	cm.updateStatus("Refreshing case data...")
	cm.loadCaseData()
}

// UI update methods

func (cm *CaseManagement) updateMetadataBar() {
	lbl := cm.theme.TagWarning
	val := cm.theme.TagTextPrimary
	acc := cm.theme.TagAccent

	// Shorten case ID (first 6 chars) and owner fallback
	shortID := cm.caseData.ID
	if len(shortID) > 10 {
		shortID = shortID[:10]
	}
	owner := strings.TrimSpace(cm.caseData.AssignedTo)
	if owner == "" {
		owner = "Unassigned"
	}

	line1 := fmt.Sprintf(
		"[%s]Case ID:[-] [%s]%s[-]  [%s]Title:[-] [%s]%s[-]  [%s]Severity:[-] [%s]%s[-]  [%s]Owner:[-] [%s]%s[-]  [%s]Events:[-] [%s]%d[-]  [%s]Created:[-] [%s]%s[-]",
		lbl, val, shortID,
		lbl, val, cm.caseData.Title,
		lbl, val, cm.caseData.Severity,
		lbl, val, owner,
		lbl, val, cm.caseData.EventCount,
		lbl, val, cm.caseData.CreatedAt.Format("2006-01-02 15:04"),
	)
	// Hotkeys row: single color (accent) for all hints; exact phrasing requested
	line2 := fmt.Sprintf("[%s]Status:[-] [%s]%s[-]   [%s]s: Change Status  E: Export   Tab: Toggle Panes  1-6: switch tabs   L: LLM Settings[-]",
		lbl, val, strings.ToUpper(cm.caseData.Status),
		acc,
	)
	cm.metadataBar.SetText(line1 + "\n" + line2)
}

func (cm *CaseManagement) updateEventsTable() {
	// Clear existing rows (keep header)
	for row := cm.eventsTable.GetRowCount() - 1; row > 0; row-- {
		cm.eventsTable.RemoveRow(row)
	}

	// Sort events by timestamp (newest first)
	sort.Slice(cm.events, func(i, j int) bool {
		return cm.events[i].Timestamp.After(cm.events[j].Timestamp)
	})

	// Add event rows
	for i, event := range cm.events {
		row := i + 1

		// Selection indicator
		selected := cm.selectedEventIDs[event.ID]
		indicator := " "
		if selected {
			indicator = "✓"
		}

		// Row cells
		cells := []struct {
			text  string
			color tcell.Color
		}{
			{indicator, cm.theme.Accent},
			{event.Timestamp.Format("15:04:05"), cm.theme.TextPrimary},
			{event.EventType, cm.theme.Accent},
			{strings.ToUpper(event.Severity), cm.getSeverityTcell(event.Severity)},
			{event.Host, cm.theme.Success},
			{truncate(event.Message, 80), cm.theme.TextPrimary},
		}

		for col, cell := range cells {
			tableCell := tview.NewTableCell(cell.text).
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

func (cm *CaseManagement) updateTimelineView() {
	if len(cm.events) == 0 {
		cm.timelineView.SetText("No events to display")
		return
	}

	// Render in chronological order (oldest -> newest) to enhance investigative flow.
	evs := make([]store.Event, len(cm.events))
	copy(evs, cm.events)
	sort.Slice(evs, func(i, j int) bool {
		return evs[i].Timestamp.Before(evs[j].Timestamp)
	})

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[%s]Timeline & Evidence[-]\n\n", cm.theme.TagWarning))

	for i, event := range evs {
		isPinned := cm.pinnedEvents[event.ID]
		pinIndicator := ""
		if isPinned {
			pinIndicator = fmt.Sprintf(" [%s]📌[-]", cm.theme.TagAccent)
		}

		// Header line: time, event type (severity color), pin
		sb.WriteString(fmt.Sprintf(
			"[%s]%s[-] [%s]%s[-]%s\n",
			cm.theme.TagAccent,
			event.Timestamp.Format("2006-01-02 15:04:05"),
			cm.severityTag(event.Severity),
			strings.ToUpper(event.EventType),
			pinIndicator,
		))

		// Message and host line
		sb.WriteString(fmt.Sprintf("[%s]%s[-] on [%s]%s[-]\n",
			cm.theme.TagTextPrimary, event.Message,
			cm.theme.TagSuccess, event.Host,
		))

		// Show additional details for pinned or recently added tail
		if isPinned || cm.timelineExpanded[i] || i >= len(evs)-5 {
			if event.SrcIP != "" {
				sb.WriteString(fmt.Sprintf("  Source: [%s]%s:%d[-]\n", cm.theme.TagAccent, event.SrcIP, event.SrcPort))
			}
			if event.DstIP != "" {
				sb.WriteString(fmt.Sprintf("  Destination: [%s]%s:%d[-]\n", cm.theme.TagAccent, event.DstIP, event.DstPort))
			}
			if event.ProcessName != "" {
				sb.WriteString(fmt.Sprintf("  Process: [%s]%s[-]\n", cm.theme.TagWarning, event.ProcessName))
			}
			if event.FileName != "" {
				sb.WriteString(fmt.Sprintf("  File: [%s]%s[-]\n", cm.theme.TagAccent, event.FileName))
			}
		}

		sb.WriteString("\n")
	}

	cm.timelineView.SetText(sb.String())
}

// Toggle expand/collapse for a timeline card by index.
func (cm *CaseManagement) toggleTimelineCard(idx int) {
	if len(cm.events) == 0 {
		return
	}
	if idx < 0 || idx >= len(cm.events) {
		idx = 0
	}
	if cm.timelineExpanded == nil {
		cm.timelineExpanded = make(map[int]bool)
	}
	cm.timelineExpanded[idx] = !cm.timelineExpanded[idx]
	cm.updateTimelineView()
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

func (cm *CaseManagement) updateNotesText() {
	if cm.notesViewer == nil {
		return
	}
	if len(cm.notes) == 0 {
		cm.notesViewer.SetText("")
		return
	}
 
	var content strings.Builder
	for _, note := range cm.notes {
		// Exclude LLM summary notes from the Notes panel (summary is shown only in Overview)
		if strings.EqualFold(note.LinkedType, "summary") {
			continue
		}
		content.WriteString(fmt.Sprintf("--- %s by %s ---\n",
			note.CreatedAt.Format("2006-01-02 15:04"), note.Author))
		content.WriteString(note.Content)
		content.WriteString("\n\n")
	}
 
	cm.notesViewer.SetText(content.String())
}

func (cm *CaseManagement) updateActivityLog() {}

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

			// Enrichments
			sb.WriteString(fmt.Sprintf("[%s]Enrichments[-]\n", lbl))
			if len(enrichments) == 0 {
				sb.WriteString("  (none)\n")
			} else {
				for _, enr := range enrichments {
					sb.WriteString(fmt.Sprintf("  [%s]%s[-] (%s)\n", acc, strings.ToUpper(enr.Source), enr.Type))
					// Render selected fields from JSON data (compact)
					if len(enr.Data) == 0 {
						sb.WriteString("    - (no data)\n")
					} else {
						// Show up to 8 keys in alpha order
						keys := make([]string, 0, len(enr.Data))
						for k := range enr.Data {
							keys = append(keys, k)
						}
						sort.Strings(keys)
						max := 8
						if len(keys) < max {
							max = len(keys)
						}
						for i := 0; i < max; i++ {
							k := keys[i]
							v := enr.Data[k]
							// Format value as JSON (single line, truncated)
							jsonVal, _ := json.Marshal(v)
							txt := string(jsonVal)
							if len(txt) > 120 {
								txt = txt[:117] + "..."
							}
							sb.WriteString(fmt.Sprintf("    - [%s]%s[-]: [%s]%s[-]\n", val, k, cm.theme.TagMuted, txt))
						}
						if len(keys) > max {
							sb.WriteString("    - ...\n")
						}
					}
				}
			}
			// Append a persistent hint at the bottom after enrichments load
			sb.WriteString(fmt.Sprintf("\n\n[%s][Esc or q] close[-]", cm.theme.TagMuted))
			render(sb.String())
		})
	}()
}

// Overview rendering (metadata, quick stats, pinned highlights)
func (cm *CaseManagement) renderOverview() {
	if cm.overviewView == nil {
		return
	}
	// Quick stats
	byType := map[string]int{}
	bySev := map[string]int{}
	var minT, maxT time.Time
	topHostCount := map[string]int{}
	for _, ev := range cm.events {
		byType[ev.EventType]++
		sev := strings.ToLower(ev.Severity)
		bySev[sev]++
		if minT.IsZero() || ev.Timestamp.Before(minT) {
			minT = ev.Timestamp
		}
		if maxT.IsZero() || ev.Timestamp.After(maxT) {
			maxT = ev.Timestamp
		}
		if ev.Host != "" {
			topHostCount[ev.Host]++
		}
	}
	// Top 5 hosts
	type kv struct{ k string; v int }
	var hosts []kv
	for h, c := range topHostCount {
		hosts = append(hosts, kv{h, c})
	}
	sort.Slice(hosts, func(i, j int) bool { return hosts[i].v > hosts[j].v })
	if len(hosts) > 5 {
		hosts = hosts[:5]
	}

	lbl := cm.theme.TagWarning
	val := cm.theme.TagTextPrimary

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[::b][%s]Case Overview[-][-]\n\n", lbl))
	sb.WriteString(fmt.Sprintf("  [%s]Title:[-] [%s]%s[-]\n", lbl, val, cm.caseData.Title))
	// Show case description (between Title and Status) when present. Truncate to a sensible length to avoid overly large overview blocks.
	if desc := strings.TrimSpace(cm.caseData.Description); desc != "" {
		if len(desc) > 400 {
			desc = desc[:400] + "..."
		}
		sb.WriteString(fmt.Sprintf("  [%s]Description:[-] [%s]%s[-]\n", lbl, val, desc))
	}
	sb.WriteString(fmt.Sprintf("  [%s]Status:[-] [%s]%s[-]\n", lbl, val, strings.ToUpper(cm.caseData.Status)))
	sb.WriteString(fmt.Sprintf("  [%s]Events:[-] [%s]%d[-]\n", lbl, val, len(cm.events)))
	// Primary timespan: prefer case creation -> now (duration). Fallback to event min/max when case CreatedAt is not available.
	if !cm.caseData.CreatedAt.IsZero() {
		start := cm.caseData.CreatedAt
		end := time.Now()
		delta := end.Sub(start)
		days := int(delta.Hours()) / 24
		hours := int(delta.Hours()) % 24
		sb.WriteString(fmt.Sprintf("  [%s]Time Span:[-] [%s]%s[-] → [%s]%s[-] [%s](%dd %dh)[-]\n",
			lbl,
			val, start.Format("2006-01-02 15:04"),
			val, end.Format("2006-01-02 15:04"),
			val, days, hours,
		))
	} else if !minT.IsZero() && !maxT.IsZero() {
		delta := maxT.Sub(minT)
		days := int(delta.Hours()) / 24
		hours := int(delta.Hours()) % 24
		sb.WriteString(fmt.Sprintf("  [%s]Time Span:[-] [%s]%s[-] → [%s]%s[-] [%s](%dd %dh)[-]\n",
			lbl,
			val, minT.Format("2006-01-02 15:04"),
			val, maxT.Format("2006-01-02 15:04"),
			val, days, hours,
		))
	}

	// (Removed) Events by Type

	// (Removed) Events by Severity

	// LLM Summary block (renders under Case Overview)
	// If no in-memory summary (and not currently generating), try to load the latest persisted summary note.
	if !cm.isSummarizing && strings.TrimSpace(cm.overviewSummary) == "" && len(cm.notes) > 0 {
		var latest store.Note
		found := false
		for _, n := range cm.notes {
			if strings.EqualFold(n.LinkedType, "summary") {
				if !found || n.CreatedAt.After(latest.CreatedAt) {
					latest = n
					found = true
				}
			}
		}
		if found {
			cm.overviewSummary = latest.Content
			cm.summaryAt = latest.CreatedAt
		}
	}

	sb.WriteString(fmt.Sprintf("\n[::b][%s]LLM Summary[-][-]\n", lbl))
	if cm.isSummarizing {
		sb.WriteString("  Generating case summary...\n")
	} else if strings.TrimSpace(cm.overviewSummary) == "" {
		sb.WriteString(fmt.Sprintf("  (none)  [%s][l] Generate summary[-]\n", cm.theme.TagMuted))
	} else {
		sb.WriteString(cm.overviewSummary + "\n")
		if !cm.summaryAt.IsZero() {
			sb.WriteString(fmt.Sprintf("  [%s]Generated:[-] [%s]%s[-]", lbl, val, cm.summaryAt.Format("2006-01-02 15:04")))
			if cm.summaryTokens > 0 {
				sb.WriteString(fmt.Sprintf("  [%s]Tokens:[-] [%s]%d[-]", lbl, val, cm.summaryTokens))
			}
			if cm.summaryCost > 0 {
				sb.WriteString(fmt.Sprintf("  [%s]Cost:[-] [%s]$%.4f[-]", lbl, val, cm.summaryCost))
			}
			sb.WriteString("\n")
		}
	}

	cm.overviewView.SetText(sb.String())
}

// IOC table rendering with extraction and grouping
func (cm *CaseManagement) renderIOCs() {
	if cm.iocsTable == nil {
		return
	}
	// Clear existing rows
	for row := cm.iocsTable.GetRowCount() - 1; row >= 0; row-- {
		cm.iocsTable.RemoveRow(row)
	}
	// Reset mapping for manual IOC selections
	cm.iocRowToManualID = map[int]string{}

	// Header: Sel, Type, Value, Count, First Seen, Last Seen, Source
	headers := []string{"Sel", "Type", "Value", "Count", "First Seen", "Last Seen", "Source"}
	for c, h := range headers {
		cell := tview.NewTableCell(h).
			SetTextColor(cm.theme.TableHeader).
			SetBackgroundColor(cm.theme.TableHeaderBg).
			SetAttributes(tcell.AttrBold).
			SetSelectable(false)
		cm.iocsTable.SetCell(0, c, cell)
	}

	// Build auto-extracted IOCs
	cm.extractIOCs()
	type orderedItem struct {
		typ   string
		item  IOCItem
	}
	var autos []orderedItem
	for _, typ := range []string{"ip", "domain", "url", "hash"} {
		for _, it := range cm.iocIndex[typ] {
			autos = append(autos, orderedItem{typ: typ, item: it})
		}
	}
	// Sort auto by type then count desc then value asc
	sort.Slice(autos, func(i, j int) bool {
		if autos[i].typ == autos[j].typ {
			if autos[i].item.Count == autos[j].item.Count {
				return autos[i].item.Value < autos[j].item.Value
			}
			return autos[i].item.Count > autos[j].item.Count
		}
		return autos[i].typ < autos[j].typ
	})

	// Build manual IOCs from notes where LinkedType=="ioc"
	type manualIOC struct {
		noteID string
		typ    string
		value  string
	}
	var manuals []manualIOC
	for _, n := range cm.notes {
		if strings.EqualFold(n.LinkedType, "ioc") && n.LinkedID != "" {
			mType := "unknown"
			// Content convention: "ioc_type:<type>" (best-effort)
			if strings.HasPrefix(strings.ToLower(n.Content), "ioc_type:") {
				mType = strings.TrimSpace(strings.ToLower(strings.TrimPrefix(strings.ToLower(n.Content), "ioc_type:")))
			}
			manuals = append(manuals, manualIOC{
				noteID: n.ID,
				typ:    mType,
				value:  n.LinkedID,
			})
		}
	}
	// Sort manual by type then value asc
	sort.Slice(manuals, func(i, j int) bool {
		if manuals[i].typ == manuals[j].typ {
			return manuals[i].value < manuals[j].value
		}
		return manuals[i].typ < manuals[j].typ
	})

	row := 1
	// Render auto-extracted (non-selectable)
	for _, a := range autos {
		zebra := cm.theme.TableZebra1
		if row%2 == 1 {
			zebra = cm.theme.TableZebra2
		}
		selCell := tview.NewTableCell(" ").SetBackgroundColor(zebra) // not selectable
		cm.iocsTable.SetCell(row, 0, selCell)

		cells := []struct {
			text  string
			color tcell.Color
		}{
			{strings.ToUpper(a.typ), cm.theme.Accent},
			{a.item.Value, cm.theme.TextPrimary},
			{fmt.Sprintf("%d", a.item.Count), cm.theme.TextPrimary},
			{a.item.First.Format("2006-01-02 15:04"), cm.theme.TextPrimary},
			{a.item.Last.Format("2006-01-02 15:04"), cm.theme.TextPrimary},
			{"auto", cm.theme.TableRowMuted}, // we will add helper via tag color
		}
		for c, cell := range cells {
			tc := tview.NewTableCell(cell.text).
				SetTextColor(cell.color).
				SetBackgroundColor(zebra)
			cm.iocsTable.SetCell(row, c+1, tc)
		}
		row++
	}

	// Render manual IOCs (selectable via space)
	for _, m := range manuals {
		zebra := cm.theme.TableZebra1
		if row%2 == 1 {
			zebra = cm.theme.TableZebra2
		}
		// selection indicator
		indicator := " "
		if cm.selectedManualIOCIDs != nil && cm.selectedManualIOCIDs[m.noteID] {
			indicator = "✓"
		}
		cm.iocRowToManualID[row] = m.noteID

		cm.iocsTable.SetCell(row, 0, tview.NewTableCell(indicator).
			SetTextColor(cm.theme.Accent).
			SetBackgroundColor(zebra))

		// No count/first/last available for manual entries (show "-")
		cells := []struct {
			text  string
			color tcell.Color
		}{
			{strings.ToUpper(m.typ), cm.theme.Accent},
			{m.value, cm.theme.TextPrimary},
			{"-", cm.theme.TextPrimary},
			{"-", cm.theme.TextPrimary},
			{"-", cm.theme.TextPrimary},
			{"manual", cm.theme.TextPrimary},
		}
		for c, cell := range cells {
			tc := tview.NewTableCell(cell.text).
				SetTextColor(cell.color).
				SetBackgroundColor(zebra)
			cm.iocsTable.SetCell(row, c+1, tc)
		}
		row++
	}

	if row == 1 {
		// no data
		bg := cm.theme.TableZebra1
		msg := tview.NewTableCell("(none)").
			SetTextColor(cm.theme.TextPrimary).
			SetBackgroundColor(bg).
			SetSelectable(false)
		cm.iocsTable.SetCell(1, 0, msg)
		for c := 1; c < len(headers); c++ {
			cm.iocsTable.SetCell(1, c, tview.NewTableCell("").
				SetBackgroundColor(bg).
				SetSelectable(false))
		}
	}
}

// extractIOCs aggregates IPs, domains, URLs, and file hashes across all case events.
func (cm *CaseManagement) extractIOCs() {
	// Choose source: use full corpus if available
	source := cm.baseEvents
	if len(source) == 0 {
		source = cm.events
	}

	index := map[string]map[string]*IOCItem{
		"ip":     {},
		"domain": {},
		"url":    {},
		"hash":   {},
	}

	ipRe := regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b`)
	urlRe := regexp.MustCompile(`https?://[^\s]+`)
	domainRe := regexp.MustCompile(`\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b`)
	md5Re := regexp.MustCompile(`\b[a-fA-F0-9]{32}\b`)
	sha1Re := regexp.MustCompile(`\b[a-fA-F0-9]{40}\b`)
	sha256Re := regexp.MustCompile(`\b[a-fA-F0-9]{64}\b`)

	add := func(typ, val, evID string, ts time.Time) {
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
				Count:           0,
				First:           ts,
				Last:            ts,
				RelatedEventIDs: []string{},
			}
			m[val] = item
		}
		// Increment once per event for de-duplication within same event
		item.Count++
		if ts.Before(item.First) {
			item.First = ts
		}
		if ts.After(item.Last) {
			item.Last = ts
		}
		// Track related event
		if len(item.RelatedEventIDs) == 0 || item.RelatedEventIDs[len(item.RelatedEventIDs)-1] != evID {
			item.RelatedEventIDs = append(item.RelatedEventIDs, evID)
		}
	}

	for _, ev := range source {
		ts := ev.Timestamp
		evID := ev.ID
		msg := ev.Message
		host := ev.Host
		if ip := strings.TrimSpace(ev.SrcIP); ip != "" {
			add("ip", ip, evID, ts)
		}
		if ip := strings.TrimSpace(ev.DstIP); ip != "" {
			add("ip", ip, evID, ts)
		}
		// From message
		for _, u := range urlRe.FindAllString(msg, -1) {
			add("url", u, evID, ts)
			// extract domain from URL if present
			if m := domainRe.FindString(u); m != "" && !ipRe.MatchString(m) {
				add("domain", m, evID, ts)
			}
		}
		for _, ip := range ipRe.FindAllString(msg, -1) {
			add("ip", ip, evID, ts)
		}
		for _, d := range domainRe.FindAllString(msg, -1) {
			if !ipRe.MatchString(d) { // avoid IP-as-domain
				add("domain", d, evID, ts)
			}
		}
		for _, h := range sha256Re.FindAllString(msg, -1) {
			add("hash", strings.ToLower(h), evID, ts)
		}
		for _, h := range sha1Re.FindAllString(msg, -1) {
			add("hash", strings.ToLower(h), evID, ts)
		}
		for _, h := range md5Re.FindAllString(msg, -1) {
			add("hash", strings.ToLower(h), evID, ts)
		}
		// From host (domain)
		if host != "" && domainRe.MatchString(host) && !ipRe.MatchString(host) {
			add("domain", host, evID, ts)
		}
		// From filename (hash-like substrings)
		if ev.FileName != "" {
			for _, h := range sha256Re.FindAllString(ev.FileName, -1) {
				add("hash", strings.ToLower(h), evID, ts)
			}
			for _, h := range sha1Re.FindAllString(ev.FileName, -1) {
				add("hash", strings.ToLower(h), evID, ts)
			}
			for _, h := range md5Re.FindAllString(ev.FileName, -1) {
				add("hash", strings.ToLower(h), evID, ts)
			}
		}
	}

	// Convert to slices
	out := make(map[string][]IOCItem, 4)
	for typ, m := range index {
		list := make([]IOCItem, 0, len(m))
		for _, v := range m {
			list = append(list, *v)
		}
		out[typ] = list
	}
	cm.iocIndex = out
}


// Activity Log rendering
func (cm *CaseManagement) renderActivityLog() {
	if cm.activityView == nil {
		return
	}
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[%s]Activity Log[-]\n\n", cm.theme.TagWarning))
	if len(cm.auditLog) == 0 {
		sb.WriteString("  (no activity)\n")
	} else {
		// Show recent entries first (newest to oldest)
		for _, a := range cm.auditLog {
			// Enhanced formatting with action descriptions
			actionDesc := cm.formatActionDescription(a.Action, a.Details)
			sb.WriteString(fmt.Sprintf("  [%s]%s[-] [%s]%s[-] [%s]%s[-]\n",
				cm.theme.TagMuted, a.Timestamp.Format("15:04:05"),
				cm.theme.TagAccent, a.Actor,
				cm.theme.TagTextPrimary, actionDesc))
		}
	}
	cm.activityView.SetText(sb.String())
}

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
	cm.overviewView.SetBorder(true).SetTitle(" Overview ").SetTitleAlign(tview.AlignLeft)
	// Overview tab input capture: l to generate case summary, Tab to toggle focus
	cm.overviewView.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch event.Key() {
		case tcell.KeyTab:
			cm.toggleLeftRightFocus()
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
	cm.iocsTable.SetBorder(true).SetTitle(" Artifacts / IOCs ").SetTitleAlign(tview.AlignLeft)
	// IOC tab input capture: add ( + ), delete ( d ), toggle select (space), Tab to switch panes.
	cm.iocsTable.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch event.Key() {
		case tcell.KeyTab:
			cm.toggleLeftRightFocus()
			return nil
		case tcell.KeyRune:
			switch event.Rune() {
			case '+':
				cm.showAddIOCModal()
				return nil
			case 'd':
				cm.deleteSelectedManualIOCs()
				return nil
			case ' ':
				// toggle selection for manual IOC rows
				row, _ := cm.iocsTable.GetSelection()
				if row > 0 && cm.iocRowToManualID != nil {
					if id, ok := cm.iocRowToManualID[row]; ok && id != "" {
						if cm.selectedManualIOCIDs == nil {
							cm.selectedManualIOCIDs = map[string]bool{}
						}
						if cm.selectedManualIOCIDs[id] {
							delete(cm.selectedManualIOCIDs, id)
							cm.updateStatus("IOC deselected")
						} else {
							cm.selectedManualIOCIDs[id] = true
							cm.updateStatus("IOC selected")
						}
						cm.renderIOCs()
						return nil
					}
				}
			}
		}
		return event
	})
	// Keep selection for keyboard navigation.
	cm.iocsTable.SetSelectedFunc(func(row, col int) {})

	cm.activityView = tview.NewTextView().SetDynamicColors(true).SetScrollable(true)
	cm.activityView.SetBorder(true).SetTitle(" Activity Log ").SetTitleAlign(tview.AlignLeft)

	// Add pages in required order: overview, events, timeline, iocs, notes, activity
	cm.tabsPages.AddPage("overview", cm.overviewView, true, true)
	cm.tabsPages.AddPage("events", cm.eventsTable, true, false)
	cm.tabsPages.AddPage("timeline", cm.timelineView, true, false)
	cm.tabsPages.AddPage("iocs", cm.iocsTable, true, false)
	cm.tabsPages.AddPage("notes", cm.notesPages, true, false)
	cm.tabsPages.AddPage("activity", cm.activityView, true, false)

	// Ensure a valid active tab, default to Overview
	if cm.activeTab < 0 || cm.activeTab > 5 {
		cm.activeTab = 0
	}
	switch cm.activeTab {
	case 0:
		cm.tabsPages.SwitchToPage("overview")
	case 1:
		cm.tabsPages.SwitchToPage("events")
	case 2:
		cm.tabsPages.SwitchToPage("timeline")
	case 3:
		cm.tabsPages.SwitchToPage("iocs")
	case 4:
		cm.tabsPages.SwitchToPage("notes")
	case 5:
		cm.tabsPages.SwitchToPage("activity")
	}

	// Initial renders
	cm.renderOverview()
	cm.renderIOCs()
	cm.renderActivityLog()

	cm.renderTabBar()
}

func (cm *CaseManagement) renderTabBar() {
	// Browser-style framed tabs using Unicode line characters.
	// Active tab appears "brought forward" by leaving an underline gap beneath it.
	names := []string{"Overview", "Events", "Timeline", "Artifacts/IOCs", "Notes", "Activity Log"}
	active := cm.activeTab
	if active < 0 || active >= len(names) {
		active = 0
	}

	// Build raw top pieces (no color tags) to compute visible widths.
	topRaw := make([]string, len(names))
	widths := make([]int, len(names))
	for i, name := range names {
		if i == active {
			topRaw[i] = fmt.Sprintf(" ╭─ %s ─╮ ", name) // active: rounded corners and spacing
		} else {
			topRaw[i] = fmt.Sprintf(" ┌ %s ┐ ", name) // inactive: squared/flat look
		}
		widths[i] = len([]rune(topRaw[i]))
	}

	// Compose colored top line.
	var topLine strings.Builder
	for i, piece := range topRaw {
		if i == active {
			topLine.WriteString("[::b]") // bold active
			topLine.WriteString(piece)
			topLine.WriteString("[-]")
		} else {
			topLine.WriteString(fmt.Sprintf("[%s]", cm.theme.TagMuted)) // dim inactive
			topLine.WriteString(piece)
			topLine.WriteString("[-]")
		}
	}

	// Compose underline line: continuous for inactive tabs, gap under active tab.
	var underline strings.Builder
	for i := range names {
		w := widths[i]
		if i == active {
			underline.WriteString(strings.Repeat(" ", w))
		} else {
			underline.WriteString(strings.Repeat("─", w))
		}
	}

	cm.tabBar.SetText(topLine.String() + "\n" + underline.String())
}

func (cm *CaseManagement) switchTab(idx int) {
	if idx < 0 || idx > 5 {
		return
	}
	cm.activeTab = idx
	switch idx {
	case 0:
		cm.tabsPages.SwitchToPage("overview")
		cm.setFocusPane(FocusOverview)
	case 1:
		cm.tabsPages.SwitchToPage("events")
		cm.setFocusPane(FocusEvents)
	case 2:
		cm.tabsPages.SwitchToPage("timeline")
		cm.setFocusPane(FocusTimeline)
	case 3:
		cm.tabsPages.SwitchToPage("iocs")
		cm.setFocusPane(FocusIOCs)
	case 4:
		cm.tabsPages.SwitchToPage("notes")
		cm.setFocusPane(FocusNotes)
	case 5:
		cm.tabsPages.SwitchToPage("activity")
		cm.setFocusPane(FocusActivity)
	}
	cm.renderTabBar()
}

func (cm *CaseManagement) toggleLeftRightFocus() {
	if cm.focusedPane == FocusCopilot {
		// Return to active left tab
		switch cm.activeTab {
		case 0:
			cm.setFocusPane(FocusOverview)
		case 1:
			cm.setFocusPane(FocusEvents)
		case 2:
			cm.setFocusPane(FocusTimeline)
		case 3:
			cm.setFocusPane(FocusIOCs)
		case 4:
			cm.setFocusPane(FocusNotes)
		case 5:
			cm.setFocusPane(FocusActivity)
		default:
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
	cm.renderOverview()
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

	// Only show selection info when there is at least one selection
	if len(cm.selectedEventIDs) > 0 {
		statusText = fmt.Sprintf("%s%s[%s]%d[-] selected", statusText, sep, acc, len(cm.selectedEventIDs))
	}

	// Standard navigation hints
	statusText = fmt.Sprintf("%s%s[%s]Tab[-]-left/right [%s]Esc[-]-close", statusText, sep, acc, acc)

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
		"[%s]%s[-]%s[%s]Analyst[-]: %s%s[%s]Focus[-]: Notes%s n=new note • Ctrl+s=save • Tab=Copilot%s[%s]Esc[-]=Exit Case",
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
		"[%s]%s[-]%s[%s]Analyst[-]: %s%s[%s]Focus[-]: Notes (editing)%s Ctrl+s=save • Esc=cancel • Tab=Copilot",
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
	if cm.notesViewer != nil {
		cm.app.SetFocus(cm.notesViewer)
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

func (cm *CaseManagement) toggleEventSelection() {
	// Use the table's authoritative current selection so Space toggles the highlighted row.
	row, _ := cm.eventsTable.GetSelection()
	if row <= 0 || row-1 >= len(cm.events) {
		return
	}
	idx := row - 1
	event := cm.events[idx]
	if cm.selectedEventIDs[event.ID] {
		delete(cm.selectedEventIDs, event.ID)
		cm.updateStatus("Event deselected")
	} else {
		cm.selectedEventIDs[event.ID] = true
		cm.updateStatus("Event selected")
	}
	cm.updateEventsTable()
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

	// Show loading state
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
			MCPMode:   "local",
			MaxTokens: 500,
		}

		resp, err := cm.llm.Chat(cm.ctx, req)
		atomic.AddInt32(&cm.pendingTokens, -1)

		cm.app.QueueUpdateDraw(func() {
			if err != nil {
				cm.updateStatus(fmt.Sprintf("Copilot error: %v", err))
				return
			}

			if resp == nil || resp.Error != "" {
				errMsg := "unknown"
				if resp != nil {
					errMsg = resp.Error
				}
				cm.updateStatus(fmt.Sprintf("Copilot error: %s", errMsg))
				return
			}

			// Add response to transcript
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
	var transcript strings.Builder

	for _, msg := range cm.chatHistory {
		timestamp := msg.Timestamp.Format("15:04")

		switch msg.Role {
		case "user":
			transcript.WriteString(fmt.Sprintf("[blue]%s You:[-]\n%s\n\n", timestamp, msg.Content))
		case "assistant":
			persona := msg.Persona
			if persona == "" {
				persona = "Copilot"
			}
			transcript.WriteString(fmt.Sprintf("[green]%s %s:[-]\n%s\n\n", timestamp, persona, msg.Content))
		}
	}

	cm.copilotTranscript.SetText(transcript.String())
	// Auto-scroll to bottom
	cm.copilotTranscript.ScrollToEnd()
}

// updateTokenEstimate updates the inline token/cost estimate below the chat transcript.
func (cm *CaseManagement) updateTokenEstimate(text string) {
	if cm.copilotEstimate == nil || cm.llm == nil {
		return
	}
	tokens := cm.llm.EstimateTokens(text)
	cost := float64(tokens) * 0.002 / 1000.0
	cm.copilotEstimate.SetText(fmt.Sprintf("[gray]Est:[-] %d tok  ~$%.4f", tokens, cost))
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
	cm.renderOverview()

	go func() {
		var (
			summary string
			tokens  int
			cost    float64
		)

		// Prefer Chat (with persona and MCP mode)
		req := llm.ChatRequest{
			Messages: []llm.ChatMessage{{
				Role:      "user",
				Content:   prompt,
				Timestamp: time.Now(),
				Persona:   cm.currentPersona,
			}},
			Persona:   cm.currentPersona,
			MCPMode:   "local",
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
					cm.renderOverview()
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

			cm.renderOverview()
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

func (cm *CaseManagement) setFocusPane(pane int) {
	cm.focusedPane = pane
	switch pane {
	case FocusOverview:
		if cm.overviewView != nil {
			cm.app.SetFocus(cm.overviewView)
		}
		cm.updateStatus("Focus: Overview")
	case FocusEvents:
		cm.app.SetFocus(cm.eventsTable)
		cm.updateStatus("Focus: Events - Space=select, e=export, f/F=filter/clear")
	case FocusTimeline:
		cm.app.SetFocus(cm.timelineView)
		cm.updateStatus("Focus: Timeline - p=pin")
	case FocusIOCs:
		if cm.iocsTable != nil {
			cm.app.SetFocus(cm.iocsTable)
		}
		cm.updateStatus("Focus: IOCs - +add d=delete Space=select Up/Down=browse")
	case FocusNotes:
		if cm.isEditingNotes {
			if cm.notesEditor != nil {
				cm.app.SetFocus(cm.notesEditor)
			}
			// Edit mode status (themed)
			cm.setStatusDirect(cm.notesEditStatusText())
		} else {
			if cm.notesViewer != nil {
				cm.app.SetFocus(cm.notesViewer)
			}
			// View mode status (themed)
			cm.setStatusDirect(cm.notesViewStatusText())
		}
	case FocusActivity:
		if cm.activityView != nil {
			cm.app.SetFocus(cm.activityView)
		}
		cm.updateStatus("Focus: Activity - r=refresh")
	case FocusCopilot:
		cm.app.SetFocus(cm.copilotInput)
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
	cm.metadataBar.SetTextColor(cm.theme.TextPrimary)

	cm.eventsTable.SetBackgroundColor(cm.theme.Surface)
	if cm.iocsTable != nil {
		cm.iocsTable.SetBackgroundColor(cm.theme.Surface)
	}

	cm.timelineView.SetBackgroundColor(cm.theme.Surface)
	cm.timelineView.SetTextColor(cm.theme.TextPrimary)

	cm.copilotPanel.SetBackgroundColor(cm.theme.Surface)

	// Copilot sub-controls
	if cm.copilotDropdown != nil {
		cm.copilotDropdown.SetFieldBackgroundColor(cm.theme.Surface)
		cm.copilotDropdown.SetFieldTextColor(cm.theme.TextPrimary)
		cm.copilotDropdown.SetLabelColor(cm.theme.TextPrimary)
	}

	cm.copilotTranscript.SetBackgroundColor(cm.theme.Surface)
	cm.copilotTranscript.SetTextColor(cm.theme.TextPrimary)

	if cm.copilotEstimate != nil {
		cm.copilotEstimate.SetBackgroundColor(cm.theme.Surface)
		cm.copilotEstimate.SetTextColor(cm.theme.TextPrimary)
	}

	if cm.notesViewer != nil {
		cm.notesViewer.SetBackgroundColor(cm.theme.Surface)
		cm.notesViewer.SetTextColor(cm.theme.TextPrimary)
	}
	if cm.notesEditor != nil {
		cm.notesEditor.SetBackgroundColor(cm.theme.Surface)
	}

	// Tab bar styling
	if cm.tabBar != nil {
		cm.tabBar.SetBackgroundColor(cm.theme.Surface)
		cm.tabBar.SetTextColor(cm.theme.TextPrimary)
	}

	cm.statusBar.SetBackgroundColor(cm.theme.Surface)
	cm.statusBar.SetTextColor(cm.theme.TextPrimary)

	// Apply borders
	cm.eventsTable.SetBorderColor(cm.theme.Border)
	cm.timelineView.SetBorderColor(cm.theme.Border)
	cm.copilotPanel.SetBorderColor(cm.theme.Border)
	if cm.notesViewer != nil {
		cm.notesViewer.SetBorderColor(cm.theme.Border)
	}
	if cm.notesEditor != nil {
		cm.notesEditor.SetBorderColor(cm.theme.Border)
	}
	if cm.overviewView != nil {
		cm.overviewView.SetBorderColor(cm.theme.Border)
	}
	if cm.iocsTable != nil {
		cm.iocsTable.SetBorderColor(cm.theme.Border)
	}
	if cm.activityView != nil {
		cm.activityView.SetBorderColor(cm.theme.Border)
	}

	// Re-render tab bar to reflect theme changes
	if cm.tabBar != nil {
		cm.renderTabBar()
	}

	// Re-apply focus highlight after theming
	cm.updateFocusStyles()
}

// Modal and action handlers

func (cm *CaseManagement) createCaseFromSelection() {
	if len(cm.selectedEventIDs) == 0 {
		cm.updateStatus("No events selected for new case")
		return
	}

	cm.showCreateCaseModal()
}

func (cm *CaseManagement) addEventsToCase() {
	if len(cm.selectedEventIDs) == 0 {
		cm.updateStatus("No events selected to add to case")
		return
	}

	cm.showAddToCaseModal()
}

func (cm *CaseManagement) showCreateCaseModal() {
	form := tview.NewForm()
	form.SetTitle(" Create New Case ")
	form.SetBorder(true)
	cm.applyModalTheme(form)

	var title, description, assignedTo string
	severity := "medium"

	form.AddInputField("Title", "", 50, nil, func(text string) {
		title = text
	})
	form.AddTextArea("Description", "", 50, 3, 0, func(text string) {
		description = text
	})
	form.AddDropDown("Severity", []string{"low", "medium", "high", "critical"}, 1, func(option string, optionIndex int) {
		severity = option
	})
	form.AddInputField("Assigned To", "", 30, nil, func(text string) {
		assignedTo = text
	})

	form.AddButton("Create", func() {
		if title == "" {
			cm.updateStatus("Title is required")
			return
		}
		cm.executeCreateCase(title, description, severity, assignedTo)
		cm.popModalRoot()
	})
	form.AddButton("Cancel", func() {
		cm.popModalRoot()
	})

	cm.pushModalRoot(form)
}

func (cm *CaseManagement) showAddToCaseModal() {
	// Get list of cases for selection
	go func() {
		cases, err := cm.store.ListCases(cm.ctx)
		if err != nil {
			cm.app.QueueUpdate(func() {
				cm.updateStatus(fmt.Sprintf("Error loading cases: %v", err))
			})
			return
		}

		cm.app.QueueUpdate(func() {
			cm.displayAddToCaseModal(cases)
		})
	}()
}

func (cm *CaseManagement) displayAddToCaseModal(cases []store.Case) {
	if len(cases) == 0 {
		cm.updateStatus("No other cases available")
		return
	}

	form := tview.NewForm()
	form.SetTitle(" Add Events to Case ")
	form.SetBorder(true)
	cm.applyModalTheme(form)

	caseOptions := make([]string, len(cases))
	for i, c := range cases {
		caseOptions[i] = fmt.Sprintf("%s (ID: %s)", c.Title, c.ID)
	}

	selectedCaseIndex := 0
	form.AddDropDown("Target Case", caseOptions, 0, func(option string, optionIndex int) {
		selectedCaseIndex = optionIndex
	})

	form.AddButton("Add Events", func() {
		if selectedCaseIndex >= len(cases) {
			return
		}
		targetCase := cases[selectedCaseIndex]
		cm.executeAddToCase(targetCase.ID)
		cm.popModalRoot()
	})
	form.AddButton("Cancel", func() {
		cm.popModalRoot()
	})

	cm.pushModalRoot(form)
}

func (cm *CaseManagement) executeCreateCase(title, description, severity, assignedTo string) {
	cm.updateStatus("Creating case...")

	go func() {
		// Create the case
		newCase := store.Case{
			Title:       title,
			Description: description,
			Severity:    severity,
			Status:      "open",
			AssignedTo:  assignedTo,
		}

		caseID, err := cm.store.CreateOrUpdateCase(cm.ctx, newCase)
		if err != nil {
			cm.app.QueueUpdate(func() {
				cm.updateStatus(fmt.Sprintf("Error creating case: %v", err))
			})
			return
		}

		// Assign selected events to the new case
		successCount := 0
		for eventID := range cm.selectedEventIDs {
			if err := cm.store.AssignEventToCase(cm.ctx, eventID, caseID); err == nil {
				successCount++
			}
		}

		// Update case event count
		_ = cm.store.UpdateCaseEventCount(cm.ctx, caseID)

		// Log the action
		_ = cm.store.LogCaseAction(cm.ctx, caseID, "case_created_from_events", cm.getCurrentAnalyst(),
			map[string]interface{}{
				"source_case_id": cm.caseData.ID,
				"events_moved":   successCount,
			})

		cm.app.QueueUpdate(func() {
			cm.selectedEventIDs = make(map[string]bool) // Clear selection
			cm.refreshCaseData()                        // Reload current case data
			cm.updateStatus(fmt.Sprintf("Created case with %d events", successCount))
		})
	}()
}

func (cm *CaseManagement) executeAddToCase(targetCaseID string) {
	cm.updateStatus("Adding events to case...")

	go func() {
		successCount := 0
		for eventID := range cm.selectedEventIDs {
			if err := cm.store.AssignEventToCase(cm.ctx, eventID, targetCaseID); err == nil {
				successCount++
			}
		}

		// Update case event counts
		_ = cm.store.UpdateCaseEventCount(cm.ctx, targetCaseID)
		_ = cm.store.UpdateCaseEventCount(cm.ctx, cm.caseData.ID)

		// Log the action
		_ = cm.store.LogEventAction(cm.ctx, targetCaseID, "", "events_added", cm.getCurrentAnalyst(),
			map[string]interface{}{
				"source_case_id": cm.caseData.ID,
				"events_moved":   successCount,
			})

		cm.app.QueueUpdate(func() {
			cm.selectedEventIDs = make(map[string]bool) // Clear selection
			cm.refreshCaseData()                        // Reload current case data
			cm.updateStatus(fmt.Sprintf("Added %d events to case", successCount))
		})
	}()
}

func (cm *CaseManagement) exportCase() {
	cm.updateStatus("Exporting case...")
	go func() {
		payload := struct {
			Case        store.Case   `json:"case"`
			Events      []store.Event`json:"events"`
			GeneratedAt time.Time    `json:"generated_at"`
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

		dir := "exports"
		_ = os.MkdirAll(dir, 0o755)
		filename := fmt.Sprintf("case_%s_%s.json", cm.caseData.ID, time.Now().Format("20060102_150405"))
		path := filepath.Join(dir, filename)

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

func (cm *CaseManagement) exportSelectedEvents() {
	if len(cm.selectedEventIDs) == 0 {
		cm.updateStatus("No events selected for export")
		return
	}
	cm.updateStatus("Exporting selected events...")
	go func() {
		// Gather selected events in the current view order
		selected := make([]store.Event, 0, len(cm.selectedEventIDs))
		for _, ev := range cm.events {
			if cm.selectedEventIDs[ev.ID] {
				selected = append(selected, ev)
			}
		}

		payload := struct {
			CaseID      string        `json:"case_id"`
			Events      []store.Event `json:"events"`
			GeneratedAt time.Time     `json:"generated_at"`
			Count       int           `json:"count"`
		}{
			CaseID:      cm.caseData.ID,
			Events:      selected,
			GeneratedAt: time.Now(),
			Count:       len(selected),
		}

		data, err := json.MarshalIndent(payload, "", "  ")
		if err != nil {
			cm.app.QueueUpdate(func() {
				cm.updateStatus(fmt.Sprintf("Export error: %v", err))
			})
			return
		}

		dir := "exports"
		_ = os.MkdirAll(dir, 0o755)
		filename := fmt.Sprintf("case_%s_events_%s.json", cm.caseData.ID, time.Now().Format("20060102_150405"))
		path := filepath.Join(dir, filename)

		if err := os.WriteFile(path, data, 0o644); err != nil {
			cm.app.QueueUpdate(func() {
				cm.updateStatus(fmt.Sprintf("Export error: %v", err))
			})
			return
		}

		// Log audit entry (non-blocking)
		go cm.store.LogCaseAction(cm.ctx, cm.caseData.ID, "events_export", cm.getCurrentAnalyst(),
			map[string]interface{}{"file": path, "events": len(selected)})

		cm.app.QueueUpdate(func() {
			cm.updateStatus(fmt.Sprintf("Exported %d events to %s", len(selected), path))
		})
	}()
}

func (cm *CaseManagement) updateFocusStyles() {
	// Reset titles and borders
	cm.eventsTable.SetBorderColor(cm.theme.Border)
	cm.eventsTable.SetTitleColor(cm.theme.TextPrimary)
	cm.timelineView.SetBorderColor(cm.theme.Border)
	cm.timelineView.SetTitleColor(cm.theme.TextPrimary)
	cm.copilotPanel.SetBorderColor(cm.theme.Border)
		cm.copilotPanel.SetTitleColor(cm.theme.TextPrimary)
		if cm.notesViewer != nil {
			cm.notesViewer.SetBorderColor(cm.theme.Border)
			cm.notesViewer.SetTitleColor(cm.theme.TextPrimary)
		}
		if cm.notesEditor != nil {
			cm.notesEditor.SetBorderColor(cm.theme.Border)
		}
	// Additional tab views
	if cm.overviewView != nil {
		cm.overviewView.SetBorderColor(cm.theme.Border)
		cm.overviewView.SetTitleColor(cm.theme.TextPrimary)
	}
	if cm.iocsTable != nil {
		cm.iocsTable.SetBorderColor(cm.theme.Border)
		cm.iocsTable.SetTitleColor(cm.theme.TextPrimary)
	}
	if cm.activityView != nil {
		cm.activityView.SetBorderColor(cm.theme.Border)
		cm.activityView.SetTitleColor(cm.theme.TextPrimary)
	}
	// TextArea does not support SetTitleColor; leave title color implicit via border focus.

	// Apply focus highlight
	switch cm.focusedPane {
	case FocusEvents:
		cm.eventsTable.SetBorderColor(cm.theme.FocusBorder)
		cm.eventsTable.SetTitleColor(cm.theme.FocusBorder)
	case FocusTimeline:
		cm.timelineView.SetBorderColor(cm.theme.FocusBorder)
		cm.timelineView.SetTitleColor(cm.theme.FocusBorder)
	case FocusCopilot:
		cm.copilotPanel.SetBorderColor(cm.theme.FocusBorder)
		cm.copilotPanel.SetTitleColor(cm.theme.FocusBorder)
	case FocusNotes:
		if cm.isEditingNotes {
			if cm.notesEditor != nil {
				cm.notesEditor.SetBorderColor(cm.theme.FocusBorder)
			}
		} else {
			if cm.notesViewer != nil {
				cm.notesViewer.SetBorderColor(cm.theme.FocusBorder)
				cm.notesViewer.SetTitleColor(cm.theme.FocusBorder)
			}
		}
	case FocusOverview:
		if cm.overviewView != nil {
			cm.overviewView.SetBorderColor(cm.theme.FocusBorder)
			cm.overviewView.SetTitleColor(cm.theme.FocusBorder)
		}
	case FocusIOCs:
		if cm.iocsTable != nil {
			cm.iocsTable.SetBorderColor(cm.theme.FocusBorder)
			cm.iocsTable.SetTitleColor(cm.theme.FocusBorder)
		}
	case FocusActivity:
		if cm.activityView != nil {
			cm.activityView.SetBorderColor(cm.theme.FocusBorder)
			cm.activityView.SetTitleColor(cm.theme.FocusBorder)
		}
	}
}

func (cm *CaseManagement) showStatusChangeModal() {
	form := tview.NewForm()
	form.SetTitle(" Change Case Status ")
	form.SetBorder(true)
	cm.applyModalTheme(form)

	statuses := []string{"open", "investigating", "contained", "closed"}
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
	statuses := []string{"open", "investigating", "contained", "closed"}
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
	// Ensure our input capture is active (parent UI capture may still be installed)
	if cm.globalInputCapture != nil {
		cm.app.SetInputCapture(cm.globalInputCapture)
	}
	cm.app.SetFocus(cm.eventsTable)
	cm.updateStatus("Focus: Events - Space=select, e=export, f/F=filter/clear")
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
// Settings are persisted to config/llm_settings.json and applied live.
func (cm *CaseManagement) showLLMSettingsModal() {
	const cfgPath = "config/llm_settings.json"

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
	provOptions := []string{"ollama", "openrouter"}
	provIdx := 0
	switch strings.ToLower(provider) {
	case "openrouter":
		provIdx = 1
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
					default:
						modelOptions = []string{"(loading...)"}
					}
					modelDD.SetOptions(modelOptions, nil)
					modelDD.SetCurrentOption(0)
				}

				// Helpful status hint
				if provider == "openrouter" && strings.TrimSpace(apiKeyIF.GetText()) == "" && strings.TrimSpace(os.Getenv("OPENROUTER_API_KEY")) == "" {
					cm.updateStatus("Provider set to OpenRouter. Enter API key to load models.")
				} else {
					cm.updateStatus(fmt.Sprintf("Provider set to %s", provider))
				}
			})

			// Auto-refresh models after provider change (no button interaction needed).
			if !(strings.EqualFold(provider, "openrouter") &&
				strings.TrimSpace(apiKeyIF.GetText()) == "" &&
				strings.TrimSpace(os.Getenv("OPENROUTER_API_KEY")) == "") {
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
		apiKeyIF = tview.NewInputField().SetLabel("API Key (OpenRouter)").SetText(apiKey)
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
			if prov == "openrouter" && key == "" && strings.TrimSpace(os.Getenv("OPENROUTER_API_KEY")) == "" {
				// Non-blocking UI update to avoid deadlock in button callback path
				cm.app.QueueUpdate(func() {
					modelOptions = []string{"(requires api key)"}
					if modelDD != nil {
						modelDD.SetOptions(modelOptions, nil)
						modelDD.SetCurrentOption(0)
					}
					cm.updateStatus("OpenRouter requires an API key to list models")
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
		// Skip auto-discovery for OpenRouter without an API key to avoid the "(requires api key)" churn.
		go func() {
			time.Sleep(150 * time.Millisecond)
			if !(strings.EqualFold(provider, "openrouter") &&
				strings.TrimSpace(apiKeyIF.GetText()) == "" &&
				strings.TrimSpace(os.Getenv("OPENROUTER_API_KEY")) == "") {
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
		cm.updateStatus("No manual IOCs selected")
		return
	}
	ids := make([]string, 0, len(cm.selectedManualIOCIDs))
	for id := range cm.selectedManualIOCIDs {
		ids = append(ids, id)
	}
	// Confirm deletion
	modal := tview.NewModal().
		SetText(fmt.Sprintf("Delete %d manual IOC(s)?", len(ids))).
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
				} else if cm.notesViewer != nil {
					cm.app.SetFocus(cm.notesViewer)
				}
			case FocusCopilot:
				cm.app.SetFocus(cm.copilotInput)
			case FocusOverview:
				if cm.overviewView != nil {
					cm.app.SetFocus(cm.overviewView)
				}
			case FocusActivity:
				if cm.activityView != nil {
					cm.app.SetFocus(cm.activityView)
				}
			}
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
		} else if cm.notesViewer != nil {
			cm.app.SetFocus(cm.notesViewer)
		}
	case FocusCopilot:
		cm.app.SetFocus(cm.copilotInput)
	case FocusOverview:
		if cm.overviewView != nil {
			cm.app.SetFocus(cm.overviewView)
		}
	case FocusActivity:
		if cm.activityView != nil {
			cm.app.SetFocus(cm.activityView)
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
		"(refresh to load)": true,
		"(none found)":      true,
		"(error)":           true,
		"(refreshing...)":   true,
		"(not required)":    true,
		"(requires api key)": true,
		"(timeout)":         true,
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