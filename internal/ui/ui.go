package ui

import (
	"context"
	"fmt"
	"log"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/llm"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/store"
	"github.com/rivo/tview"
)

/*
   Theming model (color-only change set)

   - Adds a lightweight Theme with widget colors (tcell.Color) and color tag strings for text markup.
   - Provides four palettes: dark (default), light, high-contrast, colorblind-safe.
   - Adds keyboard-first UX bindings: h/l focus move, j/k selection move, g/G top/bottom, J/K page, ?: help alias,
     t/T/C theme toggles, Esc clears status. Existing keys unchanged.
*/

// Theme defines UI color tokens used across widgets and text tags.
type Theme struct {
	// Widget colors
	Bg            tcell.Color
	Surface       tcell.Color
	Border        tcell.Color
	FocusBorder   tcell.Color
	SelectionBg   tcell.Color
	SelectionFg   tcell.Color
	TextPrimary   tcell.Color
	TextMuted     tcell.Color
	Accent        tcell.Color
	Success       tcell.Color
	Warning       tcell.Color
	Error         tcell.Color
	Header        tcell.Color

	// Table colors
	TableHeader   tcell.Color
	TableHeaderBg tcell.Color
	TableRow      tcell.Color
	TableRowMuted tcell.Color
	TableZebra1   tcell.Color
	TableZebra2   tcell.Color

	// Severity (widgets)
	SeverityCritical tcell.Color
	SeverityHigh     tcell.Color
	SeverityMedium   tcell.Color
	SeverityLow      tcell.Color
	SeverityInfo     tcell.Color

	// Text tag colors (for tview dynamic color markup)
	TagTextPrimary       string
	TagMuted             string
	TagAccent            string
	TagSuccess           string
	TagWarning           string
	TagError             string
	TagSeverityCritical  string
	TagSeverityHigh      string
	TagSeverityMedium    string
	TagSeverityLow       string
	TagSeverityInfo      string
}

// helpers
func hex(s string) tcell.Color { return tcell.GetColor(s) }

func themeDark() Theme {
	return Theme{
		Bg:            hex("#0e1116"),
		Surface:       hex("#12161e"),
		Border:        hex("#2b3240"),
		FocusBorder:   hex("#4aa8ff"),
		SelectionBg:   hex("#2b3240"),
		SelectionFg:   hex("#cfd8e3"),
		TextPrimary:   hex("#e6edf3"),
		TextMuted:     hex("#8a939f"),
		Accent:        hex("#2dd4bf"),
		Success:       hex("#22c55e"),
		Warning:       hex("#f59e0b"),
		Error:         hex("#ef4444"),
		Header:        hex("#eab308"),

		// Table colors
		TableHeader:   hex("#eab308"),
		TableHeaderBg: hex("#1a2332"),
		TableRow:      hex("#e6edf3"),
		TableRowMuted: hex("#94a3b8"),
		TableZebra1:   hex("#161c27"),
		TableZebra2:   hex("#121823"),

		SeverityCritical: hex("#ff5f5f"),
		SeverityHigh:     hex("#ffaf5f"),
		SeverityMedium:   hex("#ffd75f"),
		SeverityLow:      hex("#87ffaf"),
		SeverityInfo:     hex("#87afff"),

		TagTextPrimary:      "#e6edf3",
		TagMuted:            "#8a939f",
		TagAccent:           "#2dd4bf",
		TagSuccess:          "#22c55e",
		TagWarning:          "#f59e0b",
		TagError:            "#ef4444",
		TagSeverityCritical: "#ff5f5f",
		TagSeverityHigh:     "#ffaf5f",
		TagSeverityMedium:   "#ffd75f",
		TagSeverityLow:      "#87ffaf",
		TagSeverityInfo:     "#87afff",
	}
}

func themeLight() Theme {
	return Theme{
		Bg:            hex("#f6f8fa"),
		Surface:       hex("#ffffff"),
		Border:        hex("#d0d7de"),
		FocusBorder:   hex("#1f6feb"),
		SelectionBg:   hex("#e2e8f0"),
		SelectionFg:   hex("#111827"),
		TextPrimary:   hex("#111827"),
		TextMuted:     hex("#6b7280"),
		Accent:        hex("#2563eb"),
		Success:       hex("#15803d"),
		Warning:       hex("#b45309"),
		Error:         hex("#b91c1c"),
		Header:        hex("#1f2937"),

		// Table colors
		TableHeader:   hex("#1f2937"),
		TableHeaderBg: hex("#e5e7eb"),
		TableRow:      hex("#111827"),
		TableRowMuted: hex("#6b7280"),
		TableZebra1:   hex("#ffffff"),
		TableZebra2:   hex("#f8fafc"),

		SeverityCritical: hex("#dc2626"),
		SeverityHigh:     hex("#f97316"),
		SeverityMedium:   hex("#ca8a04"),
		SeverityLow:      hex("#16a34a"),
		SeverityInfo:     hex("#2563eb"),

		TagTextPrimary:      "#111827",
		TagMuted:            "#6b7280",
		TagAccent:           "#2563eb",
		TagSuccess:          "#15803d",
		TagWarning:          "#b45309",
		TagError:            "#b91c1c",
		TagSeverityCritical: "#dc2626",
		TagSeverityHigh:     "#f97316",
		TagSeverityMedium:   "#ca8a04",
		TagSeverityLow:      "#16a34a",
		TagSeverityInfo:     "#2563eb",
	}
}

func themeHighContrast() Theme {
	return Theme{
		Bg:            hex("#000000"),
		Surface:       hex("#000000"),
		Border:        hex("#ffffff"),
		FocusBorder:   hex("#ffff00"),
		SelectionBg:   hex("#ffffff"),
		SelectionFg:   hex("#000000"),
		TextPrimary:   hex("#ffffff"),
		TextMuted:     hex("#cccccc"),
		Accent:        hex("#00ffff"),
		Success:       hex("#00ff00"),
		Warning:       hex("#ffff00"),
		Error:         hex("#ff0000"),
		Header:        hex("#ffffff"),

		// Table colors
		TableHeader:   hex("#ffffff"),
		TableHeaderBg: hex("#000000"),
		TableRow:      hex("#ffffff"),
		TableRowMuted: hex("#cccccc"),
		TableZebra1:   hex("#000000"),
		TableZebra2:   hex("#111111"),

		SeverityCritical: hex("#ff0000"),
		SeverityHigh:     hex("#ff8800"),
		SeverityMedium:   hex("#ffff00"),
		SeverityLow:      hex("#00ff00"),
		SeverityInfo:     hex("#00aaff"),

		TagTextPrimary:      "#ffffff",
		TagMuted:            "#cccccc",
		TagAccent:           "#00ffff",
		TagSuccess:          "#00ff00",
		TagWarning:          "#ffff00",
		TagError:            "#ff0000",
		TagSeverityCritical: "#ff0000",
		TagSeverityHigh:     "#ff8800",
		TagSeverityMedium:   "#ffff00",
		TagSeverityLow:      "#00ff00",
		TagSeverityInfo:     "#00aaff",
	}
}

func themeColorblindSafe() Theme {
	// ColorBrewer-inspired RdYlBu-like palette (safe-ish)
	return Theme{
		Bg:            hex("#0e1116"),
		Surface:       hex("#12161e"),
		Border:        hex("#2b3240"),
		FocusBorder:   hex("#4aa8ff"),
		SelectionBg:   hex("#2b3240"),
		SelectionFg:   hex("#e6edf3"),
		TextPrimary:   hex("#e6edf3"),
		TextMuted:     hex("#8a939f"),
		Accent:        hex("#80b1d3"),
		Success:       hex("#5ab4ac"),
		Warning:       hex("#fdb863"),
		Error:         hex("#d7191c"),
		Header:        hex("#fee08b"),

		// Table colors
		TableHeader:   hex("#fee08b"),
		TableHeaderBg: hex("#232a38"),
		TableRow:      hex("#e6edf3"),
		TableRowMuted: hex("#94a3b8"),
		TableZebra1:   hex("#151a22"),
		TableZebra2:   hex("#10141b"),

		SeverityCritical: hex("#d73027"),
		SeverityHigh:     hex("#fc8d59"),
		SeverityMedium:   hex("#fee08b"),
		SeverityLow:      hex("#91bfdb"),
		SeverityInfo:     hex("#4575b4"),

		TagTextPrimary:      "#e6edf3",
		TagMuted:            "#8a939f",
		TagAccent:           "#80b1d3",
		TagSuccess:          "#5ab4ac",
		TagWarning:          "#fdb863",
		TagError:            "#d7191c",
		TagSeverityCritical: "#d73027",
		TagSeverityHigh:     "#fc8d59",
		TagSeverityMedium:   "#fee08b",
		TagSeverityLow:      "#91bfdb",
		TagSeverityInfo:     "#4575b4",
	}
}

func detectTrueColor() bool {
	// Best-effort detection without initializing screen
	ct := strings.ToLower(os.Getenv("COLORTERM"))
	if strings.Contains(ct, "truecolor") || strings.Contains(ct, "24bit") {
		return true
	}
	term := strings.ToLower(os.Getenv("TERM"))
	if strings.Contains(term, "truecolor") || strings.Contains(term, "24bit") || strings.Contains(term, "256color") {
		return true
	}
	return false
}

// UI represents the terminal user interface
type UI struct {
	app    *tview.Application
	store  *store.Store
	llm    llm.LLMProvider
	logger *log.Logger

	// Layout components
	layout      *tview.Flex
	appTitle    *tview.TextView
	allList     *tview.List
	allCasesInfo *tview.TextView
	sidebar     *tview.List
	mainPanel   *tview.Flex
	eventList   *tview.Table
	eventDetail *tview.TextView
	statusBar   *tview.TextView

		// State
		cases           []store.Case
		selectedCaseID  string
		events          []store.Event
		selectedEventID string
		selectedEventIDs map[string]bool // multi-select state for events
		loadingEvents   int32 // atomic flag to prevent concurrent event loads
		lastLoadStart   int64 // unix nano timestamp of last load start (for watchdog)
		showAll         bool  // when true, sidebar selection is "ALL EVENTS"
		queryStates     map[string]*EventQueryState // per-context (ALL or caseID) filter+pagination

	// Theme state
	theme        Theme
	themeName    string
	hasTrueColor bool
	themeApplying int32
	filterApplying int32

	// Filters (time window for events list)
	filterStart time.Time
	filterEnd   time.Time

	// Runtime
	running    bool
	helpActive bool
	lastFocus  tview.Primitive

	// Active Case Management screen (for live theme propagation)
	activeCM *CaseManagement

	// Global input capture for main UI (restored after returning from sub-screens)
	globalInputCapture func(*tcell.EventKey) *tcell.EventKey

	// Multi-key shortcut state
	shortcutBuffer    string
	shortcutTimer     *time.Timer
	shortcutTimeout   time.Duration

	// Context for cancellation
	ctx    context.Context
	cancel context.CancelFunc
	// Case filters (Cases sidebar)
	caseFilterName       string
	caseFilterStatuses   map[string]bool
	caseFilterSeverities map[string]bool

	// Source cases list (post-dedup); ui.cases is the filtered view
	allCases []store.Case
}

// Query context and pagination/filter state for Home Events
const contextAll = "ALL"

// EventQueryState holds per-context filters and pagination for the Home Events table.
type EventQueryState struct {
	filterStart      time.Time
	filterEnd        time.Time
	filterSeverities map[string]bool
	filterTypes      map[string]bool
	pageSize         int
	pageIndex        int
	totalCount       int
}

// getContextID resolves the current query context: ALL or a specific case ID.
func (ui *UI) getContextID() string {
	if !ui.showAll && ui.selectedCaseID != "" {
		return ui.selectedCaseID
	}
	return contextAll
}

// getOrInitState returns the per-context state, initializing defaults if missing.
func (ui *UI) getOrInitState(id string) *EventQueryState {
	if ui.queryStates == nil {
		ui.queryStates = make(map[string]*EventQueryState)
	}
	if s, ok := ui.queryStates[id]; ok && s != nil {
		return s
	}
	s := &EventQueryState{
		filterSeverities: make(map[string]bool),
		filterTypes:      make(map[string]bool),
		pageSize:         50,
		pageIndex:        0,
		totalCount:       0,
	}
	ui.queryStates[id] = s
	return s
}

// keysFromMap returns sorted, lowercased keys for which value is true.
func keysFromMap(m map[string]bool) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k, v := range m {
		if v {
			out = append(out, strings.ToLower(strings.TrimSpace(k)))
		}
	}
	sort.Strings(out)
	return out
}
// Apply in-memory CASE filters (name substring on Title, status set, severity set).
func (ui *UI) applyCaseFilters(in []store.Case) []store.Case {
	// Fast path: no filters
	if ui.caseFilterName == "" && len(ui.caseFilterStatuses) == 0 && len(ui.caseFilterSeverities) == 0 {
		// Return a copy to avoid accidental external mutation
		out := make([]store.Case, len(in))
		copy(out, in)
		return out
	}
	name := strings.ToLower(strings.TrimSpace(ui.caseFilterName))
	out := make([]store.Case, 0, len(in))
	for _, c := range in {
		// Name contains (Title)
		if name != "" && !strings.Contains(strings.ToLower(c.Title), name) {
			continue
		}
		// Status
		if len(ui.caseFilterStatuses) > 0 {
			if !ui.caseFilterStatuses[strings.ToLower(strings.TrimSpace(c.Status))] {
				continue
			}
		}
		// Severity
		if len(ui.caseFilterSeverities) > 0 {
			if !ui.caseFilterSeverities[strings.ToLower(strings.TrimSpace(c.Severity))] {
				continue
			}
		}
		out = append(out, c)
	}
	return out
}

// NewUI creates a new terminal user interface
func NewUI(ctx context.Context, store *store.Store, llmProvider llm.LLMProvider, logger *log.Logger) *UI {
	if logger == nil {
		logger = log.New(log.Writer(), "[UI] ", log.LstdFlags)
	}

	// Use the provided context and create a child context for UI operations
	uiCtx, cancel := context.WithCancel(ctx)

	ui := &UI{
		app:              tview.NewApplication(),
		store:            store,
		llm:              llmProvider,
		logger:           logger,
		ctx:              uiCtx,
		cancel:           cancel,
		hasTrueColor:     detectTrueColor(),
		selectedEventIDs: make(map[string]bool),
		shortcutBuffer:   "",
		shortcutTimeout:  750 * time.Millisecond, // 750ms timeout for multi-key input
	}

	// Initialize LLM provider from persisted settings when not provided by caller.
	if ui.llm == nil {
		if ui.logger != nil {
			ui.logger.Printf("No LLM provider passed in; attempting to load from config/llm_settings.json")
		}
		settings, _ := llm.LoadSettings("config/llm_settings.json")
		p, err := llm.Build(ui.ctx, settings.Active, ui.logger)
		if err != nil || p == nil {
			if ui.logger != nil {
				ui.logger.Printf("LLM settings load/build failed: %v; falling back to LocalStub", err)
			}
			p = &llm.LocalStub{}
		} else if ui.logger != nil {
			ui.logger.Printf("LLM provider initialized: %T (provider=%s, model=%s)", p, settings.Active.Provider, settings.Active.Model)
		}
		ui.llm = p
	}

	// Default theme
	ui.themeName = "neon"
	ui.theme = themeNeon()

	ui.setupLayout()
	ui.setupKeybindings()
	ui.applyTheme() // apply colors after layout assembled

	return ui
}

// Start starts the TUI application
func (ui *UI) Start(ctx context.Context) error {
	ui.logger.Println("Starting TUI application")

	// Debug: Check if allList is properly initialized
	if ui.logger != nil {
		if ui.allList != nil {
			ui.logger.Printf("DEBUG: allList is initialized with %d items", ui.allList.GetItemCount())
		} else {
			ui.logger.Printf("DEBUG: allList is nil!")
		}
	}

	// Show UI immediately, then load data asynchronously
	ui.logger.Println("Starting tview application...")

	// Load initial data in background
	go func() {
		ui.logger.Println("Loading initial data...")
		if err := ui.refreshCases(); err != nil {
			ui.logger.Printf("Failed to load cases: %v", err)
			ui.app.QueueUpdate(func() {
				ui.setStatusDirect("[red]Error loading cases: %v", err)
			})
		} else {
			ui.logger.Printf("Loaded %d cases successfully", len(ui.cases))
			// Set initial focus after data is loaded and auto-load ALL EVENTS
			ui.app.QueueUpdate(func() {
				// Focus the Events table directly (overview panel is non-selectable)
				ui.app.SetFocus(ui.eventList)

				// Auto-load ALL EVENTS on startup
				ui.showAll = true
				ui.selectedCaseID = ""

				// Immediate loading state in events table
				ui.eventList.Clear()
				headers := []string{"Time", "Type", "Severity", "Host", "Source", "Message"}
				for col, header := range headers {
					ui.eventList.SetCell(0, col, tview.NewTableCell(header).
						SetTextColor(ui.theme.TableHeader).
						SetBackgroundColor(ui.theme.TableHeaderBg).
						SetAttributes(tcell.AttrBold))
				}
				ui.eventList.SetCell(1, 0, tview.NewTableCell("Loading...").
					SetTextColor(ui.theme.TableRowMuted))

				// Watchdog: reset stuck load flag if necessary
				if atomic.LoadInt32(&ui.loadingEvents) == 1 {
					started := time.Unix(0, atomic.LoadInt64(&ui.lastLoadStart))
					if started.IsZero() || time.Since(started) > 3*time.Second {
						if ui.logger != nil {
							ui.logger.Printf("startup: resetting stuck loadingEvents since %v", started)
						}
						atomic.StoreInt32(&ui.loadingEvents, 0)
						atomic.StoreInt64(&ui.lastLoadStart, 0)
					}
				}
				go ui.loadAllEvents()
			})
		}
	}()

	// Handle context cancellation for both external and internal contexts
	go func() {
		select {
		case <-ctx.Done():
			ui.logger.Println("External context cancelled, stopping TUI")
		case <-ui.ctx.Done():
			ui.logger.Println("UI context cancelled, stopping TUI")
		}
		ui.cancel() // Cancel UI context if external context is done
		ui.app.Stop()
	}()

	ui.logger.Println("Calling app.Run()...")
	// Start a periodic redraw to mitigate terminals that occasionally miss repaints
	ui.startRedrawHeartbeat()

	// Optional: auto-cycle theme for diagnostics when UI_AUTOCYCLE_THEME=1
	if os.Getenv("UI_AUTOCYCLE_THEME") == "1" {
		go func() {
			if ui.logger != nil {
				ui.logger.Printf("UI_AUTOCYCLE_THEME=1 enabled: scheduling theme cycles")
			}
			time.Sleep(1200 * time.Millisecond)
			ui.app.QueueUpdate(func() { ui.cycleTheme() })
			time.Sleep(1200 * time.Millisecond)
			ui.app.QueueUpdate(func() { ui.cycleTheme() })
		}()
	}

	ui.running = true
	err := ui.app.Run()
	ui.running = false
	ui.logger.Printf("app.Run() returned with error: %v", err)
	return err
}

// Stop stops the TUI application
func (ui *UI) Stop() {
	ui.logger.Println("Stopping TUI application")
	ui.running = false
	ui.cancel()
	ui.app.Stop()
}

// setupLayout creates the main layout
func (ui *UI) setupLayout() {
	// Create components
	ui.sidebar = tview.NewList()
	ui.sidebar.SetTitle(" Cases ")
	ui.sidebar.SetBorder(true)
	ui.sidebar.SetTitleAlign(tview.AlignLeft)

	ui.eventList = tview.NewTable()
	ui.eventList.SetTitle(" Events ")
	ui.eventList.SetBorder(true)
	ui.eventList.SetTitleAlign(tview.AlignLeft)
	ui.eventList.SetSelectable(true, false)
	// Pin header row so it stays visible when selecting/scrolling.
	ui.eventList.SetFixed(1, 0)

	ui.eventDetail = tview.NewTextView()
	ui.eventDetail.SetTitle(" Event Details ")
	ui.eventDetail.SetBorder(true)
	ui.eventDetail.SetTitleAlign(tview.AlignLeft)
	ui.eventDetail.SetDynamicColors(true)
	ui.eventDetail.SetWordWrap(true)
	ui.eventDetail.SetScrollable(true)

	ui.statusBar = tview.NewTextView()
	ui.statusBar.SetDynamicColors(true)
	ui.statusBar.SetText("[yellow]Console-IR v1.0[white] | [green]q[white]:quit [green]r[white]:refresh [green]Enter[white]:select [green]Tab[white]:navigate")

	// Create main panel (right side)
	ui.mainPanel = tview.NewFlex().
		SetDirection(tview.FlexRow).
		AddItem(ui.eventList, 0, 2, true).
		AddItem(ui.eventDetail, 0, 1, false)

	// App title header (non-selectable)
	ui.appTitle = tview.NewTextView().
		SetDynamicColors(true).
		SetTextAlign(tview.AlignLeft)
	ui.appTitle.SetBorder(false)
	ui.appTitle.SetBackgroundColor(ui.theme.Surface)
	ui.appTitle.SetText(fmt.Sprintf(" [%s]Console-IR[-]", ui.theme.TagAccent))

	// Dedicated ALL EVENTS list (single item)
	ui.allList = tview.NewList()
	ui.allList.SetTitle(" ALL EVENTS ")
	ui.allList.SetBorder(true)
	ui.allList.SetTitleAlign(tview.AlignCenter)
	ui.allList.SetMainTextColor(ui.theme.TextPrimary)
	ui.allList.SetSecondaryTextColor(ui.theme.TextMuted)
	ui.allList.SetSelectedTextColor(ui.theme.SelectionFg)
	ui.allList.SetSelectedBackgroundColor(ui.theme.SelectionBg)
	ui.allList.SetBorderColor(ui.theme.FocusBorder) // Make it more visible
	ui.allList.AddItem(fmt.Sprintf("[%s]ALL EVENTS[-]", ui.theme.TagAccent), "All ingested events (watch folder)", 'A', nil)

	// Debug logging
	if ui.logger != nil {
		ui.logger.Printf("DEBUG: allList created with %d items", ui.allList.GetItemCount())
	}
	ui.allList.SetSelectedFunc(func(index int, mainText, secondaryText string, shortcut rune) {
				// Load ALL EVENTS
				ui.showAll = true
				ui.selectedCaseID = ""
		
				// Reset pagination for ALL context
				{
					s := ui.getOrInitState(contextAll)
					s.pageIndex = 0
				}
		
				// Immediate loading state in events table
		ui.eventList.Clear()
		headers := []string{"Time", "Type", "Severity", "Host", "Source", "Message"}
		for col, header := range headers {
			ui.eventList.SetCell(0, col, tview.NewTableCell(header).
				SetTextColor(ui.theme.TableHeader).
				SetBackgroundColor(ui.theme.TableHeaderBg).
				SetAttributes(tcell.AttrBold))
		}
		ui.eventList.SetCell(1, 0, tview.NewTableCell("Loading...").
			SetTextColor(ui.theme.TableRowMuted))
		ui.app.SetFocus(ui.eventList)
		ui.setStatusDirect("[%s]Loading ALL events...[-:-:-]", ui.theme.TagWarning)

		// Watchdog: reset stuck load flag if necessary
		if atomic.LoadInt32(&ui.loadingEvents) == 1 {
			started := time.Unix(0, atomic.LoadInt64(&ui.lastLoadStart))
			if started.IsZero() || time.Since(started) > 3*time.Second {
				if ui.logger != nil {
					ui.logger.Printf("allList select: resetting stuck loadingEvents since %v", started)
				}
				atomic.StoreInt32(&ui.loadingEvents, 0)
				atomic.StoreInt64(&ui.lastLoadStart, 0)
			}
		}
		go ui.loadAllEvents()
	})
	// Up/Down navigation between All and Cases
	ui.allList.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
		switch ev.Key() {
		case tcell.KeyDown:
			// Move focus into cases list
			ui.app.SetFocus(ui.sidebar)
			if ui.sidebar.GetItemCount() > 0 {
				ui.sidebar.SetCurrentItem(0)
			}
			return nil
		}
		return ev
	})

	// Sidebar list remains for cases (below ALL EVENTS)
	ui.sidebar.SetTitle(" Cases ")
// Initialize ALL CASES info block (non-selectable)
ui.allCasesInfo = tview.NewTextView().
	SetDynamicColors(true).
	SetTextAlign(tview.AlignLeft)
ui.allCasesInfo.SetTitle(" OVERVIEW ")
ui.allCasesInfo.SetBorder(true)
ui.allCasesInfo.SetTitleAlign(tview.AlignCenter)
ui.allCasesInfo.SetBackgroundColor(ui.theme.Surface)
ui.allCasesInfo.SetTextColor(ui.theme.TextPrimary)
ui.allCasesInfo.SetBorderColor(ui.theme.Border)
// Default text until cases are loaded
ui.allCasesInfo.SetText(fmt.Sprintf("[%s](A) EVENTS (0)[-]\n[%s](C) CASES (0)[-]\n[%s]OPEN[-] - 0  [%s]INVESTIGATING[-] - 0  [%s]CLOSED[-] - 0",
	ui.theme.TagAccent, ui.theme.TagAccent, ui.theme.TagTextPrimary, ui.theme.TagTextPrimary, ui.theme.TagTextPrimary))

	// Build left column: Title → All → Cases
	leftCol := tview.NewFlex().
		SetDirection(tview.FlexRow).
		AddItem(ui.appTitle, 2, 0, false).
		AddItem(ui.allCasesInfo, 5, 0, false).
		AddItem(ui.sidebar, 0, 1, false)

	// Create main layout - wider left column for better display
	ui.layout = tview.NewFlex().
		SetDirection(tview.FlexColumn).
		AddItem(leftCol, 45, 0, true).
		AddItem(ui.mainPanel, 0, 1, true)

	// Create root layout with status bar
	root := tview.NewFlex().
		SetDirection(tview.FlexRow).
		AddItem(ui.layout, 0, 1, true).
		AddItem(ui.statusBar, 1, 0, false)

	ui.app.SetRoot(root, true)

	// Set up event handlers
	ui.setupEventHandlers()

	// Sidebar input capture for navigation and multi-key shortcuts
	ui.sidebar.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
		switch ev.Key() {
		case tcell.KeyUp:
			row := ui.sidebar.GetCurrentItem()
			if row <= 0 {
				// At top; do not move focus (overview panel is non-selectable)
				return nil
			}
		case tcell.KeyRune:
			// Handle number keys for case selection (multi-key support)
			if ev.Rune() >= '1' && ev.Rune() <= '9' {
				ui.handleShortcutKey(ev.Rune())
				return nil
			}
			// Handle 0 key (only if buffer is not empty)
			if ev.Rune() == '0' && ui.shortcutBuffer != "" {
				ui.handleShortcutKey(ev.Rune())
				return nil
			}
		}
		return ev
	})

	// Set initial focus to ALL EVENTS
	ui.allList.SetCurrentItem(0)
	ui.app.SetFocus(ui.allList)

	// Debug: Confirm focus is set
	if ui.logger != nil {
		currentFocus := ui.app.GetFocus()
		if currentFocus == ui.allList {
			ui.logger.Printf("DEBUG: Focus successfully set to allList")
		} else {
			ui.logger.Printf("DEBUG: Focus not set to allList, current focus: %T", currentFocus)
		}
	}
}

// setupEventHandlers sets up event handlers for UI components
func (ui *UI) setupEventHandlers() {
	// Sidebar (cases) selection - triggered by Enter key
	ui.sidebar.SetSelectedFunc(func(index int, mainText, secondaryText string, shortcut rune) {
		ui.openCaseManagement(index)
	})

	// Rely on SetSelectedFunc to handle Enter presses for the sidebar to avoid re-entrancy in input handlers.

	// Event list selection
	ui.eventList.SetSelectedFunc(func(row, col int) {
		if row > 0 && row-1 < len(ui.events) { // Skip header row
			ui.selectedEventID = ui.events[row-1].ID
			ui.showEventDetails()
		}
	})

	// Event list selection change
	ui.eventList.SetSelectionChangedFunc(func(row, col int) {
		if row > 0 && row-1 < len(ui.events) { // Skip header row
			ui.selectedEventID = ui.events[row-1].ID
			ui.showEventDetails()
		}
	})

	// Add input capture for event list to handle Enter and Space
	ui.eventList.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch event.Key() {
		case tcell.KeyEnter:
			row, col := ui.eventList.GetSelection()
			if ui.logger != nil {
				ui.logger.Printf("EventList Enter: row=%d col=%d rows=%d", row, col, ui.eventList.GetRowCount())
			}
			if row > 0 && row-1 < len(ui.events) {
				ui.selectedEventID = ui.events[row-1].ID
				ui.showEventDetails()
			}
			return nil
		case tcell.KeyRune:
			switch event.Rune() {
			case ' ':
				if ui.logger != nil {
					ui.logger.Printf("EVENTLIST Space key pressed - calling toggleEventSelection")
				}
				// Toggle selection on current event
				ui.toggleEventSelection()
				return nil
			case 'd':
				// Delete selected events (with confirmation)
				if len(ui.selectedEventIDs) == 0 {
					ui.setStatusDirect("[%s]No events selected. Use Space to select events first. (Events: %d)[-:-:-]", ui.theme.TagWarning, len(ui.events))
					return nil
				}
				ids := make([]string, 0, len(ui.selectedEventIDs))
				for id := range ui.selectedEventIDs {
					ids = append(ids, id)
				}
				ui.showDeleteEventsConfirm(ids)
				return nil
			}
		}
		return event
	})
}

// onSidebarSelect centralizes behavior for selecting the ALL EVENTS item or a specific case.
func (ui *UI) onSidebarSelect(index int) {
	ui.logger.Printf("Sidebar selected (cases list): index=%d, cases=%d", index, len(ui.cases))

	// Prepare UI to show a loading state immediately and focus the Events table.
	showLoading := func(title string) {
		ui.eventList.Clear()
		headers := []string{"Time", "Type", "Severity", "Host", "Source", "Message"}
		for col, header := range headers {
			ui.eventList.SetCell(0, col, tview.NewTableCell(header).
				SetTextColor(ui.theme.TableHeader).
				SetBackgroundColor(ui.theme.TableHeaderBg).
				SetAttributes(tcell.AttrBold))
		}
		ui.eventList.SetCell(1, 0, tview.NewTableCell("Loading...").
			SetTextColor(ui.theme.TableRowMuted))
		ui.app.SetFocus(ui.eventList)
		ui.setStatusDirect("[%s]%s[-:-:-]", ui.theme.TagWarning, title)
	}

	// Cases list indexes map directly to ui.cases
	if index < 0 || index >= len(ui.cases) {
		ui.logger.Printf("Invalid case index: %d (cases: %d)", index, len(ui.cases))
		return
	}

	ui.showAll = false
	ui.selectedCaseID = ui.cases[index].ID
	// Reset pagination for this case context
	{
		s := ui.getOrInitState(ui.selectedCaseID)
		s.pageIndex = 0
	}
	ui.logger.Printf("Selected case ID: %s", ui.selectedCaseID)
	showLoading("Loading events for selected case...")

	// If a previous load appears stuck, clear the flag to allow a new load.
	if atomic.LoadInt32(&ui.loadingEvents) == 1 {
		started := time.Unix(0, atomic.LoadInt64(&ui.lastLoadStart))
		if started.IsZero() || time.Since(started) > 3*time.Second {
			if ui.logger != nil {
				ui.logger.Printf("onSidebarSelect: load flag stuck since %v, resetting", started)
			}
			atomic.StoreInt32(&ui.loadingEvents, 0)
		} else if ui.logger != nil {
			ui.logger.Printf("onSidebarSelect: load already in progress (%v ago)", time.Since(started))
		}
	}
	if ui.logger != nil {
		ui.logger.Printf("onSidebarSelect: starting loadCaseEvents (caseID=%s, filterStart=%v, filterEnd=%v)", ui.selectedCaseID, ui.filterStart, ui.filterEnd)
	}
	go ui.loadCaseEvents()
}

// setupKeybindings sets up global keybindings
func (ui *UI) setupKeybindings() {
	handler := func(event *tcell.EventKey) *tcell.EventKey {
		// While a modal or form is active, allow it to handle all keys (avoid global shortcuts like q/h/Tab).
		if ui.isDialogActive() {
			return event
		}

		// Log key events to help diagnose input handling
		if ui.logger != nil {
			ui.logger.Printf("Input event: Key=%v Rune=%q Mod=%v", event.Key(), event.Rune(), event.Modifiers())
		}

		switch event.Key() {
		case tcell.KeyCtrlC:
			ui.app.Stop()
			return nil
		case tcell.KeyEnter:
			// Let the focused primitive handle Enter. The sidebar's own input capture will manage selection.
			return event
		case tcell.KeyEsc:
			// Clear status line softly (UI goroutine safe)
			ui.setStatusDirect("[%s]Ready[-:-:-]", ui.theme.TagAccent)
			return nil
		case tcell.KeyTab:
			ui.cycleFocus()
			return nil
		case tcell.KeyRune:
			switch event.Rune() {
			// Existing
			case 'q', 'Q':
				ui.app.Stop()
				return nil
			case 'r', 'R':
				// Non-blocking refresh to avoid stalling the tview event loop
				ui.setStatusDirect("[%s]Refreshing...[-:-:-]", ui.theme.TagAccent)
				go func() {
					if err := ui.refreshCases(); err != nil {
						ui.app.QueueUpdate(func() {
							ui.setStatusDirect("[%s]Error refreshing cases: %v[-:-:-]", ui.theme.TagError, err)
						})
					} else {
						ui.app.QueueUpdate(func() {
							ui.setStatusDirect("[%s]Cases refreshed[-:-:-]", ui.theme.TagSuccess)
						})
					}
				}()
				// Schedule events reload according to current selection and filter state
				ui.scheduleEventsReload("key:r")
				return nil
			case 's', 'S':
				if ui.selectedCaseID != "" {
					ui.showCaseSummary()
				}
				return nil
			case 'H':
				ui.showHelp()
				return nil
			// Keyboard-first UX additions (navigation)
			case '?':
				ui.showHelp()
				return nil
			case 'h':
				ui.showHelp()
				return nil
			case 'l':
				ui.focusRight()
				return nil
			case 'j':
				ui.moveSelection(1)
				return nil
			case 'k':
				ui.moveSelection(-1)
				return nil
			case 'g':
				ui.moveToBoundary(true)
				return nil
			case 'G':
				ui.moveToBoundary(false)
				return nil
			case 'J':
				ui.pageMove(1)
				return nil
			case 'K':
				ui.pageMove(-1)
				return nil
			case 'N':
				{
					id := ui.getContextID()
					s := ui.getOrInitState(id)
					maxPages := 1
					if s.pageSize > 0 {
						maxPages = (s.totalCount + s.pageSize - 1) / s.pageSize
						if maxPages == 0 {
							maxPages = 1
						}
					}
					if s.pageIndex+1 < maxPages {
						s.pageIndex++
						ui.setStatusDirect("[%s]Next page (%d/%d)[-:-:-]", ui.theme.TagAccent, s.pageIndex+1, maxPages)
						go ui.scheduleEventsReload("page:Next")
					} else {
						ui.setStatusDirect("[%s]Already at last page (%d/%d)[-:-:-]", ui.theme.TagMuted, s.pageIndex+1, maxPages)
					}
				}
				return nil
			case 'P':
				{
					id := ui.getContextID()
					s := ui.getOrInitState(id)
					if s.pageIndex > 0 {
						s.pageIndex--
						maxPages := 1
						if s.pageSize > 0 {
							maxPages = (s.totalCount + s.pageSize - 1) / s.pageSize
							if maxPages == 0 {
								maxPages = 1
							}
						}
						ui.setStatusDirect("[%s]Prev page (%d/%d)[-:-:-]", ui.theme.TagAccent, s.pageIndex+1, maxPages)
						go ui.scheduleEventsReload("page:Prev")
					} else {
						ui.setStatusDirect("[%s]Already at first page (1/?) [-:-:-]", ui.theme.TagMuted)
					}
				}
				return nil
			// Theme toggles
			case 't':
				// Apply theme synchronously on UI goroutine to avoid queue starvation
				if ui.logger != nil {
					ui.logger.Printf("Key 't' pressed: applying theme cycle (current=%s)", ui.themeName)
				}
				ui.cycleTheme()
				return nil
			case 'T':
				// Apply theme synchronously on UI goroutine
				next := "dark"
				if ui.themeName != "high-contrast" {
					next = "high-contrast"
				}
				if ui.logger != nil {
					ui.logger.Printf("Key 'T' pressed: applying setTheme(%s) (current=%s)", next, ui.themeName)
				}
				ui.setTheme(next)
				return nil
			case 'C':
				// Apply theme synchronously on UI goroutine
				next := "dark"
				if ui.themeName != "cb-safe" {
					next = "cb-safe"
				}
				if ui.logger != nil {
					ui.logger.Printf("Key 'C' pressed: applying setTheme(%s) (current=%s)", next, ui.themeName)
				}
				ui.setTheme(next)
				return nil
			case 'f':
				// Gated by focus: Cases sidebar opens CASE filter, otherwise open Events filter
				if ui.app.GetFocus() == ui.sidebar {
					ui.showCaseFilterModal()
				} else {
					// Open combined filter modal (time + severity + type)
					ui.showCombinedFilterModal()
				}
				return nil
			case 'F':
				// Gated by focus: Cases sidebar clears CASE filters, otherwise clear Events filters
				if ui.app.GetFocus() == ui.sidebar {
					ui.clearCaseFilters()
				} else {
					// Clear filters for current context (time, severity, type)
					ui.clearCurrentContextFilters()
				}
				return nil
			// Case creation shortcuts
			case 'c':
				if ui.logger != nil {
					ui.logger.Printf("GLOBAL KEY 'c' pressed: selectedEventIDs=%d, events=%d", len(ui.selectedEventIDs), len(ui.events))
				}
				if len(ui.selectedEventIDs) > 0 {
					ui.setStatusDirect("[%s]Opening case creation modal...[-:-:-]", ui.theme.TagAccent)
					ui.showCreateCaseModal()
				} else {
					ui.setStatusDirect("[%s]No events selected. Use Space to select events first. (Events: %d)[-:-:-]", ui.theme.TagWarning, len(ui.events))
				}
				return nil
			case 'a':
				if ui.logger != nil {
					ui.logger.Printf("GLOBAL KEY 'a' pressed: selectedEventIDs=%d, events=%d", len(ui.selectedEventIDs), len(ui.events))
				}
				if len(ui.selectedEventIDs) > 0 {
					ui.setStatusDirect("[%s]Opening add to case modal...[-:-:-]", ui.theme.TagAccent)
					ui.showAddToExistingCaseModal()
				} else {
					ui.setStatusDirect("[%s]No events selected. Use Space to select events first. (Events: %d)[-:-:-]", ui.theme.TagWarning, len(ui.events))
				}
				return nil
			case 'A':
				// Quick-jump to ALL EVENTS from anywhere (overview panel is non-selectable)
				ui.app.SetFocus(ui.eventList)

				// Trigger same behavior as selecting ALL EVENTS
				ui.showAll = true
				ui.selectedCaseID = ""

				// Reset pagination for ALL context
				{
					s := ui.getOrInitState(contextAll)
					s.pageIndex = 0
				}

				// Immediate loading state in events table
				ui.eventList.Clear()
				headers := []string{"Time", "Type", "Severity", "Host", "Source", "Message"}
				for col, header := range headers {
					ui.eventList.SetCell(0, col, tview.NewTableCell(header).
						SetTextColor(ui.theme.TableHeader).
						SetBackgroundColor(ui.theme.TableHeaderBg).
						SetAttributes(tcell.AttrBold))
				}
				ui.eventList.SetCell(1, 0, tview.NewTableCell("Loading...").
					SetTextColor(ui.theme.TableRowMuted))
				ui.setStatusDirect("[%s]Loading ALL events...[-:-:-]", ui.theme.TagWarning)

				// Watchdog: reset stuck load flag if necessary
				if atomic.LoadInt32(&ui.loadingEvents) == 1 {
					started := time.Unix(0, atomic.LoadInt64(&ui.lastLoadStart))
					if started.IsZero() || time.Since(started) > 3*time.Second {
						if ui.logger != nil {
							ui.logger.Printf("hotkey 'A': resetting stuck loadingEvents since %v", started)
						}
						atomic.StoreInt32(&ui.loadingEvents, 0)
						atomic.StoreInt64(&ui.lastLoadStart, 0)
					}
				}
				go ui.loadAllEvents()
				return nil
			case 'd':
				// Context-sensitive delete:
				// - If focus is on Cases sidebar: delete the highlighted case (hover + d)
				// - Otherwise, let the focused widget handle 'd' (e.g., Events table deletes events)
				if ui.app.GetFocus() == ui.sidebar {
					// Derive case under cursor if selectedCaseID is empty
					if ui.selectedCaseID == "" || ui.showAll {
						idx := ui.sidebar.GetCurrentItem()
						if idx >= 0 && idx < len(ui.cases) {
							ui.selectedCaseID = ui.cases[idx].ID
							ui.showAll = false
						}
					}
					if ui.selectedCaseID == "" || ui.showAll {
						ui.setStatusDirect("[%s]Select a case in the sidebar first (cannot delete ALL EVENTS)[-:-:-]", ui.theme.TagWarning)
						return nil
					}
					ui.showDeleteCaseConfirm()
					return nil
				}
				// Not in sidebar: allow event list handler to process 'd'.
				return event
			}
		case tcell.KeyCtrlA:
			// Select all events
			ui.selectAllEvents()
			return nil
		case tcell.KeyCtrlD:
			// Deselect all events
			ui.deselectAllEvents()
			return nil
		}
		return event
	}
	// Save and apply the handler so we can restore it after returning from sub-screens.
	ui.globalInputCapture = handler
	ui.app.SetInputCapture(handler)
}

// refreshCases loads cases from the database
func (ui *UI) refreshCases() error {
	ui.logger.Println("Refreshing cases...")
	// Use a short timeout to avoid UI stalls under DB contention
	ctx, cancel := context.WithTimeout(ui.ctx, 4*time.Second)
	defer cancel()

	cases, err := ui.store.ListCases(ctx)
	if err != nil {
		ui.logger.Printf("Error loading cases: %v", err)
		ui.setStatus("[red]Error loading cases: %v", err)
		return err
	}

	// Filter out noisy/auto-created cases (e.g., legacy "Ingested Events" duplicates)
	// and de-duplicate by Title to keep the sidebar clean.
	filtered := make([]store.Case, 0, len(cases))
	seenTitles := make(map[string]bool)
	for _, c := range cases {
		if strings.EqualFold(c.Title, "Ingested Events") {
			continue
		}
		if seenTitles[c.Title] {
			continue
		}
		seenTitles[c.Title] = true
		filtered = append(filtered, c)
	}

	ui.logger.Printf("Loaded %d cases from database, showing %d after filtering", len(cases), len(filtered))
	// Store source list and apply CASE filters
	ui.allCases = filtered
	ui.cases = ui.applyCaseFilters(ui.allCases)

	// Selection stability: if current selected case is filtered out, clear selection and switch to ALL EVENTS
	if ui.selectedCaseID != "" {
		found := false
		for _, c := range ui.cases {
			if c.ID == ui.selectedCaseID {
				found = true
				break
			}
		}
		if !found {
			ui.selectedCaseID = ""
			ui.showAll = true
		}
	}

	ui.updateCasesList()

	// Compute ALL CASES stats (OPEN, INVESTIGATING, CLOSED)
	totalCases := len(ui.cases)
	var openN, invN, closeN int
	for _, c := range ui.cases {
		switch strings.ToLower(strings.TrimSpace(c.Status)) {
		case "open":
			openN++
		case "investigating", "investigation":
			invN++
		case "closed", "close":
			closeN++
		}
	}

	// Compute ALL EVENTS total with current ALL-context filters
	sAll := ui.getOrInitState(contextAll)
	start := sAll.filterStart
	if start.IsZero() && !ui.filterStart.IsZero() {
		start = ui.filterStart
	}
	end := sAll.filterEnd
	if end.IsZero() && !ui.filterEnd.IsZero() {
		end = ui.filterEnd
	}
	sev := keysFromMap(sAll.filterSeverities)
	typ := keysFromMap(sAll.filterTypes)
	eventsTotal, _ := ui.store.CountEventsFiltered(ctx, "", start, end, sev, typ)

	ui.updateOverview(eventsTotal, totalCases, openN, invN, closeN)

	ui.setStatus("[%s]Loaded %d cases[-:-:-]", ui.theme.TagSuccess, len(filtered))

	return nil
}

// updateCasesList updates the cases sidebar
func (ui *UI) updateCasesList() {
	ui.app.QueueUpdate(func() {
		ui.sidebar.Clear()

		// Cases list only (ALL EVENTS handled by separate allList)

		if len(ui.cases) == 0 {
			return
		}

		for i, case_ := range ui.cases {
			// Format case display - allow longer titles with wider sidebar
			title := case_.Title
			if len(title) > 40 {
				title = title[:37] + "..."
			}

			severity := strings.ToUpper(case_.Severity)
			severityColor := ui.getSeverityColor(case_.Severity)

			// Include case number in the display (1-based) using the same visual style as tview "(n)"
			caseNumber := i + 1
			mainText := fmt.Sprintf("[%s](%d)[-] [%s]%s[-]", ui.theme.TagAccent, caseNumber, ui.theme.TagTextPrimary, title)
			secondaryText := fmt.Sprintf("[%s]%s[-] | %s | %d events",
				severityColor,
				severity,
				strings.ToLower(strings.TrimSpace(case_.Status)),
				case_.EventCount,
			)

			// Do not pass tview shortcut runes at all, to avoid duplicate "(1)" style labels.
			// Multi-digit number selection is handled by our input-capture buffer.
			var shortcut rune = 0
			ui.sidebar.AddItem(mainText, secondaryText, shortcut, nil)
		}

		// Default focus to ALL EVENTS item
		ui.sidebar.SetCurrentItem(0)
	})
}

// loadCaseEvents loads events for the selected case
func (ui *UI) loadCaseEvents() {
	// Prevent concurrent loads (can happen if both per-item and selected handlers fire)
	if !atomic.CompareAndSwapInt32(&ui.loadingEvents, 0, 1) {
		ui.logger.Println("loadCaseEvents: already loading, skipping")
		return
	}
	atomic.StoreInt64(&ui.lastLoadStart, time.Now().UnixNano())
	defer func() {
		atomic.StoreInt32(&ui.loadingEvents, 0)
		atomic.StoreInt64(&ui.lastLoadStart, 0)
	}()

	defer func() {
		if r := recover(); r != nil {
			if ui.logger != nil {
				ui.logger.Printf("panic in loadCaseEvents: %v", r)
			}
			ui.setStatusDirect("[%s]Error loading events (recovered)[-:-:-]", ui.theme.TagError)
		}
	}()

	if ui.selectedCaseID == "" {
		ui.logger.Println("loadCaseEvents: no case selected")
		return
	}

	ui.logger.Printf("Loading events for case: %s", ui.selectedCaseID)
	// Show loading status immediately on the UI thread
	ui.setStatus("[%s]Loading events...[-:-:-]", ui.theme.TagWarning)

	// Run DB query with a short timeout to avoid UI freeze if DB is locked
	ctx, cancel := context.WithTimeout(ui.ctx, 4*time.Second)
	defer cancel()

	// Per-context query state and filters/pagination
	s := ui.getOrInitState(ui.selectedCaseID)
	// Bridge legacy time fields if set
	if s.filterStart.IsZero() && !ui.filterStart.IsZero() {
		s.filterStart = ui.filterStart
	}
	if s.filterEnd.IsZero() && !ui.filterEnd.IsZero() {
		s.filterEnd = ui.filterEnd
	}
	sev := keysFromMap(s.filterSeverities)
	typ := keysFromMap(s.filterTypes)

	// Count total first to clamp page index
	total, err := ui.store.CountEventsFiltered(ctx, ui.selectedCaseID, s.filterStart, s.filterEnd, sev, typ)
	if err != nil {
		ui.logger.Printf("Error counting events for case %s: %v", ui.selectedCaseID, err)
		// Reset filter apply guard on failure
		atomic.StoreInt32(&ui.filterApplying, 0)
		ui.app.QueueUpdate(func() {
			if ctx.Err() == context.DeadlineExceeded {
				ui.setStatusDirect("[%s]Timed out counting events (database busy)[-:-:-]", ui.theme.TagError)
			} else {
				ui.setStatusDirect("[%s]Error counting events: %v[-:-:-]", ui.theme.TagError, err)
			}
		})
		return
	}
	s.totalCount = total

	// Clamp page index within bounds
	maxPages := 1
	if s.pageSize > 0 {
		maxPages = (s.totalCount + s.pageSize - 1) / s.pageSize
		if maxPages == 0 {
			maxPages = 1
		}
		if s.pageIndex >= maxPages {
			s.pageIndex = maxPages - 1
		}
		if s.pageIndex < 0 {
			s.pageIndex = 0
		}
	}

	limit := s.pageSize
	offset := 0
	if limit > 0 {
		offset = s.pageIndex * limit
	}

	events, err := ui.store.GetEventsFiltered(ctx, ui.selectedCaseID, s.filterStart, s.filterEnd, sev, typ, limit, offset)
	if err != nil {
		ui.logger.Printf("Error loading events for case %s: %v", ui.selectedCaseID, err)
		// Reset filter apply guard on failure
		atomic.StoreInt32(&ui.filterApplying, 0)
		ui.app.QueueUpdate(func() {
			if ctx.Err() == context.DeadlineExceeded {
				ui.setStatusDirect("[%s]Timed out loading events (database busy)[-:-:-]", ui.theme.TagError)
			} else {
				ui.setStatusDirect("[%s]Error loading events: %v[-:-:-]", ui.theme.TagError, err)
			}
		})
		return
	}

	ui.logger.Printf("Loaded %d events for case %s", len(events), ui.selectedCaseID)
	if ui.logger != nil {
		started := time.Unix(0, atomic.LoadInt64(&ui.lastLoadStart))
		if !started.IsZero() {
			ui.logger.Printf("loadCaseEvents: query finished in %v; updating UI", time.Since(started))
		}
	}

	// Update UI in main thread
	ui.app.QueueUpdateDraw(func() {
		// Clear any previous selections when data changes (avoid stale IDs across pages)
		ui.selectedEventIDs = make(map[string]bool)
		ui.events = events
		ui.updateEventsList()

		// Ensure the table is scrolled to the top and the first data row is selected.
		ui.eventList.SetOffset(0, 0)
		if ui.eventList.GetRowCount() > 1 {
			ui.eventList.Select(1, 0) // first data row (row 0 is header)
		} else {
			ui.eventList.Select(0, 0) // header/no-data fallback
		}

		// Move focus to the Events panel so changes are immediately visible
		ui.app.SetFocus(ui.eventList)

		// Find the case title for status message
		var caseTitle string
		for _, case_ := range ui.cases {
			if case_.ID == ui.selectedCaseID {
				caseTitle = case_.Title
				break
			}
		}
		if ui.logger != nil {
			ui.logger.Printf("UI: applied events update for case=%s, events=%d, rows=%d", ui.selectedCaseID, len(events), ui.eventList.GetRowCount())
		}
		ui.setStatusDirect("[%s]Loaded %d events[-:-:-] for case: %s", ui.theme.TagSuccess, len(events), caseTitle)
		// Re-enable Apply after load completes
		atomic.StoreInt32(&ui.filterApplying, 0)
	})
}

// updateEventsList updates the events table
func (ui *UI) updateEventsList() {
	ui.eventList.Clear()

	// Selected style and border color from theme
	ui.eventList.SetSelectedStyle(tcell.StyleDefault.Background(ui.theme.SelectionBg).Foreground(ui.theme.SelectionFg))
	ui.eventList.SetBorderColor(ui.theme.Border)

	// Title with pagination info from current context
	id := ui.getContextID()
	s := ui.getOrInitState(id)
	maxPages := 1
	if s.pageSize > 0 {
		maxPages = (s.totalCount + s.pageSize - 1) / s.pageSize
		if maxPages == 0 {
			maxPages = 1
		}
	}
	ui.eventList.SetTitle(fmt.Sprintf(" Events (Page %d/%d, Total %d) ", s.pageIndex+1, maxPages, s.totalCount))

	// Set headers
	headers := []string{"Time", "Type", "Severity", "Host", "Source", "Message"}
	for col, header := range headers {
		ui.eventList.SetCell(0, col, tview.NewTableCell(header).
			SetTextColor(ui.theme.TableHeader).
			SetBackgroundColor(ui.theme.TableHeaderBg).
			SetAttributes(tcell.AttrBold))
	}

	if len(ui.events) == 0 {
		ui.eventList.SetCell(1, 0, tview.NewTableCell("No events found").
			SetTextColor(ui.theme.TableRowMuted))
		return
	}

	// Sort events by timestamp (newest first)
	sort.Slice(ui.events, func(i, j int) bool {
		return ui.events[i].Timestamp.After(ui.events[j].Timestamp)
	})

	// Add event rows
	for row, event := range ui.events {
		rowIndex := row + 1

		// Format timestamp
		timeStr := event.Timestamp.Format("15:04:05")

		// Format message
		message := event.Message
		if len(message) > 35 { // Slightly shorter to make room for selection indicator
			message = message[:32] + "..."
		}

		// Check if event is selected
		isSelected := ui.selectedEventIDs[event.ID]
		var selectionIndicator string
		var rowColor tcell.Color
		
		if isSelected {
			selectionIndicator = "✓ "
			rowColor = ui.theme.SelectionFg // Highlight selected rows
		} else {
			selectionIndicator = "  "
			rowColor = ui.theme.TableRow
		}

		// Cells with theme-aware colors and selection indicators
		cells := []struct {
			text  string
			color tcell.Color
		}{
			{selectionIndicator + timeStr, rowColor},
			{event.EventType, hex("#69a1ff")}, // subtle blue accent
			{strings.ToUpper(event.Severity), ui.getSeverityTcellColor(event.Severity)},
			{event.Host, hex("#22c55e")}, // green-ish for host
			{event.SrcIP, ui.theme.TableRowMuted},
			{message, rowColor},
		}

		for col, cell := range cells {
			tableCell := tview.NewTableCell(cell.text).SetTextColor(cell.color)

			// Row background: selection overrides zebra striping
			if isSelected {
				tableCell.SetBackgroundColor(ui.theme.SelectionBg)
			} else {
				zebra := ui.theme.TableZebra1
				if row%2 == 1 {
					zebra = ui.theme.TableZebra2
				}
				tableCell.SetBackgroundColor(zebra)
			}

			ui.eventList.SetCell(rowIndex, col, tableCell)
		}
	}
}

// showEventDetails displays details for the selected event
func (ui *UI) showEventDetails() {
	if ui.selectedEventID == "" {
		ui.eventDetail.SetText("No event selected")
		return
	}

	// Find the selected event
	var event *store.Event
	for i := range ui.events {
		if ui.events[i].ID == ui.selectedEventID {
			event = &ui.events[i]
			break
		}
	}

	if event == nil {
		ui.eventDetail.SetText("Selected event not found")
		return
	}
	var details strings.Builder

	// Use theme text tags for labels/values
	lbl := ui.theme.TagWarning
	val := ui.theme.TagTextPrimary

	details.WriteString(fmt.Sprintf("[%s]Event ID:[-] [%s]%s[-]\n", lbl, val, event.ID))
	details.WriteString(fmt.Sprintf("[%s]Timestamp:[-] [%s]%s[-]\n", lbl, val, event.Timestamp.Format("2006-01-02 15:04:05")))
	details.WriteString(fmt.Sprintf("[%s]Type:[-] [%s]%s[-]\n", lbl, val, event.EventType))
	details.WriteString(fmt.Sprintf("[%s]Severity:[-] [%s]%s[-]\n",
		lbl, ui.getSeverityColor(event.Severity), strings.ToUpper(event.Severity)))
	details.WriteString(fmt.Sprintf("[%s]Host:[-] [%s]%s[-]\n", lbl, val, event.Host))

	if event.SrcIP != "" {
		details.WriteString(fmt.Sprintf("[%s]Source IP:[-] [%s]%s[-]", lbl, val, event.SrcIP))
		if event.SrcPort > 0 {
			details.WriteString(fmt.Sprintf("[%s]:%d[-]", val, event.SrcPort))
		}
		details.WriteString("\n")
	}

	if event.DstIP != "" {
		details.WriteString(fmt.Sprintf("[%s]Destination IP:[-] [%s]%s[-]", lbl, val, event.DstIP))
		if event.DstPort > 0 {
			details.WriteString(fmt.Sprintf("[%s]:%d[-]", val, event.DstPort))
		}
		details.WriteString("\n")
	}

	if event.ProcessName != "" {
		details.WriteString(fmt.Sprintf("[%s]Process:[-] [%s]%s[-]\n", lbl, val, event.ProcessName))
	}

	if event.FileName != "" {
		details.WriteString(fmt.Sprintf("[%s]File:[-] [%s]%s[-]\n", lbl, val, event.FileName))
	}

	if event.FileHash != "" {
		details.WriteString(fmt.Sprintf("[%s]File Hash:[-] [%s]%s[-]\n", lbl, val, event.FileHash))
	}

	if event.UserName != "" {
		details.WriteString(fmt.Sprintf("[%s]User:[-] [%s]%s[-]\n", lbl, val, event.UserName))
	}

	details.WriteString(fmt.Sprintf("\n[%s]Message:[-]\n[%s]%s[-]\n", lbl, val, event.Message))

	// Show enrichments from DB (if any), newest first
	if enrichments, err := ui.store.GetEnrichmentsByEvent(ui.ctx, event.ID); err == nil && len(enrichments) > 0 {
		details.WriteString(fmt.Sprintf("\n[%s]Enrichments (latest %d):[-]\n", ui.theme.TagAccent, len(enrichments)))
		for _, enr := range enrichments {
			ts := enr.CreatedAt.Format("2006-01-02 15:04:05")
			details.WriteString(fmt.Sprintf("[%s]- %s/%s at %s[-]\n", ui.theme.TagMuted, enr.Source, enr.Type, ts))

			// Render enrichment data with stable ordering and truncation
			keys := make([]string, 0, len(enr.Data))
			for k := range enr.Data {
				keys = append(keys, k)
			}
			sort.Strings(keys)

			const maxKeys = 30
			limit := maxKeys
			if len(keys) < limit {
				limit = len(keys)
			}
			for i := 0; i < limit; i++ {
				k := keys[i]
				v := enr.Data[k]
				if len(v) > 200 {
					v = v[:197] + "..."
				}
				details.WriteString(fmt.Sprintf("  [%s]%s:[-] [%s]%s[-]\n", ui.theme.TagWarning, k, ui.theme.TagTextPrimary, v))
			}
			if len(keys) > limit {
				details.WriteString(fmt.Sprintf("  [%s]... and %d more keys[-]\n", ui.theme.TagMuted, len(keys)-limit))
			}
		}
	} else if err != nil {
		// Log failure but don't interrupt the UI
		if ui.logger != nil {
			ui.logger.Printf("Failed to load enrichments for event %s: %v", event.ID, err)
		}
	}

	// Show raw JSON if available (truncated)
	if event.RawJSON != "" {
		rawJSON := event.RawJSON
		if len(rawJSON) > 500 {
			rawJSON = rawJSON[:497] + "..."
		}
		details.WriteString(fmt.Sprintf("\n[%s]Raw Data:[-]\n[%s]%s[-]", ui.theme.TagMuted, ui.theme.TagMuted, rawJSON))
	}

	ui.eventDetail.SetText(details.String())
}

// showCaseSummary displays an AI-generated case summary
func (ui *UI) showCaseSummary() {
	if ui.selectedCaseID == "" {
		return
	}

	// Find the selected case
	var selectedCase *store.Case
	for i := range ui.cases {
		if ui.cases[i].ID == ui.selectedCaseID {
			selectedCase = &ui.cases[i]
			break
		}
	}

	if selectedCase == nil {
		ui.setStatus("[%s]Selected case not found[-:-:-]", ui.theme.TagError)
		return
	}

	ui.setStatus("[%s]Generating case summary...[-:-:-]", ui.theme.TagWarning)

	go func() {
		summary, err := ui.llm.SummarizeCase(ui.ctx, *selectedCase, ui.events)
		if err != nil {
			ui.app.QueueUpdate(func() {
				ui.setStatusDirect("[%s]Error generating summary: %v[-:-:-]", ui.theme.TagError, err)
			})
			return
		}

		ui.app.QueueUpdate(func() {
			ui.showModal("Case Summary", summary)
			ui.setStatusDirect("[%s]Case summary generated[-:-:-]", ui.theme.TagSuccess)
		})
	}()
}

// showHelp displays a professionally formatted Help using a table layout
func (ui *UI) showHelp() {
	ui.helpActive = true

	// Header
	header := tview.NewTextView().
		SetDynamicColors(true).
		SetTextAlign(tview.AlignCenter)
	header.SetBackgroundColor(ui.theme.Surface)
	header.SetTextColor(ui.theme.TextPrimary)
	header.SetText(fmt.Sprintf(" [%s]Console-IR Help[-] ", ui.theme.TagAccent))

	// Footer
	footer := tview.NewTextView().
		SetDynamicColors(true).
		SetTextAlign(tview.AlignCenter)
	footer.SetBackgroundColor(ui.theme.Surface)
	footer.SetTextColor(ui.theme.TextPrimary)
	footer.SetText(fmt.Sprintf("[%s]Close: q, Enter, Esc, or Space[-]", ui.theme.TagMuted))

	// Content table
	table := tview.NewTable().
		SetBorders(false).
		SetFixed(0, 0)
	table.SetBorder(false).
		SetTitle(" Help ").
		SetTitleAlign(tview.AlignLeft)
	table.SetBorderColor(ui.theme.FocusBorder)
	table.SetBackgroundColor(ui.theme.Surface)
	// Allow scrolling without selection highlight
	table.SetSelectable(true, false)
	table.SetSelectedStyle(tcell.StyleDefault.
		Background(ui.theme.Surface).
		Foreground(ui.theme.TextPrimary))

	row := 0
	keyColWidth := 14
	bullet := "•"
	addSection := func(title string) {
		// Two-cell header row (no spanning) to keep columns consistent.
		// Fill the left key column with spaces so the header background is visible,
		// matching the visual style of other subheadings.
		left := tview.NewTableCell(strings.Repeat(" ", keyColWidth)).
			SetBackgroundColor(ui.theme.TableHeaderBg).
			SetAlign(tview.AlignLeft).
			SetMaxWidth(keyColWidth)
		right := tview.NewTableCell(" " + title + " ").
			SetTextColor(ui.theme.TableHeader).
			SetBackgroundColor(ui.theme.TableHeaderBg).
			SetAttributes(tcell.AttrBold)
		table.SetCell(row, 0, left)
		table.SetCell(row, 1, right)
		row++
	}
	addKV := func(k, v string) {
		// Fixed key column width using left padding; values expand and align left.
		keyTxt := fmt.Sprintf("%-*s", keyColWidth, k)
		keyCell := tview.NewTableCell(keyTxt).
			SetTextColor(ui.theme.Accent).
			SetAttributes(tcell.AttrBold).
			SetAlign(tview.AlignLeft).
			SetMaxWidth(keyColWidth)
		valCell := tview.NewTableCell(bullet + " " + v).
			SetTextColor(ui.theme.TextPrimary).
			SetAlign(tview.AlignLeft).
			SetExpansion(1)
		table.SetCell(row, 0, keyCell)
		table.SetCell(row, 1, valCell)
		row++
	}
	addNote := func(text string) {
		// Note occupies the description column; keep key column empty.
		table.SetCell(row, 0, tview.NewTableCell("").SetBackgroundColor(ui.theme.Surface))
		n := tview.NewTableCell(text).SetTextColor(ui.theme.TextMuted)
		table.SetCell(row, 1, n)
		row++
	}
	// Back-compat helper (unused after replacement), keep if needed:
	addGap := func() { row++ }

	// Sections

	addSection("GLOBAL NAVIGATION")
	addKV("Tab", "Cycle through panels")
	addKV("Enter", "Select item (All/Case/Event)")
	addKV("Arrow Keys", "Navigate lists/tables")
	addKV("l", "Focus right pane")
	addKV("j / k", "Move selection down/up")
	addKV("g / G", "Jump to first/last")
	addKV("J / K", "Page down/up (table)")
	addKV("N", "Next page (events)")
	addKV("P", "Prev page (events)")
	addKV("1-99", "Quick case selection (multi-digit)")
	addKV("Esc", "Clear status line")
	addGap()

	addSection("EVENT SELECTION")
	addKV("Space", "Toggle event selection")
	addKV("Ctrl+A", "Select all events")
	addKV("Ctrl+D", "Deselect all events")
	addKV("d", "Delete selected events")
	addGap()

	addSection("CASE MANAGEMENT")
	addKV("c", "Create new case from selected events")
	addKV("a", "Add selected events to existing case")
	addKV("d", "Delete selected case")
	addNote("Note: Deleting a case unassigns its events to ALL EVENTS.")
	addGap()

	addSection("FILTERS")
	addKV("f", "Open combined filter (time | severity | type)")
	addKV("F", "Clear filters (time, severity, type) for current context")
	addNote("Severity: critical/high/medium/low/informational; Types: network/process/file/authentication/unknown. Time supports RFC3339 and tokens: now, -15m, 1h, today.")
	addGap()

	addSection("THEMING")
	addKV("t", "Cycle themes (dark → light → neon → cb-safe → high-contrast)")
	addKV("T", "Toggle high-contrast")
	addKV("C", "Toggle colorblind-safe")
	addGap()

	addSection("QUICK ACTIONS")
	addKV("A", "Jump to ALL EVENTS from anywhere")
	addKV("r", "Refresh data")
	addKV("h / H", "Show this help")
	addKV("q, Q", "Quit application")

	// Compose a centered "card" layout for a professional modal look
	panel := tview.NewFlex().
		SetDirection(tview.FlexRow).
		AddItem(header, 1, 0, false).
		AddItem(table, 0, 1, true).
		AddItem(footer, 1, 0, false)

	card := tview.NewFrame(panel)
	card.SetBorder(true).
		SetTitle(" Help ").
		SetTitleAlign(tview.AlignLeft)
	card.SetBorderColor(ui.theme.FocusBorder)
	card.SetBackgroundColor(ui.theme.Surface)

	// Center horizontally with a fixed width for the card
	leftPad := tview.NewBox()
	leftPad.SetBackgroundColor(ui.theme.Bg)
	rightPad := tview.NewBox()
	rightPad.SetBackgroundColor(ui.theme.Bg)

	centered := tview.NewFlex().
		SetDirection(tview.FlexColumn).
		AddItem(leftPad, 0, 1, false).
		AddItem(card, 96, 0, true).
		AddItem(rightPad, 0, 1, false)

	// Close on common keys; allow navigation keys to scroll
	centered.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
		switch ev.Key() {
		case tcell.KeyEsc, tcell.KeyEnter:
			ui.restoreMainLayout()
			return nil
		case tcell.KeyRune:
			switch ev.Rune() {
			case 'q', 'Q', ' ':
				ui.restoreMainLayout()
				return nil
			}
		}
		return ev
	})

	ui.lastFocus = ui.app.GetFocus()
	ui.app.SetRoot(centered, true)
	ui.app.SetFocus(table)
}

// showModal displays a modal dialog
func (ui *UI) showModal(title, text string) {
	modal := tview.NewModal()
	modal.SetText(text)
	modal.SetTitle(fmt.Sprintf(" %s ", title))
	modal.AddButtons([]string{"Close"})
	
	// Set modal colors to match theme
	modal.SetBackgroundColor(ui.theme.Surface)
	modal.SetTextColor(ui.theme.TextPrimary)
	modal.SetBorderColor(ui.theme.FocusBorder)
	modal.SetButtonBackgroundColor(ui.theme.SelectionBg)
	modal.SetButtonTextColor(ui.theme.SelectionFg)
	
	// Handle modal closure with multiple keys
	modal.SetDoneFunc(func(buttonIndex int, buttonLabel string) {
		ui.restoreMainLayout()
	})
	
	// Add input capture to handle Esc and other keys - this must come BEFORE SetRoot
	modal.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if ui.logger != nil {
			ui.logger.Printf("Modal key event: Key=%v Rune=%q", event.Key(), event.Rune())
		}
		switch event.Key() {
		case tcell.KeyEsc:
			if ui.logger != nil {
				ui.logger.Println("Esc pressed in modal - closing")
			}
			ui.restoreMainLayout()
			return nil
		case tcell.KeyEnter:
			if ui.logger != nil {
				ui.logger.Println("Enter pressed in modal - closing")
			}
			ui.restoreMainLayout()
			return nil
		case tcell.KeyRune:
			if ui.logger != nil {
				ui.logger.Printf("Rune '%c' pressed in modal - closing", event.Rune())
			}
			// Any key closes the modal (as mentioned in help text)
			ui.restoreMainLayout()
			return nil
		}
		return event
	})

	ui.lastFocus = ui.app.GetFocus()
	ui.app.SetRoot(modal, true)
	// Set focus to the modal to ensure it receives key events
	ui.app.SetFocus(modal)
}

// restoreMainLayout restores the main TUI layout after closing a modal/help view
func (ui *UI) restoreMainLayout() {
	ui.helpActive = false

	// Clear reference to Case Management when returning to main UI
	ui.activeCM = nil

	root := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(ui.layout, 0, 1, true).
		AddItem(ui.statusBar, 1, 0, false)
	ui.app.SetRoot(root, true)

	// Restore the global input handler that powers main UI keys (q, f, etc.)
	if ui.globalInputCapture != nil {
		ui.app.SetInputCapture(ui.globalInputCapture)
	}

	// Restore focus to the previously focused component if available
	target := ui.lastFocus
	if target == nil {
		if ui.allList != nil {
			target = ui.allList
		} else {
			target = ui.sidebar
		}
	}
	ui.app.SetFocus(target)
	ui.highlightFocus(target)
	ui.setStatusDirect("[%s]Help closed[-:-:-]", ui.theme.TagSuccess)
}

// cycleFocus cycles focus between UI components
func (ui *UI) cycleFocus() {
	current := ui.app.GetFocus()

	switch current {
	case ui.sidebar:
		ui.app.SetFocus(ui.eventList)
		ui.highlightFocus(ui.eventList)
		ui.setStatusDirect("[%s]Focus: Events List[-:-:-] - Use arrows to navigate, Enter to select", ui.theme.TagAccent)
	case ui.eventList:
		ui.app.SetFocus(ui.eventDetail)
		ui.highlightFocus(ui.eventDetail)
		ui.setStatusDirect("[%s]Focus: Event Details[-:-:-] - Use arrows to scroll", ui.theme.TagAccent)
	case ui.eventDetail:
		ui.app.SetFocus(ui.sidebar)
		ui.highlightFocus(ui.sidebar)
		ui.setStatusDirect("[%s]Focus: Cases[-:-:-] - Use arrows to navigate, Enter to select", ui.theme.TagAccent)
	default:
		ui.app.SetFocus(ui.sidebar)
		ui.highlightFocus(ui.sidebar)
		ui.setStatusDirect("[%s]Focus: Cases[-:-:-] - Use arrows to navigate, Enter to select", ui.theme.TagAccent)
	}
}

func (ui *UI) focusLeft() {
	switch ui.app.GetFocus() {
	case ui.eventDetail:
		ui.app.SetFocus(ui.eventList)
		ui.highlightFocus(ui.eventList)
		ui.setStatusDirect("[%s]Focus: Events List[-:-:-]", ui.theme.TagAccent)
	case ui.eventList:
		ui.app.SetFocus(ui.sidebar)
		ui.highlightFocus(ui.sidebar)
		ui.setStatusDirect("[%s]Focus: Cases[-:-:-]", ui.theme.TagAccent)
	default:
		ui.app.SetFocus(ui.sidebar)
		ui.highlightFocus(ui.sidebar)
		ui.setStatusDirect("[%s]Focus: Cases[-:-:-]", ui.theme.TagAccent)
	}
}

func (ui *UI) focusRight() {
	switch ui.app.GetFocus() {
	case ui.sidebar:
		ui.app.SetFocus(ui.eventList)
		ui.highlightFocus(ui.eventList)
		ui.setStatusDirect("[%s]Focus: Events List[-:-:-]", ui.theme.TagAccent)
	case ui.eventList:
		ui.app.SetFocus(ui.eventDetail)
		ui.highlightFocus(ui.eventDetail)
		ui.setStatusDirect("[%s]Focus: Event Details[-:-:-]", ui.theme.TagAccent)
	default:
		ui.app.SetFocus(ui.eventDetail)
		ui.highlightFocus(ui.eventDetail)
		ui.setStatusDirect("[%s]Focus: Event Details[-:-:-]", ui.theme.TagAccent)
	}
}

func (ui *UI) moveSelection(delta int) {
	switch ui.app.GetFocus() {
	case ui.sidebar:
		cur := ui.sidebar.GetCurrentItem()
		// If at the first case and moving up, jump back to ALL EVENTS list
		if cur == 0 && delta < 0 {
			if ui.allList != nil {
				ui.app.SetFocus(ui.allList)
				ui.allList.SetCurrentItem(0)
			}
			return
		}
		idx := cur + delta
		if idx < 0 {
			idx = 0
		}
		if idx >= ui.sidebar.GetItemCount() {
			idx = ui.sidebar.GetItemCount() - 1
		}
		if idx >= 0 {
			ui.sidebar.SetCurrentItem(idx)
		}
	case ui.eventList:
		row, col := ui.eventList.GetSelection()
		row += delta
		if row < 1 {
			row = 1
		}
		max := ui.eventList.GetRowCount() - 1
		if max < 1 {
			max = 1
		}
		if row > max {
			row = max
		}
		ui.eventList.Select(row, col)
	}
}

func (ui *UI) moveToBoundary(top bool) {
	switch ui.app.GetFocus() {
	case ui.sidebar:
		if ui.sidebar.GetItemCount() == 0 {
			return
		}
		if top {
			ui.sidebar.SetCurrentItem(0)
		} else {
			ui.sidebar.SetCurrentItem(ui.sidebar.GetItemCount() - 1)
		}
	case ui.eventList:
		_, col := ui.eventList.GetSelection()
		if top {
			ui.eventList.Select(1, col)
		} else {
			max := ui.eventList.GetRowCount() - 1
			if max < 1 {
				max = 1
			}
			ui.eventList.Select(max, col)
		}
	}
}

func (ui *UI) pageMove(direction int) {
	// Simple page size: 10 rows (keeps scope minimal and non-invasive)
	page := 10 * direction
	switch ui.app.GetFocus() {
	case ui.eventList:
		row, col := ui.eventList.GetSelection()
		row += page
		if row < 1 {
			row = 1
		}
		max := ui.eventList.GetRowCount() - 1
		if max < 1 {
			max = 1
		}
		if row > max {
			row = max
		}
		ui.eventList.Select(row, col)
	}
}

func (ui *UI) highlightFocus(focused tview.Primitive) {
	// Reset borders
	ui.sidebar.SetBorderColor(ui.theme.Border)
	ui.eventList.SetBorderColor(ui.theme.Border)
	ui.eventDetail.SetBorderColor(ui.theme.Border)

	// Apply focus ring
	switch focused {
	case ui.sidebar:
		ui.sidebar.SetBorderColor(ui.theme.FocusBorder)
	case ui.eventList:
		ui.eventList.SetBorderColor(ui.theme.FocusBorder)
	case ui.eventDetail:
		ui.eventDetail.SetBorderColor(ui.theme.FocusBorder)
	}
}
// startRedrawHeartbeat periodically requests a redraw to mitigate terminals that miss repaints
func (ui *UI) startRedrawHeartbeat() {
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ui.ctx.Done():
				return
			case <-ticker.C:
				if ui.running {
					// Non-blocking repaint request to avoid re-entrancy
					ui.app.QueueUpdate(func() {})
				}
			}
		}
	}()
}
// isDialogActive returns true when a dialog or the help view is focused to bypass global shortcuts.
func (ui *UI) isDialogActive() bool {
	if ui.helpActive {
		return true
	}
	if ui.app == nil {
		return false
	}
	focused := ui.app.GetFocus()
	if focused == nil {
		return false
	}
	switch focused.(type) {
	case *tview.Form,
		*tview.Modal,
		*tview.InputField,
		*tview.TextArea,
		*tview.DropDown,
		*tview.Button:
		return true
	default:
		return false
	}
}

// setStatus updates the status bar
func (ui *UI) setStatus(format string, args ...interface{}) {
	message := fmt.Sprintf(format, args...)
	timestamp := time.Now().Format("15:04:05")

	// Build main message with badges and dynamic shortcut hints
	main := ui.buildStatusMain(message)
	hints := ui.buildShortcutHints()

	statusText := fmt.Sprintf("[%s]%s[-] [%s]|[-] %s [%s]|[-] %s",
		ui.theme.TagMuted, timestamp,
		ui.theme.TagTextPrimary,
		main,
		ui.theme.TagMuted,
		hints)

	if ui.running {
		// Use non-blocking QueueUpdate to avoid potential re-entrancy stalls during input handling
		ui.app.QueueUpdate(func() {
			ui.statusBar.SetText(statusText)
		})
	} else {
		// When the app is not running (e.g., unit tests), set directly.
		ui.statusBar.SetText(statusText)
	}
}

// getSeverityColor returns the color tag for a severity level (for text markup)
func (ui *UI) getSeverityColor(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return ui.theme.TagSeverityCritical
	case "high":
		return ui.theme.TagSeverityHigh
	case "medium":
		return ui.theme.TagSeverityMedium
	case "low":
		return ui.theme.TagSeverityLow
	case "informational":
		return ui.theme.TagSeverityInfo
	default:
		return ui.theme.TagTextPrimary
	}
}

// setStatusDirect updates the status bar immediately without QueueUpdate/QueueUpdateDraw.
// Use this only from the UI goroutine (e.g., within input handlers, selection callbacks, or QueueUpdate closures).
func (ui *UI) setStatusDirect(format string, args ...interface{}) {
	message := fmt.Sprintf(format, args...)
	timestamp := time.Now().Format("15:04:05")

	// Build main message with badges and dynamic shortcut hints
	main := ui.buildStatusMain(message)
	hints := ui.buildShortcutHints()

	statusText := fmt.Sprintf("[%s]%s[-] [%s]|[-] %s [%s]|[-] %s",
		ui.theme.TagMuted, timestamp,
		ui.theme.TagTextPrimary,
		main,
		ui.theme.TagMuted,
		hints)

	ui.statusBar.SetText(statusText)
}

// getSeverityTcellColor returns the tcell color for a severity level (for widgets)
func (ui *UI) getSeverityTcellColor(severity string) tcell.Color {
	switch strings.ToLower(severity) {
	case "critical":
		return ui.theme.SeverityCritical
	case "high":
		return ui.theme.SeverityHigh
	case "medium":
		return ui.theme.SeverityMedium
	case "low":
		return ui.theme.SeverityLow
	case "informational":
		return ui.theme.SeverityInfo
	default:
		return ui.theme.TableRow
	}
}

// activeFilterTag returns a compact indicator of the active time filter for the status bar.
func (ui *UI) activeFilterTag() string {
	// Prefer per-context filters; fall back to legacy globals if unset for context.
	id := ui.getContextID()
	s := ui.getOrInitState(id)
	start := s.filterStart
	end := s.filterEnd
	if start.IsZero() && end.IsZero() {
		start = ui.filterStart
		end = ui.filterEnd
		if start.IsZero() && end.IsZero() {
			return ""
		}
	}
	if !start.IsZero() && !end.IsZero() {
		return fmt.Sprintf("%s..%s", start.Format("15:04"), end.Format("15:04"))
	}
	if !start.IsZero() {
		return fmt.Sprintf("since %s", start.Format("15:04"))
	}
	return fmt.Sprintf("until %s", end.Format("15:04"))
}

// applyTheme pushes theme colors to widgets
func (ui *UI) applyTheme() {
	if ui.logger != nil {
		ui.logger.Printf("Applying theme: %s", ui.themeName)
	}
	// Cases sidebar
	ui.sidebar.SetMainTextColor(ui.theme.TextPrimary)
	ui.sidebar.SetSecondaryTextColor(ui.theme.TextMuted)
	ui.sidebar.SetSelectedTextColor(ui.theme.SelectionFg)
	ui.sidebar.SetSelectedBackgroundColor(ui.theme.SelectionBg)
	ui.sidebar.SetBorderColor(ui.theme.Border)
	ui.sidebar.SetBackgroundColor(ui.theme.Surface)

	// ALL EVENTS list (dedicated)
	if ui.allList != nil {
		ui.allList.SetMainTextColor(ui.theme.TextPrimary)
		ui.allList.SetSecondaryTextColor(ui.theme.TextMuted)
		ui.allList.SetSelectedTextColor(ui.theme.SelectionFg)
		ui.allList.SetSelectedBackgroundColor(ui.theme.SelectionBg)
		ui.allList.SetBorderColor(ui.theme.Border)
		ui.allList.SetBackgroundColor(ui.theme.Surface)
		// Ensure the single item markup reflects current accent color
		if ui.allList.GetItemCount() > 0 {
			ui.allList.SetItemText(0, fmt.Sprintf("[%s]ALL EVENTS[-]", ui.theme.TagAccent), "All ingested events (watch folder)")
		}
	}

	// App title header
	if ui.appTitle != nil {
		ui.appTitle.SetBackgroundColor(ui.theme.Surface)
		ui.appTitle.SetText(fmt.Sprintf(" [%s]Console-IR[-]", ui.theme.TagAccent))
		ui.appTitle.SetTextColor(ui.theme.TextPrimary)
	}

	// OVERVIEW info block
	if ui.allCasesInfo != nil {
		ui.allCasesInfo.SetBackgroundColor(ui.theme.Surface)
		ui.allCasesInfo.SetTextColor(ui.theme.TextPrimary)
		ui.allCasesInfo.SetBorderColor(ui.theme.Border)

		// Recompute counts from current state to refresh tags with the new theme (no DB calls here)
		totalCases := len(ui.cases)
		openN, invN, closeN := 0, 0, 0
		for _, c := range ui.cases {
			switch strings.ToLower(strings.TrimSpace(c.Status)) {
			case "open":
				openN++
			case "investigating", "investigation":
				invN++
			case "closed", "close":
				closeN++
			}
		}
		eventsTotal := 0
		if s := ui.getOrInitState(contextAll); s != nil {
			eventsTotal = s.totalCount
		}
		ui.updateOverview(eventsTotal, totalCases, openN, invN, closeN)
	}

	// Events table and details pane
	ui.eventList.SetSelectedStyle(tcell.StyleDefault.Background(ui.theme.SelectionBg).Foreground(ui.theme.SelectionFg))
	ui.eventList.SetBorderColor(ui.theme.Border)
	ui.eventList.SetBackgroundColor(ui.theme.Surface)

	ui.eventDetail.SetTextColor(ui.theme.TextPrimary)
	ui.eventDetail.SetBorderColor(ui.theme.Border)
	ui.eventDetail.SetBackgroundColor(ui.theme.Surface)

	// Status bar
	ui.statusBar.SetTextColor(ui.theme.TextPrimary)
	ui.statusBar.SetBackgroundColor(ui.theme.Surface)

	// Re-render table and focus ring
	ui.updateEventsList()
	ui.highlightFocus(ui.app.GetFocus())
}

// cycleTheme moves to the next theme in sequence
func (ui *UI) cycleTheme() {
	if ui.logger != nil {
		ui.logger.Printf("Cycle theme requested (current=%s)", ui.themeName)
	}
	next := map[string]string{
		"dark":          "light",
		"light":         "neon",
		"neon":          "cb-safe",
		"cb-safe":       "high-contrast",
		"high-contrast": "dark",
	}
	ui.setTheme(next[ui.themeName])
}

// setTheme applies a named theme
func (ui *UI) setTheme(name string) {
	// Prevent re-entrant theme application that can stall UI updates
	if !atomic.CompareAndSwapInt32(&ui.themeApplying, 0, 1) {
		if ui.logger != nil {
			ui.logger.Printf("setTheme(%s) ignored: theme is already applying", name)
		}
		return
	}
	defer atomic.StoreInt32(&ui.themeApplying, 0)

	if ui.logger != nil {
		ui.logger.Printf("Setting theme: %s (previous=%s)", name, ui.themeName)
	}
	switch name {
	case "light":
		ui.themeName = "light"
		ui.theme = themeLight()
	case "neon":
		ui.themeName = "neon"
		ui.theme = themeNeon()
	case "high-contrast":
		ui.themeName = "high-contrast"
		ui.theme = themeHighContrast()
	case "cb-safe":
		ui.themeName = "cb-safe"
		ui.theme = themeColorblindSafe()
	default:
		ui.themeName = "dark"
		ui.theme = themeDark()
	}
	ui.applyTheme()

	// Propagate live theme to active Case Management screen, if any.
	if ui.activeCM != nil {
		ui.activeCM.OnThemeChanged(ui.theme)
	}

	// Direct status update; we're on the UI goroutine
	ui.setStatusDirect("[%s]Theme: %s[-:-:-]", ui.theme.TagAccent, strings.Title(strings.ReplaceAll(ui.themeName, "-", " ")))
	if ui.logger != nil {
		ui.logger.Printf("Theme applied: %s", ui.themeName)
	}
}

// GetStats returns UI statistics
func (ui *UI) GetStats() map[string]interface{} {
	return map[string]interface{}{
		"cases_loaded":      len(ui.cases),
		"events_loaded":     len(ui.events),
		"selected_case":     ui.selectedCaseID != "",
		"selected_event":    ui.selectedEventID != "",
		"selected_case_id":  ui.selectedCaseID,
		"selected_event_id": ui.selectedEventID,
		"selected_events":   len(ui.selectedEventIDs),
		"theme":             ui.themeName,
	}
}

// handleShortcutKey handles a number key press for case selection.
// It supports multi-digit input with disambiguation:
// - If typing this digit could still form a larger valid number (e.g., "1" when there are >=10 cases),
//   we start a short timer and wait for the next digit before selecting.
// - If no valid longer number can be formed (e.g., "7" when there are only 9 cases), we select immediately.
func (ui *UI) handleShortcutKey(digit rune) {
// Cancel any existing timer
if ui.shortcutTimer != nil {
	ui.shortcutTimer.Stop()
	ui.shortcutTimer = nil
}

// Add digit to buffer
ui.shortcutBuffer += string(digit)

// Parse current buffer
caseNum, err := strconv.Atoi(ui.shortcutBuffer)
if err != nil || caseNum < 1 {
	// Invalid prefix; reset
	ui.shortcutBuffer = ""
	return
}

max := len(ui.cases)
if max == 0 {
	ui.shortcutBuffer = ""
	return
}

// If current number is greater than max, no further digits can make it valid (numbers only grow).
if caseNum > max {
	ui.shortcutBuffer = ""
	return
}

// At this point, caseNum is within [1..max].
// Determine if a longer valid number could be formed by adding another digit.
// If caseNum*10 <= max, there exists at least one valid extension (e.g., 1 -> 10..19).
canExtendValid := (caseNum*10 <= max) && (len(ui.shortcutBuffer) < 3)

if canExtendValid {
	// Wait briefly for an additional digit; on timeout, commit current caseNum.
	ui.shortcutTimer = time.AfterFunc(ui.shortcutTimeout, func() {
		ui.app.QueueUpdate(func() {
			if num, err := strconv.Atoi(ui.shortcutBuffer); err == nil && num >= 1 && num <= len(ui.cases) {
				ui.selectCaseByNumber(num)
			}
			ui.shortcutBuffer = ""
			ui.shortcutTimer = nil
		})
	})
	return
}

// No valid extension possible or buffer length cap reached; select immediately.
ui.selectCaseByNumber(caseNum)
ui.shortcutBuffer = ""
}

// selectCaseByNumber selects a case by its 1-based number
func (ui *UI) selectCaseByNumber(caseNum int) {
	if caseNum < 1 || caseNum > len(ui.cases) {
		return
	}

	// Convert to 0-based index
	caseIndex := caseNum - 1

	// Select the case in the sidebar
	ui.sidebar.SetCurrentItem(caseIndex)

	// Trigger the selection
	ui.onSidebarSelect(caseIndex)
}

// toggleEventSelection toggles selection state for the currently focused event
func (ui *UI) toggleEventSelection() {
	row, _ := ui.eventList.GetSelection()
	if ui.logger != nil {
		ui.logger.Printf("toggleEventSelection: row=%d, events=%d", row, len(ui.events))
	}
	if row > 0 && row-1 < len(ui.events) {
		eventID := ui.events[row-1].ID
		if ui.logger != nil {
			ui.logger.Printf("toggleEventSelection: eventID=%s, currently selected=%v", eventID, ui.selectedEventIDs[eventID])
		}
		if ui.selectedEventIDs[eventID] {
			delete(ui.selectedEventIDs, eventID)
			ui.setStatusDirect("[%s]Event deselected (%d selected)[-:-:-]", ui.theme.TagAccent, len(ui.selectedEventIDs))
		} else {
			ui.selectedEventIDs[eventID] = true
			ui.setStatusDirect("[%s]Event selected (%d selected)[-:-:-]", ui.theme.TagSuccess, len(ui.selectedEventIDs))
		}
		ui.updateEventsList() // Refresh to show selection indicators
		if ui.logger != nil {
			ui.logger.Printf("toggleEventSelection: total selected=%d", len(ui.selectedEventIDs))
		}
	} else {
		if ui.logger != nil {
			ui.logger.Printf("toggleEventSelection: invalid row or no events")
		}
		ui.setStatusDirect("[%s]No event to select (row=%d, events=%d)[-:-:-]", ui.theme.TagWarning, row, len(ui.events))
	}
}

// selectAllEvents selects all visible events
func (ui *UI) selectAllEvents() {
	if len(ui.events) == 0 {
		ui.setStatusDirect("[%s]No events to select[-:-:-]", ui.theme.TagWarning)
		return
	}
	
	for _, event := range ui.events {
		ui.selectedEventIDs[event.ID] = true
	}
	ui.updateEventsList()
	ui.setStatusDirect("[%s]All %d events selected[-:-:-]", ui.theme.TagSuccess, len(ui.events))
}

// deselectAllEvents clears all event selections
func (ui *UI) deselectAllEvents() {
	if len(ui.selectedEventIDs) == 0 {
		ui.setStatusDirect("[%s]No events selected[-:-:-]", ui.theme.TagWarning)
		return
	}
	
	count := len(ui.selectedEventIDs)
	ui.selectedEventIDs = make(map[string]bool)
	ui.updateEventsList()
	ui.setStatusDirect("[%s]Deselected %d events[-:-:-]", ui.theme.TagAccent, count)
}

// showCreateCaseModal displays the case creation form
func (ui *UI) showCreateCaseModal() {
	form := tview.NewForm()
	form.SetTitle(" Create New Case ")
	form.SetBorder(true)
	
	// Apply theme colors
	form.SetBackgroundColor(ui.theme.Surface)
	form.SetFieldBackgroundColor(ui.theme.Surface)
	form.SetFieldTextColor(ui.theme.TextPrimary)
	form.SetLabelColor(ui.theme.TextPrimary)
	form.SetButtonBackgroundColor(ui.theme.SelectionBg)
	form.SetButtonTextColor(ui.theme.SelectionFg)
	form.SetBorderColor(ui.theme.FocusBorder)
	
	// Form fields
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
	
	// Install input capture on Description TextArea to enable Tab-based navigation.
	// Enter continues to insert newlines (multi-line), Tab moves next, Shift+Tab moves previous.
	{
		// Find the "Description" form item by label.
		descIdx := -1
		for i := 0; i < form.GetFormItemCount(); i++ {
			if fi := form.GetFormItem(i); fi != nil {
				if strings.TrimSpace(fi.GetLabel()) == "Description" {
					descIdx = i
					if ta, ok := fi.(*tview.TextArea); ok {
						ta.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
							switch ev.Key() {
							case tcell.KeyTab:
								// Move focus to next form item (e.g., Severity)
								next := descIdx + 1
								if next < form.GetFormItemCount() {
									ui.app.SetFocus(form.GetFormItem(next))
								}
								return nil
							case tcell.KeyBacktab:
								// Move focus to previous form item (Title)
								prev := descIdx - 1
								if prev >= 0 {
									ui.app.SetFocus(form.GetFormItem(prev))
								}
								return nil
							}
							// All other keys pass through. In particular, Enter inserts newline.
							return ev
						})
					}
					break
				}
			}
		}
	}
	
	// Buttons
	form.AddButton("Create", func() {
		if title == "" {
			ui.setStatusDirect("[%s]Title is required[-:-:-]", ui.theme.TagError)
			return
		}
		ui.createCaseWithEvents(title, description, severity, assignedTo)
		ui.restoreMainLayout()
	})
	form.AddButton("Cancel", func() {
		ui.restoreMainLayout()
	})
	
	// Handle Esc key
	form.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyEsc {
			ui.restoreMainLayout()
			return nil
		}
		return event
	})
	
	ui.lastFocus = ui.app.GetFocus()
	ui.app.SetRoot(form, true)
	ui.app.SetFocus(form)
	// Brief hint for users on Description field navigation
	ui.setStatusDirect("[%s]Description: Enter=newline, Tab/Shift+Tab move fields[-:-:-]", ui.theme.TagAccent)
}

// showAddToExistingCaseModal displays a single, organized dialog to add selected events to an existing case.
func (ui *UI) showAddToExistingCaseModal() {
	// If there are no cases, show a simple modal and exit
	if len(ui.cases) == 0 {
		modal := tview.NewModal().
			SetText("[red]No cases available. Create a new case first.[-]").
			AddButtons([]string{"OK"})
		modal.SetTitle(" Add to Existing Case ")
		modal.SetBackgroundColor(ui.theme.Surface)
		modal.SetTextColor(ui.theme.TextPrimary)
		modal.SetBorderColor(ui.theme.FocusBorder)
		modal.SetButtonBackgroundColor(ui.theme.SelectionBg)
		modal.SetButtonTextColor(ui.theme.SelectionFg)
		modal.SetDoneFunc(func(buttonIndex int, buttonLabel string) {
			ui.restoreMainLayout()
		})
		ui.app.SetRoot(modal, true)
		ui.app.SetFocus(modal)
		return
	}

	// Left: a TextView listing the cases with numbers
	caseList := tview.NewTextView().
		SetDynamicColors(true).
		SetScrollable(true).
		SetWrap(false)
	caseList.SetTitle(" Select Case ")
	caseList.SetBorder(true)
	caseList.SetBorderColor(ui.theme.FocusBorder)
	caseList.SetBackgroundColor(ui.theme.Surface)
	caseList.SetTextColor(ui.theme.TextPrimary)

	var b strings.Builder
	b.WriteString(fmt.Sprintf("[%s]Select a case to add %d events to:[-]\n\n", ui.theme.TagAccent, len(ui.selectedEventIDs)))
	for _, case_ := range ui.cases {
		sev := ui.getSeverityColor(case_.Severity)
		b.WriteString(fmt.Sprintf("[%s]%s[-] [%s]%s[-] (%d events)\n",
			sev, strings.ToUpper(case_.Severity), ui.theme.TagTextPrimary, case_.Title, case_.EventCount))
	}
	caseList.SetText(b.String())

	// Right: a small form to enter the case number and confirm
	form := tview.NewForm()
	form.SetTitle(" Add To Case ")
	form.SetBorder(true)
	form.SetBackgroundColor(ui.theme.Surface)
	form.SetFieldBackgroundColor(ui.theme.Surface)
	form.SetFieldTextColor(ui.theme.TextPrimary)
	form.SetLabelColor(ui.theme.TextPrimary)
	form.SetButtonBackgroundColor(ui.theme.SelectionBg)
	form.SetButtonTextColor(ui.theme.SelectionFg)
	form.SetBorderColor(ui.theme.FocusBorder)

	var caseNumber string
	form.AddInputField("Case Number", "", 10, nil, func(text string) {
		caseNumber = strings.TrimSpace(text)
	})
	form.AddButton("Add Events", func() {
		if ui.logger != nil {
			ui.logger.Printf("AddToExistingCase: requested add for caseNumber=%q (cases=%d, selected=%d)", caseNumber, len(ui.cases), len(ui.selectedEventIDs))
		}
		if caseNumber == "" {
			ui.setStatusDirect("[%s]Enter a case number (1-%d)[-:-:-]", ui.theme.TagWarning, len(ui.cases))
			return
		}
		ui.addEventsToCase(caseNumber)
		ui.restoreMainLayout()
	})
	form.AddButton("Cancel", func() {
		ui.restoreMainLayout()
	})

	// Layout: side-by-side
	layout := tview.NewFlex().
		SetDirection(tview.FlexColumn).
		AddItem(caseList, 0, 2, false).
		AddItem(form, 32, 0, true)

	// Handle Esc to cancel
	layout.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
		if ev.Key() == tcell.KeyEsc {
			ui.restoreMainLayout()
			return nil
		}
		return ev
	})

	// Set root to the composed layout and focus the input field
	ui.lastFocus = ui.app.GetFocus()
	ui.app.SetRoot(layout, true)
	ui.app.SetFocus(form)

	// Brief hint
	ui.setStatusDirect("[%s]Enter the case number (1-%d) and press 'Add Events'. Esc to cancel.[-:-:-]", ui.theme.TagAccent, len(ui.cases))
}

// showCaseSelectionInput shows input field for case number selection
func (ui *UI) showCaseSelectionInput() {
	form := tview.NewForm()
	form.SetTitle(" Select Case ")
	form.SetBorder(true)
	
	// Apply theme colors
	form.SetBackgroundColor(ui.theme.Surface)
	form.SetFieldBackgroundColor(ui.theme.Surface)
	form.SetFieldTextColor(ui.theme.TextPrimary)
	form.SetLabelColor(ui.theme.TextPrimary)
	form.SetButtonBackgroundColor(ui.theme.SelectionBg)
	form.SetButtonTextColor(ui.theme.SelectionFg)
	form.SetBorderColor(ui.theme.FocusBorder)
	
	var caseNumber string
	form.AddInputField("Case Number", "", 10, nil, func(text string) {
		caseNumber = text
	})
	
	form.AddButton("Add Events", func() {
		ui.addEventsToCase(caseNumber)
		ui.restoreMainLayout()
	})
	form.AddButton("Cancel", func() {
		ui.restoreMainLayout()
	})
	
	// Handle Esc key
	form.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyEsc {
			ui.restoreMainLayout()
			return nil
		}
		return event
	})
	
	ui.lastFocus = ui.app.GetFocus()
	ui.app.SetRoot(form, true)
	ui.app.SetFocus(form)
}

// createCaseWithEvents creates a new case and assigns selected events to it
func (ui *UI) createCaseWithEvents(title, description, severity, assignedTo string) {
	ui.setStatusDirect("[%s]Creating case and assigning events...[-:-:-]", ui.theme.TagWarning)
	
	go func() {
		// Create the case
		newCase := store.Case{
			Title:       title,
			Description: description,
			Severity:    severity,
			Status:      "open",
			AssignedTo:  assignedTo,
		}
		
		caseID, err := ui.store.CreateOrUpdateCase(ui.ctx, newCase)
		if err != nil {
			ui.app.QueueUpdate(func() {
				ui.setStatusDirect("[%s]Error creating case: %v[-:-:-]", ui.theme.TagError, err)
			})
			return
		}
		
		// Assign selected events to the case
		var successCount, errorCount int
		for eventID := range ui.selectedEventIDs {
			if err := ui.store.AssignEventToCase(ui.ctx, eventID, caseID); err != nil {
				errorCount++
				if ui.logger != nil {
					ui.logger.Printf("Error assigning event %s to case %s: %v", eventID, caseID, err)
				}
			} else {
				successCount++
			}
		}
		
		// Update case event count
		if err := ui.store.UpdateCaseEventCount(ui.ctx, caseID); err != nil {
			if ui.logger != nil {
				ui.logger.Printf("Error updating case event count: %v", err)
			}
		}
		
		// Refresh UI without blocking the UI goroutine on DB calls
		// 1) Clear selections and show immediate status on UI thread
		ui.app.QueueUpdate(func() {
			ui.selectedEventIDs = make(map[string]bool)
			ui.setStatusDirect("[%s]Case created; refreshing cases...[-:-:-]", ui.theme.TagWarning)
		})

		// 2) Refresh cases off the UI thread to avoid freezing the event loop
		if err := ui.refreshCases(); err != nil {
			ui.app.QueueUpdate(func() {
				ui.setStatusDirect("[%s]Error refreshing cases after create: %v[-:-:-]", ui.theme.TagError, err)
			})
		} else {
			// 3) Finalize UI updates and auto-select the newly created case
			ui.app.QueueUpdateDraw(func() {
				// Set selection to the new case
				ui.selectedCaseID = caseID
				// Find the sidebar index for the new case (cases list only; ALL EVENTS is separate)
				targetIndex := 0
				for i, c := range ui.cases {
					if c.ID == caseID {
						targetIndex = i
						break
					}
				}
				if targetIndex >= 0 && targetIndex < ui.sidebar.GetItemCount() {
					ui.sidebar.SetCurrentItem(targetIndex)
				}
				// Load events for the new case asynchronously
				go ui.loadCaseEvents()

				if errorCount > 0 {
					ui.setStatusDirect("[%s]Case created with %d events (%d errors)[-:-:-]", ui.theme.TagWarning, successCount, errorCount)
				} else {
					ui.setStatusDirect("[%s]Case created successfully with %d events[-:-:-]", ui.theme.TagSuccess, successCount)
				}
			})
		}
	}()
}

// addEventsToCase adds selected events to an existing case
func (ui *UI) addEventsToCase(caseNumberStr string) {
	// Parse case number
	var caseIndex int
	if _, err := fmt.Sscanf(caseNumberStr, "%d", &caseIndex); err != nil || caseIndex < 1 || caseIndex > len(ui.cases) {
		ui.setStatusDirect("[%s]Invalid case number. Enter 1-%d[-:-:-]", ui.theme.TagError, len(ui.cases))
		return
	}
	
	selectedCase := ui.cases[caseIndex-1]
	ui.setStatusDirect("[%s]Adding events to case: %s...[-:-:-]", ui.theme.TagWarning, selectedCase.Title)
	
	go func() {
		// Assign selected events to the case
		var successCount, errorCount int
		for eventID := range ui.selectedEventIDs {
			if err := ui.store.AssignEventToCase(ui.ctx, eventID, selectedCase.ID); err != nil {
				errorCount++
				if ui.logger != nil {
					ui.logger.Printf("Error assigning event %s to case %s: %v", eventID, selectedCase.ID, err)
				}
			} else {
				successCount++
			}
		}
		
		// Update case event count
		if err := ui.store.UpdateCaseEventCount(ui.ctx, selectedCase.ID); err != nil {
			if ui.logger != nil {
				ui.logger.Printf("Error updating case event count: %v", err)
			}
		}
		
		// Refresh UI without blocking the UI goroutine on DB calls
		// 1) Clear selections and show immediate status on UI thread
		ui.app.QueueUpdate(func() {
			ui.selectedEventIDs = make(map[string]bool)
			ui.setStatusDirect("[%s]Updating cases...[-:-:-]", ui.theme.TagWarning)
		})

		// 2) Refresh cases off the UI thread
		if err := ui.refreshCases(); err != nil {
			ui.app.QueueUpdate(func() {
				ui.setStatusDirect("[%s]Error refreshing cases after add: %v[-:-:-]", ui.theme.TagError, err)
			})
		} else {
			// 3) Finalize UI updates; keep or reselect the target case and reload its events
			ui.app.QueueUpdateDraw(func() {
				// Ensure the selected case remains the target one
				ui.selectedCaseID = selectedCase.ID
				// Find and set the sidebar index for the selected case (+1 for ALL EVENTS)
				targetIndex := 0
				for i, c := range ui.cases {
					if c.ID == selectedCase.ID {
						targetIndex = i
						break
					}
				}
				if targetIndex >= 0 && targetIndex < ui.sidebar.GetItemCount() {
					ui.sidebar.SetCurrentItem(targetIndex)
				}
				// Reload events for the selected case
				go ui.loadCaseEvents()

				if errorCount > 0 {
					ui.setStatusDirect("[%s]Added %d events to case (%d errors)[-:-:-]", ui.theme.TagWarning, successCount, errorCount)
				} else {
					ui.setStatusDirect("[%s]Successfully added %d events to case[-:-:-]", ui.theme.TagSuccess, successCount)
				}
			})
		}
	}()
}
// Neon theme (formerly "Pride"): vibrant but accessible on a dark surface
func themeNeon() Theme {
	return Theme{
		Bg:            hex("#0f0b14"),
		Surface:       hex("#14111a"),
		Border:        hex("#45385a"),
		FocusBorder:   hex("#ff79c6"), // pink focus ring
		SelectionBg:   hex("#2a1f3d"),
		SelectionFg:   hex("#f8f5ff"),
		TextPrimary:   hex("#f8f5ff"),
		TextMuted:     hex("#b8a8c9"),
		Accent:        hex("#ff6ac1"), // pink accent
		Success:       hex("#00d084"), // green
		Warning:       hex("#ffd166"), // amber
		Error:         hex("#ff5555"), // red
		Header:        hex("#ff79c6"), // header accent

		// Table colors
		TableHeader:   hex("#ff79c6"),
		TableHeaderBg: hex("#301d49"),
		TableRow:      hex("#f8f5ff"),
		TableRowMuted: hex("#b8a8c9"),
		TableZebra1:   hex("#1a1426"),
		TableZebra2:   hex("#151020"),

		// Severity colors inspired by rainbow for quick parsing
		SeverityCritical: hex("#ff3b30"), // red
		SeverityHigh:     hex("#ff9f0a"), // orange
		SeverityMedium:   hex("#ffd60a"), // yellow
		SeverityLow:      hex("#34c759"), // green
		SeverityInfo:     hex("#0a84ff"), // blue

		// Text tags
		TagTextPrimary:      "#f8f5ff",
		TagMuted:            "#b8a8c9",
		TagAccent:           "#ff6ac1",
		TagSuccess:          "#00d084",
		TagWarning:          "#ffd166",
		TagError:            "#ff5555",
		TagSeverityCritical: "#ff3b30",
		TagSeverityHigh:     "#ff9f0a",
		TagSeverityMedium:   "#ffd60a",
		TagSeverityLow:      "#34c759",
		TagSeverityInfo:     "#0a84ff",
	}
}
// showTimeFilterModal opens a modal to set start/end time filters (RFC3339).
func (ui *UI) showTimeFilterModal() {
	form := tview.NewForm()
	if ui.logger != nil {
		ui.logger.Printf("Time filter modal opened")
	}
	form.SetTitle(" Set Time Filter ")
	form.SetBorder(true)

	// Theme colors
	form.SetBackgroundColor(ui.theme.Surface)
	form.SetFieldBackgroundColor(ui.theme.Surface)
	form.SetFieldTextColor(ui.theme.TextPrimary)
	form.SetLabelColor(ui.theme.TextPrimary)
	form.SetButtonBackgroundColor(ui.theme.SelectionBg)
	form.SetButtonTextColor(ui.theme.SelectionFg)
	form.SetBorderColor(ui.theme.FocusBorder)

	// Prefill fields if present
	startPrefill := ""
	endPrefill := ""
	if !ui.filterStart.IsZero() {
		startPrefill = ui.filterStart.UTC().Format(time.RFC3339)
	}
	if !ui.filterEnd.IsZero() {
		endPrefill = ui.filterEnd.UTC().Format(time.RFC3339)
	}

	var startStr, endStr string

	// Track indices of the input fields so we can update them from preset buttons.
	startInputIndex := form.GetFormItemCount()
	form.AddInputField("Start", startPrefill, 40, nil, func(text string) { startStr = strings.TrimSpace(text) })
	endInputIndex := form.GetFormItemCount()
	form.AddInputField("End", endPrefill, 40, nil, func(text string) { endStr = strings.TrimSpace(text) })

	// Helper to update both the variables and the visible input fields.
	setFieldTexts := func(s, e string) {
		startStr = strings.TrimSpace(s)
		endStr = strings.TrimSpace(e)
		if fi, ok := form.GetFormItem(startInputIndex).(*tview.InputField); ok {
			fi.SetText(startStr)
		}
		if fi, ok := form.GetFormItem(endInputIndex).(*tview.InputField); ok {
			fi.SetText(endStr)
		}
	}

	// Quick presets to speed up filtering UX.
	form.AddButton("Last 5m", func() {
		now := time.Now().UTC()
		setFieldTexts(now.Add(-5*time.Minute).Format(time.RFC3339), now.Format(time.RFC3339))
	})
	form.AddButton("Last 1h", func() {
		now := time.Now().UTC()
		setFieldTexts(now.Add(-1*time.Hour).Format(time.RFC3339), now.Format(time.RFC3339))
	})
	form.AddButton("Last 24h", func() {
		now := time.Now().UTC()
		setFieldTexts(now.Add(-24*time.Hour).Format(time.RFC3339), now.Format(time.RFC3339))
	})
	form.AddButton("Today", func() {
		now := time.Now().UTC()
		startOfDay := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
		setFieldTexts(startOfDay.Format(time.RFC3339), now.Format(time.RFC3339))
	})

	form.AddButton("Apply", func() {
		// Read the current field values directly from the form to avoid relying solely on change callbacks.
		if fi, ok := form.GetFormItem(startInputIndex).(*tview.InputField); ok {
			startStr = strings.TrimSpace(fi.GetText())
		}
		if fi, ok := form.GetFormItem(endInputIndex).(*tview.InputField); ok {
			endStr = strings.TrimSpace(fi.GetText())
		}
		if ui.logger != nil {
			ui.logger.Printf("Filter Apply pressed: raw startStr=%q raw endStr=%q", startStr, endStr)
		}

		// Serialize apply actions
		if !atomic.CompareAndSwapInt32(&ui.filterApplying, 0, 1) {
			ui.setStatusDirect("[%s]Filter apply already in progress[-:-:-]", ui.theme.TagWarning)
			if ui.logger != nil {
				ui.logger.Printf("Filter Apply ignored: filterApplying=1")
			}
			return
		}

		var start, end time.Time
		var err error

		if strings.TrimSpace(startStr) != "" {
			start, err = parseFlexibleTime(startStr, time.Now())
			if err != nil {
				atomic.StoreInt32(&ui.filterApplying, 0)
				ui.setStatusDirect("[%s]Invalid Start time: %v[-:-:-]", ui.theme.TagError, err)
				if ui.logger != nil {
					ui.logger.Printf("Filter Apply parse error (start): %v", err)
				}
				return
			}
		}
		if strings.TrimSpace(endStr) != "" {
			end, err = parseFlexibleTime(endStr, time.Now())
			if err != nil {
				atomic.StoreInt32(&ui.filterApplying, 0)
				ui.setStatusDirect("[%s]Invalid End time: %v[-:-:-]", ui.theme.TagError, err)
				if ui.logger != nil {
					ui.logger.Printf("Filter Apply parse error (end): %v", err)
				}
				return
			}
		}

		// Assign computed filter bounds
		ui.filterStart = start
		ui.filterEnd = end

		// If a load is in-progress, we'll defer the reload rather than aborting.
		inProgress := atomic.LoadInt32(&ui.loadingEvents) == 1
		if ui.logger != nil {
			ui.logger.Printf("Filter Apply: start=%v end=%v showAll=%v selectedCaseID=%s inProgress=%v",
				start, end, ui.showAll, ui.selectedCaseID, inProgress)
		}
		if inProgress {
			ui.setStatusDirect("[%s]Load in progress; deferring filter reload...[-:-:-]", ui.theme.TagWarning)
		}

		// Restore layout and set status directly (we are on UI goroutine), then safely schedule reload
		if ui.logger != nil {
			ui.logger.Printf("Filter Apply: restoring layout and scheduling reload")
		}
		ui.restoreMainLayout()
		ui.setStatusDirect("[%s]Applying time filter...[-:-:-]", ui.theme.TagAccent)
		// Always schedule reload; scheduleEventsReload will defer if needed.
		go ui.scheduleEventsReload("filter:Apply")
	})

	form.AddButton("Clear", func() {
		// Reset filters and schedule reload; do not use QueueUpdate here to avoid UI loop stalls.
		ui.filterStart = time.Time{}
		ui.filterEnd = time.Time{}
		if ui.logger != nil {
			ui.logger.Printf("Filter Clear button pressed: cleared bounds; restoring layout and scheduling reload")
		}
		ui.restoreMainLayout()
		ui.setStatusDirect("[%s]Clearing time filter...[-:-:-]", ui.theme.TagAccent)
		go ui.scheduleEventsReload("filter:Clear")
	})

	form.AddButton("Cancel", func() {
		ui.restoreMainLayout()
	})

	// Handle Esc to cancel
	form.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
		if ev.Key() == tcell.KeyEsc {
			ui.restoreMainLayout()
			return nil
		}
		return ev
	})

	ui.lastFocus = ui.app.GetFocus()
	ui.app.SetRoot(form, true)
	ui.app.SetFocus(form)
}

// clearTimeFilter resets the time filter and reloads events.
func (ui *UI) clearTimeFilter() {
	ui.filterStart = time.Time{}
	ui.filterEnd = time.Time{}
	ui.setStatusDirect("[%s]Time filter cleared[-:-:-]", ui.theme.TagAccent)
	ui.scheduleEventsReload("filter:ClearShortcut")
}

// showCombinedFilterModal opens a structured, keyboard-friendly filter modal with dropdowns and sub-modals.
func (ui *UI) showCombinedFilterModal() {
	// Current context state
	ctxID := ui.getContextID()
	s := ui.getOrInitState(ctxID)

	// Build a clean form
	form := tview.NewForm()
	form.SetTitle(" Set Filters (Time | Severity | Type) ")
	form.SetBorder(true)
	form.SetBackgroundColor(ui.theme.Surface)
	form.SetFieldBackgroundColor(ui.theme.Surface)
	form.SetFieldTextColor(ui.theme.TextPrimary)
	form.SetLabelColor(ui.theme.TextPrimary)
	form.SetButtonBackgroundColor(ui.theme.SelectionBg)
	form.SetButtonTextColor(ui.theme.SelectionFg)
	form.SetBorderColor(ui.theme.FocusBorder)

	// Time preset dropdown
	timeOptions := []string{"All time", "Last 5m", "Last 1h", "Last 24h", "Today", "Custom..."}
	customStart := ""
	customEnd := ""
	if !s.filterStart.IsZero() {
		customStart = s.filterStart.UTC().Format(time.RFC3339)
	} else if !ui.filterStart.IsZero() {
		customStart = ui.filterStart.UTC().Format(time.RFC3339)
	}
	if !s.filterEnd.IsZero() {
		customEnd = s.filterEnd.UTC().Format(time.RFC3339)
	} else if !ui.filterEnd.IsZero() {
		customEnd = ui.filterEnd.UTC().Format(time.RFC3339)
	}

	var timePresetIdx int
	// Heuristic preselect: custom if any bound set, else All time
	if customStart != "" || customEnd != "" {
		timePresetIdx = len(timeOptions) - 1 // Custom...
	} else {
		timePresetIdx = 0 // All time
	}
	timeDD := tview.NewDropDown().
		SetLabel("Time Preset").
		SetOptions(timeOptions, func(text string, idx int) { timePresetIdx = idx })
	timeDD.SetCurrentOption(timePresetIdx)
	timeDD.SetFieldTextColor(ui.theme.TextPrimary)
	timeDD.SetFieldBackgroundColor(ui.theme.Surface)
	timeDD.SetLabelColor(ui.theme.TextPrimary)
	form.AddFormItem(timeDD)

	// Custom time fields (only read when preset == Custom...)
	startIF := tview.NewInputField().SetLabel("Start (Custom)").SetText(customStart)
	startIF.SetFieldBackgroundColor(ui.theme.Surface).SetFieldTextColor(ui.theme.TextPrimary).SetLabelColor(ui.theme.TextPrimary)
	endIF := tview.NewInputField().SetLabel("End (Custom)").SetText(customEnd)
	endIF.SetFieldBackgroundColor(ui.theme.Surface).SetFieldTextColor(ui.theme.TextPrimary).SetLabelColor(ui.theme.TextPrimary)
	form.AddFormItem(startIF)
	form.AddFormItem(endIF)

	// Severity section
	sevOptions := []string{"Any", "Critical", "High", "Medium", "Low", "Informational", "Custom..."}
	// Snapshot current selections
	customSev := map[string]bool{}
	for k, v := range s.filterSeverities {
		if v {
		customSev[strings.ToLower(k)] = true
	}
	}
	sevIdx := 0 // Any
	if len(customSev) == 1 {
		switch {
		case customSev["critical"]:
			sevIdx = 1
		case customSev["high"]:
			sevIdx = 2
		case customSev["medium"]:
			sevIdx = 3
		case customSev["low"]:
			sevIdx = 4
		case customSev["informational"]:
			sevIdx = 5
		}
	} else if len(customSev) > 1 {
		sevIdx = 6 // Custom...
	}
	// Declare before use so the callback can reference it safely.
	var sevDD *tview.DropDown
	sevDD = tview.NewDropDown()
	sevDD.SetLabel("Severity")
	sevDD.SetOptions(sevOptions, func(text string, idx int) {
		sevIdx = idx
		if text == "Custom..." {
			// Open multi-select sub-modal, return to this form after
			ui.showMultiSelectModal("Select Severities", []string{"critical", "high", "medium", "low", "informational"}, customSev, form, func(sel map[string]bool) {
				customSev = sel
				sevDD.SetCurrentOption(6)
				ui.app.SetRoot(form, true)
				ui.app.SetFocus(form)
			})
		}
	})
	sevDD.SetCurrentOption(sevIdx)
	sevDD.SetFieldTextColor(ui.theme.TextPrimary)
	sevDD.SetFieldBackgroundColor(ui.theme.Surface)
	sevDD.SetLabelColor(ui.theme.TextPrimary)
	form.AddFormItem(sevDD)

	// Type section
	typeOptions := []string{"Any", "Network", "Process", "File", "Authentication", "Unknown", "Custom..."}
	customType := map[string]bool{}
	for k, v := range s.filterTypes {
		if v {
			customType[strings.ToLower(k)] = true
		}
	}
	typeIdx := 0
	if len(customType) == 1 {
		switch {
		case customType["network"]:
			typeIdx = 1
		case customType["process"]:
			typeIdx = 2
		case customType["file"]:
			typeIdx = 3
		case customType["authentication"]:
			typeIdx = 4
		case customType["unknown"]:
			typeIdx = 5
		}
	} else if len(customType) > 1 {
		typeIdx = 6 // Custom...
	}
	// Declare before use so the callback can reference it safely.
	var typeDD *tview.DropDown
	typeDD = tview.NewDropDown()
	typeDD.SetLabel("Type")
	typeDD.SetOptions(typeOptions, func(text string, idx int) {
		typeIdx = idx
		if text == "Custom..." {
			ui.showMultiSelectModal("Select Types", []string{"network", "process", "file", "authentication", "unknown"}, customType, form, func(sel map[string]bool) {
				customType = sel
				typeDD.SetCurrentOption(6)
				ui.app.SetRoot(form, true)
				ui.app.SetFocus(form)
			})
		}
	})
	typeDD.SetCurrentOption(typeIdx)
	typeDD.SetFieldTextColor(ui.theme.TextPrimary)
	typeDD.SetFieldBackgroundColor(ui.theme.Surface)
	typeDD.SetLabelColor(ui.theme.TextPrimary)
	form.AddFormItem(typeDD)

	// Buttons
	form.AddButton("Apply", func() {
		if !atomic.CompareAndSwapInt32(&ui.filterApplying, 0, 1) {
			ui.setStatusDirect("[%s]Filter apply already in progress[-:-:-]", ui.theme.TagWarning)
			return
		}

		// Compute time bounds
		var start, end time.Time
		now := time.Now().UTC()
		switch timePresetIdx {
		case 0: // All time
			// zero bounds
		case 1: // Last 5m
			start = now.Add(-5 * time.Minute)
			end = now
		case 2: // Last 1h
			start = now.Add(-1 * time.Hour)
			end = now
		case 3: // Last 24h
			start = now.Add(-24 * time.Hour)
			end = now
		case 4: // Today
			dayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
			start = dayStart
			end = now
		case 5: // Custom...
			customStartStr := strings.TrimSpace(startIF.GetText())
			customEndStr := strings.TrimSpace(endIF.GetText())
			if customStartStr != "" {
				var err error
				start, err = parseFlexibleTime(customStartStr, time.Now())
				if err != nil {
					atomic.StoreInt32(&ui.filterApplying, 0)
					ui.setStatusDirect("[%s]Invalid Start time: %v[-:-:-]", ui.theme.TagError, err)
					return
				}
			}
			if customEndStr != "" {
				var err error
				end, err = parseFlexibleTime(customEndStr, time.Now())
				if err != nil {
					atomic.StoreInt32(&ui.filterApplying, 0)
					ui.setStatusDirect("[%s]Invalid End time: %v[-:-:-]", ui.theme.TagError, err)
					return
				}
			}
		}

		// Compute severities
		newSev := map[string]bool{}
		switch sevIdx {
		case 0: // Any
			// leave empty
		case 1:
			newSev["critical"] = true
		case 2:
			newSev["high"] = true
		case 3:
			newSev["medium"] = true
		case 4:
			newSev["low"] = true
		case 5:
			newSev["informational"] = true
		case 6: // Custom...
			for k, v := range customSev {
				if v {
					newSev[k] = true
				}
			}
		}

		// Compute types
		newTypes := map[string]bool{}
		switch typeIdx {
		case 0: // Any
			// empty
		case 1:
			newTypes["network"] = true
		case 2:
			newTypes["process"] = true
		case 3:
			newTypes["file"] = true
		case 4:
			newTypes["authentication"] = true
		case 5:
			newTypes["unknown"] = true
		case 6:
			for k, v := range customType {
				if v {
					newTypes[k] = true
				}
			}
		}

		// Apply to per-context state, clear legacy bridge, reset page
		s.filterStart = start
		s.filterEnd = end
		s.filterSeverities = newSev
		s.filterTypes = newTypes
		ui.filterStart = time.Time{}
		ui.filterEnd = time.Time{}
		s.pageIndex = 0

		ui.restoreMainLayout()
		ui.setStatusDirect("[%s]Applying filters...[-:-:-]", ui.theme.TagAccent)
		go ui.scheduleEventsReload("filter:ApplyCombinedDropdown")
	})
	form.AddButton("Clear", func() {
		ui.restoreMainLayout()
		ui.clearCurrentContextFilters()
	})
	form.AddButton("Cancel", func() {
		ui.restoreMainLayout()
	})

	// Keyboard navigation hints and Esc handling
	form.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
		switch ev.Key() {
		case tcell.KeyEsc:
			ui.restoreMainLayout()
			return nil
		}
		return ev
	})

	ui.lastFocus = ui.app.GetFocus()
	ui.app.SetRoot(form, true)
	ui.app.SetFocus(form)
	ui.setStatusDirect("[%s]Tab/Shift+Tab: navigate • Enter: open dropdown • Apply/Clear/Cancel at bottom[-:-:-]", ui.theme.TagAccent)
}

// clearCurrentContextFilters clears time, severities, and types for the current context and reloads.
func (ui *UI) clearCurrentContextFilters() {
	id := ui.getContextID()
	s := ui.getOrInitState(id)
	s.filterStart = time.Time{}
	s.filterEnd = time.Time{}
	s.filterSeverities = map[string]bool{}
	s.filterTypes = map[string]bool{}
	s.pageIndex = 0
	// Also clear legacy to avoid bridging re-introducing a time filter
	ui.filterStart = time.Time{}
	ui.filterEnd = time.Time{}

	ui.setStatusDirect("[%s]Filters cleared for current context[-:-:-]", ui.theme.TagAccent)
	go ui.scheduleEventsReload("filter:ClearCombined")
}

// showMultiSelectModal opens a checkbox modal for multi-select and returns to a parent primitive on close.
func (ui *UI) showMultiSelectModal(title string, options []string, initial map[string]bool, parent tview.Primitive, onDone func(map[string]bool)) {
	form := tview.NewForm()
	form.SetTitle(" " + title + " ")
	form.SetBorder(true)
	form.SetBackgroundColor(ui.theme.Surface)
	form.SetFieldBackgroundColor(ui.theme.Surface)
	form.SetFieldTextColor(ui.theme.TextPrimary)
	form.SetLabelColor(ui.theme.TextPrimary)
	form.SetButtonBackgroundColor(ui.theme.SelectionBg)
	form.SetButtonTextColor(ui.theme.SelectionFg)
	form.SetBorderColor(ui.theme.FocusBorder)

	// Copy initial to working map
	working := map[string]bool{}
	for _, opt := range options {
		working[opt] = initial[strings.ToLower(opt)]
	}

	for _, opt := range options {
		optKey := strings.ToLower(opt)
		checked := working[optKey]
		// Capture the current optKey to avoid closure over the loop variable.
		k := optKey
		form.AddCheckbox(strings.Title(optKey), checked, func(b bool) { working[k] = b })
	}

	form.AddButton("Save", func() {
		// Return to parent and pass selection
		onDone(working)
		ui.app.SetRoot(parent, true)
		ui.app.SetFocus(parent)
	})
	form.AddButton("Cancel", func() {
		ui.app.SetRoot(parent, true)
		ui.app.SetFocus(parent)
	})
	form.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
		if ev.Key() == tcell.KeyEsc {
			ui.app.SetRoot(parent, true)
			ui.app.SetFocus(parent)
			return nil
		}
		return ev
	})

	ui.app.SetRoot(form, true)
	ui.app.SetFocus(form)
}

// scheduleEventsReload coordinates safe event reloads after actions like filter Apply/Clear.
// It resets a stuck loading flag, logs context, and dispatches the appropriate loader.
func (ui *UI) scheduleEventsReload(source string) {
	le := atomic.LoadInt32(&ui.loadingEvents)
	last := atomic.LoadInt64(&ui.lastLoadStart)
	var sinceStr string
	if last != 0 {
		sinceStr = time.Since(time.Unix(0, last)).String()
	} else {
		sinceStr = "n/a"
	}

	if ui.logger != nil {
		ui.logger.Printf("scheduleEventsReload: source=%s showAll=%v selectedCaseID=%s filterStart=%v filterEnd=%v loadingEvents=%d lastLoadAgo=%s filterApplying=%d",
			source, ui.showAll, ui.selectedCaseID, ui.filterStart, ui.filterEnd, le, sinceStr, atomic.LoadInt32(&ui.filterApplying))
	}

	// If a load is in progress, defer dispatch until it completes or times out; then dispatch.
	if le == 1 {
		if ui.logger != nil {
			ui.logger.Printf("scheduleEventsReload: deferring reload until current load completes")
		}
		go func() {
			deadline := time.Now().Add(3 * time.Second)
			for atomic.LoadInt32(&ui.loadingEvents) == 1 && time.Now().Before(deadline) {
				time.Sleep(100 * time.Millisecond)
			}
			// If still busy after deadline, consider it stuck and reset.
			if atomic.LoadInt32(&ui.loadingEvents) == 1 {
				started := time.Unix(0, atomic.LoadInt64(&ui.lastLoadStart))
				if started.IsZero() || time.Since(started) > 3*time.Second {
					if ui.logger != nil {
						ui.logger.Printf("scheduleEventsReload: force-resetting stuck loadingEvents (since=%v)", started)
					}
					atomic.StoreInt32(&ui.loadingEvents, 0)
					atomic.StoreInt64(&ui.lastLoadStart, 0)
				}
			}
			// Now dispatch
			if ui.selectedCaseID != "" {
				if ui.logger != nil {
					ui.logger.Printf("scheduleEventsReload: dispatching deferred loadCaseEvents")
				}
				go ui.loadCaseEvents()
			} else {
				if ui.logger != nil {
					ui.logger.Printf("scheduleEventsReload: dispatching deferred loadAllEvents")
				}
				go ui.loadAllEvents()
			}
		}()
		return
	}

	// No in-progress load; dispatch immediately.
	if ui.selectedCaseID != "" {
		if ui.logger != nil {
			ui.logger.Printf("scheduleEventsReload: dispatching immediate loadCaseEvents")
		}
		go ui.loadCaseEvents()
	} else {
		if ui.logger != nil {
			ui.logger.Printf("scheduleEventsReload: dispatching immediate loadAllEvents")
		}
		go ui.loadAllEvents()
	}
}

// parseFlexibleTime parses RFC3339 or relative tokens like now, -15m, -1h, 15m, today.
func parseFlexibleTime(input string, now time.Time) (time.Time, error) {
	s := strings.TrimSpace(strings.ToLower(input))
	if s == "" {
		return time.Time{}, nil
	}
	if s == "now" {
		return now, nil
	}
	if s == "today" {
		startOfDay := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
		return startOfDay, nil
	}
	// Normalize tokens like "15m" to "-15m" (past) unless prefixed with +/-
	sign := ""
	if strings.HasPrefix(s, "+") || strings.HasPrefix(s, "-") {
		sign = s[:1]
		s = s[1:]
	}
	// Simple unit parsing without regex
	if len(s) >= 2 {
		unit := s[len(s)-1]
		numStr := s[:len(s)-1]
		if unit == 's' || unit == 'm' || unit == 'h' || unit == 'd' {
			if n, err := strconv.Atoi(numStr); err == nil {
				// Days require manual expansion
				var dur time.Duration
				switch unit {
				case 's':
					dur = time.Duration(n) * time.Second
				case 'm':
					dur = time.Duration(n) * time.Minute
				case 'h':
					dur = time.Duration(n) * time.Hour
				case 'd':
					dur = time.Duration(n) * 24 * time.Hour
				}
				if sign == "+" {
					return now.Add(dur), nil
				}
				// Default to past if no sign provided
				return now.Add(-dur), nil
			}
		}
	}
	// Fallback: RFC3339
	if t, err := time.Parse(time.RFC3339, input); err == nil {
		return t, nil
	}
	return time.Time{}, fmt.Errorf("unsupported time format %q", input)
}


// loadAllEvents loads all events across all cases (respects time filters if set)
func (ui *UI) loadAllEvents() {
	// Prevent concurrent loads
	if !atomic.CompareAndSwapInt32(&ui.loadingEvents, 0, 1) {
		if ui.logger != nil {
			ui.logger.Println("loadAllEvents: already loading, skipping")
		}
		return
	}
	atomic.StoreInt64(&ui.lastLoadStart, time.Now().UnixNano())
	defer func() {
		atomic.StoreInt32(&ui.loadingEvents, 0)
		atomic.StoreInt64(&ui.lastLoadStart, 0)
	}()

	defer func() {
		if r := recover(); r != nil {
			if ui.logger != nil {
				ui.logger.Printf("panic in loadAllEvents: %v", r)
			}
			ui.setStatusDirect("[%s]Error loading all events (recovered)[-:-:-]", ui.theme.TagError)
		}
	}()

	ui.logger.Println("Loading ALL events...")
	if ui.logger != nil {
		ui.logger.Printf("loadAllEvents: filterStart=%v filterEnd=%v", ui.filterStart, ui.filterEnd)
	}
	ui.setStatus("[%s]Loading ALL events...[-:-:-]", ui.theme.TagWarning)

	// Run DB query with a short timeout to avoid UI freeze if DB is locked
	ctx, cancel := context.WithTimeout(ui.ctx, 4*time.Second)
	defer cancel()

	var (
		events []store.Event
		err    error
	)

	// Resolve per-context query state for ALL and bridge time filters from legacy fields
	s := ui.getOrInitState(contextAll)
	if s.filterStart.IsZero() && !ui.filterStart.IsZero() {
		s.filterStart = ui.filterStart
	}
	if s.filterEnd.IsZero() && !ui.filterEnd.IsZero() {
		s.filterEnd = ui.filterEnd
	}
	sev := keysFromMap(s.filterSeverities)
	typ := keysFromMap(s.filterTypes)

	// Count total to compute pagination/clamp page index
	total, err := ui.store.CountEventsFiltered(ctx, "", s.filterStart, s.filterEnd, sev, typ)
	if err != nil {
		if ui.logger != nil {
			ui.logger.Printf("Error counting ALL events: %v", err)
		}
		// Reset filter apply guard on failure
		atomic.StoreInt32(&ui.filterApplying, 0)
		ui.app.QueueUpdate(func() {
			if ctx.Err() == context.DeadlineExceeded {
				ui.setStatusDirect("[%s]Timed out counting ALL events (database busy)[-:-:-]", ui.theme.TagError)
			} else {
				ui.setStatusDirect("[%s]Error counting ALL events: %v[-:-:-]", ui.theme.TagError, err)
			}
		})
		return
	}
	s.totalCount = total

	// Clamp page index based on total
	maxPages := 1
	if s.pageSize > 0 {
		maxPages = (s.totalCount + s.pageSize - 1) / s.pageSize
		if maxPages == 0 {
			maxPages = 1
		}
		if s.pageIndex >= maxPages {
			s.pageIndex = maxPages - 1
		}
		if s.pageIndex < 0 {
			s.pageIndex = 0
		}
	}

	limit := s.pageSize
	offset := 0
	if limit > 0 {
		offset = s.pageIndex * limit
	}

	events, err = ui.store.GetEventsFiltered(ctx, "", s.filterStart, s.filterEnd, sev, typ, limit, offset)
	if err != nil {
		if ui.logger != nil {
			ui.logger.Printf("Error loading ALL events: %v", err)
		}
		// Reset filter apply guard on failure
		atomic.StoreInt32(&ui.filterApplying, 0)
		ui.app.QueueUpdate(func() {
			if ctx.Err() == context.DeadlineExceeded {
				ui.setStatusDirect("[%s]Timed out loading ALL events (database busy)[-:-:-]", ui.theme.TagError)
			} else {
				ui.setStatusDirect("[%s]Error loading ALL events: %v[-:-:-]", ui.theme.TagError, err)
			}
		})
		return
	}

	if ui.logger != nil {
		ui.logger.Printf("Loaded %d ALL events", len(events))
		started := time.Unix(0, atomic.LoadInt64(&ui.lastLoadStart))
		if !started.IsZero() {
			ui.logger.Printf("loadAllEvents: query finished in %v; updating UI", time.Since(started))
		}
	}

	// Update UI in main thread
	ui.app.QueueUpdateDraw(func() {
		ui.selectedEventIDs = make(map[string]bool)
		ui.events = events
		ui.updateEventsList()

		// Ensure the table is scrolled to the top and the first data row is selected.
		ui.eventList.SetOffset(0, 0)
		if ui.eventList.GetRowCount() > 1 {
			ui.eventList.Select(1, 0) // first data row (row 0 is header)
		} else {
			ui.eventList.Select(0, 0) // header/no-data fallback
		}

		// Move focus to the Events panel so changes are immediately visible
		ui.app.SetFocus(ui.eventList)

		// Update OVERVIEW with latest ALL EVENTS total and current case stats
		totalCases := len(ui.cases)
		openN, invN, closeN := 0, 0, 0
		for _, c := range ui.cases {
			switch strings.ToLower(strings.TrimSpace(c.Status)) {
			case "open":
				openN++
			case "investigating", "investigation":
				invN++
			case "closed", "close":
				closeN++
			}
		}
		ui.updateOverview(s.totalCount, totalCases, openN, invN, closeN)

		ui.setStatusDirect("[%s]Loaded %d events[-:-:-] (ALL EVENTS)", ui.theme.TagSuccess, len(events))
		// Re-enable Apply after load completes
		atomic.StoreInt32(&ui.filterApplying, 0)
	})
}
// showDeleteCaseConfirm confirms and deletes the selected case, unassigning its events to ALL EVENTS.
func (ui *UI) showDeleteCaseConfirm() {
	if ui.selectedCaseID == "" || ui.showAll {
		ui.setStatusDirect("[%s]Select a case in the sidebar first (cannot delete ALL EVENTS)[-:-:-]", ui.theme.TagWarning)
		return
	}

	// Resolve case title for confirmation text
	var caseTitle string
	for _, c := range ui.cases {
		if c.ID == ui.selectedCaseID {
			caseTitle = c.Title
			break
		}
	}
	if caseTitle == "" {
		caseTitle = ui.selectedCaseID
	}

	msg := fmt.Sprintf("Delete case:\n\n[%s]%s[-]\n\nThis will unassign all its events to ALL EVENTS.\nThis action cannot be undone.", ui.theme.TagTextPrimary, caseTitle)

	modal := tview.NewModal().
		SetText(msg).
		AddButtons([]string{"Delete", "Cancel"})
	modal.SetTitle(" Confirm Delete Case ")
	modal.SetBackgroundColor(ui.theme.Surface)
	modal.SetTextColor(ui.theme.TextPrimary)
	modal.SetBorderColor(ui.theme.FocusBorder)
	modal.SetButtonBackgroundColor(ui.theme.SelectionBg)
	modal.SetButtonTextColor(ui.theme.SelectionFg)

	// Handle modal buttons
	modal.SetDoneFunc(func(buttonIndex int, buttonLabel string) {
		if buttonLabel != "Delete" {
			ui.restoreMainLayout()
			return
		}

		caseID := ui.selectedCaseID
		ui.setStatusDirect("[%s]Deleting case...[-:-:-]", ui.theme.TagWarning)
		// Run DB ops off the UI goroutine
		go func() {
			if ui.logger != nil {
				ui.logger.Printf("DeleteCase: deleting caseID=%s (unassigning events)", caseID)
			}
			if err := ui.store.DeleteCaseAndUnassign(ui.ctx, caseID); err != nil {
				ui.app.QueueUpdate(func() {
					ui.restoreMainLayout()
					ui.setStatusDirect("[%s]Error deleting case: %v[-:-:-]", ui.theme.TagError, err)
				})
				return
			}

			// Refresh cases off the UI goroutine
			if err := ui.refreshCases(); err != nil {
				ui.app.QueueUpdate(func() {
					ui.restoreMainLayout()
					ui.setStatusDirect("[%s]Error refreshing cases after delete: %v[-:-:-]", ui.theme.TagError, err)
				})
				return
			}

			// Finalize UI: select ALL EVENTS and reload
			ui.app.QueueUpdateDraw(func() {
				ui.restoreMainLayout()
				ui.selectedCaseID = ""
				ui.showAll = true
				// Focus and select ALL EVENTS
				if ui.allList != nil {
					ui.allList.SetCurrentItem(0)
					ui.app.SetFocus(ui.allList)
				}
				go ui.loadAllEvents()
				ui.setStatusDirect("[%s]Case deleted. Events moved to ALL EVENTS.[-:-:-]", ui.theme.TagSuccess)
			})
		}()
	})

	// Esc closes the modal
	modal.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyEsc {
			ui.restoreMainLayout()
			return nil
		}
		return event
	})

	ui.lastFocus = ui.app.GetFocus()
	ui.app.SetRoot(modal, true)
	ui.app.SetFocus(modal)
}
// buildShortcutHints returns a colored, space-separated list of the most relevant
// shortcuts based on current focus and UI state. It caps the list to a small,
// readable set to avoid clutter. Ensures `h:help` is always shown and omits
// `A:all events` when already in ALL EVENTS to free a slot.
func (ui *UI) buildShortcutHints() string {
	accent := ui.theme.TagAccent

	// Snapshot focus safely
	var focused tview.Primitive
	if ui.app != nil {
		focused = ui.app.GetFocus()
	}
	inEvents := focused == ui.eventList
	inSidebar := focused == ui.sidebar
	inAll := focused == ui.allList

	// Snapshot state
	selectionCount := len(ui.selectedEventIDs)
	caseSelected := ui.selectedCaseID != "" && !ui.showAll
	id := ui.getContextID()
	s := ui.getOrInitState(id)
	filterActive := ui.activeFilterTag() != "" || len(s.filterSeverities) > 0 || len(s.filterTypes) > 0

	type kv struct{ key, label string }
	base := make([]kv, 0, 16)

	// 1) Context-critical by focus/state
	if inEvents {
		base = append(base,
			kv{"Space", "toggle"},
			kv{"Ctrl+A", "all"},
			kv{"Ctrl+D", "none"},
		)
		if selectionCount > 0 {
			base = append(base,
				kv{"d", "delete"},
				kv{"c", "new case"},
				kv{"a", "add to case"},
			)
		}
		base = append(base,
			kv{"N", "next"},
			kv{"P", "prev"},
		)
	}
	if inSidebar && caseSelected {
		base = append(base,
			kv{"Enter", "open"},
			kv{"d", "delete"},
		)
	}
	if inAll {
		base = append(base, kv{"Enter", "load"})
	}

	// 2) Filters
	base = append(base, kv{"f", "filter"})
	if filterActive {
		base = append(base, kv{"F", "clear"})
	}
	// Also surface clear when Cases sidebar filters are active
	if inSidebar {
		caseFilterActive := ui.caseFilterName != "" || len(ui.caseFilterStatuses) > 0 || len(ui.caseFilterSeverities) > 0
		if caseFilterActive {
			base = append(base, kv{"F", "clear"})
		}
	}

	// 3) Global essentials (without help; help will be pinned)
	base = append(base,
		kv{"Tab", "panels"},
		kv{"A", "all events"},
		kv{"r", "refresh"},
		kv{"q", "quit"},
	)

	// 4) Theme (lowest priority)
	base = append(base,
		kv{"t", "theme"},
		kv{"T", "high-contrast"},
		kv{"C", "cb-safe"},
	)

	// Post-process:
	// - Omit "A" when already in ALL EVENTS to free a slot.
	// - Pin "h:help" so it's always visible.
	final := make([]kv, 0, 16)
	seen := map[string]bool{}

	// Always start with help
	final = append(final, kv{"h", "help"})
	seen["h"] = true

	for _, h := range base {
		if h.key == "A" && ui.showAll {
			continue
		}
		if seen[h.key] {
			continue
		}
		final = append(final, h)
		seen[h.key] = true
	}

	// Cap to 6 tokens
	const maxTokens = 6
	if len(final) > maxTokens {
		final = final[:maxTokens]
	}

	var sb strings.Builder
	for i, h := range final {
		if i > 0 {
			sb.WriteString(" ")
		}
		sb.WriteString(fmt.Sprintf("[%s]%s[-]:%s", accent, h.key, h.label))
	}
	return sb.String()
}

// buildStatusMain augments the base message with compact badges such as Case title,
// selection count, time filter, severity/type filters, and pagination. It returns a single inline string.
func (ui *UI) buildStatusMain(message string) string {
	accent := ui.theme.TagAccent
	parts := []string{message}

	// Case badge
	if !ui.showAll && ui.selectedCaseID != "" {
		title := ""
		for _, c := range ui.cases {
			if c.ID == ui.selectedCaseID {
				title = c.Title
				break
			}
		}
		if title != "" {
			parts = append(parts, fmt.Sprintf("[%s]Case:[-] %s", accent, title))
		}
	}

	// Selection badge (only if Events table focused)
	if ui.app != nil && ui.app.GetFocus() == ui.eventList {
		if n := len(ui.selectedEventIDs); n > 0 {
			parts = append(parts, fmt.Sprintf("[%s]Sel:[-] %d", accent, n))
		}
	}

	// Time filter badge
	if tag := ui.activeFilterTag(); tag != "" {
		parts = append(parts, fmt.Sprintf("[%s]%s[-]", accent, tag))
	}

	// Severity/type filters and pagination (per-context)
	{
		id := ui.getContextID()
		s := ui.getOrInitState(id)

		// Severity badge
		if len(s.filterSeverities) > 0 {
			sevKeys := keysFromMap(s.filterSeverities)
			for i := range sevKeys {
				if sevKeys[i] != "" {
					sevKeys[i] = strings.Title(sevKeys[i])
				}
			}
			parts = append(parts, fmt.Sprintf("[%s]Sev:[-] %s", accent, strings.Join(sevKeys, ",")))
		}

		// Type badge
		if len(s.filterTypes) > 0 {
			typKeys := keysFromMap(s.filterTypes)
			for i := range typKeys {
				if typKeys[i] != "" {
					typKeys[i] = strings.Title(typKeys[i])
				}
			}
			parts = append(parts, fmt.Sprintf("[%s]Type:[-] %s", accent, strings.Join(typKeys, ",")))
		}

		// Pagination badge
		maxPages := 1
		if s.pageSize > 0 {
			maxPages = (s.totalCount + s.pageSize - 1) / s.pageSize
			if maxPages == 0 {
				maxPages = 1
			}
			parts = append(parts, fmt.Sprintf("[%s]Page:[-] %d/%d [%s]Tot:[-] %d", accent, s.pageIndex+1, maxPages, accent, s.totalCount))
		}
	}

	return strings.Join(parts, " ")
}

// openCaseManagement opens the Case Management TUI for the selected case (Enter on a case).
func (ui *UI) openCaseManagement(index int) {
	if index < 0 || index >= len(ui.cases) {
		ui.setStatusDirect("[%s]Invalid case selection[-:-:-]", ui.theme.TagError)
		return
	}
	selected := ui.cases[index]
	ui.setStatusDirect("[%s]Opening Case Management for: %s[-:-:-]", ui.theme.TagAccent, selected.Title)

	// Launch the new Case Management screen
	cm := NewCaseManagement(ui, selected)
	// Track active CM to propagate theme updates live
	ui.activeCM = cm
	cm.Show()
}

// updateOverview updates the non-selectable Overview block with ALL EVENTS and ALL CASES stats.
func (ui *UI) updateOverview(eventsTotal, casesTotal, open, investigating, closed int) {
	if ui.allCasesInfo == nil {
		return
	}
	line1 := fmt.Sprintf("[%s](A) EVENTS (%d)[-]", ui.theme.TagAccent, eventsTotal)
	line2 := fmt.Sprintf("[%s](C) CASES (%d)[-]", ui.theme.TagAccent, casesTotal)
	line3 := fmt.Sprintf("[%s]OPEN[-] - %d  [%s]INVESTIGATING[-] - %d  [%s]CLOSED[-] - %d",
		ui.theme.TagTextPrimary, open,
		ui.theme.TagTextPrimary, investigating,
		ui.theme.TagTextPrimary, closed,
	)
	ui.allCasesInfo.SetText(line1 + "\n" + line2 + "\n" + line3)
}

// showDeleteEventsConfirm shows a confirmation dialog and deletes the selected events upon approval.
// After deletion it clears selection, refreshes cases (for event_count), and reloads the current context.
func (ui *UI) showDeleteEventsConfirm(ids []string) {
	if len(ids) == 0 {
		ui.setStatusDirect("[%s]No events selected to delete[-:-:-]", ui.theme.TagWarning)
		return
	}

	msg := fmt.Sprintf("Delete %d selected event(s)?\n\nThis action cannot be undone.", len(ids))
	modal := tview.NewModal().
		SetText(msg).
		AddButtons([]string{"Delete", "Cancel"})
	modal.SetTitle(" Confirm Delete Events ")
	modal.SetBackgroundColor(ui.theme.Surface)
	modal.SetTextColor(ui.theme.TextPrimary)
	modal.SetBorderColor(ui.theme.FocusBorder)
	modal.SetButtonBackgroundColor(ui.theme.SelectionBg)
	modal.SetButtonTextColor(ui.theme.SelectionFg)

	modal.SetDoneFunc(func(buttonIndex int, buttonLabel string) {
		if buttonLabel != "Delete" {
			ui.restoreMainLayout()
			return
		}

		ui.setStatusDirect("[%s]Deleting selected events...[-:-:-]", ui.theme.TagWarning)

		// Run deletion in background
		go func(idsCopy []string) {
			if err := ui.store.DeleteEvents(ui.ctx, idsCopy); err != nil {
				ui.app.QueueUpdate(func() {
					ui.restoreMainLayout()
					ui.setStatusDirect("[%s]Error deleting events: %v[-:-:-]", ui.theme.TagError, err)
				})
				return
			}

			// Best-effort: refresh cases to update event_count numbers in the sidebar
			_ = ui.refreshCases()

			// Finalize UI: clear selections and reload current context
			ui.app.QueueUpdateDraw(func() {
				ui.restoreMainLayout()
				ui.selectedEventIDs = make(map[string]bool)
				// Reload events for current context
				go ui.scheduleEventsReload("delete:events")
				ui.setStatusDirect("[%s]Deleted %d event(s)[-:-:-]", ui.theme.TagSuccess, len(idsCopy))
			})
		}(append([]string(nil), ids...))
	})

	// Allow Esc to cancel
	modal.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
		if ev.Key() == tcell.KeyEsc {
			ui.restoreMainLayout()
			return nil
		}
		return ev
	})

	ui.lastFocus = ui.app.GetFocus()
	ui.app.SetRoot(modal, true)
	ui.app.SetFocus(modal)
}

// Case Filter modal: filter cases by name (Title), status, and severity.
// Only intended to be opened when the Cases sidebar has focus.
func (ui *UI) showCaseFilterModal() {
	// Build form with theme styling
	form := tview.NewForm()
	form.SetTitle(" Set Case Filters (Name | Status | Severity) ")
	form.SetBorder(true)
	form.SetBackgroundColor(ui.theme.Surface)
	form.SetFieldBackgroundColor(ui.theme.Surface)
	form.SetFieldTextColor(ui.theme.TextPrimary)
	form.SetLabelColor(ui.theme.TextPrimary)
	form.SetButtonBackgroundColor(ui.theme.SelectionBg)
	form.SetButtonTextColor(ui.theme.SelectionFg)
	form.SetBorderColor(ui.theme.FocusBorder)

	// Name contains
	nameStr := ui.caseFilterName
	form.AddInputField("Name contains", nameStr, 40, nil, func(text string) {
		nameStr = text
	})

	// Status section (no custom multi-select)
	statusOptions := []string{"Any", "Open", "Investigating", "Contained", "Closed"}
	statusIdx := 0 // Any
	if len(ui.caseFilterStatuses) == 1 {
		switch {
		case ui.caseFilterStatuses["open"]:
			statusIdx = 1
		case ui.caseFilterStatuses["investigating"]:
			statusIdx = 2
		case ui.caseFilterStatuses["contained"]:
			statusIdx = 3
		case ui.caseFilterStatuses["closed"]:
			statusIdx = 4
		}
	}
	statusDD := tview.NewDropDown()
	statusDD.SetLabel("Status")
	statusDD.SetOptions(statusOptions, func(text string, idx int) {
		statusIdx = idx
	})
	statusDD.SetCurrentOption(statusIdx)
	statusDD.SetFieldTextColor(ui.theme.TextPrimary)
	statusDD.SetFieldBackgroundColor(ui.theme.Surface)
	statusDD.SetLabelColor(ui.theme.TextPrimary)
	form.AddFormItem(statusDD)

	// Severity section (no custom multi-select)
	sevOptions := []string{"Any", "Low", "Medium", "High", "Critical"}
	sevIdx := 0 // Any
	if len(ui.caseFilterSeverities) == 1 {
		switch {
		case ui.caseFilterSeverities["low"]:
			sevIdx = 1
		case ui.caseFilterSeverities["medium"]:
			sevIdx = 2
		case ui.caseFilterSeverities["high"]:
			sevIdx = 3
		case ui.caseFilterSeverities["critical"]:
			sevIdx = 4
		}
	}
	sevDD := tview.NewDropDown()
	sevDD.SetLabel("Severity")
	sevDD.SetOptions(sevOptions, func(text string, idx int) {
		sevIdx = idx
	})
	sevDD.SetCurrentOption(sevIdx)
	sevDD.SetFieldTextColor(ui.theme.TextPrimary)
	sevDD.SetFieldBackgroundColor(ui.theme.Surface)
	sevDD.SetLabelColor(ui.theme.TextPrimary)
	form.AddFormItem(sevDD)

	// Buttons
	form.AddButton("Apply", func() {
		// Compute new status map (single-choice only)
		newStatus := map[string]bool{}
		switch statusIdx {
		case 0: // Any -> leave empty
		case 1:
			newStatus["open"] = true
		case 2:
			newStatus["investigating"] = true
		case 3:
			newStatus["contained"] = true
		case 4:
			newStatus["closed"] = true
		}

		newSev := map[string]bool{}
		switch sevIdx {
		case 0: // Any -> leave empty
		case 1:
			newSev["low"] = true
		case 2:
			newSev["medium"] = true
		case 3:
			newSev["high"] = true
		case 4:
			newSev["critical"] = true
		}

		// Update state first
		ui.caseFilterName = strings.TrimSpace(nameStr)
		ui.caseFilterStatuses = newStatus
		ui.caseFilterSeverities = newSev
		ui.cases = ui.applyCaseFilters(ui.allCases)

		// Selection stability: clear if filtered out
		if ui.selectedCaseID != "" {
			found := false
			for _, c := range ui.cases {
				if c.ID == ui.selectedCaseID {
					found = true
					break
				}
			}
			if !found {
				ui.selectedCaseID = ""
				ui.showAll = true
			}
		}

		// Restore layout first to close modal
		ui.restoreMainLayout()
		
		// Update UI in background to avoid deadlock
		go func() {
			ui.app.QueueUpdateDraw(func() {
				ui.sidebar.Clear()
				if len(ui.cases) > 0 {
					for i, case_ := range ui.cases {
						title := case_.Title
						if len(title) > 40 {
							title = title[:37] + "..."
						}
						severity := strings.ToUpper(case_.Severity)
						severityColor := ui.getSeverityColor(case_.Severity)
						caseNumber := i + 1
						mainText := fmt.Sprintf("[%s](%d)[-] [%s]%s[-]", ui.theme.TagAccent, caseNumber, ui.theme.TagTextPrimary, title)
						secondaryText := fmt.Sprintf("[%s]%s[-] | %s | %d events",
							severityColor,
							severity,
							strings.ToLower(strings.TrimSpace(case_.Status)),
							case_.EventCount,
						)
						ui.sidebar.AddItem(mainText, secondaryText, 0, nil)
					}
					ui.sidebar.SetCurrentItem(0)
				}

				ui.recomputeOverviewAfterCaseFilter()
				ui.setStatusDirect("[%s]Applied case filters (visible cases: %d)[-:-:-]", ui.theme.TagAccent, len(ui.cases))
			})
		}()
	})

	// Clear button removed per UX: Shift+F remains as the global clear shortcut when Cases sidebar is focused.

	form.AddButton("Cancel", func() {
		ui.restoreMainLayout()
	})

	// Esc to cancel (schedule UI change to avoid re-entrancy)
	form.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
		if ev.Key() == tcell.KeyEsc {
			ui.restoreMainLayout()
			return nil
		}
		return ev
	})

	ui.lastFocus = ui.app.GetFocus()
	ui.app.SetRoot(form, true)
	ui.app.SetFocus(form)
	ui.setStatusDirect("[%s]Tab/Shift+Tab: navigate • Enter: open dropdown • Apply/Cancel at bottom[-:-:-]", ui.theme.TagAccent)
}

// clearCaseFilters resets the case filters and updates the sidebar and overview.
func (ui *UI) clearCaseFilters() {
	// Reset state first
	ui.caseFilterName = ""
	ui.caseFilterStatuses = map[string]bool{}
	ui.caseFilterSeverities = map[string]bool{}

	// Recompute filtered list
	ui.cases = ui.applyCaseFilters(ui.allCases)

	// Perform UI mutations in a single batch from a background goroutine to avoid deadlock
	// when invoked from key handlers (e.g., Shift+F).
	go func() {
		ui.app.QueueUpdateDraw(func() {
			// Rebuild sidebar directly (avoid nested QueueUpdate calls)
			ui.sidebar.Clear()
			if len(ui.cases) > 0 {
				for i, case_ := range ui.cases {
					title := case_.Title
					if len(title) > 40 {
						title = title[:37] + "..."
					}
					severity := strings.ToUpper(case_.Severity)
					severityColor := ui.getSeverityColor(case_.Severity)
					caseNumber := i + 1
					mainText := fmt.Sprintf("[%s](%d)[-] [%s]%s[-]", ui.theme.TagAccent, caseNumber, ui.theme.TagTextPrimary, title)
					secondaryText := fmt.Sprintf("[%s]%s[-] | %s | %d events",
						severityColor,
						severity,
						strings.ToLower(strings.TrimSpace(case_.Status)),
						case_.EventCount,
					)
					ui.sidebar.AddItem(mainText, secondaryText, 0, nil)
				}
				ui.sidebar.SetCurrentItem(0)
			}

			// Update overview and status within the same batch
			ui.recomputeOverviewAfterCaseFilter()
			ui.setStatusDirect("[%s]Case filters cleared[-:-:-]", ui.theme.TagAccent)
		})
	}()
}

// recomputeOverviewAfterCaseFilter recomputes the Cases overview counts using the current filtered list.
// It keeps the ALL EVENTS total from the current ALL-context state to avoid blocking DB calls on the UI thread.
func (ui *UI) recomputeOverviewAfterCaseFilter() {
	totalCases := len(ui.cases)
	openN, invN, closeN := 0, 0, 0
	for _, c := range ui.cases {
		switch strings.ToLower(strings.TrimSpace(c.Status)) {
		case "open":
			openN++
		case "investigating", "investigation":
			invN++
		case "contained":
			// treat contained as its own or fold into closed? keep as-is (separate count not displayed)
			// We don't have a separate field in UI so ignore; most UIs tally open/investigating/closed.
		case "closed", "close":
			closeN++
		}
	}
	eventsTotal := 0
	if s := ui.getOrInitState(contextAll); s != nil {
		eventsTotal = s.totalCount
	}
	ui.updateOverview(eventsTotal, totalCases, openN, invN, closeN)
}

// ApplyLLMProvider updates the active LLM provider for the UI and propagates
// the change to the active Case Management screen (Copilot and Overview summary).
func (ui *UI) ApplyLLMProvider(p llm.LLMProvider) {
	if p == nil {
		p = &llm.LocalStub{}
	}
	ui.llm = p
	// Propagate to active Case Management instance (live switch)
	if ui.activeCM != nil {
		if cp, ok := p.(llm.ChatProvider); ok {
			ui.activeCM.llm = cp
		} else {
			ui.activeCM.llm = &llm.LocalStub{}
		}
	}
	// Reflect change in status (safe even if not running)
	if ui.statusBar != nil {
		ui.setStatusDirect("[%s]LLM provider applied[-:-:-]", ui.theme.TagAccent)
	}
}

// RefreshAllEventsAsync triggers a non-blocking reload of events using the UI's
// existing guarded reload scheduler. If source is empty, a default label is used.
// Safe to call from background goroutines; it does not block the UI thread.
func (ui *UI) RefreshAllEventsAsync(source string) {
	if ui == nil {
		return
	}
	if strings.TrimSpace(source) == "" {
		source = "live:auto"
	}
	// scheduleEventsReload handles re-entrancy, context, and dispatching the correct loader.
	go ui.scheduleEventsReload(source)
}