package ui

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/buildinfo"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/ingest"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/llm"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/logging"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/ocsf"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/paths"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/store"
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

/*
   Theming model (color-only change set)

   - Adds a lightweight Theme with widget colors (tcell.Color) and color tag strings for text markup.
   - Provides three palettes: dark (default), gruvbox, light.
   - Adds keyboard-first UX bindings: h/l focus move, j/k selection move, g/G top/bottom, J/K page, ?: help alias,
     t/T/C theme toggles, Esc clears status. Existing keys unchanged.
*/

// Theme defines UI color tokens used across widgets and text tags.
type Theme struct {
	// Widget colors
	Canvas        tcell.Color
	Bg            tcell.Color
	Surface       tcell.Color
	SurfaceRaised tcell.Color
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
	TagTextPrimary      string
	TagMuted            string
	TagAccent           string
	TagSuccess          string
	TagWarning          string
	TagError            string
	TagSeverityCritical string
	TagSeverityHigh     string
	TagSeverityMedium   string
	TagSeverityLow      string
	TagSeverityInfo     string
}

// helpers
func hex(s string) tcell.Color { return tcell.GetColor(s) }

func themeDark() Theme {
	return Theme{
		Canvas:        hex("#080b0f"),
		Bg:            hex("#0e1116"),
		Surface:       hex("#12161e"),
		SurfaceRaised: hex("#1c2330"),
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
		SeverityHigh:     hex("#ff9e3d"),
		SeverityMedium:   hex("#ffe066"),
		SeverityLow:      hex("#87ffaf"),
		SeverityInfo:     hex("#87afff"),

		TagTextPrimary:      "#e6edf3",
		TagMuted:            "#8a939f",
		TagAccent:           "#2dd4bf",
		TagSuccess:          "#22c55e",
		TagWarning:          "#f59e0b",
		TagError:            "#ef4444",
		TagSeverityCritical: "#ff5f5f",
		TagSeverityHigh:     "#ff9e3d",
		TagSeverityMedium:   "#ffe066",
		TagSeverityLow:      "#87ffaf",
		TagSeverityInfo:     "#87afff",
	}
}

func themeMidnight() Theme {
	return Theme{
		Canvas:        hex("#0b1016"),
		Bg:            hex("#0b1016"),
		Surface:       hex("#111923"),
		SurfaceRaised: hex("#182432"),
		Border:        hex("#1f2d3e"),
		FocusBorder:   hex("#56d4ff"),
		SelectionBg:   hex("#182432"),
		SelectionFg:   hex("#e6edf3"),
		TextPrimary:   hex("#e6edf3"),
		TextMuted:     hex("#8b9bad"),
		Accent:        hex("#56d4ff"),
		Success:       hex("#67d39a"),
		Warning:       hex("#f4c95d"),
		Error:         hex("#ff5c70"),
		Header:        hex("#56d4ff"),

		TableHeader:   hex("#56d4ff"),
		TableHeaderBg: hex("#111923"),
		TableRow:      hex("#e6edf3"),
		TableRowMuted: hex("#8b9bad"),
		TableZebra1:   hex("#111923"),
		TableZebra2:   hex("#0b1016"),

		SeverityCritical: hex("#ff5c70"),
		SeverityHigh:     hex("#ff8c33"),
		SeverityMedium:   hex("#f6d365"),
		SeverityLow:      hex("#78d6a3"),
		SeverityInfo:     hex("#56d4ff"),

		TagTextPrimary:      "#e6edf3",
		TagMuted:            "#8b9bad",
		TagAccent:           "#56d4ff",
		TagSuccess:          "#67d39a",
		TagWarning:          "#f4c95d",
		TagError:            "#ff5c70",
		TagSeverityCritical: "#ff5c70",
		TagSeverityHigh:     "#ff8c33",
		TagSeverityMedium:   "#f6d365",
		TagSeverityLow:      "#78d6a3",
		TagSeverityInfo:     "#56d4ff",
	}
}

func themeHighContrast() Theme {
	return Theme{
		Canvas:        hex("#000000"),
		Bg:            hex("#000000"),
		Surface:       hex("#1a1a1a"),
		SurfaceRaised: hex("#333333"),
		Border:        hex("#ffffff"),
		FocusBorder:   hex("#ffff00"),
		SelectionBg:   hex("#ffffff"),
		SelectionFg:   hex("#000000"),
		TextPrimary:   hex("#ffffff"),
		TextMuted:     hex("#cccccc"),
		Accent:        hex("#ffff00"),
		Success:       hex("#00ff00"),
		Warning:       hex("#ffaa00"),
		Error:         hex("#ff0000"),
		Header:        hex("#ffff00"),

		TableHeader:   hex("#ffff00"),
		TableHeaderBg: hex("#333333"),
		TableRow:      hex("#ffffff"),
		TableRowMuted: hex("#cccccc"),
		TableZebra1:   hex("#1a1a1a"),
		TableZebra2:   hex("#000000"),

		SeverityCritical: hex("#ff0000"),
		SeverityHigh:     hex("#ffaa00"),
		SeverityMedium:   hex("#ffff00"),
		SeverityLow:      hex("#00ff00"),
		SeverityInfo:     hex("#00ffff"),

		TagTextPrimary:      "#ffffff",
		TagMuted:            "#cccccc",
		TagAccent:           "#ffff00",
		TagSuccess:          "#00ff00",
		TagWarning:          "#ffaa00",
		TagError:            "#ff0000",
		TagSeverityCritical: "#ff0000",
		TagSeverityHigh:     "#ffaa00",
		TagSeverityMedium:   "#ffff00",
		TagSeverityLow:      "#00ff00",
		TagSeverityInfo:     "#00ffff",
	}
}

func themeColorblind() Theme {
	return Theme{
		Canvas:        hex("#121212"),
		Bg:            hex("#121212"),
		Surface:       hex("#1e1e1e"),
		SurfaceRaised: hex("#2c2c2c"),
		Border:        hex("#3d3d3d"),
		FocusBorder:   hex("#56b4e9"), // Sky blue
		SelectionBg:   hex("#0072b2"), // Blue
		SelectionFg:   hex("#ffffff"),
		TextPrimary:   hex("#ffffff"),
		TextMuted:     hex("#a0a0a0"),
		Accent:        hex("#56b4e9"), // Sky blue
		Success:       hex("#009e73"), // Bluish green
		Warning:       hex("#f0e442"), // Yellow
		Error:         hex("#d55e00"), // Vermillion
		Header:        hex("#56b4e9"),

		TableHeader:   hex("#56b4e9"),
		TableHeaderBg: hex("#2c2c2c"),
		TableRow:      hex("#ffffff"),
		TableRowMuted: hex("#a0a0a0"),
		TableZebra1:   hex("#1e1e1e"),
		TableZebra2:   hex("#121212"),

		// Chosen against the three dichromacies rather than by eye.
		// Vermillion and orange are 67 apart in ordinary vision and
		// collapse to 51 under deuteranopia — the exact failure this
		// palette exists to avoid. This set keeps the familiar
		// red-orange-yellow-green-blue and stays 69 apart at worst under
		// protanopia, deuteranopia and tritanopia alike.
		SeverityCritical: hex("#cc3311"),
		SeverityHigh:     hex("#ee7733"),
		SeverityMedium:   hex("#f0e442"), // Yellow
		SeverityLow:      hex("#009e73"), // Bluish green
		SeverityInfo:     hex("#56b4e9"), // Sky blue

		TagTextPrimary:      "#ffffff",
		TagMuted:            "#a0a0a0",
		TagAccent:           "#56b4e9",
		TagSuccess:          "#009e73",
		TagWarning:          "#f0e442",
		TagError:            "#d55e00",
		TagSeverityCritical: "#cc3311",
		TagSeverityHigh:     "#ee7733",
		TagSeverityMedium:   "#f0e442",
		TagSeverityLow:      "#009e73",
		TagSeverityInfo:     "#56b4e9",
	}
}

func themeGruvbox() Theme {
	return Theme{
		Canvas:        hex("#1d2021"),
		Bg:            hex("#282828"), // bg0
		Surface:       hex("#32302f"), // bg0_s
		SurfaceRaised: hex("#3c3836"),
		Border:        hex("#504945"), // bg2
		FocusBorder:   hex("#fe8019"), // bright orange
		SelectionBg:   hex("#504945"),
		SelectionFg:   hex("#fbf1c7"), // fg0
		TextPrimary:   hex("#ebdbb2"), // fg1
		TextMuted:     hex("#928374"), // gray
		Accent:        hex("#fe8019"), // bright orange
		Success:       hex("#b8bb26"), // bright green
		Warning:       hex("#fabd2f"), // bright yellow
		Error:         hex("#fb4934"), // bright red
		Header:        hex("#fabd2f"),

		// Table colors
		TableHeader:   hex("#fabd2f"),
		TableHeaderBg: hex("#3c3836"), // bg1
		TableRow:      hex("#ebdbb2"),
		TableRowMuted: hex("#a89984"), // fg4
		TableZebra1:   hex("#32302f"),
		TableZebra2:   hex("#282828"),

		SeverityCritical: hex("#fb4934"), // red
		SeverityHigh:     hex("#fe8019"), // orange
		SeverityMedium:   hex("#fabd2f"), // yellow
		SeverityLow:      hex("#b8bb26"), // green
		SeverityInfo:     hex("#83a598"), // blue

		TagTextPrimary:      "#ebdbb2",
		TagMuted:            "#928374",
		TagAccent:           "#fe8019",
		TagSuccess:          "#b8bb26",
		TagWarning:          "#fabd2f",
		TagError:            "#fb4934",
		TagSeverityCritical: "#fb4934",
		TagSeverityHigh:     "#fe8019",
		TagSeverityMedium:   "#fabd2f",
		TagSeverityLow:      "#b8bb26",
		TagSeverityInfo:     "#83a598",
	}
}

func themeLight() Theme {
	return Theme{
		Canvas:        hex("#eef2f6"),
		Bg:            hex("#f6f8fa"),
		Surface:       hex("#ffffff"),
		SurfaceRaised: hex("#e2e8f0"),
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

		SeverityCritical: hex("#b91c1c"),
		SeverityHigh:     hex("#ea580c"),
		SeverityMedium:   hex("#a16207"),
		SeverityLow:      hex("#15803d"),
		SeverityInfo:     hex("#1d4ed8"),

		TagTextPrimary:      "#111827",
		TagMuted:            "#6b7280",
		TagAccent:           "#2563eb",
		TagSuccess:          "#15803d",
		TagWarning:          "#b45309",
		TagError:            "#b91c1c",
		TagSeverityCritical: "#b91c1c",
		TagSeverityHigh:     "#ea580c",
		TagSeverityMedium:   "#a16207",
		TagSeverityLow:      "#15803d",
		TagSeverityInfo:     "#1d4ed8",
	}
}

// themeBasic is a 16-color safe theme for terminals without truecolor support.
func themeBasic() Theme {
	return Theme{
		Canvas:        tcell.ColorBlack,
		Bg:            tcell.ColorBlack,
		Surface:       tcell.ColorBlack,
		SurfaceRaised: tcell.ColorBlack,
		Border:        tcell.ColorWhite,
		FocusBorder:   tcell.ColorBlue,
		SelectionBg:   tcell.ColorWhite,
		SelectionFg:   tcell.ColorBlack,
		TextPrimary:   tcell.ColorWhite,
		TextMuted:     tcell.ColorGray,
		Accent:        tcell.ColorBlue,
		Success:       tcell.ColorGreen,
		Warning:       tcell.ColorYellow,
		Error:         tcell.ColorRed,
		Header:        tcell.ColorYellow,

		// Table colors
		TableHeader:   tcell.ColorYellow,
		TableHeaderBg: tcell.ColorBlack,
		TableRow:      tcell.ColorWhite,
		TableRowMuted: tcell.ColorGray,
		TableZebra1:   tcell.ColorBlack,
		TableZebra2:   tcell.ColorBlack,

		SeverityCritical: tcell.ColorRed,
		SeverityHigh:     tcell.ColorFuchsia,
		SeverityMedium:   tcell.ColorYellow,
		SeverityLow:      tcell.ColorGreen,
		SeverityInfo:     tcell.ColorBlue,

		TagTextPrimary:      "white",
		TagMuted:            "gray",
		TagAccent:           "blue",
		TagSuccess:          "green",
		TagWarning:          "yellow",
		TagError:            "red",
		TagSeverityCritical: "red",
		TagSeverityHigh:     "fuchsia",
		TagSeverityMedium:   "yellow",
		TagSeverityLow:      "green",
		TagSeverityInfo:     "blue",
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
	logger *logging.Logger

	// Layout components
	layout       *tview.Flex
	leftCol      *tview.Flex
	allCasesInfo *tview.TextView
	sidebar      *tview.List
	mainPanel    *tview.Flex
	eventList    *tview.Table
	eventDetail  *tview.TextView
	statusBar    *tview.TextView

	// State
	cases           []store.Case
	selectedCaseID  string
	events          []store.Event
	selectedEventID string
	// map of selected event IDs for multi-select actions
	selectedEventIDs map[string]bool

	// map of selected finding IDs for multi-select actions

	// eventsLoad and findingsLoad guard their own collections. One flag served
	// both, so entering Triage and then Events in quick succession left the
	// events load a no-op while the findings load repainted the shared table.
	eventsLoad   loadGuard
	findingsLoad loadGuard
	showAll      bool                        // when true, sidebar selection is "ALL EVENTS"
	queryStates  map[string]*EventQueryState // per-context (ALL or caseID) filter+pagination
	// triageSearchBar is the findings search field while it is open, and
	// triageSearchGen discards results for a query the analyst has moved on from.
	triageSearchBar *tview.InputField
	triageSearchGen int

	// indicators is the cross-database Indicators screen.
	indicators *indicatorsView

	// activeModal is whatever is currently rooted over the main layout. Set by
	// showModal and friends, cleared when the layout is restored.
	activeModal tview.Primitive

	// termWidth is the terminal's width from the last frame's preamble.
	//
	// Panels that wrap text need a width before they draw, and tview's
	// GetInnerRect reports the *previous* frame's rect — zero on the first
	// paint, so a pane that asked the widget wrapped to a fallback width and
	// corrected itself one repaint later.
	termWidth int

	// findingAsset is the host or user each loaded finding fired on, keyed by
	// finding id and filled once per page rather than once per row.
	findingAsset map[string]string
	// findingCase is the title of each case the loaded findings belong to,
	// keyed by case id.
	findingCase map[string]string
	// filterModal is Triage's filter panel while it is open, so a reload can
	// refresh the count it shows.
	filterModal *triageFilterModal
	// reports is the Reports screen, built on first use.
	reports *reportsView

	// ephemeral marks a session whose database is thrown away when it ends —
	// the demo. Everything works; nothing survives, and the screen says so.
	ephemeral bool

	// listener is the HTTP receiver, when the build has one.
	listener IngestListener

	// findingInspect holds the selected finding's context — its indicators and
	// their prevalence, and the name of the case it belongs to — loaded off the
	// UI goroutine behind a debounce.
	findingInspect inspectorContext

	// loads counts the screen loads started and not yet finished.
	loads sync.WaitGroup

	// queryStatesMu guards the map itself, not the states in it.
	//
	// Load goroutines reach it through setStatus → buildStatusMain →
	// activeFilterTag while the UI goroutine is reading the same map to lay out
	// the status bar. The map was unsynchronised; the race was invisible only
	// because those goroutines used to deadlock on the update queue before they
	// got this far.
	queryStatesMu sync.Mutex

	// Findings triage queue. Findings are the analyst's unit of work; ALL EVENTS
	// remains available alongside it for raw-log triage.
	showFindings      bool
	findings          []store.Finding
	selectedFindingID string

	// lastVisit and markSince drive the dashboard's new-since-you-looked mark.
	// lastVisit is persisted; markSince is what it held when this visit began.
	lastVisit time.Time
	markSince time.Time

	// pendingFindingID is a finding to select once the Triage list has loaded.
	// It carries a selection across a screen change — Home's Enter, for one —
	// and is cleared as soon as it is honoured or found to be missing.
	pendingFindingID string
	findingsOpenOnly bool
	// findingsTotal is the unfiltered count from the last load, kept so the
	// queue can be repainted (e.g. on a theme change) without re-querying.
	findingsTotal int

	// Layout state
	currentLayoutMode LayoutMode
	isShortScreen     bool

	// Copilot drawer state

	// Theme state
	theme        Theme
	themeName    string
	hasTrueColor bool
	// screenAdopted records that the palette has been settled against the real
	// terminal, which can only happen once one exists.
	screenAdopted  bool
	themeApplying  int32
	filterApplying int32

	// Navigation tracking
	recentCases  []string
	recentPivots []string

	// Filters (time window for events list)
	filterStart time.Time
	filterEnd   time.Time

	// home is the Analyst Home screen while it is open. It owns timers, so it
	// has to be closed when the screen is replaced.
	home *homeView

	// casesPane is the Cases screen: the case list beside a briefing.
	casesPane *tview.Flex

	// Triage state. The filter is what the chip row shows and what the loader
	// turns into a query; the selection is keyed by finding uid so it survives
	// refresh, sort and filter changes.
	triage    *triageFilter
	triageSel *triageSelection
	chipRow   *tview.TextView
	strip     *tview.TextView

	// eventAtRow maps a table row to an index into ui.events. Cluster headers
	// occupy rows and hold no event, so a row number is no longer an offset.
	eventAtRow map[int]int

	// searchQuery is the active `/` search, empty when none. It is state
	// because the empty result of a search and the empty result of an unloaded
	// list say different things, and because the chip that shows it must be
	// removable.
	searchQuery string

	// pivot is the observable the event list is currently narrowed to, or nil.
	// It is state rather than a query parameter because the chip that shows it
	// has to be removable, and an invisible filter is indistinguishable from
	// missing data.
	pivot *pivotTarget

	// eventGroup is what the event list clusters by, eventClusters is the
	// result over the loaded page, and expandedCluster is the one open cluster.
	//
	// Expansion is keyed by label rather than by index so it survives a
	// re-render, and only one is open at a time: a list where everything is
	// expanded is the wall of log lines clustering exists to avoid.
	eventGroup      groupKey
	eventClusters   []eventCluster
	expandedCluster string

	// findingsUnfiltered is how many findings exist ignoring the filter, which
	// is what tells the two empty states apart. findingsErr degrades the table
	// body without replacing the screen.
	findingsUnfiltered int
	findingsErr        error

	// navRail is the destination list shown on every screen wider than 80
	// columns, and destination is the entry it marks. See nav.go.
	navRail     *tview.TextView
	destination destinationID

	// railShown is the navigation rail's current width, and needsClear marks a
	// frame that must clear the screen before drawing. See applyRailVisibility.
	railShown  int
	needsClear bool

	// watcher and enrichment report subsystem health to the evidence pulse.
	// Function-typed so the ui package depends on a shape rather than on the
	// ingest package and the plugin manager.
	watcher    func() WatcherStatus
	enrichment func() EnrichmentStatus

	// ingestDir is the drop folder actually being watched, so empty-state hints
	// can name it. Hardcoding a path in those hints is how they came to point at
	// data/incoming long after the watcher had moved to ./incoming.
	ingestDir string

	// Live enrichment refresh. openEventID mirrors selectedEventID for readers on
	// other goroutines; enrichNotify carries the IDs worth redrawing for.
	openEventID  atomic.Value // string
	enrichNotify chan string

	// Runtime
	// running is set for as long as app.Run() is in its event loop. Atomic
	// because background loaders read it from their own goroutines to decide
	// whether queueUpdate can be used. See queueUpdate.
	running atomic.Bool
	// inlineUpdate serialises queueUpdate's no-loop fallback, standing in for
	// the ordering the event loop gives once it is running.
	inlineUpdate sync.Mutex
	helpActive   bool
	lastFocus    tview.Primitive

	// Active Case Management screen (for live theme propagation)
	activeCM *CaseManagement

	// Global input capture for main UI (restored after returning from sub-screens)
	globalInputCapture func(*tcell.EventKey) *tcell.EventKey

	// Multi-key shortcut state

	// Context for cancellation
	ctx    context.Context
	cancel context.CancelFunc

	// Version info
	version string
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
	if ui.showFindings {
		return contextFindings
	}
	if !ui.showAll && ui.selectedCaseID != "" {
		return ui.selectedCaseID
	}
	return contextAll
}

// getOrInitState returns the per-context state, initializing defaults if missing.
func (ui *UI) getOrInitState(id string) *EventQueryState {
	ui.queryStatesMu.Lock()
	defer ui.queryStatesMu.Unlock()

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
func NewUI(ctx context.Context, store *store.Store, llmProvider llm.LLMProvider, logger *logging.Logger, version string) *UI {

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
		version:          version,
		// Buffered so an enrichment worker never waits on the UI. Arrivals for the
		// open event are rare (its own lookups), so this is generous.
		enrichNotify: make(chan string, 32),
	}
	ui.findingInspect.ui = ui
	ui.openEventID.Store("")

	// Enrichment is asynchronous, so without this the detail pane shows whatever
	// was true when the event was opened until the analyst presses 'r'.
	if store != nil {
		store.OnEnrichment(ui.enrichmentApplied)
	}

	// Initialize LLM provider from persisted settings when not provided by caller.
	if ui.llm == nil {
		if ui.logger != nil {
			ui.logger.Printf("No LLM provider passed in; attempting to load from %s", paths.Current().ConfigFile(paths.LLMSettingsName))
		}
		settings, _ := llm.LoadSettings(paths.Current().ConfigFile(paths.LLMSettingsName))
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
	// Restore the analyst's last choice; the default is used on a fresh
	// install or if the settings file is missing or unreadable.
	uiSettings := loadUISettings()
	ui.themeName = uiSettings.Theme
	ui.recentCases = uiSettings.RecentCases
	ui.recentPivots = uiSettings.RecentPivots
	ui.lastVisit = uiSettings.LastVisit
	if !ui.hasTrueColor {
		ui.theme = themeBasic()
	} else {
		ui.theme = themeBuilders[ui.themeName]()
	}

	ui.setupLayout()
	ui.setupKeybindings()
	ui.applyTheme() // apply colors after layout assembled
	ui.app.EnableMouse(true)

	return ui
}

// enrichmentApplied runs on the goroutine that applied the enrichment — an
// enrichment worker, mid-ingest. It must not block, so it filters on the open
// event and drops the notification if the UI is already behind: the next arrival
// or a manual 'r' will pick the change up either way.
func (ui *UI) enrichmentApplied(eventID string) {
	if open, _ := ui.openEventID.Load().(string); open != eventID {
		return
	}
	select {
	case ui.enrichNotify <- eventID:
	default:
	}
}

// watchEnrichments redraws the detail pane when the open event's enrichment lands.
func (ui *UI) watchEnrichments() {
	for {
		select {
		case <-ui.ctx.Done():
			return
		case eventID := <-ui.enrichNotify:
			ui.queueUpdate(func() {
				// Re-check on the UI goroutine: the selection may have moved
				// between the notification and this redraw.
				if ui.selectedEventID == eventID {
					ui.showEventDetails()
				}
			})
		}
	}
}

// Start starts the TUI application
func (ui *UI) Start(ctx context.Context) error {
	ui.logger.Println("Starting TUI application")

	// Live before any goroutine below can queue against the application.
	//
	// ui.queueUpdate runs its function inline when this is false, which is what
	// makes the UI drivable from tests. Setting it here rather than beside
	// app.Run means the startup goroutines cannot read "not running", decide to
	// mutate widgets inline, and then race the event loop that started between
	// the two. They queue instead, and the queue drains as soon as Run does.
	ui.running.Store(true)

	go ui.watchEnrichments()

	// Show UI immediately, then load data asynchronously
	ui.logger.Println("Starting tview application...")

	// Load initial data in background
	go func() {
		ui.logger.Println("Loading initial data...")
		if err := ui.refreshCases(); err != nil {
			ui.logger.Printf("Failed to load cases: %v", err)
			ui.queueUpdate(func() {
				ui.setStatusDirect("[red]Error loading cases: %v", err)
			})
		} else {
			ui.logger.Printf("Loaded %d cases successfully", len(ui.cases))
			// Entry routing: the UI always opens on Analyst Home.
			//
			// Whether there is a database at all is decided in cmd, before the
			// store is opened, and a missing one never reaches here — it gets
			// the Welcome Screen instead. So by the time the UI starts there is
			// exactly one destination, and it renders its own empty states.
			//
			// This used to branch four ways, on whether there were findings,
			// then cases, then events. It meant the first screen an analyst saw
			// changed with the contents of the database, so there was no screen
			// to learn and no stable place to return to.
			ui.queueUpdate(func() {
				ui.enterScreen(destHome)
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
			ui.queueUpdate(func() { ui.cycleTheme() })
			time.Sleep(1200 * time.Millisecond)
			ui.queueUpdate(func() { ui.cycleTheme() })
		}()
	}

	err := ui.app.Run()
	ui.running.Store(false)
	ui.logger.Printf("app.Run() returned with error: %v", err)
	return err
}

// adoptScreen settles the palette against the terminal that is actually there.
//
// Two things are only knowable once a screen exists, and both were decided
// before there was one.
//
// The theme's background becomes the screen's default style. tcell clears with
// that style — at Init, and on every screen switch here — and it starts as the
// terminal's own colours, so the application showed the terminal's background
// until the first panel painted over it and kept it anywhere no panel reached.
// On a light terminal profile that reads as the application starting light
// whichever theme is set.
//
// And the colour depth comes from the terminal rather than from a guess at the
// environment. detectTrueColor reads COLORTERM and TERM before the screen is
// open, and terminals that set neither — kitty, alacritty and screen among them
// — were told they had no colour, so the analyst's chosen theme was silently
// replaced by the sixteen-colour fallback. tcell downsamples a full palette to
// whatever the terminal can show, so the fallback is only for terminals that
// genuinely cannot manage 256.
func (ui *UI) adoptScreen(screen tcell.Screen) {
	if screen == nil {
		return
	}

	if !ui.screenAdopted {
		ui.screenAdopted = true
		if !ui.hasTrueColor && screen.Colors() >= 256 {
			ui.hasTrueColor = true
			if build, ok := themeBuilders[ui.themeName]; ok {
				ui.theme = build()
				// Restyling walks every widget and repaints the screen, which
				// is not something to do part-way through a draw — it queues
				// updates, and this is running on the loop those updates wait
				// for. It goes back to the loop as an update of its own.
				go ui.queueUpdate(ui.applyTheme)
			}
		}
	}

	screen.SetStyle(tcell.StyleDefault.Background(ui.theme.Canvas))
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
	attachTableScrollbar(ui.eventList, 1, &ui.theme)

	ui.eventDetail = tview.NewTextView()
	ui.eventDetail.SetTitle(" Event Details ")
	ui.eventDetail.SetBorder(true)
	ui.eventDetail.SetTitleAlign(tview.AlignLeft)
	ui.eventDetail.SetDynamicColors(true)
	ui.eventDetail.SetWordWrap(true)
	ui.eventDetail.SetScrollable(true)
	// A pane that scrolls with no mark on it gives no way to know there is
	// anything below the fold. The theme is passed by pointer so the bar
	// follows a theme change without rebuilding the widget.
	attachScrollbar(ui.eventDetail, &ui.theme)

	ui.statusBar = tview.NewTextView()
	ui.statusBar.SetDynamicColors(true)
	ui.statusBar.SetText("[yellow]Console-IR v1.0[white] | [green]q[white]:quit [green]r[white]:refresh [green]Enter[white]:select [green]Tab[white]:navigate")

	// Create main panel (right side)
	ui.mainPanel = tview.NewFlex().
		SetDirection(tview.FlexRow).
		AddItem(ui.eventList, 0, 2, true).
		AddItem(ui.eventDetail, 0, 1, false)

	// The navigation rail. Its contents come from the destination table in
	// nav.go, so the rail cannot advertise a screen the keys do not reach.
	ui.navRail = ui.buildNavRail()
	ui.renderNavRail()

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
	ui.allCasesInfo.SetText(fmt.Sprintf("[%s](2) EVENTS (0)[-]\n[%s](3) CASES (0)[-]\n[%s]OPEN[-] - 0  [%s]INVESTIGATING[-] - 0  [%s]CLOSED[-] - 0",
		ui.theme.TagAccent, ui.theme.TagAccent, ui.theme.TagTextPrimary, ui.theme.TagTextPrimary, ui.theme.TagTextPrimary))

	// The left column is the rail and nothing else. It used to carry the app
	// title and the Cases list too, which is why it needed 45 columns and had
	// to be hidden on Home.
	// The rail alone. The version block that used to sit under it said
	// "Console-IR" a second time and spent two of twenty-two columns saying it;
	// both facts are in the status bar, which every screen has anyway.
	ui.leftCol = tview.NewFlex().
		SetDirection(tview.FlexRow).
		AddItem(ui.navRail, 0, 1, false)

	// Create main layout - wider left column for better display
	ui.layout = tview.NewFlex().
		SetDirection(tview.FlexColumn).
		AddItem(ui.leftCol, navRailWidth, 0, true).
		AddItem(ui.mainPanel, 0, 1, true)
	// Track the width the layout was actually built with. Left at the zero
	// value, applyRailVisibility would read "already hidden" on a first launch
	// that lands on Home and never hide it.
	ui.railShown = navRailWidth

	// Create root layout with status bar
	root := tview.NewFlex().
		SetDirection(tview.FlexRow).
		AddItem(ui.layout, 0, 1, true).
		AddItem(ui.statusBar, 1, 0, false)

	ui.app.SetRoot(root, true)

	// Responsive layout handling, plus the rail's visibility, which depends on
	// the destination as well as on the width.
	ui.app.SetBeforeDrawFunc(func(screen tcell.Screen) bool {
		ui.adoptScreen(screen)
		ui.termWidth, _ = screen.Size()
		ui.updateLayoutMode(screen)
		ui.applyRailVisibility()
		// tview does not clear between frames, so a panel that shrinks or
		// disappears leaves its old cells on screen. Hiding the rail vacates 45
		// columns that nothing then paints over, and switching the main view
		// leaves the previous screen's borders showing around the new one.
		if ui.needsClear {
			screen.Clear()
			ui.needsClear = false
		}
		return false
	})

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
			// The digits belong to navigation. They used to be intercepted here
			// for "type a case number", which the global capture claimed first
			// for 1 to 5 — so it worked from the sixth case onwards and was
			// discoverable by nobody. Arrowing the list swaps the briefing now.
		}
		return ev
	})

	// The rail is a read-only legend, not a focus target: it is reached with
	// the digits, from anywhere. Focus starts on the content.
	ui.app.SetFocus(ui.eventList)
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
		if ui.showFindings {
			ui.showFindingDetails()
			return
		}
		if row > 0 && row-1 < len(ui.events) { // Skip header row
			e := ui.eventForRow(row)
			if e == nil {
				return
			}
			ui.selectedEventID = e.ID
			ui.showEventDetails()
		}
	})

	// Event list selection change
	ui.eventList.SetSelectionChangedFunc(func(row, col int) {
		if ui.showFindings {
			// Debounced: this fires once per row while an arrow key is held,
			// and the inspector's context costs a query per indicator.
			ui.findingSelectionChanged()
			return
		}
		if row > 0 && row-1 < len(ui.events) { // Skip header row
			e := ui.eventForRow(row)
			if e == nil {
				return
			}
			ui.selectedEventID = e.ID
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
			if ui.showFindings {
				ui.showFindingDetails()
				return nil
			}
			// A cluster header has no event behind it; Enter there is handled
			// by the global capture, which expands the cluster.
			if e := ui.eventForRow(row); e != nil {
				ui.selectedEventID = e.ID
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
			case 'y':
				// Copy raw JSON of selected item to clipboard via OSC 52
				row, _ := ui.eventList.GetSelection()
				if ui.showFindings {
					if row > 0 && row-1 < len(ui.findings) {
						ui.copyToClipboard(ui.findings[row-1].RawJSON)
					}
				} else {
					if row > 0 && row-1 < len(ui.events) {
						if e := ui.eventForRow(row); e != nil {
							ui.copyToClipboard(e.RawJSON)
						}
					}
				}
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

// copyToClipboard uses OSC 52 escape sequences to copy text to the system clipboard
// over SSH or terminal emulators that support it.
func (ui *UI) copyToClipboard(text string) {
	// Print OSC 52 sequence directly to stdout (bypassing tview briefly, though it might cause a slight flicker,
	// or write it through tcell if possible. tcell Screen does not have direct OSC 52 methods,
	// but writing to os.Stdout usually works).
	// For safety, we'll just log it for now since raw stdout writes can disrupt the TUI.
	// Actually, fmt.Printf("\033]52;c;%s\007", base64.StdEncoding.EncodeToString([]byte(text)))
	// works in most terminals.
	if ui.logger != nil {
		ui.logger.Printf("Clipboard copy triggered via OSC 52")
	}
	encoded := base64.StdEncoding.EncodeToString([]byte(text))
	fmt.Printf("\033]52;c;%s\007", encoded)
	ui.setStatusDirect("[%s]Copied to clipboard[-:-:-]", ui.theme.TagSuccess)
}

// screenKeys is the current screen's own key handler, or nil where the screen
// owns no keys.
//
// Adding a screen here is how it gets keys of its own. Returning nil from the
// handler claims the key; returning the event passes it on to the global
// bindings below.
func (ui *UI) screenKeys() func(*tcell.EventKey) *tcell.EventKey {
	switch ui.destination {
	case destHome:
		if ui.home != nil {
			return ui.home.handleKey
		}
	case destTriage:
		return ui.triageKeys
	case destEvents:
		return ui.eventsKeys
	case destCases:
		return ui.casesKeys
	case destIndicators:
		return ui.indicatorKeys
	case destReports:
		return ui.reportKeys
	}
	return nil
}

// Each screen's own key handler.
//
// Returning the event passes it on to the global bindings below; returning nil
// claims it. They start empty and are filled in per screen, which is what makes
// each screen's repair revertable on its own — a handler that claims nothing
// leaves that screen behaving exactly as it did before.
//
// Reports is deliberately absent: it is a static panel with no keys of its own.

// triageKeys are the queue's own.
//
// Everything here would otherwise be handled globally against the wrong state:
// c, a and Ctrl+A/Ctrl+D read the events selection map, so they answered "No
// events selected" with findings marked; s and v acted on the cursor row only
// while the strip above them advertised them as bulk actions.
func (ui *UI) triageKeys(ev *tcell.EventKey) *tcell.EventKey {
	switch ev.Key() {
	case tcell.KeyTab, tcell.KeyBacktab:
		// Between the two panels this screen has.
		//
		// Unclaimed it reached cycleFocus, which cycles the case sidebar, the
		// events list and the event detail — and the sidebar is not in Triage's
		// tree, so one of the three stops was invisible and the status line
		// announced "Focus: Cases" on the findings queue.
		ui.cycleTriageFocus()
		return nil

	case tcell.KeyEnter:
		// Nothing. It called showFindingDetails, which repaints what moving the
		// cursor has already painted — so Enter looked bound and did nothing.
		// Reading the detail is Tab; escalating is e.
		return nil

	case tcell.KeyCtrlA:
		ui.selectAllFindings()
		return nil
	case tcell.KeyCtrlD:
		ui.triageSelection().clear()
		ui.updateFindingsList(ui.findingsTotal)
		ui.repaintTriageChrome()
		return nil
	case tcell.KeyRune:
		switch ev.Rune() {
		case 'e':
			// One key. Escalation already offers "create a new case" beside
			// every existing one, so c and a were the same form under two more
			// names — three keys for one action.
			ui.escalateFindings(ui.triageTargets())
			return nil
		case 's', 'S':
			ui.showFindingStatusModal()
			return nil
		case 'v':
			ui.showFindingVerdictModal()
			return nil
		case 'f':
			// The chip menu. Globally f opens the events filter modal, and on
			// Triage it printed a sentence listing keys instead.
			ui.showTriageFilter()
			return nil
		case '/':
			// Findings, not events. Globally / opens the events full-text
			// search, which repainted this queue as an events list.
			ui.showTriageSearch()
			return nil
		}
	}
	return ev
}

// cycleTriageFocus moves between the queue and the detail pane.
func (ui *UI) cycleTriageFocus() {
	if ui.app == nil || ui.eventList == nil || ui.eventDetail == nil {
		return
	}
	if ui.app.GetFocus() == ui.eventDetail {
		ui.app.SetFocus(ui.eventList)
		ui.highlightFocus(ui.eventList)
		ui.setStatusDirect("[%s]Queue[-:-:-]", ui.theme.TagAccent)
		return
	}
	ui.app.SetFocus(ui.eventDetail)
	ui.highlightFocus(ui.eventDetail)
	ui.setStatusDirect("[%s]Selected finding[-:-:-] · ↑↓ scrolls", ui.theme.TagAccent)
}

// selectAllFindings marks every finding currently loaded.
func (ui *UI) selectAllFindings() {
	sel := ui.triageSelection()
	for _, f := range ui.findings {
		sel.ids[f.FindingUID] = true
	}
	ui.updateFindingsList(ui.findingsTotal)
	ui.repaintTriageChrome()
	ui.setStatusDirect("[%s]%s selected[-:-:-]", ui.theme.TagAccent, plural(sel.count(), "finding"))
}

// eventsKeys are the events list's own — including a case's event list, which
// is the same table over a narrower query.
func (ui *UI) eventsKeys(ev *tcell.EventKey) *tcell.EventKey {
	switch ev.Key() {
	case tcell.KeyTab, tcell.KeyBacktab:
		ui.cycleTriageFocus()
		return nil
	case tcell.KeyEnter:
		// Expand or collapse the cluster under the cursor.
		if c := ui.clusterAtRow(rowOf(ui.eventList)); c != nil {
			ui.toggleCluster(c.Label)
			return nil
		}
	case tcell.KeyRune:
		switch ev.Rune() {
		case 'z':
			// Cycle the grouping. Guarded globally on showAll, but
			// updateEventsList clusters a case's event list too — so inside a
			// case only the first cluster ever opened and the rest of the
			// events could not be reached at all.
			if len(ui.eventClusters) > 0 {
				ui.cycleEventGrouping()
				return nil
			}
		case 'p':
			// Pivot on an observable of the event under the cursor.
			//
			// Handled globally it had no screen guard and read ui.events, which
			// Triage does not clear — so p on a findings row mapped that row
			// through a stale row-to-event map and opened a menu for an
			// unrelated event.
			if e := ui.eventForRow(rowOf(ui.eventList)); e != nil {
				ui.showPivotMenu(*e)
			}
			return nil
		}
	}
	return ev
}

// rowOf is the selected row of a table, or -1 when there is none.
func rowOf(t *tview.Table) int {
	if t == nil {
		return -1
	}
	row, _ := t.GetSelection()
	return row
}

// casesKeys are the Cases screen's own.
func (ui *UI) casesKeys(ev *tcell.EventKey) *tcell.EventKey {
	if ev.Key() != tcell.KeyRune {
		return ev
	}
	switch ev.Rune() {
	case 'f':
		// The case filter, whatever has focus. Globally f picks between the
		// case filter and the events filter by asking which widget is focused,
		// so on this screen it opened the events filter whenever focus had
		// moved off the list.
		ui.showCaseFilterModal()
		return nil
	case 'c':
		// A new case, straight to the form.
		//
		// The global c is the events flow — mark events, then file them into a
		// new case — so on this screen, where there are no events to mark, the
		// key the footer advertises as "new case" answered "No events
		// selected. Use Space to select events first."
		ui.showCreateCaseModal()
		return nil
	case 'r':
		// The case list, and only that. Globally r also schedules an events
		// reload, which on this screen queries a table that is not on screen.
		ui.reloadCases()
		return nil
	}
	return ev
}

// reloadCases re-reads the case list without blocking the event loop.
func (ui *UI) reloadCases() {
	ui.setStatusDirect("[%s]Refreshing cases…[-:-:-]", ui.theme.TagAccent)
	ui.spawnLoad(func() {
		if err := ui.refreshCases(); err != nil {
			ui.queueUpdate(func() {
				ui.setStatusDirect("[%s]Could not refresh cases: %v[-:-:-]", ui.theme.TagError, err)
			})
			return
		}
		ui.queueUpdate(func() {
			ui.setStatusDirect("[%s]Cases refreshed[-:-:-]", ui.theme.TagSuccess)
		})
	})
}

// setupKeybindings sets up global keybindings
func (ui *UI) setupKeybindings() {
	handler := func(event *tcell.EventKey) *tcell.EventKey {
		// While a modal or form is active, allow it to handle all keys (avoid global shortcuts like q/h/Tab).
		if ui.isDialogActive() {
			return event
		}

		// The screen showing gets first refusal on every key.
		//
		// tview runs this application-wide capture before any primitive's own,
		// so a screen cannot own a key by binding it to one of its widgets:
		// whatever this handler claims never reaches the screen below. Asking
		// the screen first is the only way it can own anything — and until it
		// did, Home's handler was unreachable code and Tab on the dashboard
		// reached cycleFocus, which cycles widgets Home does not contain.
		if screen := ui.screenKeys(); screen != nil {
			if screen(event) == nil {
				return nil
			}
		}

		// A case owns Tab and Shift+Tab, which move between its seven tabs.
		//
		// This handler runs before any primitive's own capture, so anything it
		// claims never reaches the screen below. That is why case tabs did not
		// work: they were bound to digits, which this handler routes to
		// destinations, and then to brackets, which it routes to the copilot
		// drawer. Global navigation still applies inside a case; only the two
		// keys the case owns are passed through.
		// Log key events to help diagnose input handling
		if ui.logger != nil {
			ui.logger.Debug("input: key=%v rune=%q mod=%v", event.Key(), event.Rune(), event.Modifiers())
		}

		switch event.Key() {
		case tcell.KeyCtrlC:
			ui.app.Stop()
			return nil
		case tcell.KeyEnter:
			// Expanding a cluster is the Events screen's, and eventsKeys has it.
			// Let the focused primitive handle Enter otherwise — the sidebar's
			// own capture manages selection.
			return event
		case tcell.KeyEsc:
			// Esc moves one level out. Modals consume it before it reaches here,
			// so at this point the level to leave is the screen, and the level
			// outside every screen is Home. It never quits.
			if ui.onHome() {
				ui.setStatusDirect("[%s]Ready[-:-:-]", ui.theme.TagAccent)
				return nil
			}
			ui.enterScreen(destHome)
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
			case 'r':
				// Non-blocking refresh to avoid stalling the tview event loop
				ui.setStatusDirect("[%s]Refreshing...[-:-:-]", ui.theme.TagAccent)
				go func() {
					if err := ui.refreshCases(); err != nil {
						ui.queueUpdate(func() {
							ui.setStatusDirect("[%s]Error refreshing cases: %v[-:-:-]", ui.theme.TagError, err)
						})
					} else {
						ui.queueUpdate(func() {
							ui.setStatusDirect("[%s]Cases refreshed[-:-:-]", ui.theme.TagSuccess)
						})
					}
				}()
				// Schedule events reload according to current selection and filter state
				ui.refreshCurrentView("key:r")
				return nil
			case 's', 'S':
				if ui.showFindings {
					ui.showFindingStatusModal()
					return nil
				}
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
			case 'z':
				// Grouping is the Events screen's, and eventsKeys has it — §8
				// assigns `g`, but §7 already binds `g`/`G` to top and bottom,
				// so grouping took `z`: vim's fold prefix, which is what a
				// cluster is. Recorded as a deviation in the spec.
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
				if ui.showFindings {
					// The findings queue is not paged; without this, paging
					// would swap the queue out for events.
					ui.setStatusDirect("[%s]Findings are not paged • o toggles open/all[-:-:-]", ui.theme.TagMuted)
					return nil
				}
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
						ui.spawnLoad(func() { ui.scheduleEventsReload("page:Next") })
					} else {
						ui.setStatusDirect("[%s]Already at last page (%d/%d)[-:-:-]", ui.theme.TagMuted, s.pageIndex+1, maxPages)
					}
				}
				return nil
			case 'P':
				if ui.showFindings {
					// The findings queue is not paged; without this, paging
					// would swap the queue out for events.
					ui.setStatusDirect("[%s]Findings are not paged • o toggles open/all[-:-:-]", ui.theme.TagMuted)
					return nil
				}
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
						ui.spawnLoad(func() { ui.scheduleEventsReload("page:Prev") })
					} else {
						ui.setStatusDirect("[%s]Already at first page (1/?) [-:-:-]", ui.theme.TagMuted)
					}
				}
				return nil
			// Theme toggles
			case 't':
				// Applied on the UI goroutine: a theme change repaints every
				// screen, and queueing that from here would wait on the loop
				// this handler is running on.
				ui.cycleTheme()
				return nil
			case ',':
				// The comma is the settings key everywhere else, and this panel
				// is where the HTTP receiver's state is legible: whether it is
				// listening, on what address, and whether anyone who can reach
				// it may post.
				ui.showSettings()
				return nil
			case 'f':
				// Whose filter this is follows the screen, not the focus.
				//
				// It used to ask which widget had focus: the case sidebar meant
				// the case filter and anything else meant the events filter. So
				// the events filter opened on Indicators, on Reports, and on
				// Cases whenever the cursor had moved off the list — filtering
				// a table that screen does not show. Triage, Cases and
				// Indicators each claim f before this handler is reached.
				if !ui.hasEventsContext() {
					return event
				}
				ui.showCombinedFilterModal()
				return nil
			case 'F':
				if !ui.showFindings && ui.searchQuery != "" {
					ui.clearSearch()
					return nil
				}
				if !ui.showFindings && ui.pivot != nil {
					ui.clearPivot()
					return nil
				}
				if ui.showFindings {
					// Was a hint string with no effect. F is what the
					// filtered-out empty state tells the analyst to press.
					ui.clearTriageFilters()
					return nil
				}
				// By screen, for the same reason f is: clearing the events
				// filters from Indicators cleared filters on a list that
				// screen does not show.
				if ui.onCases() {
					ui.clearCaseFilters()
					return nil
				}
				if !ui.hasEventsContext() {
					return event
				}
				ui.clearCurrentContextFilters()
				return nil
			// Case creation shortcuts
			case 'c', 'a':
				// Both act on marked events, so both are the events screen's.
				//
				// Handled everywhere, they answered on screens that have no
				// events to mark: pressing a on the dashboard replied "No
				// events selected. Use Space to select events first", naming a
				// key that does nothing there either. Left unclaimed here, a
				// screen that has its own meaning for the key gets it — which
				// is how c on Cases opens the new-case form.
				if !ui.hasEventsContext() {
					return event
				}
				if len(ui.selectedEventIDs) == 0 {
					ui.setStatusDirect("[%s]No events selected — Space marks the row under the cursor[-:-:-]",
						ui.theme.TagWarning)
					return nil
				}
				if event.Rune() == 'c' {
					ui.showCreateCaseModal()
				} else {
					ui.showAddToExistingCaseModal()
				}
				return nil
			case 'v':
				if ui.showFindings {
					ui.showFindingVerdictModal()
					return nil
				}
			case 'e':
				if ui.showFindings {
					ui.escalateFindingToCase()
					return nil
				}
			case 'o':
				if ui.showFindings {
					ui.toggleTriageChip(chipOpen)
					return nil
				}
			case 'V':
				if ui.showFindings {
					ui.cycleTriageView()
					return nil
				}
			case 'x':
				if ui.showFindings && ui.triageSelection().count() > 0 {
					ui.triageSelection().clear()
					ui.updateFindingsList(ui.findingsTotal)
					ui.repaintTriageChrome()
					ui.setStatusDirect("[%s]Selection cleared[-:-:-]", ui.theme.TagAccent)
					return nil
				}
			case '1', '2', '3', '4', '5':
				// Dispatched from the destination table, so the rail, the
				// palette and this handler cannot disagree about where a
				// digit goes. See nav.go.
				if ui.navigate(event.Rune()) {
					return nil
				}
			case ':':
				ui.showCommandPalette()
				return nil
			case '/':
				ui.showFilterBar()
				return nil
			case 'p':
				// Events owns this key — see eventsKeys. Reaching here means
				// no screen claimed it, so there is nothing to pivot on.
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

	// Every case in the database is shown.
	//
	// This used to drop any case titled "Ingested Events" — the exact title the
	// folder ingestor gives the case it creates — and then de-duplicate by
	// title. So `console-ir list cases` reported a case the TUI insisted did
	// not exist, and two genuinely different investigations that happened to
	// share a name became one. Analyst Home reads the store directly and showed
	// it in RECENT CASES, so the application contradicted itself on two screens
	// at once.
	//
	// If auto-created cases are noise, the fix is not to create them, or to
	// mark them; it is not to hide rows the analyst can see from the CLI.
	filtered := cases

	ui.logger.Printf("Loaded %d cases from database", len(cases))

	// The all-events filters, read on the UI goroutine, for the overview total.
	var plan eventQueryPlan
	ui.queueUpdate(func() { plan = ui.planEventQuery(contextAll, "") })
	eventsTotal, _ := ui.store.CountEventsFiltered(ctx, "",
		plan.start, plan.end, plan.severities, plan.types)

	// Everything that touches the screen, on the screen's goroutine.
	ui.queueUpdate(func() { ui.applyCases(filtered, eventsTotal) })

	ui.setStatus("[%s]Loaded %d cases[-:-:-]", ui.theme.TagSuccess, len(filtered))

	return nil
}

// applyCases records a freshly read case list.
//
// It must run on the UI goroutine. refreshCases used to do all of this from
// whichever goroutine called it — assigning ui.cases, clearing the selection,
// repainting the list — while the key handler was writing the same fields on
// the event loop.
func (ui *UI) applyCases(cases []store.Case, eventsTotal int) {
	ui.allCases = cases
	ui.cases = ui.applyCaseFilters(ui.allCases)

	// Selection stability: a case the filters removed is no longer the
	// selection, and the events list falls back to all events.
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

	ui.renderCasesList()

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
	ui.updateOverview(eventsTotal, len(ui.cases), openN, invN, closeN)
}

// updateCasesList updates the cases sidebar
// updateCasesList repaints the case list from off the UI goroutine.
//
// The two halves are separate deliberately. queueUpdate blocks until the event
// loop drains it, so calling this from a key handler — which runs *on* that
// loop — deadlocks the application. Anything already on the UI goroutine calls
// renderCasesList instead.
func (ui *UI) updateCasesList() {
	ui.queueUpdate(ui.renderCasesList)
}

// renderCasesList paints the rows. It must already be on the UI goroutine.
func (ui *UI) renderCasesList() {
	// Which case the cursor was on, before the list is torn down. A
	// refresh used to send it back to the first case, so pressing r while
	// reading case four put case one's briefing on screen.
	wasOn := ui.selectedCaseID
	if i := ui.sidebar.GetCurrentItem(); i >= 0 && i < len(ui.cases) {
		wasOn = ui.cases[i].ID
	}

	ui.sidebar.Clear()

	if len(ui.cases) == 0 {
		return
	}

	// The title has whatever the list's width leaves after the number.
	room := casesListWidth(ui.termWidth) - 10

	for i, case_ := range ui.cases {
		title := truncate(case_.Title, room)

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

	ui.selectCaseByID(wasOn)
}

// selectCaseByID puts the cursor on a case, falling back to the first.
//
// By identity rather than by index: a refresh can add or remove a case, and an
// index survives neither.
func (ui *UI) selectCaseByID(id string) {
	if ui.sidebar.GetItemCount() == 0 {
		return
	}
	for i, c := range ui.cases {
		if c.ID == id && i < ui.sidebar.GetItemCount() {
			ui.sidebar.SetCurrentItem(i)
			return
		}
	}
	ui.sidebar.SetCurrentItem(0)
}

// loadCaseEvents loads events for the selected case
func (ui *UI) loadCaseEvents() {
	// Prevent concurrent loads (can happen if both per-item and selected handlers fire).
	// A case's event list and the all-events list are the same collection, so
	// they share a guard; the findings queue does not.
	if !ui.eventsLoad.begin() {
		ui.logger.Println("loadCaseEvents: already loading, skipping")
		return
	}
	defer ui.eventsLoad.end()

	defer func() {
		if r := recover(); r != nil {
			if ui.logger != nil {
				ui.logger.Printf("panic in loadCaseEvents: %v", r)
			}
			ui.setStatus("[%s]Error loading events (recovered)[-:-:-]", ui.theme.TagError)
		}
	}()

	// Which case, and its filters, read on the UI goroutine.
	var plan eventQueryPlan
	ui.queueUpdate(func() {
		if ui.selectedCaseID == "" {
			return
		}
		plan = ui.planEventQuery(ui.selectedCaseID, ui.selectedCaseID)
	})
	if plan.caseID == "" {
		ui.logger.Println("loadCaseEvents: no case selected")
		return
	}

	ui.logger.Printf("Loading events for case: %s", plan.caseID)
	// Show loading status immediately on the UI thread
	ui.setStatus("[%s]Loading events...[-:-:-]", ui.theme.TagWarning)

	// Run DB query with a short timeout to avoid UI freeze if DB is locked
	ctx, cancel := context.WithTimeout(ui.ctx, 4*time.Second)
	defer cancel()

	// Count total first to clamp page index
	total, err := ui.store.CountEventsFiltered(ctx, plan.caseID, plan.start, plan.end, plan.severities, plan.types)
	if err != nil {
		ui.logger.Printf("Error counting events for case %s: %v", plan.caseID, err)
		// Reset filter apply guard on failure
		atomic.StoreInt32(&ui.filterApplying, 0)
		ui.queueUpdate(func() {
			if ctx.Err() == context.DeadlineExceeded {
				ui.setStatusDirect("[%s]Timed out counting events (database busy)[-:-:-]", ui.theme.TagError)
			} else {
				ui.setStatusDirect("[%s]Error counting events: %v[-:-:-]", ui.theme.TagError, err)
			}
		})
		return
	}
	page, offset := pageOffset(total, plan.pageSize, plan.pageIndex)

	events, err := ui.store.GetEventsFiltered(ctx, plan.caseID,
		plan.start, plan.end, plan.severities, plan.types, plan.pageSize, offset)
	if err != nil {
		ui.logger.Printf("Error loading events for case %s: %v", plan.caseID, err)
		// Reset filter apply guard on failure
		atomic.StoreInt32(&ui.filterApplying, 0)
		ui.queueUpdate(func() {
			if ctx.Err() == context.DeadlineExceeded {
				ui.setStatusDirect("[%s]Timed out loading events (database busy)[-:-:-]", ui.theme.TagError)
			} else {
				ui.setStatusDirect("[%s]Error loading events: %v[-:-:-]", ui.theme.TagError, err)
			}
		})
		return
	}

	ui.logger.Printf("Loaded %d events for case %s", len(events), plan.caseID)
	if ui.logger != nil {
		if d := ui.eventsLoad.startedAgo(); d > 0 {
			ui.logger.Printf("loadCaseEvents: query finished in %v; updating UI", d)
		}
	}

	// Update UI in main thread
	ui.queueUpdate(func() {
		ui.recordEventQuery(plan, total, page)
		// Clear any previous selections when data changes (avoid stale IDs across pages)
		ui.selectedEventIDs = make(map[string]bool)
		ui.events = events
		ui.updateEventsList()

		// Ensure the table is scrolled to the top and the first *event* is
		// selected — row 1 is a cluster header, not an event.
		ui.eventList.SetOffset(0, 0)
		if ui.eventList.GetRowCount() > 1 {
			ui.selectFirstEvent()
		} else {
			ui.eventList.Select(0, 0) // header/no-data fallback
		}

		// Focus follows the events table only where it is on screen.
		//
		// This load runs on the Cases screen too — r refreshes there — and the
		// case list and briefing are what is showing, not this table. Taking
		// focus anyway put it on a widget nobody could see, and the arrow keys
		// stopped moving the case list.
		if ui.eventsListOnScreen() {
			ui.app.SetFocus(ui.eventList)
		}

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
	// The title describes the list beneath it. It used to report the page count
	// from before a pivot or a search, so a narrowed list of 2 sat under a
	// heading claiming 6 — two numbers on one screen, both describing it, and
	// disagreeing.
	title := fmt.Sprintf(" EVENTS  ·  %d ", len(ui.events))
	switch {
	case ui.searchQuery != "":
		title = fmt.Sprintf(" EVENTS  ·  %d matching %q ", len(ui.events), ui.searchQuery)
	case ui.pivot != nil:
		title = fmt.Sprintf(" EVENTS  ·  %d for %s ", len(ui.events), ui.pivot.Value)
	case maxPages > 1:
		title = fmt.Sprintf(" EVENTS  ·  %d of %d · page %d/%d ",
			len(ui.events), s.totalCount, s.pageIndex+1, maxPages)
	}
	ui.eventList.SetTitle(title)

	// Set headers
	headers := []string{"Time", "Type", "Severity", "Host", "Source", "Message"}
	for col, header := range headers {
		ui.eventList.SetCell(0, col, tview.NewTableCell(header).
			SetTextColor(ui.theme.TableHeader).
			SetBackgroundColor(ui.theme.TableHeaderBg).
			SetAttributes(tcell.AttrBold))
	}

	if len(ui.events) == 0 {
		// Two distinct empty states, as on Triage. Telling an analyst to go
		// ingest data because their own search excluded it is telling them
		// their data is missing.
		var hint []string
		switch {
		case ui.searchQuery != "":
			hint = []string{
				"No events match.",
				"",
				fmt.Sprintf("Search: %q", ui.searchQuery),
				"",
				"[F] Clear the search      [Esc] restores the previous list",
			}
		case ui.pivot != nil:
			hint = []string{
				"No events match.",
				"",
				fmt.Sprintf("Pivot: %s %s", ui.pivot.Kind, ui.pivot.Value),
				"",
				"[F] Clear the pivot",
			}
		default:
			// A fresh install has no data and no obvious next step. Point the
			// analyst at the drop folder and the shipped sample.
			hint = []string{
				"No events yet.",
				"",
				fmt.Sprintf("Drop OCSF JSONL files into  %s  to ingest and enrich them.", ui.watchedDir()),
				// Not "ingest examples/…": examples/ is not in the release
				// archive, so a brew or curl install has no such file. The demo
				// data is embedded in the binary, which works everywhere.
				"Or run   console-ir demo   to explore a sample incident first.",
				"Then press  r  to refresh this list.",
			}
		}
		for i, line := range hint {
			// Escaped: a table cell parses colour tags, so "[F]" is read as one
			// and disappears — taking with it the only instruction on screen.
			cell := tview.NewTableCell(tview.Escape(line)).
				SetTextColor(ui.theme.TableRowMuted).
				SetExpansion(1)
			if i == 0 {
				cell.SetAttributes(tcell.AttrBold)
			}
			ui.eventList.SetCell(1+i, 0, cell)
		}
		return
	}

	// Sort events by timestamp (newest first)
	sort.Slice(ui.events, func(i, j int) bool {
		return ui.events[i].Timestamp.After(ui.events[j].Timestamp)
	})

	// Cluster the page already loaded. Grouping is a display concern: it never
	// re-queries, and expanding a cluster never re-queries either.
	ui.eventClusters = clusterEvents(ui.events, ui.eventGroup)
	ui.eventAtRow = map[int]int{}
	indexOf := map[string]int{}
	for i, e := range ui.events {
		indexOf[e.ID] = i
	}
	if ui.expandedCluster == "" && len(ui.eventClusters) > 0 {
		ui.expandedCluster = ui.eventClusters[0].Label
	}

	rowIndex := 0
	for ci := range ui.eventClusters {
		cluster := &ui.eventClusters[ci]
		rowIndex++
		cluster.headerRow = rowIndex

		glyph := "▸"
		if cluster.Label == ui.expandedCluster {
			glyph = "▾"
		}
		header := tview.NewTableCell(fmt.Sprintf("[%s]%s %s[-:-:-]",
			ui.theme.TagAccent, glyph, tview.Escape(cluster.Header()))).
			SetExpansion(1).
			SetBackgroundColor(ui.theme.Surface)
		ui.eventList.SetCell(rowIndex, 0, header)
		for col := 1; col < 6; col++ {
			ui.eventList.SetCell(rowIndex, col,
				tview.NewTableCell("").SetBackgroundColor(ui.theme.Surface))
		}

		if cluster.Label != ui.expandedCluster {
			continue
		}

		for _, event := range cluster.Events {
			rowIndex++
			ui.eventAtRow[rowIndex] = indexOf[event.ID]
			ui.renderEventRow(rowIndex, event)
		}
	}
	return
}

// renderEventRow draws one event beneath its cluster header.
func (ui *UI) renderEventRow(rowIndex int, event store.Event) {
	{
		row := rowIndex

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
	// Publish what the pane is showing so the enrichment notifier, which runs on
	// a worker goroutine, can tell whether an arrival is worth a redraw without
	// reading UI state.
	ui.openEventID.Store(ui.selectedEventID)

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

	// §8 order: summary first, raw last. This opened with the event id — a
	// machine identifier nobody will ever type — and put the sentence
	// describing what happened several lines below it. Triage and Home already
	// lead with the human summary; this screen was the one that disagreed.
	summary := strings.TrimSpace(event.Message)
	if summary == "" {
		summary = event.EventType
	}
	details.WriteString(fmt.Sprintf("[%s:-:b]%s[-:-:-]\n", ui.theme.TagAccent, tview.Escape(summary)))
	details.WriteString(fmt.Sprintf("[%s]%s · %s · %s[-]\n\n",
		ui.theme.TagMuted, event.Timestamp.Format("2006-01-02 15:04:05"),
		event.EventType, strings.ToUpper(event.Severity)))

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

	// Show enrichments from the DB, grouped into one card per indicator.
	if enrichments, err := ui.store.GetEnrichmentsByEvent(ui.ctx, event.ID); err == nil && len(enrichments) > 0 {
		// Observables are only needed to name the cards, so the query stays
		// inside this branch: an unenriched event costs nothing extra.
		var observables []store.Observable
		if byEvent, obsErr := ui.store.GetObservablesForEvents(ui.ctx, []string{event.ID}); obsErr == nil {
			observables = byEvent[event.ID]
		} else if ui.logger != nil {
			ui.logger.Printf("Failed to load observables for event %s: %v", event.ID, obsErr)
		}

		cards := groupEnrichments(enrichments, eventIndicatorValues(observables, event))
		details.WriteString(fmt.Sprintf("\n[%s]ENRICHMENT (%d)[-]\n", ui.theme.TagAccent, len(cards)))
		renderEnrichmentCards(&details, ui.theme, cards, enrichmentRenderOptions{
			Indent:      "  ",
			MaxFields:   30,
			MaxValueLen: 200,
		})
	} else {
		// §8: the enrichment states must be explicit. An empty region here is a
		// defect — the analyst cannot tell a lookup that failed from one that
		// has not run from an indicator nobody enriches, and all three look
		// identical to a blank space.
		details.WriteString(fmt.Sprintf("\n[%s]ENRICHMENT[-]\n", ui.theme.TagAccent))
		switch {
		case err != nil:
			if ui.logger != nil {
				ui.logger.Warn("could not load enrichments for event %s: %v", event.ID, err)
			}
			details.WriteString(fmt.Sprintf("  [%s]Lookup failed — see %s[-]\n",
				ui.theme.TagError, runtimeLogHint()))
		case ui.enrichmentStatus().Pending > 0:
			details.WriteString(fmt.Sprintf("  [%s]Enrichment pending …[-]\n", ui.theme.TagWarning))
		case ui.enrichmentStatus().Failed > 0:
			details.WriteString(fmt.Sprintf("  [%s]Lookup failed — see %s[-]\n",
				ui.theme.TagError, runtimeLogHint()))
		default:
			details.WriteString(fmt.Sprintf("  [%s]No enrichment available[-]\n", ui.theme.TagMuted))
		}
	}

	details.WriteString(fmt.Sprintf("\n[%s]Event ID:[-] [%s]%s[-]\n", lbl, ui.theme.TagMuted, event.ID))

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
		ui.setStatusDirect("[%s]Selected case not found[-:-:-]", ui.theme.TagError)
		return
	}

	// The constructor falls back to a local stub, so this is normally set — but
	// it is also assigned from the provider settings modal, and a summary is
	// not worth a nil dereference on the one path that could clear it.
	if ui.llm == nil {
		ui.setStatusDirect("[%s]No LLM provider configured — press L to set one up[-:-:-]", ui.theme.TagWarning)
		return
	}

	ui.setStatusDirect("[%s]Generating case summary...[-:-:-]", ui.theme.TagWarning)

	caseID := selectedCase.ID
	go func() {
		// The case's own events, not whatever the events screen last loaded.
		// ui.events belongs to a different screen, is empty on the one this key
		// is pressed from, and is cleared outright when a screen changes — so
		// the summary was written from either nothing or the wrong evidence.
		events, err := ui.store.GetCaseEventMembers(ui.ctx, caseID)
		if err != nil {
			ui.queueUpdate(func() {
				ui.setStatusDirect("[%s]Could not read the case's events: %v[-:-:-]", ui.theme.TagError, err)
			})
			return
		}

		summary, err := ui.llm.SummarizeCase(ui.ctx, *selectedCase, events)
		if err != nil {
			ui.queueUpdate(func() {
				ui.setStatusDirect("[%s]Error generating summary: %v[-:-:-]", ui.theme.TagError, err)
			})
			return
		}

		ui.queueUpdate(func() {
			ui.showModal("Case Summary", summary)
			ui.setStatusDirect("[%s]Case summary generated[-:-:-]", ui.theme.TagSuccess)
		})
	}()
}

// showHelp displays a professionally formatted Help using a table layout
func (ui *UI) showHelp() {
	ui.helpActive = true
	card, table := ui.buildHelpCard(ui.restoreMainLayout)
	ui.rootModal(card)
	ui.app.SetFocus(table)
}

// buildHelpCard assembles the key reference and returns it with the widget that
// should hold focus.
//
// close is what dismisses it, because who is showing the help decides where
// closing it returns to. The case screen roots its own modals on its own stack;
// sending it back through restoreMainLayout would drop the analyst out of the
// case they were reading about.
func (ui *UI) buildHelpCard(close func()) (tview.Primitive, tview.Primitive) {

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
		left := tview.NewTableCell(strings.Repeat(" ", keyColWidth)).
			SetBackgroundColor(ui.theme.TableHeaderBg).
			SetAlign(tview.AlignLeft).
			SetMaxWidth(keyColWidth)
		right := tview.NewTableCell(" " + title + " ").
			SetTextColor(ui.theme.TableHeader).
			SetBackgroundColor(ui.theme.TableHeaderBg).
			SetAttributes(tcell.AttrBold).
			SetExpansion(1)
		table.SetCell(row, 0, left)
		table.SetCell(row, 1, right)
		row++
	}

	addKey := func(key string, desc string) {
		kCell := tview.NewTableCell(key).
			SetTextColor(ui.theme.Accent).
			SetAlign(tview.AlignRight).
			SetMaxWidth(keyColWidth).
			SetExpansion(0)
		dCell := tview.NewTableCell(fmt.Sprintf("%s %s", bullet, desc)).
			SetTextColor(ui.theme.TextPrimary).
			SetExpansion(1)
		table.SetCell(row, 0, kCell)
		table.SetCell(row, 1, dCell)
		row++
	}

	// Dynamic Contextual Help
	focused := ui.app.GetFocus()
	if focused == ui.eventList && ui.showFindings {
		addSection("CONTEXT: FINDINGS QUEUE")
		addKey("Space", "Toggle selection for bulk actions")
		addKey("e", "Escalate selected finding(s)")
		addKey("s", "Update finding status")
		addKey("y", "Copy raw JSON to clipboard")
		addKey("Enter", "View finding details")
	} else if focused == ui.eventList && ui.showAll {
		addSection("CONTEXT: EVENTS LIST")
		addKey("Space", "Toggle selection")
		addKey("p", "Pivot on current event")
		addKey("y", "Copy raw JSON to clipboard")
		addKey("Enter", "View event details")
	} else if ui.activeCM != nil && ui.selectedCaseID != "" {
		addSection("CONTEXT: CASE MANAGEMENT")
		// What the case screen's own handler does, since it owns every key
		// while it is open. `e` used to be listed as "escalate to an external
		// system", which does not exist.
		addKey("Tab / Shift+Tab", "Next and previous tab")
		addKey("[, ]", "Close and open the copilot")
		addKey("Space", "Pin the event under the cursor as evidence")
		addKey("h / l", "Move left to the tab, right to the copilot")
		addKey("E", "Write the case up as a report")
		addKey("J", "Export the whole case as JSON")
		addKey("e", "Export the pinned evidence as JSON")
		addKey("t", "Change the theme")
		addKey("Esc", "Leave the case")
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

	addSection("DESTINATIONS")
	// Listed from the destination table in nav.go, so the help cannot document
	// a key the rail does not show or the handler does not dispatch.
	for _, d := range destinations() {
		addKV(string(d.key), d.name+" — "+d.desc)
	}
	addKV("Esc", "Home — "+homeDestination().desc)
	addGap()

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
	addGap()

	addSection("FINDINGS (TRIAGE)")
	addKV("D", "Open the findings queue")
	addKV("Enter", "Finding details: evidence, related events, observables")
	addKV("s", "Set status (New / In Progress / Suppressed / Resolved / Archived)")
	addKV("v", "Set verdict (True / False Positive, Suspicious, Benign, ...)")
	addKV("e", "Escalate finding into a new or existing case")
	addKV("o", "Toggle open-only / all findings")
	row++

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
	addKV("t", "Cycle themes (colorblind, dark, gruvbox, high-contrast, light, midnight)")
	addGap()

	addSection("QUICK ACTIONS")
	addKV("D", "Jump to FINDINGS from anywhere")
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
			close()
			return nil
		case tcell.KeyRune:
			switch ev.Rune() {
			case 'q', 'Q', ' ':
				close()
				return nil
			}
		}
		return ev
	})

	return centered, table
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

	ui.overlayPrimitive(modal)
}

// restoreMainLayout restores the main TUI layout after closing a modal/help view
func (ui *UI) restoreMainLayout() {
	ui.helpActive = false
	ui.activeModal = nil
	ui.filterModal = nil

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
		target = ui.screenFocus()
	}
	ui.lastFocus = nil
	ui.app.SetFocus(target)
	ui.highlightFocus(target)

	// Say where you now are, not what you just closed. This announced "Help
	// closed" unconditionally — after a pivot menu, after a form, and after
	// leaving a case, none of which involved the help screen.
	if d, ok := lookupDestinationByID(ui.destination); ok {
		ui.setStatusDirect("[%s]%s[-:-:-]", ui.theme.TagAccent, d.name)
		return
	}
	ui.setStatusDirect("[%s]Ready[-:-:-]", ui.theme.TagAccent)
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
		// The rail above is not focusable, so moving up off the first case
		// stays put rather than focusing a widget the analyst cannot see.
		if cur == 0 && delta < 0 {
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
				if ui.running.Load() {
					// Non-blocking repaint request to avoid re-entrancy
					ui.app.QueueUpdate(func() {})
				}
			}
		}
	}()
}

// isDialogActive returns true when a dialog or the help view is focused to bypass global shortcuts.
// rootModal puts a modal over the main layout and records that one is up.
//
// The global key handler stands down while a modal is rooted — see
// isDialogActive. Recording it explicitly rather than inferring it from what
// has focus is what lets a modal built from a List suppress keys: the pivot
// menu is one, and q used to quit the application straight through it.
func (ui *UI) rootModal(p tview.Primitive) {
	// Remember what to give focus back to, here rather than at each call site.
	//
	// Eight of the eighteen callers set ui.lastFocus by hand and the rest
	// forgot, so closing one of those left focus wherever the previous modal
	// had put it — or, when there had been none, on the navigation rail. That
	// is what made the arrow keys stop scrolling the findings queue after
	// choosing a filter: the keys were moving an unfocused rail instead.
	//
	// Guarded against nesting, so a modal opened over a modal does not record
	// the outer modal as the thing to return to.
	if ui.activeModal == nil && ui.app != nil {
		ui.lastFocus = ui.app.GetFocus()
	}
	ui.activeModal = p
	ui.app.SetRoot(p, true)
}

// screenFocus is the widget an analyst works in on the current screen.
//
// The fallback when nothing was recorded. It used to be the case sidebar
// unconditionally, which is the working widget on exactly one of the six
// screens.
func (ui *UI) screenFocus() tview.Primitive {
	switch ui.destination {
	case destHome:
		if ui.home != nil && ui.home.root != nil {
			return ui.home.root
		}
	case destCases:
		if ui.sidebar != nil {
			return ui.sidebar
		}
	case destIndicators:
		if ui.indicators != nil && ui.indicators.table != nil {
			return ui.indicators.table
		}
	case destTriage, destEvents:
		if ui.eventList != nil {
			return ui.eventList
		}
	}
	if ui.eventList != nil {
		return ui.eventList
	}
	return ui.sidebar
}

func (ui *UI) isDialogActive() bool {
	if ui.helpActive {
		return true
	}
	// What is rooted, not what has focus.
	//
	// The type switch below cannot see a modal built from a List — and the
	// pivot menu is one, so every global key reached straight through it: q
	// quit the application, the digits navigated away, j and k moved the table
	// behind it. Adding *tview.List to the switch would be wrong, because the
	// case sidebar is a List too and must not suppress anything.
	if ui.activeModal != nil {
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

// composeStatus builds the one bar at the foot of the screen.
//
// It is the only status bar there is. Home used to carry a second row of its
// own beneath this one — two bars, four hints repeated between them, and the
// two disagreed about which key opened the filter.
//
// The product name lives here and nowhere else. It used to be under the
// navigation rail as well, and in every screen's header, so a single screen
// said "Console-IR" three times and the rail spent two of its twenty-two
// columns on a version string.
func (ui *UI) composeStatus(message string) string {
	t := ui.theme
	brand := fmt.Sprintf("[%s:-:b]Console-IR[-:-:-] [%s]%s · OCSF %s[-:-:-]",
		t.TagAccent, t.TagMuted, buildinfo.Display(ui.version), ocsf.SchemaVersion())

	return fmt.Sprintf("%s  [%s]│[-:-:-] %s  [%s]│[-:-:-] %s",
		brand,
		t.TagMuted, ui.buildStatusMain(message),
		t.TagMuted, ui.buildShortcutHints())
}

// setStatus updates the status bar from anywhere.
//
// Composed on the UI goroutine and posted without waiting for it. Both halves
// of that are fixes:
//
// Composing at the call site read ui.destination, the theme and the screen's
// flags off whatever goroutine called — a data race against the key handler
// that writes them while a loader is announcing itself.
//
// And waiting was worse. QueueUpdate blocks until the event loop drains it, so
// any caller already on that loop froze the entire application — which is what
// pressing s on a case did, through showCaseSummary.
//
// The cost is ordering: two callers racing can land out of order and the bar
// shows the loser. A momentarily stale line beats a dead application, and
// anything already on the UI goroutine calls setStatusDirect, which keeps both.
func (ui *UI) setStatus(format string, args ...interface{}) {
	message := fmt.Sprintf(format, args...)

	if !ui.running.Load() {
		// No loop to post to (unit tests).
		ui.statusBar.SetText(ui.composeStatus(message))
		return
	}
	go ui.app.QueueUpdate(func() {
		ui.statusBar.SetText(ui.composeStatus(message))
	})
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
	statusText := ui.composeStatus(fmt.Sprintf(format, args...))

	if ui.statusBar != nil {
		ui.statusBar.SetText(statusText)
	}
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
	// Cases sidebar. Most widgets below are nil-guarded already; the ones that
	// were not made applyTheme unsafe to call before the layout is assembled,
	// which setTheme now does when restoring the persisted choice.
	if ui.sidebar != nil {
		ui.sidebar.SetMainTextColor(ui.theme.TextPrimary)
		ui.sidebar.SetSecondaryTextColor(ui.theme.TextMuted)
		ui.sidebar.SetSelectedTextColor(ui.theme.SelectionFg)
		ui.sidebar.SetSelectedBackgroundColor(ui.theme.SelectionBg)
		ui.sidebar.SetBorderColor(ui.theme.Border)
		ui.sidebar.SetBackgroundColor(ui.theme.Surface)
	}

	// The navigation rail is rendered from the destination table, so restyling
	// it is a repaint rather than a list of SetItemText calls. The call this
	// replaced rewrote the rail's first item to "ALL EVENTS" on every theme
	// change, advertising a destination that key 1 does not go to.
	if ui.navRail != nil {
		stylePanel(ui.navRail.Box, "NAVIGATION", PanelRoleRail, ui.theme)
		ui.navRail.SetBackgroundColor(ui.theme.Bg)
		ui.renderNavRail()
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
	if ui.eventList != nil {
		ui.eventList.SetSelectedStyle(tcell.StyleDefault.Background(ui.theme.SelectionBg).Foreground(ui.theme.SelectionFg))
		ui.eventList.SetBorderColor(ui.theme.Border)
		ui.eventList.SetBackgroundColor(ui.theme.Surface)
	}

	if ui.eventDetail != nil {
		ui.eventDetail.SetTextColor(ui.theme.TextPrimary)
		ui.eventDetail.SetBorderColor(ui.theme.Border)
		ui.eventDetail.SetBackgroundColor(ui.theme.Surface)
	}

	// Status bar
	if ui.statusBar != nil {
		ui.statusBar.SetTextColor(ui.theme.TextPrimary)
		ui.statusBar.SetBackgroundColor(ui.theme.Surface)
	}

	// The dashboard builds its own widgets from the theme it was constructed
	// with, so nothing above reaches them. Without this, changing the theme on
	// Home recoloured the rail and the status bar around a dashboard still
	// drawn in the old palette.
	if ui.home != nil {
		ui.home.applyTheme()
	}

	// Re-render table and focus ring
	ui.repaintCurrentList()
	if ui.app != nil {
		ui.highlightFocus(ui.app.GetFocus())
	}
}

// cycleTheme moves to the next theme in sequence
func (ui *UI) cycleTheme() {
	if ui.logger != nil {
		ui.logger.Printf("Cycle theme requested (current=%s)", ui.themeName)
	}
	names := themeNames()
	for i, n := range names {
		if n == ui.themeName {
			ui.setTheme(names[(i+1)%len(names)])
			return
		}
	}
	ui.setTheme(defaultThemeName)
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
	build, ok := themeBuilders[name]
	if !ok {
		name, build = defaultThemeName, themeBuilders[defaultThemeName]
	}
	ui.themeName = name
	if !ui.hasTrueColor {
		ui.theme = themeBasic()
	} else {
		ui.theme = build()
	}
	ui.applyTheme()
	ui.saveUISettings()

	// Propagate live theme to active Case Management screen, if any.
	if ui.activeCM != nil {
		ui.activeCM.OnThemeChanged(ui.theme)
	}

	// Direct status update; we're on the UI goroutine
	ui.setStatusDirect("[%s]Theme:%s[-:-:-]", ui.theme.TagAccent, strings.Title(strings.ReplaceAll(ui.themeName, "-", " ")))
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

// toggleEventSelection toggles selection state for the currently focused event or finding
func (ui *UI) toggleEventSelection() {
	row, _ := ui.eventList.GetSelection()

	if ui.showFindings {
		if row > 0 && row-1 < len(ui.findings) {
			// Keyed by finding uid, not by row: the selection has to survive a
			// refresh, a re-sort and a filter change, and a row index survives
			// none of them.
			sel := ui.triageSelection()
			sel.toggle(ui.findings[row-1].FindingUID)
			ui.updateFindingsList(ui.findingsTotal)
			ui.repaintTriageChrome()
			ui.setStatusDirect("[%s]%d selected[-:-:-]", ui.theme.TagAccent, sel.count())
		}
		return
	}

	if row > 0 && row-1 < len(ui.events) {
		e := ui.eventForRow(row)
		if e == nil {
			return
		}
		eventID := e.ID
		if ui.selectedEventIDs[eventID] {
			delete(ui.selectedEventIDs, eventID)
			ui.setStatusDirect("[%s]Event deselected (%d selected)[-:-:-]", ui.theme.TagAccent, len(ui.selectedEventIDs))
		} else {
			ui.selectedEventIDs[eventID] = true
			ui.setStatusDirect("[%s]Event selected (%d selected)[-:-:-]", ui.theme.TagSuccess, len(ui.selectedEventIDs))
		}
		ui.updateEventsList() // Refresh to show selection indicators
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
		// The selection is read here, on the UI goroutine, rather than from
		// the goroutine that does the work.
		ui.createCase(title, description, severity, assignedTo, ui.selectedEventIDList())
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

	ui.overlayForm(form, 64)
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
		ui.overlayPrimitive(modal)
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

	// Over the events it is about to file, and focus the input field.
	//
	// Through the modal path, not SetRoot: rooted directly it never registered
	// as a modal, so the global capture went on claiming 1-5 for navigation
	// while a case number was being typed into the field.
	ui.overlayModal(layout, 92, 20)
	ui.app.SetFocus(form)

	// Brief hint
	ui.setStatusDirect("[%s]Enter the case number (1-%d) and press 'Add Events'. Esc to cancel.[-:-:-]", ui.theme.TagAccent, len(ui.cases))
}

// selectedEventIDList is the marked events, as a stable slice.
//
// It must run on the UI goroutine. The map itself is replaced by the loaders,
// so a background reader can find it changing underneath.
func (ui *UI) selectedEventIDList() []string {
	ids := make([]string, 0, len(ui.selectedEventIDs))
	for id := range ui.selectedEventIDs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// createCase files a new case, with the events it was given.
//
// The events are a parameter rather than something read from the screen: this
// is reached both from the events flow, where a selection is the point, and
// from the Cases screen, where there is nothing selected and a case with no
// evidence yet is exactly what is wanted.
func (ui *UI) createCase(title, description, severity, assignedTo string, eventIDs []string) {
	if len(eventIDs) == 0 {
		ui.setStatusDirect("[%s]Creating case…[-:-:-]", ui.theme.TagWarning)
	} else {
		ui.setStatusDirect("[%s]Creating case and assigning %s…[-:-:-]",
			ui.theme.TagWarning, plural(len(eventIDs), "event"))
	}

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
			ui.queueUpdate(func() {
				ui.setStatusDirect("[%s]Error creating case: %v[-:-:-]", ui.theme.TagError, err)
			})
			return
		}

		// Assign selected events to the case
		var successCount, errorCount int
		for _, eventID := range eventIDs {
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
		ui.queueUpdate(func() {
			ui.selectedEventIDs = make(map[string]bool)
			ui.setStatusDirect("[%s]Case created; refreshing cases...[-:-:-]", ui.theme.TagWarning)
		})

		// 2) Refresh cases off the UI thread to avoid freezing the event loop
		if err := ui.refreshCases(); err != nil {
			ui.queueUpdate(func() {
				ui.setStatusDirect("[%s]Error refreshing cases after create: %v[-:-:-]", ui.theme.TagError, err)
			})
		} else {
			// 3) Finalize UI updates and auto-select the newly created case
			ui.queueUpdate(func() {
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
				ui.spawnLoad(ui.loadCaseEvents)

				switch {
				case errorCount > 0:
					ui.setStatusDirect("[%s]Case created with %s (%d could not be attached)[-:-:-]",
						ui.theme.TagWarning, plural(successCount, "event"), errorCount)
				case successCount == 0:
					// Not "with 0 events", which reads as a failure. An empty
					// case is what this key does on the Cases screen.
					ui.setStatusDirect("[%s]Case created[-:-:-]", ui.theme.TagSuccess)
				default:
					ui.setStatusDirect("[%s]Case created with %s[-:-:-]",
						ui.theme.TagSuccess, plural(successCount, "event"))
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
		ui.queueUpdate(func() {
			ui.selectedEventIDs = make(map[string]bool)
			ui.setStatusDirect("[%s]Updating cases...[-:-:-]", ui.theme.TagWarning)
		})

		// 2) Refresh cases off the UI thread
		if err := ui.refreshCases(); err != nil {
			ui.queueUpdate(func() {
				ui.setStatusDirect("[%s]Error refreshing cases after add: %v[-:-:-]", ui.theme.TagError, err)
			})
		} else {
			// 3) Finalize UI updates; keep or reselect the target case and reload its events
			ui.queueUpdate(func() {
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
				ui.spawnLoad(ui.loadCaseEvents)

				if errorCount > 0 {
					ui.setStatusDirect("[%s]Added %d events to case (%d errors)[-:-:-]", ui.theme.TagWarning, successCount, errorCount)
				} else {
					ui.setStatusDirect("[%s]Successfully added %d events to case[-:-:-]", ui.theme.TagSuccess, successCount)
				}
			})
		}
	}()
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
				ui.overlayForm(form, 64)
			})
		}
	})
	sevDD.SetCurrentOption(sevIdx)
	sevDD.SetFieldTextColor(ui.theme.TextPrimary)
	sevDD.SetFieldBackgroundColor(ui.theme.Surface)
	sevDD.SetLabelColor(ui.theme.TextPrimary)
	form.AddFormItem(sevDD)

	// Category section. Options are driven by the embedded OCSF registry rather
	// than a hardcoded list, so every category is selectable and correctly named.
	typeOptions, typeSlugs := ui.ocsfCategoryOptions()
	customTypeIdx := len(typeOptions) - 1 // "Custom..." is always last
	customType := map[string]bool{}
	for k, v := range s.filterTypes {
		if v {
			customType[strings.ToLower(k)] = true
		}
	}
	typeIdx := 0
	if len(customType) == 1 {
		for i, slug := range typeSlugs {
			if slug != "" && customType[slug] {
				typeIdx = i
				break
			}
		}
	} else if len(customType) > 1 {
		typeIdx = customTypeIdx
	}
	// Declare before use so the callback can reference it safely.
	var typeDD *tview.DropDown
	typeDD = tview.NewDropDown()
	typeDD.SetLabel("Category")
	typeDD.SetOptions(typeOptions, func(text string, idx int) {
		typeIdx = idx
		if text == "Custom..." {
			selectable := make([]string, 0, len(typeSlugs))
			for _, slug := range typeSlugs {
				if slug != "" {
					selectable = append(selectable, slug)
				}
			}
			ui.showMultiSelectModal("Select Categories", selectable, customType, form, func(sel map[string]bool) {
				customType = sel
				typeDD.SetCurrentOption(customTypeIdx)
				ui.overlayForm(form, 64)
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

		// Compute categories
		newTypes := map[string]bool{}
		switch {
		case typeIdx == 0: // Any
			// empty
		case typeIdx == customTypeIdx:
			for k, v := range customType {
				if v {
					newTypes[k] = true
				}
			}
		case typeIdx > 0 && typeIdx < len(typeSlugs):
			if slug := typeSlugs[typeIdx]; slug != "" {
				newTypes[slug] = true
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
		ui.spawnLoad(func() { ui.scheduleEventsReload("filter:ApplyCombinedDropdown") })
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

	ui.overlayForm(form, 64)
	ui.setStatusDirect("[%s]Tab/Shift+Tab: navigate • Enter: open dropdown • Apply/Clear/Cancel at bottom[-:-:-]", ui.theme.TagAccent)
}

// clearCurrentContextFilters clears time, severities, and types for the current context and reloads.
// ocsfCategoryOptions builds the Category dropdown from the embedded OCSF
// registry. It returns the display labels and a parallel slice of the slug each
// label filters on; index 0 ("Any") and the trailing "Custom..." entry both map
// to an empty slug.
func (ui *UI) ocsfCategoryOptions() (labels []string, slugs []string) {
	cats := ocsf.Categories()
	labels = make([]string, 0, len(cats)+3)
	slugs = make([]string, 0, len(cats)+3)

	labels = append(labels, "Any")
	slugs = append(slugs, "")
	for _, c := range cats {
		labels = append(labels, c.Name)
		slugs = append(slugs, c.Slug)
	}
	labels = append(labels, "Unknown")
	slugs = append(slugs, string(ocsf.EventTypeUnknown))
	labels = append(labels, "Custom...")
	slugs = append(slugs, "")

	return labels, slugs
}

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
	ui.spawnLoad(func() { ui.scheduleEventsReload("filter:ClearCombined") })
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

	ui.overlayForm(form, 64)
}

// scheduleEventsReload coordinates safe event reloads after actions like filter Apply/Clear.
// It resets a stuck loading flag, logs context, and dispatches the appropriate loader.
func (ui *UI) scheduleEventsReload(source string) {
	sinceStr := "n/a"
	if d := ui.eventsLoad.startedAgo(); d > 0 {
		sinceStr = d.String()
	}
	le := 0
	if ui.eventsLoad.busyNow() {
		le = 1
	}

	if ui.logger != nil {
		ui.logger.Debug("scheduleEventsReload: source=%s showFindings=%v showAll=%v selectedCaseID=%s filterStart=%v filterEnd=%v eventsBusy=%d lastLoadAgo=%s filterApplying=%d",
			source, ui.showFindings, ui.showAll, ui.selectedCaseID, ui.filterStart, ui.filterEnd, le, sinceStr, atomic.LoadInt32(&ui.filterApplying))
	}

	// If a load is in progress, defer dispatch until it completes or times out; then dispatch.
	if le == 1 {
		if ui.logger != nil {
			ui.logger.Printf("scheduleEventsReload: deferring reload until current load completes")
		}
		go func() {
			deadline := time.Now().Add(loadWatchdog)
			for ui.eventsLoad.busyNow() && time.Now().Before(deadline) {
				time.Sleep(100 * time.Millisecond)
			}
			// If still busy after the deadline, consider it stuck and reclaim.
			if ui.eventsLoad.busyNow() {
				if ui.eventsLoad.reclaimIfStuck() {
					if ui.logger != nil {
						ui.logger.Printf("scheduleEventsReload: reclaimed a stuck events load")
					}
				}
			}
			// Now dispatch
			if ui.selectedCaseID != "" {
				if ui.logger != nil {
					ui.logger.Printf("scheduleEventsReload: dispatching deferred loadCaseEvents")
				}
				ui.spawnLoad(ui.loadCaseEvents)
			} else {
				if ui.logger != nil {
					ui.logger.Printf("scheduleEventsReload: dispatching deferred loadAllEvents")
				}
				ui.spawnLoad(ui.loadAllEvents)
			}
		}()
		return
	}

	// No in-progress load; dispatch immediately.
	if ui.selectedCaseID != "" {
		if ui.logger != nil {
			ui.logger.Printf("scheduleEventsReload: dispatching immediate loadCaseEvents")
		}
		ui.spawnLoad(ui.loadCaseEvents)
	} else {
		if ui.logger != nil {
			ui.logger.Printf("scheduleEventsReload: dispatching immediate loadAllEvents")
		}
		ui.spawnLoad(ui.loadAllEvents)
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
	if !ui.eventsLoad.begin() {
		if ui.logger != nil {
			ui.logger.Println("loadAllEvents: already loading, skipping")
		}
		return
	}
	defer ui.eventsLoad.end()

	defer func() {
		if r := recover(); r != nil {
			if ui.logger != nil {
				ui.logger.Printf("panic in loadAllEvents: %v", r)
			}
			ui.setStatus("[%s]Error loading all events (recovered)[-:-:-]", ui.theme.TagError)
		}
	}()

	ui.logger.Println("Loading ALL events...")
	ui.setStatus("[%s]Loading ALL events...[-:-:-]", ui.theme.TagWarning)

	// Run DB query with a short timeout to avoid UI freeze if DB is locked
	ctx, cancel := context.WithTimeout(ui.ctx, 4*time.Second)
	defer cancel()

	// The query context, read once on the UI goroutine.
	var plan eventQueryPlan
	ui.queueUpdate(func() { plan = ui.planEventQuery(contextAll, "") })
	if ui.logger != nil {
		ui.logger.Printf("loadAllEvents: filterStart=%v filterEnd=%v", plan.start, plan.end)
	}

	var events []store.Event

	// Count total to compute pagination/clamp page index
	total, err := ui.store.CountEventsFiltered(ctx, "", plan.start, plan.end, plan.severities, plan.types)
	if err != nil {
		if ui.logger != nil {
			ui.logger.Printf("Error counting ALL events: %v", err)
		}
		// Reset filter apply guard on failure
		atomic.StoreInt32(&ui.filterApplying, 0)
		ui.queueUpdate(func() {
			if ctx.Err() == context.DeadlineExceeded {
				ui.setStatusDirect("[%s]Timed out counting ALL events (database busy)[-:-:-]", ui.theme.TagError)
			} else {
				ui.setStatusDirect("[%s]Error counting ALL events: %v[-:-:-]", ui.theme.TagError, err)
			}
		})
		return
	}
	page, offset := pageOffset(total, plan.pageSize, plan.pageIndex)

	events, err = ui.store.GetEventsFiltered(ctx, "",
		plan.start, plan.end, plan.severities, plan.types, plan.pageSize, offset)
	if err != nil {
		if ui.logger != nil {
			ui.logger.Printf("Error loading ALL events: %v", err)
		}
		// Reset filter apply guard on failure
		atomic.StoreInt32(&ui.filterApplying, 0)
		ui.queueUpdate(func() {
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
		if d := ui.eventsLoad.startedAgo(); d > 0 {
			ui.logger.Printf("loadAllEvents: query finished in %v; updating UI", d)
		}
	}

	// Update UI in main thread
	ui.queueUpdate(func() {
		ui.recordEventQuery(plan, total, page)
		ui.selectedEventIDs = make(map[string]bool)
		ui.events = events
		ui.updateEventsList()

		// Ensure the table is scrolled to the top and the first *event* is
		// selected — row 1 is a cluster header, not an event.
		ui.eventList.SetOffset(0, 0)
		if ui.eventList.GetRowCount() > 1 {
			ui.selectFirstEvent()
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
		ui.updateOverview(total, totalCases, openN, invN, closeN)

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
				ui.queueUpdate(func() {
					ui.restoreMainLayout()
					ui.setStatusDirect("[%s]Error deleting case: %v[-:-:-]", ui.theme.TagError, err)
				})
				return
			}

			// Refresh cases off the UI goroutine
			if err := ui.refreshCases(); err != nil {
				ui.queueUpdate(func() {
					ui.restoreMainLayout()
					ui.setStatusDirect("[%s]Error refreshing cases after delete: %v[-:-:-]", ui.theme.TagError, err)
				})
				return
			}

			// Finalize UI: select ALL EVENTS and reload
			ui.queueUpdate(func() {
				ui.restoreMainLayout()
				ui.selectedCaseID = ""
				ui.showAll = true
				ui.app.SetFocus(ui.eventList)
				ui.spawnLoad(ui.loadAllEvents)
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

	ui.overlayPrimitive(modal)
}

// buildShortcutHints is the right-hand half of the status bar: the keys the
// screen you are on actually has.
//
// It used to choose them from which widget held focus, with a six-token cap and
// a dead flag that made one branch unreachable. On Triage, Cases and Indicators
// no relevant widget has focus, so all three fell through to the same six —
// "Tab:panels" and "A:all events" on screens with neither, and nothing about
// what those screens could do. The list now comes from the destination table,
// beside the rail's label, so a key can only be advertised by naming the screen
// that handles it.
func (ui *UI) buildShortcutHints() string {
	hints := ui.screenHints()

	// What is true right now rather than always, appended after the screen's
	// own keys so the fixed part of the bar does not move as state changes.
	if ui.hasEventsContext() {
		if len(ui.selectedEventIDs) > 0 {
			hints = append(hints,
				keyHint{"d", "delete"},
				keyHint{"c", "new case"},
				keyHint{"a", "add to case"})
		}
		if ui.activeFilterTag() != "" {
			hints = append(hints, keyHint{"F", "clear"})
		}
	}
	return actionBar(ui.theme, hints...)
}

func (ui *UI) buildStatusMain(message string) string {
	accent := ui.theme.TagAccent
	parts := []string{message}

	// Every badge below describes an events context: which case is open, how
	// many events are selected, which page of them is showing. Only the Events
	// screen has one. They were drawn everywhere — "Page:1/1 Tot:25" under the
	// Cases list, and "Tot:0" under a Triage queue holding two hundred findings,
	// because the findings context's total is never written.
	if !ui.hasEventsContext() {
		return message
	}

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
			parts = append(parts, fmt.Sprintf("[%s]Page:[-]%d/%d  [%s]Tot:[-]%d", accent, s.pageIndex+1, maxPages, accent, s.totalCount))
		}
	}

	return strings.Join(parts, "  ")
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
	// Findings lead: they are the triage queue, and events are the corroboration
	// layer beneath them.
	openFindings, _ := ui.store.CountFindings(ui.ctx, store.FindingFilter{OpenOnly: true})
	line0 := fmt.Sprintf("[%s](D) FINDINGS (%d open)[-]", ui.theme.TagAccent, openFindings)
	line1 := fmt.Sprintf("[%s](2) EVENTS (%d)[-]", ui.theme.TagAccent, eventsTotal)
	// Was "(C) CASES". C had no handler at all, so the panel advertised a key
	// that did nothing. Cases is destination 3.
	line2 := fmt.Sprintf("[%s](3) CASES (%d)[-]", ui.theme.TagAccent, casesTotal)
	line3 := fmt.Sprintf("[%s]OPEN[-] - %d  [%s]INVESTIGATING[-] - %d  [%s]CLOSED[-] - %d",
		ui.theme.TagTextPrimary, open,
		ui.theme.TagTextPrimary, investigating,
		ui.theme.TagTextPrimary, closed,
	)
	ui.allCasesInfo.SetText(line0 + "\n" + line1 + "\n" + line2 + "\n" + line3)
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
				ui.queueUpdate(func() {
					ui.restoreMainLayout()
					ui.setStatusDirect("[%s]Error deleting events: %v[-:-:-]", ui.theme.TagError, err)
				})
				return
			}

			// Best-effort: refresh cases to update event_count numbers in the sidebar
			_ = ui.refreshCases()

			// Finalize UI: clear selections and reload current context
			ui.queueUpdate(func() {
				ui.restoreMainLayout()
				ui.selectedEventIDs = make(map[string]bool)
				// Reload events for current context
				ui.spawnLoad(func() { ui.scheduleEventsReload("delete:events") })
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

	ui.overlayPrimitive(modal)
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
			ui.queueUpdate(func() {
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

	ui.overlayForm(form, 64)
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
		ui.queueUpdate(func() {
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
	ui.spawnLoad(func() { ui.scheduleEventsReload(source) })
}

// SetIngestDir records the drop folder being watched, so empty-state hints name
// the real path rather than a hardcoded one that drifts when the default moves.
func (ui *UI) SetIngestDir(dir string) { ui.ingestDir = dir }

// MarkEphemeral tells the interface its database will not outlive the session.
//
// Set by the demo, which builds a throwaway database in a temporary directory
// and removes it on exit. An analyst can triage the queue, write notes and
// produce a report in there, and none of it survives quitting — so the screen
// says so while there is still time to act on it.
func (ui *UI) MarkEphemeral() { ui.ephemeral = true }

// SetWatcherStatus supplies folder-ingestion health to the evidence pulse.
// Without it the pulse says "not watching", which is the truthful answer for a
// UI built without a watcher (tests, live-events).
func (ui *UI) SetWatcherStatus(fn func() WatcherStatus) { ui.watcher = fn }

// SetEnrichmentStatus supplies the enrichment backlog to the evidence pulse.
func (ui *UI) SetEnrichmentStatus(fn func() EnrichmentStatus) { ui.enrichment = fn }

// watcherStatus reports folder-ingestion health, or a zero value when no
// watcher was wired in.
func (ui *UI) watcherStatus() WatcherStatus {
	if ui.watcher == nil {
		return WatcherStatus{}
	}
	return ui.watcher()
}

// enrichmentStatus reports the enrichment backlog, or a zero value when no
// plugin manager was wired in.
func (ui *UI) enrichmentStatus() EnrichmentStatus {
	if ui.enrichment == nil {
		return EnrichmentStatus{}
	}
	return ui.enrichment()
}

// watchedDir is the folder to name in hints, falling back to the default when
// the UI was constructed without one (tests, live-events).
func (ui *UI) watchedDir() string {
	if strings.TrimSpace(ui.ingestDir) == "" {
		return ingest.DefaultDir
	}
	return ui.ingestDir
}

// applyRailVisibility hides the navigation rail in compact mode and shows it
// everywhere else, including Home.
//
// Home hid it for one release, because at 45 columns the rail took a third of
// the screen from the one view that has three panels to fit. At 22 it costs a
// sixth, and an analyst who cannot see the destinations cannot learn them.
func (ui *UI) applyRailVisibility() {
	if ui.layout == nil || ui.leftCol == nil {
		return
	}
	want := navRailWidth
	if !ui.navRailVisible() {
		want = 0
	}
	if want == ui.railShown {
		return
	}
	ui.railShown = want
	ui.needsClear = true
	ui.layout.ResizeItem(ui.leftCol, want, 0)
}

// queueUpdate applies fn on the UI goroutine and redraws.
//
// tview's QueueUpdateDraw is synchronous: it blocks until the application's
// event loop picks the update up. Called before app.Run() has started — or from
// a test, which never starts it — that is a deadlock, not a slow path. Running
// fn directly in that case is safe precisely because nothing is drawing yet.
// spawnLoad runs a load off the UI goroutine, tracked so a caller that needs
// the result — or that is about to take the database away — can wait for it.
//
// Every screen entry starts a load and returns before it has run. Without a
// handle on those goroutines a test cannot tell "the load has not started yet"
// from "the load has finished", and the two look identical from outside.
func (ui *UI) spawnLoad(fn func()) {
	ui.loads.Add(1)
	go func() {
		defer ui.loads.Done()
		fn()
	}()
}

// waitForLoads blocks until no screen load is in flight.
//
// It is not called by the application: a load part-way through queueing a
// repaint is waiting for the UI goroutine, so waiting on one from there would
// deadlock. Tests call it before they let a store go away.
func (ui *UI) waitForLoads() {
	ui.loads.Wait()
}

func (ui *UI) queueUpdate(fn func()) {
	if !ui.running.Load() {
		// Serialised, because that is the property being stood in for. The
		// event loop runs one update at a time; running fn straight on the
		// caller's goroutine let two loads that finished together paint the
		// same widgets at once — a race that exists only without a loop, but a
		// real one, and -race cannot tell the two situations apart.
		//
		// Nesting a queueUpdate inside a queued fn would deadlock here. It
		// deadlocks under a running loop too, for the same reason, so this
		// makes an existing rule visible rather than adding one.
		ui.inlineUpdate.Lock()
		defer ui.inlineUpdate.Unlock()
		fn()
		return
	}
	ui.app.QueueUpdateDraw(fn)
}

func (ui *UI) setMainView(p tview.Primitive) {
	if ui.mainPanel == nil {
		return
	}
	// Home owns a clock and a refresh ticker. Leaving them running behind
	// another screen leaks a goroutine and keeps queueing redraws for a screen
	// nobody is looking at.
	if ui.home != nil && p != ui.home.root {
		ui.home.close()
		ui.home = nil
	}
	// The outgoing screen's borders are not painted over by the incoming one.
	ui.needsClear = true
	ui.mainPanel.Clear()
	ui.mainPanel.AddItem(p, 0, 1, true)
	ui.app.SetFocus(p)
}

func (ui *UI) restoreEventsView() {
	if ui.mainPanel == nil {
		return
	}
	ui.mainPanel.Clear()
	ui.mainPanel.SetDirection(tview.FlexRow)

	if ui.showFindings {
		ui.mainPanel.AddItem(ui.triageChipRow(), 1, 0, false)
	} else if ui.pivot != nil {
		// A pivot is a filter, so it gets a chip. Narrowing the list without
		// saying so leaves the analyst looking at a subset they cannot see the
		// edge of, which is indistinguishable from missing data.
		chip := tview.NewTextView().SetDynamicColors(true)
		chip.SetBackgroundColor(ui.theme.Bg)
		chip.SetText(fmt.Sprintf("  [%s:%s] %s: %s ✕[-:-:-]   [%s]F clears[-:-:-]",
			ui.theme.TagTextPrimary, ui.theme.TagAccent,
			ui.pivot.Kind, tview.Escape(ui.pivot.Value), ui.theme.TagMuted))
		ui.mainPanel.AddItem(chip, 1, 0, false)
	}

	// Table and inspector side by side once there is room for both, stacked
	// below that. The inspector used to be stacked at every width, which on a
	// 140-column terminal wasted half the screen to show six fields.
	body := tview.NewFlex()
	if ui.currentLayoutMode == LayoutWide {
		body.SetDirection(tview.FlexColumn)
		body.AddItem(ui.eventList, 0, 2, true).
			AddItem(ui.eventDetail, 0, 1, false)
	} else {
		body.SetDirection(tview.FlexRow)
		body.AddItem(ui.eventList, 0, 2, true).
			AddItem(ui.eventDetail, 0, 1, false)
	}
	ui.mainPanel.AddItem(body, 0, 1, true)

	if ui.showFindings {
		ui.mainPanel.AddItem(ui.triageStrip(), 1, 0, false)
	}
	ui.app.SetFocus(ui.eventList)
}

// triageChipRow returns the quick-filter row, creating it on first use.
func (ui *UI) triageChipRow() *tview.TextView {
	if ui.chipRow == nil {
		ui.chipRow = tview.NewTextView().SetDynamicColors(true)
	}
	ui.chipRow.SetBackgroundColor(ui.theme.Bg)
	ui.chipRow.SetText(ui.triageFilterState().renderChips(ui.theme))
	return ui.chipRow
}

// triageStrip returns the bar below the table: the action bar normally, and the
// selection strip whenever rows are selected.
//
// It replaces the action bar rather than joining it. With a selection live, the
// bulk actions are the only ones that apply, and offering both invites pressing
// a single-row action on a multi-row selection.
func (ui *UI) triageStrip() *tview.TextView {
	if ui.strip == nil {
		ui.strip = tview.NewTextView().SetDynamicColors(true)
	}
	ui.strip.SetBackgroundColor(ui.theme.Bg)
	ui.strip.SetText(ui.renderTriageStrip())
	return ui.strip
}

func (ui *UI) renderTriageStrip() string {
	t := ui.theme

	// Only the selection. The screen's keys are on the status bar, and this
	// listed them a second time — two bars, one above the other, that between
	// them offered "/" for a filter the other did not mention and disagreed
	// about whether s and v were bulk actions.
	n := ui.triageSelection().count()
	if n == 0 {
		return ""
	}
	return fmt.Sprintf("  [%s:-:b]%s selected[-:-:-]  %s",
		t.TagAccent, plural(n, "finding"), actionBar(t,
			keyHint{"e", "escalate"},
			keyHint{"s", "status"},
			keyHint{"v", "verdict"},
			keyHint{"x", "clear"},
		))
}

// triageFilterState returns the filter, creating it on first use.
func (ui *UI) triageFilterState() *triageFilter {
	if ui.triage == nil {
		ui.triage = newTriageFilter()
	}
	return ui.triage
}

// triageSelection returns the selection, creating it on first use.
func (ui *UI) triageSelection() *triageSelection {
	if ui.triageSel == nil {
		ui.triageSel = newTriageSelection()
	}
	return ui.triageSel
}

// repaintTriageChrome repaints the chip row and the strip without re-querying.
func (ui *UI) repaintTriageChrome() {
	if ui.chipRow != nil {
		ui.chipRow.SetText(ui.triageFilterState().renderChips(ui.theme))
	}
	if ui.strip != nil {
		ui.strip.SetText(ui.renderTriageStrip())
	}
}

func (ui *UI) switchToAllEvents() {
	ui.restoreEventsView()

	s := ui.getOrInitState(contextAll)
	s.pageIndex = 0

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

	ui.eventsLoad.reclaimIfStuck()
	ui.spawnLoad(ui.loadAllEvents)
}

func (ui *UI) switchToCases() {
	if len(ui.cases) == 0 {
		// An empty Cases screen, not a bounce to Home. Sending the analyst
		// somewhere else makes the key look broken — and now that the rail
		// marks the destination, it visibly contradicts itself.
		ui.setMainView(emptyState("",
			"No investigations yet",
			"A case is what you escalate a finding into.",
			[]string{"1 Triage", "c New case"}, ui.theme))
		ui.setStatusDirect("[%s]Cases • press 'c' to create one[-:-:-]", ui.theme.TagAccent)
		return
	}
	// The case list beside the briefing of whichever case is selected.
	//
	// The list used to be pinned under the navigation rail on every screen,
	// which is why the rail needed 45 columns. It belongs here: on the Cases
	// screen it is the content, and everywhere else it was furniture.
	ui.casesPane = tview.NewFlex().SetDirection(tview.FlexColumn)
	ui.casesPane.SetBackgroundColor(ui.theme.Bg)
	ui.casesPane.AddItem(ui.sidebar, casesListWidth(ui.termWidth), 0, true)
	ui.casesPane.AddItem(ui.buildCaseBriefingTab(ui.cases[0]), 0, 1, false)
	ui.selectedCaseID = ui.cases[0].ID

	// Moving down the list changes the briefing beside it.
	//
	// The list had no changed-handler at all, so the briefing was pinned to the
	// first case. Its only swap path was a digit typed into the list — and the
	// global capture claims 1 to 5 for navigation, so it worked for the sixth
	// case onwards and for nothing anyone would find.
	ui.sidebar.SetChangedFunc(func(index int, _, _ string, _ rune) {
		// Guarded: updateCasesList calls Clear, which fires this with -1.
		if !ui.onCases() || index < 0 || index >= len(ui.cases) {
			return
		}
		ui.showCaseBriefing(ui.cases[index])
	})

	ui.setMainView(ui.casesPane)
	ui.app.SetFocus(ui.sidebar)
	if ui.sidebar.GetItemCount() > 0 {
		ui.sidebar.SetCurrentItem(0)
	}
	// Rebuild the rows for the width in force now.
	//
	// The list is filled once at start-up, when the terminal's width is not yet
	// known, and the titles are cut to fit it — so a wide terminal showed
	// titles trimmed to the narrowest layout until something else refreshed
	// the list.
	//
	// Rendered directly: this runs on the UI goroutine, and the queued form
	// waits for a loop that is currently executing this function.
	ui.renderCasesList()
	ui.setStatusDirect("[%s]Cases • Enter opens a case · c creates one[-:-:-]", ui.theme.TagAccent)
}

// The case list's width on the Cases screen.
//
// It was a fixed 38, which truncated "Suspected account compromise — m.chen"
// mid-word — and the title is what the list is for. A third of the terminal,
// bounded at both ends so a narrow terminal keeps a readable briefing beside
// it and a very wide one does not hand the list half the screen.
const (
	casesListMin = 38
	casesListMax = 64
)

func casesListWidth(termWidth int) int {
	w := termWidth / 3
	if w < casesListMin {
		return casesListMin
	}
	if w > casesListMax {
		return casesListMax
	}
	return w
}

// showCaseBriefing swaps the briefing pane to a different case, keeping the
// list beside it. Without this the list could select a case it could not open.
func (ui *UI) showCaseBriefing(c store.Case) {
	ui.selectedCaseID = c.ID
	if ui.casesPane == nil || ui.casesPane.GetItemCount() < 2 {
		ui.setMainView(ui.buildCaseBriefingTab(c))
		return
	}
	ui.casesPane.RemoveItem(ui.casesPane.GetItem(1))
	ui.casesPane.AddItem(ui.buildCaseBriefingTab(c), 0, 1, false)
}

func (ui *UI) showHelpModal() {
	ui.showHelp()
}
