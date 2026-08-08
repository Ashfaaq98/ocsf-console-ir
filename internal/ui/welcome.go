package ui

import (
	"fmt"
	"strings"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/logging"
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// The Welcome Screen is the first thing a new install shows, and it is the only
// screen that runs without a database. It is deliberately built from its own
// root rather than from the main layout with panels hidden: a first-time user
// shown an empty dashboard with zeroed metric cards concludes the tool is
// broken. Nothing here constructs a table, an inspector or a sidebar.
//
// The screen itself is a two-column page — see welcome_page.go for the layout,
// welcome_brand.go for the identity column, welcome_actions.go for the choices.
// This file owns the state machine, the keys and the lifecycle.

// WelcomeAction is the choice an analyst made on the Welcome Screen.
type WelcomeAction int

const (
	// WelcomeQuit is the zero value so an abandoned screen — Ctrl+C, a closed
	// terminal — can never be mistaken for a request to create anything.
	WelcomeQuit WelcomeAction = iota
	WelcomeCreate
	WelcomeDemo
	WelcomeImport
	WelcomeWatch
)

// String names the action for logs and tests.
func (a WelcomeAction) String() string {
	switch a {
	case WelcomeCreate:
		return "create"
	case WelcomeDemo:
		return "demo"
	case WelcomeImport:
		return "import"
	case WelcomeWatch:
		return "watch"
	default:
		return "quit"
	}
}

// WelcomeResult is what the Welcome Screen returns to its caller.
type WelcomeResult struct {
	Action WelcomeAction
	// Path is the file to import or the directory to watch, and is empty for
	// every other action.
	Path string
}

// WelcomeOptions configures the Welcome Screen.
type WelcomeOptions struct {
	// DBPath is the database that was looked for and not found. It is named on
	// the page before anything is created, and again if creating it fails:
	// "could not create the database" is unactionable without knowing where it
	// was attempted, and so is "a database will be created".
	DBPath string

	// WatchDir pre-fills the watch-folder prompt with the folder the running
	// configuration would actually watch.
	WatchDir string

	// DemoSummary says what the demo investigation actually contains, in one
	// line. The caller supplies it because the counts live in two places this
	// package has no business reaching into — the embedded dataset and the
	// seeded cases — and because a literal here would rot the first time either
	// changed. Empty is fine; the action simply loses its detail line.
	DemoSummary string

	// Version is the build being run, shown beside the name. This is the first
	// screen a new install shows and often the only one a bug report can be
	// written from, so the answer to "what am I running" belongs on it. It is
	// passed through buildinfo.Display, so it reads the same here as it does in
	// the main header and in `console-ir version`.
	Version string

	// Perform carries out the chosen action. It runs off the UI goroutine and
	// reports each stage through progress, which is safe to call from it.
	//
	// Everything that touches a database lives behind this callback: the view
	// decides what the analyst asked for, the caller decides how to do it.
	Perform func(res WelcomeResult, progress func(string)) error

	Logger *logging.Logger
}

// Copy is fixed by the specification. It is defined once, here, so the screen
// and its tests cannot disagree about what the product says.
const (
	welcomeTitleText   = "Console-IR"
	welcomeDescription = "Terminal-native incident response."
	welcomePrivacyA    = "Everything stays on this machine"
	welcomePrivacyB    = "No cloud, no account, no telemetry"

	// welcomeDatabaseLead* introduce the path the first action will write to.
	// Two short lines rather than one long one: the block's width is already
	// set by the path itself, and there is no reason for the prose to widen the
	// brand column past it.
	welcomeDatabaseLeadA = "No database yet."
	welcomeDatabaseLeadB = "One will be created at"
)

// welcomeState is which face the right-hand column is showing. The page is one
// layout in four states rather than four layouts, so a state change cannot
// leave two of them on screen at once.
type welcomeState int

const (
	welcomeStateMenu welcomeState = iota
	welcomeStatePrompt
	welcomeStateLoading
	welcomeStateError
)

// welcomeFooterRows is the navigation bar pinned to the bottom row.
const welcomeFooterRows = 1

// welcomeView is the screen. It owns its own root and none of the main layout.
type welcomeView struct {
	opts  WelcomeOptions
	theme Theme
	app   *tview.Application

	root  *tview.Flex
	page  *tview.Flex
	input *tview.InputField
	bar   *tview.TextView

	// rows are the page's lines, one single-line widget each. See setPage.
	rows []*tview.TextView

	// promptRow hosts the input field in the right-hand column, which is the
	// one row of the page that cannot be a rendered string.
	promptRow  *tview.Flex
	promptLead *tview.TextView

	// Layout state, so a redraw at an unchanged size costs nothing.
	mode   LayoutMode
	short  bool
	width  int
	height int
	built  bool

	// Screen state.
	state welcomeState
	// cursor is the action the arrow keys are resting on.
	cursor int
	// watchStatus is what the drop folder looked like when the screen opened.
	watchStatus string
	// density is how much optional content the current page is carrying. It is
	// settled by pageRows, which composes the page at each level until one fits.
	density welcomeDensity
	// truecolor is whether this terminal can draw the wordmark's gradient.
	truecolor bool

	// The reveal. frame is the animation clock and is meaningless while
	// revealing is false, which is when every part of the page is on screen.
	revealing  bool
	frame      int
	revealDone chan struct{}
	pending    WelcomeResult
	loading    string
	err        error

	// Outcome, read by RunWelcome once the application stops.
	result  WelcomeResult
	outcome error
}

// RunWelcome shows the Welcome Screen and blocks until the analyst has chosen.
//
// It runs its own tview.Application. The main UI is constructed only after this
// returns, and only if a database now exists, so the two never share a widget
// tree or a lifetime.
func RunWelcome(opts WelcomeOptions) (WelcomeResult, error) {
	v := newWelcomeView(opts)
	v.app = tview.NewApplication()

	v.app.SetInputCapture(v.handleKey)

	// The layout tier is recomputed here rather than in a primitive's draw
	// function: this callback runs before the root is drawn, which is the only
	// point at which rebuilding the tree is safe.
	v.app.SetBeforeDrawFunc(v.beforeDraw)

	v.app.SetRoot(v.root, true)
	v.focusForState()
	v.startReveal()

	if err := v.app.Run(); err != nil {
		return WelcomeResult{}, err
	}
	return v.result, v.outcome
}

// newWelcomeView builds the widget tree.
//
// Its only I/O is reading the persisted theme and probing the drop folder, both
// of which are a single local read, so the first paint does not wait on
// anything. Nothing here opens a database or touches the network.
func newWelcomeView(opts WelcomeOptions) *welcomeView {
	theme := themeBuilders[loadThemeName()]()

	v := &welcomeView{
		opts:      opts,
		theme:     theme,
		cursor:    welcomeDefaultCursor,
		truecolor: supportsTrueColor(),
	}
	v.probe()

	v.page = tview.NewFlex().SetDirection(tview.FlexRow)

	// The label and placeholder are the affordance: an empty field on a page
	// whose background it shares is indistinguishable from a blank row, and a
	// screen that looks like it is waiting for nothing is a screen people quit.
	v.input = tview.NewInputField()
	v.input.SetLabel("› ").
		SetFieldBackgroundColor(theme.Surface).
		SetFieldTextColor(theme.TextPrimary).
		SetPlaceholderTextColor(theme.TextMuted).
		SetLabelColor(theme.Accent)
	v.input.SetBackgroundColor(theme.Canvas)
	v.input.SetDoneFunc(v.promptDone)

	v.promptLead = welcomeText(theme, tview.AlignLeft)
	v.promptRow = tview.NewFlex()

	v.bar = welcomeText(theme, tview.AlignLeft)

	// No SetBackgroundColor here: tview.NewFlex sets dontClear on its Box, so a
	// Flex never paints its own background and the call would be a silent no-op.
	// The canvas is painted in beforeDraw, which says why.
	v.root = tview.NewFlex().SetDirection(tview.FlexRow)

	// A sensible size until the first draw reports the real one, so the tree is
	// never empty and tests can drive the view without a screen.
	v.width, v.height = 120, 34
	v.render()
	return v
}

// welcomeText builds one of the screen's text widgets.
//
// The background is the canvas, not theme.Bg. These widgets are full-width, so
// any colour of their own reads as a horizontal band across the screen rather
// than as a background — which is exactly what the screen used to render.
func welcomeText(theme Theme, align int) *tview.TextView {
	tv := tview.NewTextView().
		SetDynamicColors(true).
		SetTextAlign(align)
	tv.SetBackgroundColor(theme.Canvas)
	return tv
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

// render repaints everything that depends on the current state and rebuilds the
// layout, because the page's height is state-dependent.
func (v *welcomeView) render() {
	v.bar.SetText(v.footerText())
	v.built = false
	v.rebuild()
	v.focusForState()
}

// beforeDraw is the frame preamble, run once per repaint before the root is
// drawn. It re-tiers the layout for the current terminal size and paints the
// canvas the whole screen is built on.
//
// The fill is not optional, and it has to be a fill rather than screen.Clear().
//
// Clear() fills with tcell.StyleDefault, which is the terminal's own background
// — so every row not covered by a widget showed the user's terminal colours
// instead of the theme's, and the screen rendered as horizontal stripes. Nor
// can the root Flex be asked to do it: tview.NewFlex sets dontClear on its Box,
// so SetBackgroundColor on a Flex is a permanent no-op.
//
// Filling unconditionally also retires the dirty-tracking this function used to
// do. tview does not clear between frames and the page changes shape between
// states, so a missed clear left the previous state's rows on screen; repainting
// the canvas every frame makes that impossible rather than merely accounted for.
// It costs nothing on the wire — tcell only emits cells that actually changed.
func (v *welcomeView) beforeDraw(screen tcell.Screen) bool {
	width, height := screen.Size()
	v.relayout(width, height)
	screen.Fill(' ', tcell.StyleDefault.Background(v.theme.Canvas))
	return false
}

// relayout recomputes the responsive tier and rebuilds only when it changed.
// It returns whether it rebuilt.
func (v *welcomeView) relayout(width, height int) bool {
	mode, short := GetLayoutMode(width, height)
	if v.built && mode == v.mode && short == v.short && width == v.width && height == v.height {
		return false
	}
	v.mode, v.short = mode, short
	v.width, v.height = width, height
	v.rebuild()
	return true
}

// rebuild assembles the root from scratch: the page anchored a little above
// centre, with the navigation bar pinned to the bottom row.
func (v *welcomeView) rebuild() {
	v.mode, v.short = GetLayoutMode(v.width, v.height)

	rows := v.pageRows()
	rows = v.trimToHeight(rows)
	v.setPage(rows)

	v.root.Clear()
	v.root.AddItem(nil, v.topSpace(len(rows)), 0, false)
	v.root.AddItem(v.page, len(rows), 0, true)
	v.root.AddItem(nil, 0, 1, false)
	v.root.AddItem(v.bar, welcomeFooterRows, 0, false)

	v.built = true
}

// topSpace is how many rows sit above the page.
//
// True centring puts as much space above the page as below it, which on a tall
// terminal reads as a small block floating in a void. Anchoring a little above
// centre reads as composed, and on a short terminal it degrades to nothing
// rather than to a negative.
func (v *welcomeView) topSpace(pageRows int) int {
	free := v.height - pageRows - welcomeFooterRows
	if free <= 0 {
		return 0
	}
	return free * welcomeAnchor / 100
}

// trimToHeight drops rows from the end when the terminal cannot hold the page.
//
// It is a backstop, not the layout: the columns drop their optional content
// first, and reaching this point means even the reduced page does not fit. The
// actions are the last thing standing because without them the screen does
// nothing at all.
func (v *welcomeView) trimToHeight(rows []string) []string {
	if max := v.height - welcomeFooterRows; len(rows) > max && max > 0 {
		return rows[:max]
	}
	return rows
}

// setPage fills the page with one single-line widget per row.
//
// One widget per line rather than one multi-line TextView, because tview's
// escaped-tag state leaks between the lines of a single TextView: a block built
// that way renders with one more character of the previous line's colour tag
// bleeding onto every subsequent row.
//
// The widgets are reused across rebuilds, so a redraw allocates nothing.
func (v *welcomeView) setPage(rows []string) {
	v.page.Clear()

	promptAt := -1
	if v.state == welcomeStatePrompt {
		promptAt = v.promptRowIndex(len(rows))
	}

	for i, line := range rows {
		if i >= len(v.rows) {
			v.rows = append(v.rows, welcomeText(v.theme, tview.AlignLeft))
		}
		v.rows[i].SetText(line)

		if i == promptAt {
			v.page.AddItem(v.promptFlex(line), 1, 0, true)
			continue
		}
		v.page.AddItem(v.rows[i], 1, 0, false)
	}
}

// promptFlex is the one row of the page that is two widgets rather than a
// string: the brand column's text, then the real input field beside it.
//
// No truncation is needed to make room. The prompt's cell for this row is
// deliberately empty, so the composed line already stops where the right-hand
// column begins — which matters, because cutting a tagged string at a screen
// column can land inside a colour tag and put the markup on the screen.
func (v *welcomeView) promptFlex(line string) *tview.Flex {
	v.promptLead.SetText(line)

	v.promptRow.Clear()
	v.promptRow.AddItem(v.promptLead, v.rightColumnAt(), 0, false)
	v.promptRow.AddItem(v.input, 0, 1, true)
	return v.promptRow
}

// rightColumnAt is the screen column the right-hand column begins at, or 0 when
// the page is stacked rather than split.
func (v *welcomeView) rightColumnAt() int {
	left, right := v.leftColumn(), v.rightColumn()
	if !v.splitFits(left, right) {
		return v.stackedIndent(left, right)
	}
	return welcomePageIndent + widestCell(left) + welcomeGutter
}

// promptRowIndex is which page row carries the input field.
func (v *welcomeView) promptRowIndex(total int) int {
	left, right := v.leftColumn(), v.rightColumn()
	if v.splitFits(left, right) {
		return promptFieldRow
	}
	// Stacked, the right-hand column starts after the brand and the gap.
	row := len(left) + welcomeStackedGap + promptFieldRow
	if total > 0 && row >= total {
		return total - 1
	}
	return row
}

// pageLines is the page as it reaches the screen, one string per row.
func (v *welcomeView) pageLines() []string {
	out := make([]string, 0, v.page.GetItemCount())
	for i := 0; i < v.page.GetItemCount(); i++ {
		switch row := v.page.GetItem(i).(type) {
		case *tview.TextView:
			out = append(out, row.GetText(true))
		case *tview.Flex:
			out = append(out, v.promptLead.GetText(true)+v.input.GetText())
		default:
			out = append(out, "")
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// The footer
// ---------------------------------------------------------------------------

// footerText is the bottom row: how to drive this state on the left, and what
// the screen has detected about this terminal on the right.
//
// It no longer repeats the action list. The page already lists every action
// with its key, and a bar that lists them again taught nothing while taking the
// only row it had.
func (v *welcomeView) footerText() string {
	t := v.theme
	var hints string
	switch v.state {
	case welcomeStatePrompt:
		hints = actionBar(t, keyHint{"Enter", "Continue"}, keyHint{"Esc", "Back"})
	case welcomeStateLoading:
		hints = actionBar(t, keyHint{"Ctrl+C", "Cancel"})
	case welcomeStateError:
		hints = actionBar(t, keyHint{"r", "Retry"}, keyHint{"q", "Quit"})
	default:
		hints = actionBar(t,
			keyHint{welcomeArrows(), "Move"},
			keyHint{welcomeEnter(), "Select"},
			keyHint{"1-4", "Jump"},
			keyHint{"q", "Quit"})
	}

	status := v.statusText()
	pad := v.width - len([]rune(stripTags(hints))) - len([]rune(status)) - 2
	if pad < 2 {
		return " " + hints
	}
	return " " + hints + strings.Repeat(" ", pad) + fmt.Sprintf("[%s]%s[-:-:-]", t.TagMuted, status)
}

// welcomeArrows and welcomeEnter name the movement keys in whichever alphabet
// this terminal can draw. A footer that teaches the keys in glyphs the screen
// cannot render teaches nothing.
func welcomeArrows() string {
	if supportsUnicode() {
		return "↑↓"
	}
	return "up/dn"
}

func welcomeEnter() string {
	if supportsUnicode() {
		return "⏎"
	}
	return "Enter"
}

// statusText is what the screen worked out about this terminal. It is a small
// thing that says the detection ran, on the one screen where a rendering fault
// would otherwise look like a broken install.
func (v *welcomeView) statusText() string {
	parts := []string{loadThemeName()}
	if supportsUnicode() {
		parts = append(parts, "UTF-8")
	} else {
		parts = append(parts, "ASCII")
	}
	if v.truecolor {
		parts = append(parts, "truecolor")
	}
	return strings.Join(parts, " · ")
}

// ---------------------------------------------------------------------------
// Copy that depends on state
// ---------------------------------------------------------------------------

// verb names an action the way an error message needs to.
func (a WelcomeAction) verb() string {
	switch a {
	case WelcomeDemo:
		return "load the demo investigation"
	case WelcomeImport:
		return "import that file"
	case WelcomeWatch:
		return "watch that folder"
	default:
		return "create the database"
	}
}

func (v *welcomeView) errorText() string {
	if v.err == nil {
		return ""
	}
	return v.err.Error()
}

// attemptedPath is the path the failed action was aimed at, which is the file
// or folder for import and watch and the database for everything else.
func (v *welcomeView) attemptedPath() string {
	if v.pending.Path != "" {
		return v.pending.Path
	}
	return v.opts.DBPath
}

func (v *welcomeView) promptLabel() string {
	if v.pending.Action == WelcomeWatch {
		return "Folder to watch for OCSF files:"
	}
	return "Path to a JSON or JSONL file:"
}

// ---------------------------------------------------------------------------
// Input
// ---------------------------------------------------------------------------

// handleKey is the screen's only key handler. Each state accepts exactly the
// keys its footer advertises, so nothing on this screen is reachable without
// being shown.
func (v *welcomeView) handleKey(ev *tcell.EventKey) *tcell.EventKey {
	// Whatever the key was, it means the analyst is ready and the reveal is
	// not. Finishing it here rather than in each branch means no key can be
	// swallowed by an animation that happened to be running when it arrived.
	v.finishReveal()

	switch v.state {
	case welcomeStateLoading:
		// Work is in flight against the filesystem; the only safe answer is to
		// abandon the process, which tview's own Ctrl+C handling does.
		if ev.Key() == tcell.KeyCtrlC {
			return ev
		}
		return nil

	case welcomeStatePrompt:
		// The input field owns its own keys, including Enter and Esc.
		return ev

	case welcomeStateError:
		switch ev.Key() {
		case tcell.KeyCtrlC:
			return ev
		case tcell.KeyRune:
			switch ev.Rune() {
			case 'r', 'R':
				v.launch(v.pending)
			case 'q', 'Q':
				v.quit()
			}
		}
		return nil

	default:
		switch ev.Key() {
		case tcell.KeyCtrlC:
			return ev
		case tcell.KeyUp:
			v.moveCursor(-1)
		case tcell.KeyDown:
			v.moveCursor(1)
		case tcell.KeyEnter:
			v.activate(v.cursorOption())
		case tcell.KeyRune:
			switch ev.Rune() {
			case 'k':
				v.moveCursor(-1)
			case 'j':
				v.moveCursor(1)
			default:
				// The digits still act immediately rather than moving the
				// cursor. That is what the screen has always done and what the
				// footer advertises; the cursor is a second way in, not a
				// replacement that makes everyone press a key twice.
				v.choose(ev.Rune())
			}
		}
		return nil
	}
}

// choose acts on a key from the action list.
func (v *welcomeView) choose(r rune) {
	for _, o := range welcomeOptions {
		if o.key != r {
			continue
		}
		v.activate(o)
		return
	}
}

// activate carries out one option.
func (v *welcomeView) activate(o welcomeOption) {
	switch o.action {
	case WelcomeQuit:
		v.quit()
	case WelcomeImport, WelcomeWatch:
		v.ask(o.action)
	default:
		v.launch(WelcomeResult{Action: o.action})
	}
}

// ask opens the path prompt for the actions that need one.
func (v *welcomeView) ask(action WelcomeAction) {
	v.pending = WelcomeResult{Action: action}
	v.state = welcomeStatePrompt
	if action == WelcomeWatch {
		// Pre-filled with the folder this process would watch anyway, so the
		// common answer is Enter.
		v.input.SetText(v.opts.WatchDir)
		v.input.SetPlaceholder("./incoming")
	} else {
		v.input.SetText("")
		v.input.SetPlaceholder("/path/to/events.jsonl")
	}
	v.render()
}

// promptDone handles the prompt's terminal keys. Esc returns to the page with
// no side effects at all: nothing has been created at this point.
func (v *welcomeView) promptDone(key tcell.Key) {
	switch key {
	case tcell.KeyEscape:
		v.pending = WelcomeResult{}
		v.state = welcomeStateMenu
		v.render()
	case tcell.KeyEnter:
		path := strings.TrimSpace(v.input.GetText())
		if path == "" {
			return
		}
		v.launch(WelcomeResult{Action: v.pending.Action, Path: path})
	}
}

// quit leaves without creating anything. From the error state it carries the
// failure out, so the process exits non-zero rather than reporting success for
// a run that produced no database.
func (v *welcomeView) quit() {
	v.result = WelcomeResult{Action: WelcomeQuit}
	if v.state == welcomeStateError {
		v.outcome = v.err
	}
	v.stop()
}

// launch starts an action and shows the loading state while it runs.
func (v *welcomeView) launch(res WelcomeResult) {
	v.pending = res
	v.state = welcomeStateLoading
	v.loading = "Working…"
	v.err = nil
	v.render()

	if v.app == nil {
		// No application: this is a test driving the view directly. Running the
		// work inline keeps assertions deterministic.
		v.perform(res)
		return
	}
	go v.perform(res)
}

// perform runs the action off the UI goroutine and settles the screen on the
// result. It is the only place that decides between "done" and "error".
func (v *welcomeView) perform(res WelcomeResult) {
	if v.opts.Perform == nil {
		v.update(func() { v.succeed(res) })
		return
	}

	progress := func(stage string) {
		v.update(func() {
			v.loading = stage
			v.render()
		})
	}

	err := v.opts.Perform(res, progress)

	v.update(func() {
		if err != nil {
			v.log("welcome: %s failed: %v", res.Action, err)
			v.err = err
			v.state = welcomeStateError
			v.render()
			return
		}
		v.succeed(res)
	})
}

// succeed finishes the screen. Settings are initialised here rather than in the
// caller so every route out of Welcome leaves the same install behind.
func (v *welcomeView) succeed(res WelcomeResult) {
	if err := ensureUISettings(); err != nil {
		// A missing preferences file is not a reason to refuse a database that
		// was created successfully.
		v.log("welcome: could not write the settings file: %v", err)
	}
	v.log("welcome: %s completed", res.Action)
	v.result = res
	v.outcome = nil
	v.stop()
}

// focusForState puts the cursor where the current state expects typing.
func (v *welcomeView) focusForState() {
	if v.app == nil {
		return
	}
	if v.state == welcomeStatePrompt {
		v.app.SetFocus(v.input)
		return
	}
	v.app.SetFocus(v.root)
}

// update runs fn on the UI goroutine, or inline when there is no application.
func (v *welcomeView) update(fn func()) {
	if v.app == nil {
		fn()
		return
	}
	v.app.QueueUpdateDraw(fn)
}

func (v *welcomeView) stop() {
	// Before the application, so the reveal's goroutine sees the screen going
	// away rather than queueing an update nothing will ever run.
	v.finishReveal()
	if v.app != nil {
		v.app.Stop()
	}
}

func (v *welcomeView) log(format string, args ...any) {
	if v.opts.Logger != nil {
		v.opts.Logger.Info(format, args...)
	}
}

// ---------------------------------------------------------------------------
// Text helpers
// ---------------------------------------------------------------------------

// wrapText breaks s onto lines of at most width columns, on word boundaries.
func wrapText(s string, width int) []string {
	if width < 1 {
		width = 1
	}
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return []string{""}
	}

	var lines []string
	line := fields[0]
	for _, w := range fields[1:] {
		if len(line)+1+len(w) > width {
			lines = append(lines, line)
			line = w
			continue
		}
		line += " " + w
	}
	return append(lines, line)
}
