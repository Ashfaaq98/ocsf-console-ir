package ui

import (
	"fmt"
	"os"
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
	// DBPath is the database that was looked for and not found. It is shown in
	// the error state, because "could not create the database" is unactionable
	// without knowing where it was attempted.
	DBPath string

	// WatchDir pre-fills the watch-folder prompt with the folder the running
	// configuration would actually watch.
	WatchDir string

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
	welcomeDescription = "Terminal-native incident response, OCSF-native."
	welcomeMessage     = "No local database was found."
	welcomePrivacyA    = "Everything stays on this machine."
	welcomePrivacyB    = "No cloud. No account. No telemetry."
	welcomeTipText     = "Press 2 to immediately explore Console-IR."
)

// welcomeOption is one row of the action list.
type welcomeOption struct {
	key    rune
	label  string
	action WelcomeAction
}

var welcomeOptions = []welcomeOption{
	{'1', "Create database", WelcomeCreate},
	{'2', "Load demo investigation", WelcomeDemo},
	{'3', "Import JSON / JSONL", WelcomeImport},
	{'4', "Watch a folder", WelcomeWatch},
	{'q', "Quit", WelcomeQuit},
}

// welcomeState is which face of the card is showing. The card is one widget in
// four states rather than four widgets, so a state change cannot leave two of
// them on screen at once.
type welcomeState int

const (
	welcomeStateMenu welcomeState = iota
	welcomeStatePrompt
	welcomeStateLoading
	welcomeStateError
)

// Row budget. The screen has to survive an 80x24 terminal, so the order in
// which things are dropped is stated here rather than discovered at runtime.
const (
	welcomeLogoRows  = 3
	welcomeTitleRows = 2
	welcomeTipRows   = 1
	welcomeBarRows   = 1
	welcomeGapRows   = 1

	// The prompt state adds an input field and its hint below the card body.
	welcomePromptInputRows = 1
	welcomePromptHintRows  = 3
)

// Card widths per responsive tier.
const (
	welcomeCardWide     = 60
	welcomeCardStandard = 48
	welcomeCardMinimum  = 24
)

// welcomeLogoUnicode and welcomeLogoASCII are the same mark twice. Terminals
// without a UTF-8 locale render the block-drawing characters as replacement
// glyphs, which looks like a rendering fault on the very first screen.
var welcomeLogoUnicode = []string{
	" ▄▄▄  ▄▄▄ ",
	"█   ██   █",
	" ▀▀▀  ▀▀▀ ",
}

var welcomeLogoASCII = []string{
	" ___  ___ ",
	"|   ||   |",
	" ---  --- ",
}

// welcomeView is the screen. It owns its own root and none of the main layout.
type welcomeView struct {
	opts  WelcomeOptions
	theme Theme
	app   *tview.Application

	root  *tview.Flex
	logo  *tview.TextView
	title *tview.TextView
	card  *tview.Flex
	body  *tview.Flex
	input *tview.InputField
	hint  *tview.TextView
	tip   *tview.TextView
	bar   *tview.TextView

	// bodyRows are the card's lines, one widget each. See setBody.
	bodyRows []*tview.TextView

	// Layout state, so a redraw at an unchanged size costs nothing.
	mode   LayoutMode
	short  bool
	width  int
	height int
	built  bool

	// privacyOverride lets the layout measure the card with and without the
	// privacy statement while deciding what fits. Nil outside that measurement.
	privacyOverride *bool

	// dirty means the tree changed shape and the screen owes a clear.
	dirty bool

	// Screen state.
	state   welcomeState
	pending WelcomeResult
	loading string
	err     error

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

	if err := v.app.Run(); err != nil {
		return WelcomeResult{}, err
	}
	return v.result, v.outcome
}

// newWelcomeView builds the widget tree. It performs no I/O beyond reading the
// persisted theme, so the first paint does not wait on anything.
func newWelcomeView(opts WelcomeOptions) *welcomeView {
	theme := themeBuilders[loadThemeName()]()

	v := &welcomeView{opts: opts, theme: theme}

	v.logo = welcomeText(theme, tview.AlignCenter)
	v.logo.SetText(v.logoText())

	v.title = welcomeText(theme, tview.AlignCenter)
	v.title.SetText(fmt.Sprintf("[%s:-:b]%s[-:-:-]\n[%s]%s[-:-:-]",
		theme.TagAccent, welcomeTitleText, theme.TagMuted, welcomeDescription))

	v.body = tview.NewFlex().SetDirection(tview.FlexRow)
	v.body.SetBackgroundColor(theme.SurfaceRaised)

	v.hint = welcomeText(theme, tview.AlignLeft)
	v.hint.SetBackgroundColor(theme.SurfaceRaised)

	// The label and placeholder are the affordance: an empty field on a card
	// whose background it shares is indistinguishable from a blank row, and a
	// screen that looks like it is waiting for nothing is a screen people quit.
	v.input = tview.NewInputField()
	v.input.SetLabel("  › ").
		SetFieldBackgroundColor(theme.Surface).
		SetFieldTextColor(theme.TextPrimary).
		SetPlaceholderTextColor(theme.TextMuted).
		SetLabelColor(theme.Accent)
	v.input.SetBackgroundColor(theme.SurfaceRaised)
	v.input.SetDoneFunc(v.promptDone)

	v.card = tview.NewFlex().SetDirection(tview.FlexRow)
	stylePanel(v.card.Box, "", PanelRoleModal, theme)

	v.tip = welcomeText(theme, tview.AlignCenter)
	v.bar = welcomeText(theme, tview.AlignLeft)

	v.root = tview.NewFlex().SetDirection(tview.FlexRow)
	v.root.SetBackgroundColor(theme.Bg)

	// A sensible size until the first draw reports the real one, so the tree is
	// never empty and tests can drive the view without a screen.
	v.width, v.height = 100, 30
	v.render()
	return v
}

// welcomeText builds one of the screen's text widgets.
func welcomeText(theme Theme, align int) *tview.TextView {
	tv := tview.NewTextView().
		SetDynamicColors(true).
		SetTextAlign(align)
	tv.SetBackgroundColor(theme.Bg)
	return tv
}

// logoText picks the mark the terminal can actually draw.
func (v *welcomeView) logoText() string {
	lines := welcomeLogoUnicode
	if !supportsUnicode() {
		lines = welcomeLogoASCII
	}
	return fmt.Sprintf("[%s]%s[-:-:-]", v.theme.TagAccent, strings.Join(lines, "\n"))
}

// supportsUnicode reports whether the terminal's locale is UTF-8. tcell will
// happily draw block characters into a Latin-1 terminal, where they arrive as
// question marks.
func supportsUnicode() bool {
	for _, key := range []string{"LC_ALL", "LC_CTYPE", "LANG"} {
		if val := os.Getenv(key); val != "" {
			v := strings.ToLower(val)
			return strings.Contains(v, "utf-8") || strings.Contains(v, "utf8")
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

// render repaints every part of the screen that depends on the current state,
// then rebuilds the layout, because the card's height is state-dependent. The
// card body itself is written by rebuild, which is what decides how much of it
// fits.
func (v *welcomeView) render() {
	v.tip.SetText(v.tipText())
	v.bar.SetText(v.barText())
	v.built = false
	v.rebuild()
	v.focusForState()
}

// bodyLines is the content of the card, one line per row, so the card's height
// is derived from what it holds rather than guessed.
func (v *welcomeView) bodyLines() []string {
	t := v.theme

	switch v.state {
	case welcomeStatePrompt:
		return []string{
			"",
			fmt.Sprintf("  [%s]%s[-:-:-]", t.TagTextPrimary, v.promptLabel()),
			"",
		}

	case welcomeStateError:
		lines := []string{
			"",
			fmt.Sprintf("  [%s]%s[-:-:-]", t.TagError, "Could not "+v.pending.Action.verb()+"."),
			"",
		}
		for _, l := range wrapText(v.errorText(), v.cardInnerWidth()-4) {
			lines = append(lines, fmt.Sprintf("  [%s]%s[-:-:-]", t.TagTextPrimary, tview.Escape(l)))
		}
		lines = append(lines, "")
		for _, l := range wrapText(v.attemptedPath(), v.cardInnerWidth()-4) {
			lines = append(lines, fmt.Sprintf("  [%s]%s[-:-:-]", t.TagMuted, tview.Escape(l)))
		}
		lines = append(lines, "",
			welcomeActionLine('r', "Retry", t),
			welcomeActionLine('q', "Quit", t),
			"")
		return lines

	case welcomeStateLoading:
		lines := v.cardIntro()
		lines = append(lines, "  "+loadingState(v.loading, t), "")
		// Hold the card at its menu height so it does not jump while working.
		return padLines(lines, len(v.menuLines()))

	default:
		return v.menuLines()
	}
}

// cardIntro is the part of the card that does not change with state: the
// message, and the privacy statement when there is room for it.
func (v *welcomeView) cardIntro() []string {
	t := v.theme
	lines := []string{
		"",
		fmt.Sprintf("  [%s]%s[-:-:-]", t.TagTextPrimary, welcomeMessage),
		"",
	}
	if v.showPrivacy() {
		lines = append(lines,
			fmt.Sprintf("  [%s]%s[-:-:-]", t.TagMuted, welcomePrivacyA),
			fmt.Sprintf("  [%s]%s[-:-:-]", t.TagMuted, welcomePrivacyB),
			"")
	}
	return lines
}

// menuLines is the card in its resting state.
func (v *welcomeView) menuLines() []string {
	lines := v.cardIntro()
	for _, o := range welcomeOptions {
		lines = append(lines, welcomeActionLine(o.key, o.label, v.theme))
	}
	return append(lines, "")
}

// welcomeActionLine renders one "[k]  Label" row of the action list.
//
// The brackets have to be escaped: tview reads "[q]" in dynamic-colour text as
// a colour tag and swallows it, so an unescaped action list loses exactly the
// keys it is there to teach.
func welcomeActionLine(key rune, label string, theme Theme) string {
	return fmt.Sprintf("   [%s]%s[-:-:-]  [%s]%s[-:-:-]",
		theme.TagAccent, tview.Escape(fmt.Sprintf("[%c]", key)), theme.TagTextPrimary, label)
}

func (v *welcomeView) tipText() string {
	if v.state != welcomeStateMenu {
		return ""
	}
	return fmt.Sprintf("[%s]%s[-:-:-]", v.theme.TagMuted, welcomeTipText)
}

func (v *welcomeView) barText() string {
	t := v.theme
	switch v.state {
	case welcomeStatePrompt:
		return actionBar(t, keyHint{"Enter", "Continue"}, keyHint{"Esc", "Back"})
	case welcomeStateLoading:
		return actionBar(t, keyHint{"Ctrl+C", "Cancel"})
	case welcomeStateError:
		return actionBar(t, keyHint{"r", "Retry"}, keyHint{"q", "Quit"})
	default:
		hints := make([]keyHint, 0, len(welcomeOptions))
		for _, o := range welcomeOptions {
			hints = append(hints, keyHint{string(o.key), welcomeShortLabel(o.action)})
		}
		return actionBar(t, hints...)
	}
}

// welcomeShortLabel is the action bar's one-word form of each action.
func welcomeShortLabel(a WelcomeAction) string {
	switch a {
	case WelcomeCreate:
		return "Create"
	case WelcomeDemo:
		return "Demo"
	case WelcomeImport:
		return "Import"
	case WelcomeWatch:
		return "Watch"
	default:
		return "Quit"
	}
}

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
// Layout
// ---------------------------------------------------------------------------

// beforeDraw is the frame preamble, run once per repaint before the root is
// drawn. It re-tiers the layout for the current terminal size and clears the
// screen when the tree has changed shape.
//
// The clear is not optional. tview does not clear between frames, and the card
// changes height between states — menu, prompt, error — so without it the rows
// the previous card occupied keep its border, and the screen accumulates two
// overlapping cards.
func (v *welcomeView) beforeDraw(screen tcell.Screen) bool {
	width, height := screen.Size()
	v.relayout(width, height)
	if v.dirty {
		screen.Clear()
		v.dirty = false
	}
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

// rebuild assembles the root from scratch. The card is centred on an otherwise
// empty canvas, with the action bar pinned to the bottom row.
func (v *welcomeView) rebuild() {
	v.mode, v.short = GetLayoutMode(v.width, v.height)
	showLogo, showPrivacy := v.blocks()

	// The card's content depends on whether the privacy lines fit, so it is
	// re-rendered here rather than only on a state change.
	lines := v.bodyLinesFor(showPrivacy)
	v.setBody(lines)

	cardWidth := v.cardWidth()
	cardRows := v.cardRows(showPrivacy)

	v.card.Clear()
	if v.state == welcomeStatePrompt {
		// Fixed rows throughout: a proportional split would size the prompt
		// against the hint rather than against its own content.
		v.card.AddItem(v.body, len(lines), 0, false)
		v.card.AddItem(v.input, welcomePromptInputRows, 0, true)
		v.card.AddItem(v.hint, welcomePromptHintRows, 0, false)
		v.hint.SetText(fmt.Sprintf("\n  [%s]Enter to continue · Esc to go back[-:-:-]", v.theme.TagMuted))
	} else {
		v.card.AddItem(v.body, 0, 1, false)
	}

	v.root.Clear()
	v.root.AddItem(nil, 0, 1, false)
	if showLogo {
		v.root.AddItem(v.logo, welcomeLogoRows, 0, false)
		v.root.AddItem(nil, welcomeGapRows, 0, false)
	}
	v.root.AddItem(v.title, welcomeTitleRows, 0, false)
	v.root.AddItem(nil, welcomeGapRows, 0, false)
	v.root.AddItem(centred(v.card, cardWidth), cardRows, 0, true)
	if v.state == welcomeStateMenu {
		v.root.AddItem(nil, welcomeGapRows, 0, false)
		v.root.AddItem(v.tip, welcomeTipRows, 0, false)
	}
	v.root.AddItem(nil, 0, 1, false)
	v.root.AddItem(v.bar, welcomeBarRows, 0, false)

	v.built = true
	v.dirty = true
}

// setBody fills the card with one single-line widget per row.
//
// One widget per line rather than one multi-line TextView, because tview's
// escaped-tag state leaks between the lines of a single TextView: an action
// list built that way renders with one more character of the previous line's
// colour tag bleeding onto every subsequent row, so "[3]  Import" arrives as
// "]   [3]  Import". A widget per line resets that state, and the card is a
// stack of rows anyway.
//
// The widgets are reused across rebuilds, so a redraw allocates nothing.
func (v *welcomeView) setBody(lines []string) {
	v.body.Clear()
	for i, line := range lines {
		if i >= len(v.bodyRows) {
			row := welcomeText(v.theme, tview.AlignLeft)
			row.SetBackgroundColor(v.theme.SurfaceRaised)
			v.bodyRows = append(v.bodyRows, row)
		}
		v.bodyRows[i].SetText(line)
		v.body.AddItem(v.bodyRows[i], 1, 0, false)
	}
}

// cardLines is the card as it reaches the screen, one string per row.
func (v *welcomeView) cardLines() []string {
	out := make([]string, 0, v.body.GetItemCount())
	for i := 0; i < v.body.GetItemCount(); i++ {
		if row, ok := v.body.GetItem(i).(*tview.TextView); ok {
			out = append(out, row.GetText(true))
		}
	}
	return out
}

// bodyLinesFor renders the card body for a given privacy-line decision, which
// the layout owns and the state does not.
func (v *welcomeView) bodyLinesFor(showPrivacy bool) []string {
	saved := v.privacyOverride
	v.privacyOverride = &showPrivacy
	defer func() { v.privacyOverride = saved }()
	return v.bodyLines()
}

// blocks decides which optional blocks fit in the available height. The order
// is fixed: the logo goes first, then the privacy statement. The actions and
// the tip are never dropped, because without them the screen does nothing.
func (v *welcomeView) blocks() (showLogo, showPrivacy bool) {
	showLogo = v.mode != LayoutCompact && !v.short
	showPrivacy = !v.short

	for {
		if v.requiredRows(showLogo, showPrivacy) <= v.height {
			return showLogo, showPrivacy
		}
		switch {
		case showLogo:
			showLogo = false
		case showPrivacy:
			showPrivacy = false
		default:
			return false, false
		}
	}
}

// requiredRows is the height the screen needs with the given blocks present.
func (v *welcomeView) requiredRows(showLogo, showPrivacy bool) int {
	rows := welcomeTitleRows + welcomeGapRows + v.cardRows(showPrivacy) + welcomeBarRows
	if showLogo {
		rows += welcomeLogoRows + welcomeGapRows
	}
	if v.state == welcomeStateMenu {
		rows += welcomeGapRows + welcomeTipRows
	}
	return rows
}

// cardRows is the card's height including its border.
func (v *welcomeView) cardRows(showPrivacy bool) int {
	rows := len(v.bodyLinesFor(showPrivacy)) + 2
	if v.state == welcomeStatePrompt {
		rows += welcomePromptInputRows + welcomePromptHintRows
	}
	return rows
}

// cardWidth is the card's width per responsive tier.
func (v *welcomeView) cardWidth() int {
	switch v.mode {
	case LayoutWide:
		return welcomeCardWide
	case LayoutStandard:
		return welcomeCardStandard
	default:
		if w := v.width - 2; w > welcomeCardMinimum {
			return w
		}
		return welcomeCardMinimum
	}
}

// cardInnerWidth is the width text has inside the card's border.
func (v *welcomeView) cardInnerWidth() int {
	if w := v.cardWidth() - 2; w > 8 {
		return w
	}
	return 8
}

// showPrivacy answers for the current render pass. The layout overrides it
// while measuring; outside that it follows the short-screen rule.
func (v *welcomeView) showPrivacy() bool {
	if v.privacyOverride != nil {
		return *v.privacyOverride
	}
	return !v.short
}

// centred wraps a primitive in a fixed-width column on an empty canvas.
func centred(p tview.Primitive, width int) *tview.Flex {
	return tview.NewFlex().
		AddItem(nil, 0, 1, false).
		AddItem(p, width, 0, true).
		AddItem(nil, 0, 1, false)
}

// ---------------------------------------------------------------------------
// Input
// ---------------------------------------------------------------------------

// handleKey is the screen's only key handler. Each state accepts exactly the
// keys its action bar advertises, so nothing on this screen is reachable
// without being shown.
func (v *welcomeView) handleKey(ev *tcell.EventKey) *tcell.EventKey {
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
		case tcell.KeyRune:
			v.choose(ev.Rune())
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
		switch o.action {
		case WelcomeQuit:
			v.quit()
		case WelcomeImport, WelcomeWatch:
			v.ask(o.action)
		default:
			v.launch(WelcomeResult{Action: o.action})
		}
		return
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

// promptDone handles the prompt's terminal keys. Esc returns to the card with
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

// padLines extends lines with blanks so a state change does not move the card.
func padLines(lines []string, want int) []string {
	for len(lines) < want {
		lines = append(lines, "")
	}
	return lines
}
