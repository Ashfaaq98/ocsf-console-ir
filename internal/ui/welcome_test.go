package ui

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// newTestWelcome builds a view with no application behind it, so key handling
// and the Perform callback both run inline and assertions are deterministic.
func newTestWelcome(t *testing.T, opts WelcomeOptions) *welcomeView {
	t.Helper()
	withTempConfig(t)
	if opts.DBPath == "" {
		opts.DBPath = filepath.Join(t.TempDir(), "console-ir.db")
	}
	return newWelcomeView(opts)
}

// press sends one rune through the screen's key handler.
func press(v *welcomeView, r rune) {
	v.handleKey(tcell.NewEventKey(tcell.KeyRune, r, tcell.ModNone))
}

// cardText is the card as it reaches the screen: colour tags resolved away and
// escaped brackets restored, which is exactly what an analyst reads.
func cardText(v *welcomeView) string {
	return strings.Join(v.cardLines(), "\n")
}

// The Welcome Screen must not look like the main application. A first-time user
// shown an empty dashboard concludes the tool is broken, so these widgets have
// to be absent from the tree rather than merely empty.
func TestWelcomeTreeHasNoApplicationWidgets(t *testing.T) {
	v := newTestWelcome(t, WelcomeOptions{})

	var tables, lists, trees int
	walk(v.root, func(p tview.Primitive) {
		switch p.(type) {
		case *tview.Table:
			tables++
		case *tview.List:
			lists++
		case *tview.TreeView:
			trees++
		}
	})

	if tables != 0 {
		t.Errorf("welcome tree contains %d table(s); it must contain none", tables)
	}
	if lists != 0 {
		t.Errorf("welcome tree contains %d list(s); it must contain none", lists)
	}
	if trees != 0 {
		t.Errorf("welcome tree contains %d tree view(s); it must contain none", trees)
	}
}

// walk visits every primitive in a Flex tree, including nested flexes.
func walk(p tview.Primitive, visit func(tview.Primitive)) {
	if p == nil {
		return
	}
	visit(p)
	if flex, ok := p.(*tview.Flex); ok {
		for i := 0; i < flex.GetItemCount(); i++ {
			walk(flex.GetItem(i), visit)
		}
	}
}

// The copy is specified exactly. Paraphrasing it in the code is a silent
// product change, so the strings are pinned here.
func TestWelcomeCopy(t *testing.T) {
	v := newTestWelcome(t, WelcomeOptions{})
	text := cardText(v)

	for _, want := range []string{
		welcomeMessage,
		welcomePrivacyA,
		welcomePrivacyB,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("card is missing %q\ngot:\n%s", want, text)
		}
	}

	if got := v.title.GetText(true); !strings.Contains(got, welcomeTitleText) ||
		!strings.Contains(got, welcomeDescription) {
		t.Errorf("title block = %q", got)
	}
	if got := v.tip.GetText(true); !strings.Contains(got, welcomeTipText) {
		t.Errorf("tip = %q, want it to contain %q", got, welcomeTipText)
	}

	// Every action must be listed, or the screen teaches a key it does not show.
	for _, o := range welcomeOptions {
		want := fmt.Sprintf("[%c]", o.key)
		if !strings.Contains(text, want) {
			t.Errorf("action list is missing %s %s\ngot:\n%s", want, o.label, text)
		}
		if !strings.Contains(text, o.label) {
			t.Errorf("action list is missing the label %q", o.label)
		}
	}
}

// The literal copy must survive tview's dynamic-colour parser: an unescaped
// "[q]" is read as a colour tag and vanishes from the screen.
func TestWelcomeActionKeysSurviveColourTags(t *testing.T) {
	v := newTestWelcome(t, WelcomeOptions{})

	// GetText(false) keeps the markup; the escape is what has to be there.
	var raw strings.Builder
	for i := 0; i < v.body.GetItemCount(); i++ {
		if row, ok := v.body.GetItem(i).(*tview.TextView); ok {
			raw.WriteString(row.GetText(false))
			raw.WriteByte('\n')
		}
	}
	if !strings.Contains(raw.String(), "[q[]") {
		t.Errorf("the quit key is not escaped, so tview will swallow it:\n%s", raw.String())
	}

	// And with tags interpreted, the brackets are still on screen.
	if got := cardText(v); !strings.Contains(got, "[q]") {
		t.Errorf("rendered card does not show [q]:\n%s", got)
	}
}

func TestWelcomeKeysChooseTheRightAction(t *testing.T) {
	for _, tc := range []struct {
		key    rune
		action WelcomeAction
	}{
		{'1', WelcomeCreate},
		{'2', WelcomeDemo},
	} {
		t.Run(tc.action.String(), func(t *testing.T) {
			var got WelcomeResult
			v := newTestWelcome(t, WelcomeOptions{
				Perform: func(res WelcomeResult, _ func(string)) error {
					got = res
					return nil
				},
			})

			press(v, tc.key)

			if got.Action != tc.action {
				t.Errorf("Perform ran for %v, want %v", got.Action, tc.action)
			}
			if v.result.Action != tc.action {
				t.Errorf("result = %v, want %v", v.result.Action, tc.action)
			}
			if v.outcome != nil {
				t.Errorf("outcome = %v, want nil", v.outcome)
			}
		})
	}
}

// Quit must create nothing at all. This is the one guarantee the privacy copy
// makes on behalf of the screen.
func TestWelcomeQuitPerformsNothing(t *testing.T) {
	called := false
	v := newTestWelcome(t, WelcomeOptions{
		Perform: func(WelcomeResult, func(string)) error {
			called = true
			return nil
		},
	})

	press(v, 'q')

	if called {
		t.Error("quitting ran the action callback")
	}
	if v.result.Action != WelcomeQuit {
		t.Errorf("result = %v, want WelcomeQuit", v.result.Action)
	}
	if v.outcome != nil {
		t.Errorf("outcome = %v, want nil — quitting from the menu is a success", v.outcome)
	}
}

// Import and watch ask for a path first; nothing may happen until they have one.
func TestWelcomePromptsBeforeActing(t *testing.T) {
	for _, tc := range []struct {
		key    rune
		action WelcomeAction
	}{
		{'3', WelcomeImport},
		{'4', WelcomeWatch},
	} {
		t.Run(tc.action.String(), func(t *testing.T) {
			called := false
			v := newTestWelcome(t, WelcomeOptions{
				WatchDir: "/tmp/incoming",
				Perform: func(WelcomeResult, func(string)) error {
					called = true
					return nil
				},
			})

			press(v, tc.key)

			if v.state != welcomeStatePrompt {
				t.Fatalf("state = %v, want prompt", v.state)
			}
			if called {
				t.Error("the action ran before a path was given")
			}
			if tc.action == WelcomeWatch && v.input.GetText() != "/tmp/incoming" {
				t.Errorf("watch prompt = %q, want it pre-filled with the configured folder", v.input.GetText())
			}
		})
	}
}

func TestWelcomePromptCarriesThePath(t *testing.T) {
	var got WelcomeResult
	v := newTestWelcome(t, WelcomeOptions{
		Perform: func(res WelcomeResult, _ func(string)) error {
			got = res
			return nil
		},
	})

	press(v, '3')
	v.input.SetText("/evidence/day1.jsonl")
	v.promptDone(tcell.KeyEnter)

	if got.Action != WelcomeImport || got.Path != "/evidence/day1.jsonl" {
		t.Errorf("Perform got %+v, want an import of /evidence/day1.jsonl", got)
	}
}

// Esc has to be free: at this point nothing has been created, and a first-run
// screen that punishes backing out is worse than no screen.
func TestWelcomeEscapeLeavesNoSideEffects(t *testing.T) {
	called := false
	v := newTestWelcome(t, WelcomeOptions{
		Perform: func(WelcomeResult, func(string)) error {
			called = true
			return nil
		},
	})

	press(v, '3')
	v.promptDone(tcell.KeyEscape)

	if v.state != welcomeStateMenu {
		t.Errorf("state = %v, want the menu back", v.state)
	}
	if called {
		t.Error("escaping the prompt still ran the action")
	}
	if v.pending.Action != WelcomeQuit {
		t.Errorf("pending action = %v, want it cleared", v.pending.Action)
	}
	if !strings.Contains(cardText(v), welcomeMessage) {
		t.Error("the card did not return to the menu")
	}
}

// An empty path is not a choice; Enter on it must do nothing rather than fail.
func TestWelcomePromptIgnoresEmptyInput(t *testing.T) {
	called := false
	v := newTestWelcome(t, WelcomeOptions{
		Perform: func(WelcomeResult, func(string)) error {
			called = true
			return nil
		},
	})

	press(v, '3')
	v.input.SetText("   ")
	v.promptDone(tcell.KeyEnter)

	if called {
		t.Error("an empty path was accepted")
	}
	if v.state != welcomeStatePrompt {
		t.Errorf("state = %v, want to stay on the prompt", v.state)
	}
}

// The failure that matters: an unwritable data directory. The screen must say
// so and stay put — falling through to the main UI with no database is how a
// first run turns into a crash.
func TestWelcomeErrorStateNeverFallsThrough(t *testing.T) {
	boom := errors.New("permission denied")
	v := newTestWelcome(t, WelcomeOptions{
		DBPath: "/nowhere/console-ir.db",
		Perform: func(WelcomeResult, func(string)) error {
			return boom
		},
	})

	press(v, '1')

	if v.state != welcomeStateError {
		t.Fatalf("state = %v, want the error state", v.state)
	}
	if v.result.Action != WelcomeQuit {
		t.Errorf("result = %v; a failure must not report a completed action", v.result.Action)
	}

	text := cardText(v)
	for _, want := range []string{"permission denied", "/nowhere/console-ir.db", "[r]", "[q]"} {
		if !strings.Contains(text, want) {
			t.Errorf("error card is missing %q\ngot:\n%s", want, text)
		}
	}
}

// Quitting from the error state has to exit non-zero, so a script that launched
// the binary learns that nothing was created.
func TestWelcomeQuitAfterErrorCarriesTheFailure(t *testing.T) {
	boom := errors.New("read-only file system")
	v := newTestWelcome(t, WelcomeOptions{
		Perform: func(WelcomeResult, func(string)) error { return boom },
	})

	press(v, '1')
	press(v, 'q')

	if !errors.Is(v.outcome, boom) {
		t.Errorf("outcome = %v, want the underlying failure", v.outcome)
	}
}

func TestWelcomeRetryReattemptsTheSameAction(t *testing.T) {
	attempts := 0
	v := newTestWelcome(t, WelcomeOptions{
		Perform: func(res WelcomeResult, _ func(string)) error {
			attempts++
			if attempts == 1 {
				return errors.New("disk full")
			}
			if res.Action != WelcomeCreate {
				t.Errorf("retry ran %v, want the original create", res.Action)
			}
			return nil
		},
	})

	press(v, '1')
	if v.state != welcomeStateError {
		t.Fatalf("state = %v, want the error state", v.state)
	}

	press(v, 'r')

	if attempts != 2 {
		t.Errorf("attempts = %d, want 2", attempts)
	}
	if v.result.Action != WelcomeCreate {
		t.Errorf("result = %v, want the retried action to succeed", v.result.Action)
	}
	if v.outcome != nil {
		t.Errorf("outcome = %v, want nil after a successful retry", v.outcome)
	}
}

// Keys are ignored while work is in flight, so a second press cannot start a
// second database creation on top of the first.
func TestWelcomeIgnoresKeysWhileWorking(t *testing.T) {
	v := newTestWelcome(t, WelcomeOptions{})
	v.state = welcomeStateLoading

	if got := v.handleKey(tcell.NewEventKey(tcell.KeyRune, '1', tcell.ModNone)); got != nil {
		t.Error("a rune was passed through during loading")
	}
	// Ctrl+C is the exception: abandoning the process is always available.
	ctrlC := tcell.NewEventKey(tcell.KeyCtrlC, 0, tcell.ModNone)
	if got := v.handleKey(ctrlC); got != ctrlC {
		t.Error("Ctrl+C was swallowed during loading")
	}
}

// Each stage of a multi-step action has to reach the card, or a slow demo load
// looks like a hang.
func TestWelcomeShowsEachStage(t *testing.T) {
	var v *welcomeView
	var seen []string

	v = newTestWelcome(t, WelcomeOptions{
		Perform: func(_ WelcomeResult, progress func(string)) error {
			for _, stage := range []string{"Creating database…", "Loading sample incident…"} {
				progress(stage)
				seen = append(seen, cardText(v))
			}
			return nil
		},
	})

	press(v, '2')

	if len(seen) != 2 {
		t.Fatalf("saw %d stages, want 2", len(seen))
	}
	if !strings.Contains(seen[0], "Creating database") {
		t.Errorf("first stage on the card = %q", seen[0])
	}
	if !strings.Contains(seen[1], "Loading sample incident") {
		t.Errorf("second stage on the card = %q", seen[1])
	}

	// The message and the actions swap places, not the whole card: a card that
	// changes height mid-action jumps around the screen.
	if !strings.Contains(seen[0], welcomeMessage) {
		t.Error("the loading card dropped the message")
	}
	if strings.Contains(seen[0], "Create database") {
		t.Error("the loading card still lists the actions")
	}
}

// Compact terminals drop decoration, never the actions. An 80x24 window is a
// normal size, not an edge case.
func TestWelcomeResponsiveTiers(t *testing.T) {
	for _, tc := range []struct {
		name          string
		width, height int
		wantCardWidth int
		wantLogo      bool
	}{
		{"wide", 140, 40, welcomeCardWide, true},
		{"standard", 100, 30, welcomeCardStandard, true},
		{"compact", 70, 30, 68, false},
		{"short", 100, 20, welcomeCardStandard, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := newTestWelcome(t, WelcomeOptions{})
			v.relayout(tc.width, tc.height)

			if got := v.cardWidth(); got != tc.wantCardWidth {
				t.Errorf("card width = %d, want %d", got, tc.wantCardWidth)
			}
			showLogo, _ := v.blocks()
			if showLogo != tc.wantLogo {
				t.Errorf("logo shown = %v, want %v", showLogo, tc.wantLogo)
			}

			// Whatever else is dropped, every action and the tip stay on screen.
			text := cardText(v)
			for _, o := range welcomeOptions {
				if !strings.Contains(text, o.label) {
					t.Errorf("%dx%d dropped the action %q", tc.width, tc.height, o.label)
				}
			}
			if got := v.tip.GetText(true); !strings.Contains(got, welcomeTipText) {
				t.Errorf("%dx%d dropped the tip", tc.width, tc.height)
			}
		})
	}
}

// The screen has to fit the terminal it is given, down to the smallest one the
// layout tiers acknowledge.
func TestWelcomeFitsSmallTerminals(t *testing.T) {
	for _, size := range [][2]int{{140, 40}, {100, 30}, {100, 24}, {80, 24}, {70, 20}} {
		v := newTestWelcome(t, WelcomeOptions{})
		v.relayout(size[0], size[1])

		showLogo, showPrivacy := v.blocks()
		if rows := v.requiredRows(showLogo, showPrivacy); rows > size[1] {
			t.Errorf("%dx%d needs %d rows", size[0], size[1], rows)
		}
	}
}

// Completing any action leaves an install with an explicit theme, so the very
// first preference is a file the analyst can read and edit.
func TestWelcomeInitialisesSettings(t *testing.T) {
	dir := withTempConfig(t)
	v := newWelcomeView(WelcomeOptions{DBPath: filepath.Join(t.TempDir(), "db")})

	press(v, '1')

	if _, err := os.Stat(filepath.Join(dir, uiSettingsName)); err != nil {
		t.Fatalf("settings were not initialised: %v", err)
	}
	if got := loadThemeName(); got != defaultThemeName {
		t.Errorf("initial theme = %q, want %q", got, defaultThemeName)
	}
}

// An existing preference is not a fresh install's to reset.
func TestWelcomeKeepsAnExistingThemeChoice(t *testing.T) {
	dir := withTempConfig(t)
	if err := os.WriteFile(filepath.Join(dir, uiSettingsName), []byte(`{"theme":"gruvbox"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	v := newWelcomeView(WelcomeOptions{DBPath: filepath.Join(t.TempDir(), "db")})
	press(v, '1')

	if got := loadThemeName(); got != "gruvbox" {
		t.Errorf("theme = %q, want the existing gruvbox choice untouched", got)
	}
}

func TestWrapText(t *testing.T) {
	got := wrapText("could not create the database at that path", 20)
	for _, line := range got {
		if len(line) > 20 {
			t.Errorf("line %q exceeds the width", line)
		}
	}
	if strings.Join(got, " ") != "could not create the database at that path" {
		t.Errorf("wrapping lost text: %q", got)
	}
}

// errPermission is the failure the error-state tests provoke.
var errPermission = errors.New("permission denied")
