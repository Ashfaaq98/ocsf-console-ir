package ui

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/llm"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/paths"
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// The editors behind the settings rows.
//
// Each takes a `done` callback rather than redrawing anything itself: the panel
// rebuilds from the live state afterwards, so a change to the theme, to a
// value, and to that value's source all land together and none of them has to
// be pushed back by hand.

// applyPreferences persists the current preferences and repaints anything that
// reads them.
func (ui *UI) applyPreferences() {
	ui.saveUISettings()
	ui.applyRuntimePreferences()
	ui.repaintCurrentList()
}

// editAnalystName asks for the name that goes into the record.
func (ui *UI) editAnalystName(done func()) {
	ui.promptSetting("Analyst name", ui.prefs.analystName(),
		"The name written into the audit trail, notes and reports. Empty takes it from the environment.",
		func(value string) {
			ui.prefs.Analyst = strings.TrimSpace(value)
			ui.applyPreferences()
			done()
		}, done)
}

// editAutoRefresh asks for an interval in seconds.
func (ui *UI) editAutoRefresh(done func()) {
	current := "off"
	if ui.prefs.AutoRefreshSeconds > 0 {
		current = strconv.Itoa(ui.prefs.AutoRefreshSeconds)
	}
	ui.promptSetting("Auto-refresh (seconds)", current,
		"Seconds between reloads. 0 or empty switches it off, which is the default.",
		func(value string) {
			n, err := strconv.Atoi(strings.TrimSpace(value))
			if err != nil || n < 0 {
				n = 0
			}
			if n > 0 && n < 5 {
				// Below this it fights the analyst rather than helping.
				n = 5
			}
			ui.prefs.AutoRefreshSeconds = n
			ui.applyPreferences()
			done()
		}, done)
}

// editCopilotTimeout asks how long a request may take.
func (ui *UI) editCopilotTimeout(done func()) {
	ui.promptSetting("Request timeout (seconds)",
		strconv.Itoa(int(ui.prefs.copilotTimeout().Seconds())),
		"How long a copilot request may take. Local inference on a CPU can need several minutes.",
		func(value string) {
			n, err := strconv.Atoi(strings.TrimSpace(value))
			if err != nil || n <= 0 {
				n = 0 // back to the built-in default
			}
			ui.prefs.CopilotTimeoutSeconds = n
			ui.applyPreferences()
			done()
		}, done)
}

// editTokenWarning asks for the estimate above which a request confirms first.
func (ui *UI) editTokenWarning(done func()) {
	ui.promptSetting("Ask above (tokens)",
		strconv.Itoa(ui.prefs.copilotTokenWarning()),
		"A request estimated above this asks first, with the cost. 0 restores the default.",
		func(value string) {
			n, err := strconv.Atoi(strings.TrimSpace(value))
			if err != nil || n < 0 {
				n = 0
			}
			ui.prefs.CopilotTokenWarning = n
			ui.applyPreferences()
			done()
		}, done)
}

// editTheme opens the palette list, applying each as the cursor moves.
//
// Applied on the way past rather than on Enter: a palette is judged against a
// real screen, and closing a dialog to look at one and reopening it to try the
// next is not judging it.
func (ui *UI) editTheme(done func()) {
	t := ui.theme
	original := ui.themeName
	names := themeNames()

	list := tview.NewList().ShowSecondaryText(true)
	list.SetBackgroundColor(t.SurfaceRaised)
	list.SetMainTextColor(t.TextPrimary)
	list.SetSecondaryTextColor(t.TextMuted)
	list.SetSelectedBackgroundColor(t.SelectionBg)
	list.SetSelectedTextColor(t.SelectionFg)

	current := 0
	for i, name := range names {
		if name == ui.themeName {
			current = i
		}
		list.AddItem(name, "   "+themeBlurb(name), 0, nil)
	}

	list.SetChangedFunc(func(i int, _, _ string, _ rune) {
		if i >= 0 && i < len(names) {
			ui.setTheme(names[i])
		}
	})
	list.SetSelectedFunc(func(i int, _, _ string, _ rune) {
		ui.closeModal()
		done()
	})
	list.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
		if ev.Key() == tcell.KeyEscape {
			// Escape puts back what was there, so browsing costs nothing.
			ui.setTheme(original)
			ui.closeModal()
			done()
			return nil
		}
		return ev
	})

	body := tview.NewFlex().SetDirection(tview.FlexRow)
	footer := tview.NewTextView().SetDynamicColors(true)
	footer.SetBackgroundColor(t.SurfaceRaised)
	footer.SetText(fmt.Sprintf("  [%s]↑↓[-] try   [%s]⏎[-] keep   [%s]esc[-] put it back",
		t.TagAccent, t.TagAccent, t.TagAccent))

	body.AddItem(list, len(names)*2, 0, true)
	body.AddItem(blankRow(t.SurfaceRaised), 1, 0, false)
	body.AddItem(footer, 1, 0, false)

	ui.overlayModal(modalPanel(body, "Theme", t), 62, len(names)*2+5)
	ui.app.SetFocus(list)
	list.SetCurrentItem(current)
}

// themeBlurb is the one line under a palette's name.
func themeBlurb(name string) string {
	switch name {
	case "dark":
		return "a plain dark palette"
	case "light":
		return "for bright rooms and projectors"
	case "gruvbox":
		return "the published gruvbox dark palette · default"
	case "midnight":
		return "a darker variant of dark"
	case "high-contrast":
		return "experimental — not verified screen by screen"
	case "colorblind":
		return "experimental — not verified screen by screen"
	}
	return ""
}

// promptSetting is the one-field dialog the value editors share.
//
// A form rather than an inline edit: a value being typed into a table row is
// indistinguishable from one already saved, and these are settings whose old
// value matters while you decide on the new one.
func (ui *UI) promptSetting(label, current, help string, save func(string), cancel func()) {
	t := ui.theme
	value := current

	form := tview.NewForm()
	form.SetBackgroundColor(t.SurfaceRaised)
	form.SetFieldBackgroundColor(t.Surface)
	form.SetFieldTextColor(t.TextPrimary)
	form.SetLabelColor(t.TextMuted)
	form.SetButtonBackgroundColor(t.SelectionBg)
	form.SetButtonTextColor(t.SelectionFg)

	form.AddInputField(label, current, 40, nil, func(text string) { value = text })
	form.AddButton("Save", func() {
		ui.closeModal()
		save(value)
	})
	form.AddButton("Cancel", func() {
		ui.closeModal()
		cancel()
	})
	form.SetCancelFunc(func() {
		ui.closeModal()
		cancel()
	})

	hint := tview.NewTextView().SetDynamicColors(true).SetWrap(true)
	hint.SetBackgroundColor(t.SurfaceRaised)
	hint.SetText(fmt.Sprintf("  [%s]%s[-]", t.TagMuted, help))

	body := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(form, formHeight(form), 0, true).
		AddItem(hint, 2, 0, false)

	ui.overlayModal(modalPanel(body, label, t), 66, formHeight(form)+4)
	ui.app.SetFocus(form)
}

// copilotProviderSummary names the provider and model in one line.
func (ui *UI) copilotProviderSummary() string {
	s, err := llm.LoadSettings(paths.Current().ConfigFile(paths.LLMSettingsName))
	if err != nil {
		return "unreadable"
	}
	model := strings.TrimSpace(s.Active.Model)
	if model == "" {
		model = "no model"
	}
	provider := strings.TrimSpace(s.Active.Provider)
	if provider == "" {
		provider = "none"
	}
	key := ""
	if strings.TrimSpace(s.Active.APIKey) != "" {
		key = " · key set"
	}
	return fmt.Sprintf("%s / %s%s", provider, model, key)
}

// ingestDirLabel names the folder being watched.
//
// The default rather than the resolved path: the folder stays relative to
// wherever the binary was launched, which is the point of it — a landing zone
// under ~/.local/share is one you cannot drop a file into.
func (ui *UI) ingestDirLabel() string {
	if dir := strings.TrimSpace(os.Getenv("CONSOLE_IR_INGEST_DIR")); dir != "" {
		return dir
	}
	return "./incoming (relative to where you launched)"
}

// editLLMProvider opens the copilot's provider form over the settings panel.
func (ui *UI) editLLMProvider(done func()) {
	showLLMSettingsForm(llmSettingsHost{
		app:    ui.app,
		theme:  ui.theme,
		logger: ui.logger,
		ctx:    ui.ctx,
		themeModal: func(p tview.Primitive) {
			if form, ok := p.(*tview.Form); ok {
				ui.applyModalFormTheme(form)
			}
		},
		mount:   func(p tview.Primitive) { ui.overlayModal(p, 78, 24) },
		dismiss: ui.closeModal,
		status:  func(msg string) { ui.setStatusDirect("%s", msg) },
		apply:   ui.ApplyLLMProvider,
		search:  ui.showModelSearch,
	}, done)
}

// applyModalFormTheme paints a form in the current palette.
func (ui *UI) applyModalFormTheme(form *tview.Form) {
	t := ui.theme
	form.SetBackgroundColor(t.SurfaceRaised)
	form.SetFieldBackgroundColor(t.Surface)
	form.SetFieldTextColor(t.TextPrimary)
	form.SetLabelColor(t.TextMuted)
	form.SetButtonBackgroundColor(t.SelectionBg)
	form.SetButtonTextColor(t.SelectionFg)
	form.SetBorderColor(t.Border)
	form.SetTitleColor(t.TextPrimary)
}

// showModelSearch is a searchable list of the models a provider offers.
func (ui *UI) showModelSearch(options []string, choose func(string)) {
	t := ui.theme
	list := tview.NewList().ShowSecondaryText(false)
	list.SetBackgroundColor(t.SurfaceRaised)
	list.SetMainTextColor(t.TextPrimary)
	list.SetSelectedBackgroundColor(t.SelectionBg)
	list.SetSelectedTextColor(t.SelectionFg)

	for _, opt := range options {
		name := opt
		list.AddItem(name, "", 0, func() {
			ui.closeModal()
			choose(name)
		})
	}
	list.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
		if ev.Key() == tcell.KeyEscape {
			ui.closeModal()
			return nil
		}
		return ev
	})

	height := len(options) + 4
	if height > 20 {
		height = 20
	}
	ui.overlayModal(modalPanel(list, "Model", t), 70, height)
	ui.app.SetFocus(list)
}

// showSettingsAt opens the panel on a named category.
func (ui *UI) showSettingsAt(category string) {
	p := &settingsPanel{ui: ui, categories: settingsCatalog()}
	for i, c := range p.categories {
		if strings.EqualFold(c.name, category) {
			p.active = i
			break
		}
	}
	p.build()
}

// applyRuntimePreferences pushes the preferences that other code reads through
// package-level funnels into those funnels.
//
// Two of them are not fields anyone can consult: supportsUnicode and
// renderRelativeTime are called from every renderer in the package, and
// threading a preference through all of them would be a worse trade than
// setting one flag in one place when the preference changes.
func (ui *UI) applyRuntimePreferences() {
	setForceASCII(ui.prefs.ASCII)
	setAbsoluteAges(!ui.prefs.relativeAges())
	ui.restartAutoRefresh()
}

// restartAutoRefresh starts, stops or re-times the refresh ticker.
//
// Off by default, and the interval has a floor: below a few seconds it fights
// the analyst rather than helping, re-sorting a list under a cursor that is
// trying to read it.
func (ui *UI) restartAutoRefresh() {
	if ui.autoRefresh != nil {
		ui.autoRefresh.Stop()
		ui.autoRefresh = nil
	}
	secs := ui.prefs.AutoRefreshSeconds
	if secs <= 0 {
		return
	}

	ui.autoRefresh = time.NewTicker(time.Duration(secs) * time.Second)
	ticker := ui.autoRefresh
	go func() {
		for range ticker.C {
			if ui.ctx.Err() != nil {
				return
			}
			// Through the guarded helper: this fires from a goroutine of its
			// own, and painting from there is what a load guard exists to stop.
			ui.queueUpdate(func() {
				// Never while a modal is open. A list re-sorting behind a
				// dialog moves the row the dialog is about.
				if ui.activeModal == nil && !ui.helpActive {
					ui.repaintCurrentList()
				}
			})
		}
	}()
}
