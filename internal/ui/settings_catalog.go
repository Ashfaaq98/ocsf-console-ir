package ui

import (
	"fmt"
	"runtime"
	"strings"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/buildinfo"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/ocsf"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/paths"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/store"
)

// Every setting, in the order they are read.
//
// Built fresh each time the panel opens rather than held as a package variable:
// the rows close over the live UI, and a value that is a function of the
// application cannot be captured at init time.
func settingsCatalog() []settingsCategory {
	return []settingsCategory{
		generalSettings(),
		appearanceSettings(),
		ingestionSettings(),
		copilotSettings(),
		pluginSettings(),
		systemSettings(),
	}
}

func generalSettings() settingsCategory {
	return settingsCategory{
		name:  "General",
		blurb: "Who you are, and how records read.",
		settings: []setting{
			{
				name:   "Analyst name",
				search: "user author owner who signature",
				value:  func(ui *UI) string { return ui.currentAnalyst() },
				source: func(ui *UI) settingSource {
					if strings.TrimSpace(ui.prefs.Analyst) != "" {
						return srcYou
					}
					return srcDetected
				},
				detail: []string{
					"The name written into the audit trail, case ownership, notes and reports.",
					"Taken from the environment when unset — which is wrong on a shared machine.",
				},
				edit: func(ui *UI, done func()) { ui.editAnalystName(done) },
			},
			{
				name:   "Relative ages",
				search: "ago age duration",
				value:  func(ui *UI) string { return onOff(ui.prefs.relativeAges()) },
				source: func(ui *UI) settingSource { return chosen(ui.prefs.NoRelativeAges) },
				detail: []string{
					`Show "4m ago" rather than a bare clock time where a list has room for one.`,
					"Off gives absolute times everywhere, which is what a report wants.",
				},
				edit: func(ui *UI, done func()) {
					ui.prefs.NoRelativeAges = !ui.prefs.NoRelativeAges
					ui.applyPreferences()
					done()
				},
			},
			{
				name:   "Confirm destructive actions",
				search: "confirm ask delete detach warn",
				value:  func(ui *UI) string { return onOff(ui.prefs.confirmDestructive()) },
				source: func(ui *UI) settingSource { return chosen(ui.prefs.NoConfirmDestructive) },
				detail: []string{
					"Ask before deleting a report, detaching a finding, or leaving a case with an",
					"unsaved note. Off is for someone who knows exactly what they are doing.",
				},
				edit: func(ui *UI, done func()) {
					ui.prefs.NoConfirmDestructive = !ui.prefs.NoConfirmDestructive
					ui.applyPreferences()
					done()
				},
			},
		},
	}
}

func appearanceSettings() settingsCategory {
	return settingsCategory{
		name:  "Appearance",
		blurb: "What the screen looks like. Changes apply as you move.",
		settings: []setting{
			{
				name:   "Theme",
				search: "colour color palette dark light gruvbox",
				value:  func(ui *UI) string { return ui.themeName },
				source: func(ui *UI) settingSource {
					if ui.themeName != defaultThemeName {
						return srcYou
					}
					return srcDefault
				},
				detail: []string{
					"Six palettes ship. Every one is tested to keep the severity colours apart —",
					"a palette that confuses two of them is a correctness problem, not a taste one.",
				},
				edit: func(ui *UI, done func()) { ui.editTheme(done) },
			},
			{
				name:   "Colour depth",
				search: "truecolor 24-bit 256 terminal",
				value: func(ui *UI) string {
					if ui.hasTrueColor {
						return "24-bit"
					}
					return "16 colours"
				},
				source: func(ui *UI) settingSource { return srcDetected },
				locked: "Measured from the terminal at start-up. A 16-colour terminal falls back to " +
					"a palette built for one; there is nothing to choose.",
				detail: []string{
					"What the terminal said it can render, and what the palettes were built against.",
				},
			},
			{
				name:   "Glyphs",
				search: "unicode ascii box drawing symbols",
				value: func(ui *UI) string {
					if ui.prefs.ASCII || !supportsUnicode() {
						return "ASCII"
					}
					return "Unicode"
				},
				source: func(ui *UI) settingSource {
					if ui.prefs.ASCII {
						return srcYou
					}
					return srcDetected
				},
				detail: []string{
					"Borders, marks and the timeline rail. Forced to ASCII for a terminal that",
					"claims UTF-8 and renders boxes as question marks.",
				},
				edit: func(ui *UI, done func()) {
					ui.prefs.ASCII = !ui.prefs.ASCII
					ui.applyPreferences()
					done()
				},
			},
		},
	}
}

func ingestionSettings() settingsCategory {
	return settingsCategory{
		name:  "Ingestion",
		blurb: "What comes in, and what happens to it on the way.",
		settings: []setting{
			{
				name: "HTTP receiver",
				value: func(ui *UI) string {
					switch {
					case ui.listener == nil:
						return "unavailable"
					case ui.listener.Listening():
						return "listening on " + ui.listener.Address()
					default:
						return "off"
					}
				},
				source: func(ui *UI) settingSource {
					if ui.listener != nil && ui.listener.Listening() {
						return srcYou
					}
					return srcDefault
				},
				search: "http listener post ingest api token warning",
				detailFor: func(ui *UI) []string {
					switch {
					case ui.listener == nil:
						return []string{"This build has no receiver."}
					case ui.listener.Listening() && !ui.listener.HasToken():
						// Said while it is open, not only before it is opened.
						return []string{
							"NO TOKEN — anything that can reach " + ui.listener.Address() +
								" can write into your cases.",
							fmt.Sprintf("%s accepted so far.", plural(ui.listener.Received(), "payload")),
						}
					case ui.listener.Listening():
						return []string{
							"Token required. " +
								fmt.Sprintf("%s accepted so far.", plural(ui.listener.Received(), "payload")),
						}
					case !ui.listener.HasToken():
						return []string{
							"⏎ starts it. No token is set, so anything that can reach " +
								ui.listener.Address() + " could post once it is running.",
						}
					}
					return []string{
						"⏎ starts it. Posted records are ingested as if dropped in the folder.",
					}
				},
				edit: func(ui *UI, done func()) {
					ui.toggleIngestListener(done)
				},
			},
			{
				name:   "Receiver address",
				search: "bind port host address expose",
				value: func(ui *UI) string {
					if ui.listener == nil {
						return "—"
					}
					return ui.listener.Address()
				},
				source: func(ui *UI) settingSource { return srcFlag },
				locked: "Set with --http-ingest-bind. Where a service listens is a decision about " +
					"what to expose and to whom, often taken by someone other than the analyst — " +
					"so it does not move when a preference does.",
				detail: []string{
					"A bearer token is required on anything other than a loopback address.",
				},
			},
			{
				name:   "Receiver token",
				search: "token bearer auth secret",
				value: func(ui *UI) string {
					if ui.listener == nil {
						return "—"
					}
					if ui.listener.HasToken() {
						return "set"
					}
					return "not set"
				},
				source: func(ui *UI) settingSource {
					if ui.listener != nil && ui.listener.HasToken() {
						return srcFlag
					}
					return srcNone
				},
				locked: "Set with --http-ingest-token or $INGEST_TOKEN. Never shown, and never " +
					"editable here: a secret typed into a panel is a secret in a screenshot.",
				detail: []string{
					"Without one, anything that can reach the address can write into your cases.",
				},
			},
			{
				name:   "Auto-refresh",
				search: "reload poll interval timer",
				value: func(ui *UI) string {
					if ui.prefs.AutoRefreshSeconds <= 0 {
						return "off"
					}
					return seconds(ui.prefs.AutoRefreshSeconds)
				},
				source: func(ui *UI) settingSource { return chosen(ui.prefs.AutoRefreshSeconds > 0) },
				detail: []string{
					"Off by default, and that is deliberate: a list that re-sorts itself while you",
					"are reading it loses your place. Press r when you want fresh data.",
				},
				edit: func(ui *UI, done func()) { ui.editAutoRefresh(done) },
			},
		},
	}
}

func copilotSettings() settingsCategory {
	return settingsCategory{
		name:  "Copilot",
		blurb: "The assistant. Optional, and off unless a provider answers.",
		settings: []setting{
			{
				name:   "Copilot",
				search: "ai llm assistant enable disable",
				value:  func(ui *UI) string { return onOff(!ui.prefs.CopilotOff) },
				source: func(ui *UI) settingSource { return chosen(ui.prefs.CopilotOff) },
				detail: []string{
					"Off means no drawer, no suggestions and no requests — nothing leaves this",
					"machine on the copilot's account.",
				},
				edit: func(ui *UI, done func()) {
					ui.prefs.CopilotOff = !ui.prefs.CopilotOff
					ui.applyPreferences()
					done()
				},
			},
			{
				name:   "Provider and model",
				search: "ollama openrouter groq endpoint api key model",
				value:  func(ui *UI) string { return ui.copilotProviderSummary() },
				source: func(ui *UI) settingSource { return srcConfig },
				detail: []string{
					"Provider, endpoint, model and API key. With none configured this defaults to a",
					"local Ollama model, so nothing is sent anywhere until you point it elsewhere.",
				},
				edit: func(ui *UI, done func()) { ui.editLLMProvider(done) },
			},
			{
				name:   "Ask above",
				search: "tokens cost confirm threshold",
				value:  func(ui *UI) string { return fmt.Sprintf("%d tokens", ui.prefs.copilotTokenWarning()) },
				source: func(ui *UI) settingSource { return chosen(ui.prefs.CopilotTokenWarning > 0) },
				detail: []string{
					"A request estimated above this asks before it is sent, with the cost. Money and",
					"data both leave on a large request, so the confirmation is about both.",
				},
				edit: func(ui *UI, done func()) { ui.editTokenWarning(done) },
			},
		},
	}
}

func pluginSettings() settingsCategory {
	return settingsCategory{
		name:  "Plugins",
		blurb: "External enrichment. GeoIP and WHOIS are not here — they run in-process.",
		settings: []setting{
			{
				name:   "External plugins",
				search: "redis misp opencti intelowl threat intel",
				value: func(ui *UI) string {
					return "none registered"
				},
				source: func(ui *UI) settingSource { return srcNone },
				locked: "External plugins need a Redis transport, enabled with --redis. Nothing is " +
					"registered in this session.",
				detail: []string{
					"MISP, OpenCTI and IntelOwl run as separate executables over Redis streams.",
					"Their health and last error will be listed here once one is registered.",
				},
			},
		},
	}
}

func systemSettings() settingsCategory {
	return settingsCategory{
		name:  "System",
		blurb: "Where things are and what this build is. Read-only.",
		settings: []setting{
			{
				name:   "Version",
				search: "build commit ocsf schema",
				value: func(ui *UI) string {
					return fmt.Sprintf("%s · OCSF %s", buildinfo.Display(ui.version), ocsf.SchemaVersion())
				},
				source: func(ui *UI) settingSource { return srcDetected },
				locked: "Fixed at build time.",
				detail: []string{
					"The binary, and the OCSF schema registry vendored into it.",
				},
			},
			{
				name:   "SQLite driver",
				search: "cgo sqlite driver database engine",
				value:  func(ui *UI) string { return store.DriverName() },
				source: func(ui *UI) settingSource { return srcDetected },
				locked: "Chosen at build time by CGO_ENABLED, not by a flag.",
				detail: []string{
					"The shipped binary uses the pure-Go driver. The two take different spellings",
					"for the same pragmas, which is worth knowing when a database behaves oddly.",
				},
			},
			{
				name:   "Database",
				search: "db path file storage location",
				value:  func(ui *UI) string { return paths.Current().DB() },
				source: func(ui *UI) settingSource { return srcConfig },
				locked: "Set with --db or --data-dir, or in the configuration file. Where data " +
					"lives is not a preference.",
				detail: []string{
					"One SQLite file. --portable keeps it beside the working directory instead.",
				},
			},
			{
				name:   "Configuration",
				search: "config directory settings path",
				value:  func(ui *UI) string { return paths.Current().Config },
				source: func(ui *UI) settingSource { return srcConfig },
				locked: "Set with --config-dir.",
				detail: []string{
					"Holds your preferences and the copilot's settings. Created mode 0700, because",
					"the copilot's settings can hold an API key.",
				},
			},
			{
				name:   "Logs",
				search: "log directory path debug",
				value:  func(ui *UI) string { return paths.Current().State },
				source: func(ui *UI) settingSource { return srcConfig },
				locked: "Set with --log-dir. The level is set with --log-level.",
				detail: []string{
					"One file, rotated at 5 MB with three kept. --log-level debug adds keystrokes",
					"and query timings, which is what to send with a bug report.",
				},
			},
			{
				name:   "Drop folder",
				search: "incoming watch directory ingest folder",
				value:  func(ui *UI) string { return ui.ingestDirLabel() },
				source: func(ui *UI) settingSource { return srcConfig },
				locked: "Set with --ingest-dir. It stays relative to where you launched, unlike the " +
					"database — a landing zone you cannot find is not a landing zone.",
				detail: []string{
					"Files dropped here are ingested while the application runs.",
				},
			},
			{
				name:   "Platform",
				search: "os architecture goos",
				value:  func(ui *UI) string { return fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH) },
				source: func(ui *UI) settingSource { return srcDetected },
				locked: "What this binary was built for.",
				detail: []string{
					"Worth quoting in a bug report alongside the terminal you are using.",
				},
			},
		},
	}
}
