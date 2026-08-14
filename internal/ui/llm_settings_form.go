package ui

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/llm"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/logging"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/paths"
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// The copilot's provider settings, shared by the two screens that open them.
//
// It lived on the case screen and could only be reached from inside a case —
// the one place where being unable to change the provider is most annoying,
// because the copilot is right there failing. The form itself is unchanged; it
// takes what it needs from whichever screen mounted it rather than from a case.
type llmSettingsHost struct {
	app    *tview.Application
	theme  Theme
	logger *logging.Logger
	// ctx bounds the model-list and provider-build calls.
	ctx context.Context
	// apply installs a freshly built provider wherever the host keeps one.
	apply func(llm.LLMProvider)
	// search opens the searchable model list, which each host mounts its own
	// way for the same reason mount and dismiss exist.
	search func(options []string, choose func(string))
	// themeModal paints a form in the host's palette.
	themeModal func(tview.Primitive)
	// mount puts the form on screen and dismiss takes it off. The two screens
	// stack modals differently — a case pushes a root, the main UI overlays a
	// page — so the form asks rather than assumes.
	mount   func(tview.Primitive)
	dismiss func()
	status  func(string)
}

func showLLMSettingsForm(h llmSettingsHost, done func()) {
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
	h.themeModal(form)
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
			h.app.QueueUpdate(func() {
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
					h.status("Provider set to OpenRouter. Enter API key to load models.")
				} else if provider == "groq" && strings.TrimSpace(apiKeyIF.GetText()) == "" && strings.TrimSpace(os.Getenv("GROQ_API_KEY")) == "" {
					h.status("Provider set to Groq. Enter API key to load models.")
				} else if provider == "synthetic" && strings.TrimSpace(apiKeyIF.GetText()) == "" && strings.TrimSpace(os.Getenv("SYNTHETIC_API_KEY")) == "" {
					h.status("Provider set to Synthetic. Enter API key to load models.")
				} else {
					h.status(fmt.Sprintf("Provider set to %s", provider))
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
	endpointIF.SetFieldBackgroundColor(h.theme.Surface).SetFieldTextColor(h.theme.TextPrimary).SetLabelColor(h.theme.TextPrimary)
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
	modelDD.SetFieldBackgroundColor(h.theme.Surface).SetFieldTextColor(h.theme.TextPrimary).SetLabelColor(h.theme.TextPrimary)
	form.AddFormItem(modelDD)

	// API Key (for OpenRouter)
	apiKey := settings.Active.APIKey
	apiKeyIF = tview.NewInputField().SetLabel("API Key (OpenRouter/Groq)").SetText(apiKey)
	apiKeyIF.SetMaskCharacter('*')
	apiKeyIF.SetFieldBackgroundColor(h.theme.Surface).SetFieldTextColor(h.theme.TextPrimary).SetLabelColor(h.theme.TextPrimary)
	form.AddFormItem(apiKeyIF)

	// (Removed) separate discovered models dropdown — using single Model dropdown above.

	// Helper to refresh model list from current Provider/Endpoint
	refreshModels = func() {
		// Concurrency guard: prevent overlapping refreshes which can deadlock the UI.
		if !atomic.CompareAndSwapInt32(&refreshing, 0, 1) {
			// Use non-blocking QueueUpdate from UI goroutine to avoid draw re-entrancy
			h.app.QueueUpdate(func() {
				h.status("Model refresh already in progress")
			})
			return
		}

		// Show immediate loading placeholder in the Model dropdown (non-blocking UI update)
		h.app.QueueUpdate(func() {
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

		if h.logger != nil {
			h.logger.Printf("LLM Settings: refreshModels start provider=%s endpoint=%s key_len=%d", prov, ep, len(key))
		}

		// If OpenRouter selected without an API key, don't attempt network calls; show helpful placeholder.
		if (prov == "openrouter" && key == "" && strings.TrimSpace(os.Getenv("OPENROUTER_API_KEY")) == "") ||
			(prov == "groq" && key == "" && strings.TrimSpace(os.Getenv("GROQ_API_KEY")) == "") ||
			(prov == "synthetic" && key == "" && strings.TrimSpace(os.Getenv("SYNTHETIC_API_KEY")) == "") {
			// Non-blocking UI update to avoid deadlock in button callback path
			h.app.QueueUpdate(func() {
				modelOptions = []string{"(requires api key)"}
				if modelDD != nil {
					modelDD.SetOptions(modelOptions, nil)
					modelDD.SetCurrentOption(0)
				}
				if prov == "groq" {
					h.status("Groq requires an API key to list models")
				} else if prov == "synthetic" {
					h.status("Synthetic requires an API key to list models")
				} else {
					h.status("OpenRouter requires an API key to list models")
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
			buildCtx, buildCancel := context.WithTimeout(h.ctx, buildTimeout)
			defer buildCancel()

			p, err := llm.Build(buildCtx, cfg, h.logger)
			if err != nil {
				if h.logger != nil {
					h.logger.Printf("LLM Settings: provider build failed provider=%s err=%v", prov, err)
				}
				// Use QueueUpdate from background goroutine to avoid potential QueueUpdateDraw deadlocks.
				h.app.QueueUpdate(func() {
					modelOptions = []string{"(error)"}
					if modelDD != nil {
						modelDD.SetOptions(modelOptions, nil)
					}
					h.status(fmt.Sprintf("Model list error: %v", err))
					atomic.StoreInt32(&refreshing, 0)
				})
				return
			}

			timeout := 3 * time.Second
			if strings.EqualFold(prov, "openrouter") {
				timeout = 8 * time.Second
			}
			ctx, cancel := context.WithTimeout(h.ctx, timeout)
			defer cancel()
			list, err := llm.TryListModels(ctx, p)
			duration := time.Since(start)

			// Use QueueUpdate (not QueueUpdateDraw) from background goroutine to avoid blocking the UI draw thread.
			h.app.QueueUpdate(func() {
				if err != nil {
					// Detect context timeout
					timedOut := ctx.Err() == context.DeadlineExceeded
					if timedOut {
						modelOptions = []string{"(timeout)"}
						h.status(fmt.Sprintf("Model discovery timed out after %s", timeout))
					} else {
						modelOptions = []string{"(error)"}
						h.status(fmt.Sprintf("Model list error: %v", err))
					}
					if modelDD != nil {
						modelDD.SetOptions(modelOptions, nil)
					}
					if h.logger != nil {
						h.logger.Printf("LLM Settings: list models failed provider=%s duration=%s err=%v", prov, duration, err)
					}
					atomic.StoreInt32(&refreshing, 0)
					return
				}
				if len(list) == 0 {
					modelOptions = []string{"(none found)"}
					if modelDD != nil {
						modelDD.SetOptions(modelOptions, nil)
					}
					h.status("No models discovered")
					if h.logger != nil {
						h.logger.Printf("LLM Settings: list models returned 0 models provider=%s duration=%s", prov, duration)
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
				h.status(fmt.Sprintf("Discovered %d models in %s", len(list), duration.Truncate(time.Millisecond)))
				if h.logger != nil {
					h.logger.Printf("LLM Settings: discovered %d models provider=%s duration=%s", len(list), prov, duration)
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
		h.search(opts, func(sel string) {
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
				h.app.SetFocus(modelDD)
			}
			// Track in local variable; persisted on Save
			model = sel
			h.status(fmt.Sprintf("Model set to %s", sel))
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
			h.status(fmt.Sprintf("Save failed: %v", err))
			return
		}
		// Build provider and apply to UI + current CM
		p, err := llm.Build(h.ctx, settings.Active, h.logger)
		if err != nil {
			h.status(fmt.Sprintf("Provider build failed: %v", err))
			return
		}
		h.apply(p)
		h.status("LLM settings saved and applied")
		h.dismiss()
		done()
	})

	form.AddButton("Cancel", func() {
		h.dismiss()
		done()
	})

	// Esc to close
	form.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
		if ev.Key() == tcell.KeyEsc {
			h.dismiss()
			done()
			return nil
		}
		return ev
	})

	h.mount(form)
}
