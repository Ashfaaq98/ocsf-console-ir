package llm

import (
	"context"
	"fmt"
	"log"
)

// Discovery is an optional capability a provider can implement to expose
// model listing and health checks for settings UIs.
type Discovery interface {
	ListModels(ctx context.Context) ([]string, error)
	HealthCheck(ctx context.Context) error
}

// Build constructs an LLMProvider from a ProviderConfig.
// Returns an error if the provider cannot be built; callers should handle the error.
func Build(ctx context.Context, cfg ProviderConfig, logger *log.Logger) (LLMProvider, error) {
	switch normalize(cfg.Provider) {
	case "ollama":
		p, err := NewOllama(cfg.Endpoint, cfg.Model, logger)
		if err != nil {
			return nil, err
		}
		return p, nil
	case "openrouter":
		p, err := NewOpenRouter(cfg.Endpoint, cfg.Model, cfg.APIKey, logger)
		if err != nil {
			return nil, err
		}
		return p, nil
	case "local_stub", "local", "stub", "":
		// Local stub provider is deprecated/removed as a selectable runtime provider.
		// Return an error so callers surface a configurable provider (e.g., "ollama").
		return nil, fmt.Errorf("local stub provider is deprecated; set provider to 'ollama' or 'openrouter'")
	default:
		return nil, fmt.Errorf("unknown LLM provider: %s", cfg.Provider)
	}
}

// TryHealthCheck attempts a provider health check when supported.
func TryHealthCheck(ctx context.Context, p LLMProvider) error {
	if d, ok := p.(Discovery); ok {
		return d.HealthCheck(ctx)
	}
	return nil
}

// TryListModels attempts to list models for a provider when supported.
func TryListModels(ctx context.Context, p LLMProvider) ([]string, error) {
	if d, ok := p.(Discovery); ok {
		return d.ListModels(ctx)
	}
	return nil, fmt.Errorf("model listing not supported by this provider")
}

func normalize(s string) string {
	switch s {
	case "Ollama", "OLLAMA":
		return "ollama"
	case "OpenRouter", "OPENROUTER":
		return "openrouter"
	case "LocalStub", "LOCAL", "STUB", "LOCAL_STUB":
		return "local_stub"
	default:
		return s
	}
}