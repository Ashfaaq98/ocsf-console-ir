package ui

import (
	"testing"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/llm"
)

// Ensures ApplyLLMProvider updates both ui.llm and activeCM.llm (when ChatProvider).
func TestApplyLLMProviderPropagatesToActiveCM(t *testing.T) {
	u := &UI{}
	cm := &CaseManagement{}
	u.activeCM = cm

	// Provide a concrete ChatProvider (LocalStub implements ChatProvider + LLMProvider)
	provider := &llm.LocalStub{}
	u.ApplyLLMProvider(provider)

	if u.llm == nil {
		t.Fatalf("ui.llm not set after ApplyLLMProvider")
	}
	if u.activeCM == nil || u.activeCM.llm == nil {
		t.Fatalf("activeCM.llm not set after ApplyLLMProvider")
	}
}

// Ensures passing nil falls back to LocalStub and still updates activeCM.llm.
func TestApplyLLMProviderWithNilFallsBackToStub(t *testing.T) {
	u := &UI{}
	cm := &CaseManagement{}
	u.activeCM = cm

	u.ApplyLLMProvider(nil)

	if u.llm == nil {
		t.Fatalf("ui.llm should fall back to LocalStub when nil provider passed")
	}
	if _, ok := u.llm.(*llm.LocalStub); !ok {
		t.Fatalf("ui.llm should be *llm.LocalStub fallback")
	}

	if u.activeCM == nil || u.activeCM.llm == nil {
		t.Fatalf("activeCM.llm not set after fallback ApplyLLMProvider")
	}
}