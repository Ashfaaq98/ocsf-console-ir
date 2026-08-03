package ui

import (
	"context"
	"io"
	"path/filepath"
	"testing"
	"time"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/logging"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/store"
	"github.com/gdamore/tcell/v2"
)

func TestUISnapshots(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_ui_snapshot.db")
	st, err := store.NewStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer st.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	logger := logging.New(io.Discard, logging.LevelDebug, "test")
	uiInstance := NewUI(ctx, st, nil, logger, "midnight")

	sim := tcell.NewSimulationScreen("")
	if err := sim.Init(); err != nil {
		t.Fatalf("failed to init simulation screen: %v", err)
	}
	defer sim.Fini()

	viewports := []struct {
		name   string
		width  int
		height int
	}{
		{"Compact_80x24", 79, 24},
		{"Standard_100x30", 100, 30},
		{"Wide_140x40", 140, 40},
	}

	for _, vp := range viewports {
		t.Run(vp.name, func(t *testing.T) {
			sim.SetSize(vp.width, vp.height)
			uiInstance.updateLayoutMode(sim)

			mode, isShort := GetLayoutMode(vp.width, vp.height)
			if vp.width < 80 && mode != LayoutCompact {
				t.Errorf("expected LayoutCompact, got %v", mode)
			}
			if vp.width >= 140 && mode != LayoutWide {
				t.Errorf("expected LayoutWide, got %v", mode)
			}
			if vp.height < 24 != isShort {
				t.Errorf("isShort mismatch for height %d", vp.height)
			}
		})
	}
}

func TestThemeTokens(t *testing.T) {
	for name, builder := range themeBuilders {
		t.Run(name, func(t *testing.T) {
			theme := builder()
			if theme.TagTextPrimary == "" {
				t.Errorf("theme %s missing TagTextPrimary", name)
			}
			if theme.TagSeverityCritical == "" {
				t.Errorf("theme %s missing TagSeverityCritical", name)
			}
		})
	}
}
