package cmd

import (
	"strings"
	"testing"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/demo"
)

// The Welcome Screen tells a first-time user what the demo actually contains
// before they load it. Both numbers are counted from what will really be seeded
// rather than written down, so this checks the counting rather than the text:
// a literal would be right today and quietly wrong the next time either the
// dataset or the case list changed.
func TestDemoSummaryCountsWhatIsSeeded(t *testing.T) {
	got := demoSummary()

	if n := demo.RecordCount(); n == 0 {
		t.Fatal("the embedded demo dataset is empty")
	} else if !strings.Contains(got, plural(n, "event")) {
		t.Errorf("summary = %q, want the dataset's %d events", got, n)
	}

	if n := len(demoCases()); n == 0 {
		t.Fatal("the demo seeds no cases")
	} else if !strings.Contains(got, plural(n, "case")) {
		t.Errorf("summary = %q, want the seeded %d cases", got, n)
	}
}
