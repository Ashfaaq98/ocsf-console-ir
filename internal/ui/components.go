package ui

import (
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/rivo/tview"
)

// PanelRole defines visual weight and styling for panels.
type PanelRole int

const (
	PanelRolePrimary PanelRole = iota
	PanelRoleInspector
	PanelRoleRail
	PanelRoleModal
)

// BadgeKind defines semantic badge types.
type BadgeKind int

const (
	BadgeKindSeverity BadgeKind = iota
	BadgeKindStatus
	BadgeKindVerdict
	BadgeKindSource
	BadgeKindCount
)

// newPanel creates a tview Box with standard title, border, and background styling.
func newPanel(title string, role PanelRole, theme Theme) *tview.Box {
	return stylePanel(tview.NewBox(), title, role, theme)
}

// stylePanel applies the standard panel border, title and background to any
// bordered primitive. Widgets embed *tview.Box rather than being one, so the
// styling has to be reachable without constructing a fresh Box.
func stylePanel(box *tview.Box, title string, role PanelRole, theme Theme) *tview.Box {
	box.SetBorder(true)
	if title != "" {
		box.SetTitle(fmt.Sprintf(" %s ", title))
	}
	box.SetTitleColor(theme.Header).
		SetTitleAlign(tview.AlignLeft)

	switch role {
	case PanelRolePrimary:
		box.SetBorderColor(theme.Border).
			SetBackgroundColor(theme.Bg)
	case PanelRoleInspector:
		box.SetBorderColor(theme.Border).
			SetBackgroundColor(theme.Surface)
	case PanelRoleRail:
		box.SetBorderColor(theme.Border).
			SetBackgroundColor(theme.Bg)
	case PanelRoleModal:
		box.SetBorderColor(theme.FocusBorder).
			SetBackgroundColor(theme.SurfaceRaised)
	}

	return box
}

// badge renders a color-tagged badge string for tview text widgets.
func badge(kind BadgeKind, label string, theme Theme) string {
	if label == "" {
		return ""
	}

	var color string
	switch kind {
	case BadgeKindSeverity:
		upper := strings.ToUpper(label)
		switch {
		case strings.Contains(upper, "CRIT") || upper == "5" || upper == "FATAL":
			color = theme.TagSeverityCritical
		case strings.Contains(upper, "HIGH") || upper == "4":
			color = theme.TagSeverityHigh
		case strings.Contains(upper, "MED") || upper == "3":
			color = theme.TagSeverityMedium
		case strings.Contains(upper, "LOW") || upper == "2":
			color = theme.TagSeverityLow
		default:
			color = theme.TagSeverityInfo
		}
	case BadgeKindStatus:
		upper := strings.ToUpper(label)
		switch upper {
		case "OPEN", "NEW", "UNRESOLVED", "INVESTIGATING":
			color = theme.TagWarning
		case "CLOSED", "RESOLVED", "COMPLETED":
			color = theme.TagSuccess
		case "IN_PROGRESS", "TRIAGED":
			color = theme.TagAccent
		default:
			color = theme.TagMuted
		}
	case BadgeKindVerdict:
		upper := strings.ToUpper(label)
		switch upper {
		case "TRUE_POSITIVE", "TP", "MALICIOUS":
			color = theme.TagError
		case "FALSE_POSITIVE", "FP", "BENIGN":
			color = theme.TagSuccess
		default:
			color = theme.TagWarning
		}
	case BadgeKindSource:
		color = theme.TagAccent
	case BadgeKindCount:
		color = theme.TagMuted
	default:
		color = theme.TagTextPrimary
	}

	return fmt.Sprintf("[%s][%s][-:-:-]", color, label)
}

// metric renders a compact dashboard metric card string.
func metric(label, value, delta string, tone string, theme Theme) string {
	var valColor string
	switch tone {
	case "critical":
		valColor = theme.TagSeverityCritical
	case "high":
		valColor = theme.TagSeverityHigh
	case "medium":
		valColor = theme.TagSeverityMedium
	case "low":
		valColor = theme.TagSeverityLow
	case "success":
		valColor = theme.TagSuccess
	case "accent":
		valColor = theme.TagAccent
	default:
		valColor = theme.TagTextPrimary
	}

	// An empty label emits no line at all. It used to emit a blank one, which
	// cost a row: in a card sized to its content that pushed the value off the
	// bottom and rendered the card empty.
	var res string
	if label != "" {
		res = fmt.Sprintf("[%s]%s[-:-:-]\n", theme.TagMuted, label)
	}
	res += fmt.Sprintf("[%s:b]%s[-:-:-]", valColor, value)
	if delta != "" {
		res += fmt.Sprintf("   [%s]%s[-:-:-]", theme.TagMuted, delta)
	}
	return res
}

// emptyState builds an empty state view explaining what the pane is and key actions to take.
func emptyState(icon, title, body string, actions []string, theme Theme) *tview.TextView {
	tv := tview.NewTextView().
		SetDynamicColors(true).
		SetTextAlign(tview.AlignCenter)
	tv.SetBackgroundColor(theme.Bg)

	var sb strings.Builder
	sb.WriteString("\n\n")
	if icon != "" {
		sb.WriteString(fmt.Sprintf("[%s]%s[-:-:-]\n\n", theme.TagMuted, icon))
	}
	sb.WriteString(fmt.Sprintf("[%s:b]%s[-:-:-]\n", theme.TagTextPrimary, title))
	if body != "" {
		sb.WriteString(fmt.Sprintf("[%s]%s[-:-:-]\n\n", theme.TagMuted, body))
	}
	if len(actions) > 0 {
		sb.WriteString(fmt.Sprintf("[%s]Actions: %s[-:-:-]\n", theme.TagAccent, strings.Join(actions, "  ·  ")))
	}

	tv.SetText(sb.String())
	return tv
}

// loadingState returns a standardized loading string.
func loadingState(label string, theme Theme) string {
	if label == "" {
		label = "Loading..."
	}
	return fmt.Sprintf("[%s]… %s[-:-:-]", theme.TagWarning, label)
}

// renderKey formats a single keyboard shortcut hint string.
func renderKey(key, label string, theme Theme) string {
	return fmt.Sprintf("[%s]%s[-:-:-] [%s]%s[-:-:-]", theme.TagAccent, key, theme.TagTextPrimary, label)
}

// keyHint is one entry in an action bar.
type keyHint struct{ Key, Label string }

// actionBar renders the single-line key legend that closes every screen. Every
// screen builds it from the same helper so the separator and ordering cannot
// drift between them.
func actionBar(theme Theme, hints ...keyHint) string {
	parts := make([]string, 0, len(hints))
	for _, h := range hints {
		parts = append(parts, renderKey(h.Key, h.Label, theme))
	}
	return strings.Join(parts, fmt.Sprintf(" [%s]·[-:-:-] ", theme.TagMuted))
}

// renderRelativeTime formats a timestamp into relative compact string e.g. 2m, 4h, 3d.
func renderRelativeTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	d := time.Since(t)
	if d < 0 {
		d = 0
	}
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		days := int(math.Floor(d.Hours() / 24))
		return fmt.Sprintf("%dd", days)
	}
}

// formatRisk converts a numeric risk score (0-100) into a color badge string.
func formatRisk(score int, theme Theme) string {
	var color string
	var glyph string
	switch {
	case score >= 80:
		color = theme.TagSeverityCritical
		glyph = "●"
	case score >= 60:
		color = theme.TagSeverityHigh
		glyph = "▲"
	case score >= 30:
		color = theme.TagSeverityMedium
		glyph = "◆"
	default:
		color = theme.TagSeverityLow
		glyph = "·"
	}
	return fmt.Sprintf("[%s]%s %02d[-:-:-]", color, glyph, score)
}

// formatVerdict formats verdict values into standard badges.
func formatVerdict(verdict string, theme Theme) string {
	if verdict == "" {
		verdict = "UNSET"
	}
	return badge(BadgeKindVerdict, verdict, theme)
}

// formatCaseStatus formats case status into standard badges.
func formatCaseStatus(status string, theme Theme) string {
	if status == "" {
		status = "NEW"
	}
	return badge(BadgeKindStatus, status, theme)
}

// formatSeverityBadge converts severity string into badge with glyph.
func formatSeverityBadge(sev string, theme Theme) string {
	upper := strings.ToUpper(sev)
	var glyph string
	var color string
	switch {
	case strings.Contains(upper, "CRIT") || upper == "5" || upper == "FATAL":
		glyph = "●"
		color = theme.TagSeverityCritical
	case strings.Contains(upper, "HIGH") || upper == "4":
		glyph = "▲"
		color = theme.TagSeverityHigh
	case strings.Contains(upper, "MED") || upper == "3":
		glyph = "◆"
		color = theme.TagSeverityMedium
	case strings.Contains(upper, "LOW") || upper == "2":
		glyph = "·"
		color = theme.TagSeverityLow
	default:
		glyph = "·"
		color = theme.TagSeverityInfo
	}
	return fmt.Sprintf("[%s]%s %s[-:-:-]", color, glyph, upper)
}
