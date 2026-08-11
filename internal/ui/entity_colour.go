package ui

import (
	"regexp"
	"strings"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/ocsf"
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// Colour by what a thing *is*.
//
// The case screen was three colours — cream for values, grey for labels, and an
// accent — so a hostname, a username, an address and a file hash all rendered
// identically. Six kinds of fact in one colour is a screen you have to read
// word by word.
//
// The classes come from OCSF, not from taste: every observable the schema
// derives carries a type_id, and this collapses that enum into four classes
// that are worth telling apart at a glance during an incident.
//
//	host      the machine        workstation-14, dc-01
//	user      the person         j.rivera, a.novak
//	network   where it went      10.20.4.14, cdn-metrics.example
//	artifact  what it left       invoice-88213.docm, svc_update.exe, a hash
//
// Four rather than seven. File, hash and process are one class because they
// answer one question — what did it drop or run — and because every hue added
// here is one more that has to stay separable from the five severity colours
// and from each other under colour blindness. Four is what the palettes can
// carry honestly.
type entityClass int

const (
	entityHost entityClass = iota
	entityUser
	entityNetwork
	entityArtifact
	entityClassCount
)

// entityClassOf maps an OCSF observable type_id to a colour class.
//
// The bool is false for types with no class — an entity nobody has a colour for
// is drawn as an ordinary value rather than in some default hue that would
// claim a meaning it does not have.
func entityClassOf(typeID int) (entityClass, bool) {
	switch typeID {
	case ocsf.ObservableTypeHostname, ocsf.ObservableTypeMACAddress:
		return entityHost, true
	case ocsf.ObservableTypeUserName, ocsf.ObservableTypeEmail:
		return entityUser, true
	case ocsf.ObservableTypeIPAddress, ocsf.ObservableTypeURL, ocsf.ObservableTypeURLString:
		return entityNetwork, true
	case ocsf.ObservableTypeFileName, ocsf.ObservableTypeHash, ocsf.ObservableTypeProcessName:
		return entityArtifact, true
	}
	return 0, false
}

// entityColour is a class's colour in a theme.
func entityColour(class entityClass, t Theme) tcell.Color {
	if class < 0 || int(class) >= len(t.Entity) {
		return t.TextPrimary
	}
	if c := t.Entity[class]; c != tcell.ColorDefault {
		return c
	}
	// A palette that has not declared a ramp keeps its ordinary value colour
	// rather than borrowing another theme's.
	return t.TextPrimary
}

// entityTag is a class's colour as a tview markup tag.
func entityTag(class entityClass, t Theme) string {
	return tagColor(entityColour(class, t))
}

// paintEntity renders one value in its class's colour, escaped.
func paintEntity(value string, class entityClass, t Theme) string {
	if strings.TrimSpace(value) == "" {
		return ""
	}
	return "[" + entityTag(class, t) + "]" + tview.Escape(value) + "[-]"
}

// paintEntities renders a list of values of one class, comma separated.
func paintEntities(values []string, class entityClass, t Theme) string {
	if len(values) == 0 {
		return ""
	}
	painted := make([]string, 0, len(values))
	for _, v := range values {
		if p := paintEntity(v, class, t); p != "" {
			painted = append(painted, p)
		}
	}
	return strings.Join(painted, ", ")
}

// Entities inside free text.
//
// A finding's title and an event's message are prose written by whatever
// produced them — "Outbound session to 45.147.230.11 from workstation-14" — and
// the interesting words are inside the sentence. These patterns find the ones
// that can be recognised from their shape alone, which is deliberately fewer
// than the ones OCSF types: a bare word may be a hostname or an English noun,
// and colouring a guess is worse than colouring nothing.
var (
	// Dotted quads, with a word boundary so a version string is not an address.
	reIPv4 = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	// 32 hex characters or more: md5, sha1, sha256.
	reHash = regexp.MustCompile(`\b[a-fA-F0-9]{32,64}\b`)
	// A filename with an extension that means something on an endpoint.
	reFile = regexp.MustCompile(`\b[\w.\-]+\.(?:exe|dll|ps1|bat|cmd|vbs|js|jar|docm?|xlsm?|pdf|zip|scr|lnk|sys|tmp)\b`)
	// A dotted name with a plausible TLD. Anchored on the tail so it does not
	// swallow the sentence around it.
	reDomain = regexp.MustCompile(`\b(?:[a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}\b`)
)

// paintText colours the entities inside a sentence, in the theme's value
// colour.
func paintText(s string, t Theme) string {
	return paintTextOn(s, t.TagTextPrimary, t)
}

// paintTextOn colours the entities inside a sentence and escapes the rest,
// returning to `base` after each one.
//
// Returning to a named colour rather than to tview's reset: `[-]` restores the
// widget's default, not the colour the sentence was being written in, so the
// prose after the first entity came out in whatever the widget happened to be
// rather than in the colour of the line it belongs to.
//
// Order matters among the patterns: a hash is checked before a filename and a
// filename before a domain, because "svc_update.exe" matches the domain pattern
// too and the more specific reading is the right one.
func paintTextOn(s, base string, t Theme) string {
	if strings.TrimSpace(s) == "" {
		return ""
	}

	type span struct {
		lo, hi int
		class  entityClass
	}
	var spans []span
	taken := func(lo, hi int) bool {
		for _, s := range spans {
			if lo < s.hi && s.lo < hi {
				return true
			}
		}
		return false
	}

	for _, m := range []struct {
		re    *regexp.Regexp
		class entityClass
	}{
		{reIPv4, entityNetwork},
		{reHash, entityArtifact},
		{reFile, entityArtifact},
		{reDomain, entityNetwork},
	} {
		for _, loc := range m.re.FindAllStringIndex(s, -1) {
			if !taken(loc[0], loc[1]) {
				spans = append(spans, span{loc[0], loc[1], m.class})
			}
		}
	}
	if len(spans) == 0 {
		return tview.Escape(s)
	}
	back := "[-]"
	if base != "" {
		back = "[" + base + "]"
	}

	// In order, so the sentence is rebuilt rather than reordered.
	for i := 1; i < len(spans); i++ {
		for j := i; j > 0 && spans[j].lo < spans[j-1].lo; j-- {
			spans[j], spans[j-1] = spans[j-1], spans[j]
		}
	}

	var b strings.Builder
	at := 0
	for _, sp := range spans {
		b.WriteString(tview.Escape(s[at:sp.lo]))
		b.WriteString("[" + entityTag(sp.class, t) + "]")
		b.WriteString(tview.Escape(s[sp.lo:sp.hi]))
		b.WriteString(back)
		at = sp.hi
	}
	b.WriteString(tview.Escape(s[at:]))
	return b.String()
}
