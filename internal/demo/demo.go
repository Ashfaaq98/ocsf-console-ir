// Package demo provides the sample OCSF data behind `console-ir demo`.
//
// The dataset is embedded rather than read from the repository: an installed
// binary (Homebrew, curl, a release tarball) has no checkout to read
// examples/ from, and `demo` is meant to be the first command anyone runs.
package demo

import (
	_ "embed"
	"strings"
)

// scenarioJSONL is a single coherent incident rather than an assortment of
// unrelated records: a phishing attachment leads to encoded PowerShell,
// credential access and C2 beaconing on one host. That makes the triage queue,
// the case model and the indicator pivot all show something real when explored.
//
//go:embed data/scenario.jsonl
var scenarioJSONL []byte

// Scenario returns the demo dataset as OCSF JSONL.
func Scenario() []byte { return scenarioJSONL }

// RecordCount reports how many records the demo dataset contains.
func RecordCount() int {
	n := 0
	for _, line := range strings.Split(string(scenarioJSONL), "\n") {
		if strings.TrimSpace(line) != "" {
			n++
		}
	}
	return n
}
