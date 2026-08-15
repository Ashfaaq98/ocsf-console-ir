//go:build !windows

package ui

import (
	"os"
	"strings"
)

// On Unix the locale says it.
//
// LC_ALL, LC_CTYPE and LANG are the convention, in that order of precedence,
// and a terminal whose locale is not UTF-8 will render a block character as a
// question mark. Absent entirely means the locale is "C", which is not UTF-8 —
// so the honest answer to silence here is no.
func platformSupportsUnicode() bool {
	for _, key := range []string{"LC_ALL", "LC_CTYPE", "LANG"} {
		if val := os.Getenv(key); val != "" {
			v := strings.ToLower(val)
			return strings.Contains(v, "utf-8") || strings.Contains(v, "utf8")
		}
	}
	return false
}
