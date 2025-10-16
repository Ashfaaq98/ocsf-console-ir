//go:build !windows
// +build !windows

package cmd

import (
	"os"
	"strconv"
	"syscall"
	"unsafe"
)

// getTerminalSize returns terminal dimensions for Unix-like systems
func getTerminalSize() (int, int) {
	// Try environment variables first
	if cols := os.Getenv("COLUMNS"); cols != "" {
		if rows := os.Getenv("LINES"); rows != "" {
			if c, err := strconv.Atoi(cols); err == nil {
				if r, err := strconv.Atoi(rows); err == nil {
					return c, r
				}
			}
		}
	}
	
	// Try syscall (Unix-like systems)
	type winsize struct {
		Row    uint16
		Col    uint16
		Xpixel uint16
		Ypixel uint16
	}
	
	ws := &winsize{}
	retCode, _, errno := syscall.Syscall(syscall.SYS_IOCTL,
		os.Stdout.Fd(), // Use stdout instead of stdin
		uintptr(syscall.TIOCGWINSZ),
		uintptr(unsafe.Pointer(ws)))
	
	if int(retCode) == -1 {
		_ = errno // Ignore error
		return 0, 0
	}
	
	return int(ws.Col), int(ws.Row)
}
