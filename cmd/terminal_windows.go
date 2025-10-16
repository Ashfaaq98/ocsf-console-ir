//go:build windows
// +build windows

package cmd

import (
	"os"
	"strconv"
	"syscall"
	"unsafe"
)

var (
	kernel32                = syscall.NewLazyDLL("kernel32.dll")
	procGetConsoleScreenBufferInfo = kernel32.NewProc("GetConsoleScreenBufferInfo")
)

type (
	coord struct {
		X int16
		Y int16
	}
	smallRect struct {
		Left   int16
		Top    int16
		Right  int16
		Bottom int16
	}
	consoleScreenBufferInfo struct {
		Size              coord
		CursorPosition    coord
		Attributes        int16
		Window            smallRect
		MaximumWindowSize coord
	}
)

// getTerminalSize returns terminal dimensions for Windows
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
	
	// Try Windows API
	var csbi consoleScreenBufferInfo
	ret, _, _ := procGetConsoleScreenBufferInfo.Call(
		uintptr(syscall.Stdout),
		uintptr(unsafe.Pointer(&csbi)))
	
	if ret != 0 {
		width := int(csbi.Window.Right - csbi.Window.Left + 1)
		height := int(csbi.Window.Bottom - csbi.Window.Top + 1)
		if width > 0 && height > 0 {
			return width, height
		}
	}
	
	// Fallback: let tview handle terminal size detection
	return 0, 0
}
