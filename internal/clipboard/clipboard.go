package clipboard

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"time"
)

// CopyToClipboard copies text to clipboard
func CopyToClipboard(text string) error {
	switch runtime.GOOS {
	case "windows":
		cmd := exec.Command("clip")
		cmd.Stdin = os.Stdin
		// Use echo to pipe text to clip
		echoCmd := exec.Command("cmd", "/c", "echo "+text+" | clip")
		return echoCmd.Run()
	case "darwin":
		cmd := exec.Command("pbcopy")
		cmd.Stdin = os.Stdin
		return cmd.Run()
	case "linux":
		cmd := exec.Command("xclip", "-selection", "clipboard")
		cmd.Stdin = os.Stdin
		return cmd.Run()
	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}

// CopyWithTimeout copies text to clipboard and clears after timeout
func CopyWithTimeout(text string, timeout time.Duration) error {
	if err := CopyToClipboard(text); err != nil {
		return err
	}

	// Start goroutine to clear clipboard after timeout
	go func() {
		time.Sleep(timeout)
		ClearClipboard()
	}()

	return nil
}

// ClearClipboard clears the clipboard
func ClearClipboard() error {
	switch runtime.GOOS {
	case "windows":
		cmd := exec.Command("cmd", "/c", "echo off | clip")
		return cmd.Run()
	case "darwin":
		cmd := exec.Command("pbcopy")
		cmd.Stdin = nil
		return cmd.Run()
	case "linux":
		cmd := exec.Command("xclip", "-selection", "clipboard")
		cmd.Stdin = nil
		return cmd.Run()
	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}

// CopyPassword copies a password to clipboard with auto-clear
func CopyPassword(password string) error {
	return CopyWithTimeout(password, 30*time.Second)
}

// CopyTOTP copies a TOTP code to clipboard with auto-clear
func CopyTOTP(code string) error {
	return CopyWithTimeout(code, 10*time.Second)
}
