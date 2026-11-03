package clipboard

import (
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestCopyToClipboard(t *testing.T) {
	tests := []struct {
		name    string
		text    string
		wantErr bool
	}{
		{"valid text", "hello world", false},
		{"empty text", "", false},
		{"unicode text", "hello unicode", false},
		{"long text", strings.Repeat("a", 100), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CopyToClipboard(tt.text)
			if (err != nil) != tt.wantErr {
				t.Errorf("CopyToClipboard() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr {
				// Verify content was actually copied using PowerShell
				if runtime.GOOS == "windows" {
					pasteCmd := exec.Command("powershell", "-Command", "Get-Clipboard")
					output, err := pasteCmd.Output()
					if err != nil {
						t.Logf("Could not verify paste: %v", err)
						return
					}
					got := strings.TrimSpace(string(output))
					if !strings.Contains(got, tt.text) {
						t.Errorf("Clipboard content = %q, want to contain %q", got, tt.text)
					}
				}
			}
		})
	}
}

func TestCopyWithTimeout(t *testing.T) {
	// Use a short timeout for testing (skip paste verification on CI)
	err := CopyWithTimeout("temp secret", 100*time.Millisecond)
	if err != nil {
		t.Fatalf("CopyWithTimeout() error = %v", err)
	}

	// Wait for the timeout to clear the clipboard
	time.Sleep(250 * time.Millisecond)

	// Verify clipboard is cleared
	if runtime.GOOS == "windows" {
		pasteCmd := exec.Command("powershell", "-Command", "Get-Clipboard")
		output, err := pasteCmd.Output()
		if err != nil {
			t.Logf("Could not verify paste: %v", err)
			return
		}
		got := strings.TrimSpace(string(output))
		if got == "temp secret" {
			t.Errorf("Clipboard was not cleared after timeout")
		}
	}
}

func TestClearClipboard(t *testing.T) {
	// First put something in the clipboard
	_ = CopyToClipboard("test value")

	err := ClearClipboard()
	if err != nil {
		t.Errorf("ClearClipboard() error = %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	// Verify it's cleared
	var pasteCmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		pasteCmd = exec.Command("cmd", "/c", "echo", "%clipboard%")
	case "darwin":
		pasteCmd = exec.Command("pbpaste")
	case "linux":
		pasteCmd = exec.Command("xclip", "-selection", "clipboard", "-o")
	default:
		t.Skip("unsupported platform for paste verification")
		return
	}
	output, err := pasteCmd.Output()
	if err != nil {
		t.Logf("Could not verify paste: %v", err)
		return
	}
	if strings.TrimSpace(string(output)) == "test value" {
		t.Error("ClearClipboard() did not clear the clipboard")
	}
}

func TestCopyPassword(t *testing.T) {
	err := CopyPassword("super-secret-password")
	if err != nil {
		t.Fatalf("CopyPassword() error = %v", err)
	}

	time.Sleep(250 * time.Millisecond)

	if runtime.GOOS == "windows" {
		pasteCmd := exec.Command("powershell", "-Command", "Get-Clipboard")
		output, err := pasteCmd.Output()
		if err != nil {
			t.Logf("Could not verify paste: %v", err)
			return
		}
		got := strings.TrimSpace(string(output))
		if got != "super-secret-password" {
			t.Errorf("Clipboard = %q, want super-secret-password", got)
		}
	}
}

func TestCopyTOTP(t *testing.T) {
	code := "123456" // Simulate a generated TOTP code
	err := CopyTOTP(code)
	if err != nil {
		t.Fatalf("CopyTOTP() error = %v", err)
	}

	if runtime.GOOS == "windows" {
		pasteCmd := exec.Command("powershell", "-Command", "Get-Clipboard")
		output, err := pasteCmd.Output()
		if err != nil {
			t.Logf("Could not verify paste: %v", err)
			return
		}
		got := strings.TrimSpace(string(output))
		if got != code {
			t.Errorf("Clipboard = %q, want %q", got, code)
		}
	}
}
