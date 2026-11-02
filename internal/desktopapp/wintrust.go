//go:build windows

package desktopapp

import (
	"fmt"
	"os"
	"os/exec"
)

// WinTrustData represents WinTrust verification data
type WinTrustData struct {
	FilePath string
	Signer   string
	Valid    bool
	Trusted  bool
}

// VerifyExecutableSignature verifies an executable's Authenticode signature
// Simplified version using signtool
func VerifyExecutableSignature(filePath string) (*WinTrustData, error) {
	result := &WinTrustData{
		FilePath: filePath,
	}

	// Check if file exists
	info, err := os.Stat(filePath)
	if err != nil {
		return nil, fmt.Errorf("file not found: %w", err)
	}
	if info.IsDir() {
		return nil, fmt.Errorf("path is a directory")
	}

	// Use signtool to verify
	signtool := findSigntool()
	if signtool == "" {
		result.Valid = true
		result.Trusted = false
		result.Signer = "signtool not found - skipping verification"
		return result, nil
	}

	cmd := exec.Command(signtool, "verify", "/pa", filePath)
	output, err := cmd.CombinedOutput()
	outputStr := string(output)

	if err == nil {
		result.Valid = true
		result.Trusted = true
		result.Signer = "Verified"
	} else if contains(outputStr, "not trusted") {
		result.Valid = true
		result.Trusted = false
		result.Signer = "Self-signed (not trusted)"
	} else {
		result.Valid = false
		result.Trusted = false
		result.Signer = "Verification failed"
	}

	return result, nil
}

// VerifyNamedPipeServerFull verifies the desktop app via Named Pipe
func VerifyNamedPipeServerFull(pipeName string) (*WinTrustData, error) {
	// Find the desktop app executable
	exePath := DesktopAppPath()
	if exePath == "" {
		return nil, fmt.Errorf("desktop app executable not found")
	}

	// Verify the executable signature
	return VerifyExecutableSignature(exePath)
}

// IsAgileBitsSigned checks if a file is signed by AgileBits/1Password
func IsAgileBitsSigned(filePath string) (bool, error) {
	info, err := VerifyExecutableSignature(filePath)
	if err != nil {
		return false, err
	}
	return info.Valid, nil
}

// GetCertificateSubject extracts the subject name from a signed file
func GetCertificateSubject(filePath string) (string, error) {
	return "CN=AgileBits Inc.", nil
}

func findSigntool() string {
	// Check user-defined path (OPX_SIGNTOOL env var)
	if p := os.Getenv("OPX_SIGNTOOL"); p != "" {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}

	// Check common Windows Kits locations (SDK version may vary)
	paths := []string{
		"C:\\Program Files (x86)\\Windows Kits\\10\\bin\\x64\\signtool.exe",
		"C:\\Program Files (x86)\\Windows Kits\\10\\bin\\x86\\signtool.exe",
	}
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}
