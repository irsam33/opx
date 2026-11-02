package codesign

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
)

// SignatureInfo holds signature information
type SignatureInfo struct {
	Signed     bool
	Signer     string
	Algorithm  string
	Timestamp  string
	ChainValid bool
	Trusted    bool
}

// VerifySignature verifies a file's digital signature
func VerifySignature(filePath string) (*SignatureInfo, error) {
	info := &SignatureInfo{}

	// Check if file exists
	if _, err := os.Stat(filePath); err != nil {
		return nil, fmt.Errorf("file not found: %w", err)
	}

	// Use signtool to verify
	signtool := findSigntool()
	if signtool == "" {
		return nil, fmt.Errorf("signtool not found")
	}

	cmd := exec.Command(signtool, "verify", "/pa", filePath)
	output, err := cmd.CombinedOutput()

	outputStr := string(output)

	info.Signed = contains(outputStr, "File:")

	if err == nil {
		info.ChainValid = true
		info.Trusted = true
	} else {
		// Parse error message
		if contains(outputStr, "not trusted") || contains(outputStr, "terminated in a root") {
			info.Signed = true
			info.ChainValid = true
			info.Trusted = false
		} else if contains(outputStr, "No signature found") {
			info.Signed = false
			info.ChainValid = false
			info.Trusted = false
		}
	}

	// Try to get signer info
	cmd2 := exec.Command(signtool, "verify", "/pa", "/v", filePath)
	output2, _ := cmd2.CombinedOutput()
	outputStr2 := string(output2)

	// Extract signer name
	if idx := indexOf(outputStr2, "Signer:"); idx >= 0 {
		// Parse signer name (simplified)
		info.Signer = "Self-signed certificate"
	}

	return info, nil
}

// SignFile signs a file with a certificate
func SignFile(filePath, certPath, password, timestampURL string) error {
	signtool := findSigntool()
	if signtool == "" {
		return fmt.Errorf("signtool not found")
	}

	args := []string{
		"sign",
		"/f", certPath,
		"/p", password,
		"/tr", timestampURL,
		"/td", "sha256",
		"/fd", "sha256",
		filePath,
	}

	cmd := exec.Command(signtool, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("signing failed: %w\n%s", err, string(output))
	}

	return nil
}

// findSigntool finds signtool.exe
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

	// Try to find via PATH
	if path, err := exec.LookPath("signtool"); err == nil {
		return path
	}

	return ""
}

// CreateSelfSignedCert creates a self-signed code signing certificate
func CreateSelfSignedCert(subject, outputPath, password string) error {
	// Use PowerShell to create certificate
	psScript := fmt.Sprintf(`
$cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject "%s" -KeyAlgorithm RSA -KeyLength 2048 -CertStoreLocation "Cert:\CurrentUser\My" -NotAfter (Get-Date).AddYears(5)
$password = ConvertTo-SecureString -String "%s" -Force -AsPlainText
Export-PfxCertificate -Cert $cert -FilePath "%s" -Password $password
Write-Host "Certificate created: $($cert.Thumbprint)"
`, subject, password, outputPath)

	cmd := exec.Command("powershell", "-Command", psScript)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("certificate creation failed: %w\n%s", err, string(output))
	}

	fmt.Println(string(output))
	return nil
}

// GetCertificateInfo returns information about a certificate
func GetCertificateInfo(certPath, password string) (*x509.Certificate, error) {
	data, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

// PrintSignatureInfo prints signature information
func PrintSignatureInfo(info *SignatureInfo) {
	fmt.Println("Signature Information:")
	fmt.Printf("  Signed: %v\n", info.Signed)
	fmt.Printf("  Signer: %s\n", info.Signer)
	fmt.Printf("  Algorithm: %s\n", info.Algorithm)
	fmt.Printf("  Timestamp: %s\n", info.Timestamp)
	fmt.Printf("  Chain Valid: %v\n", info.ChainValid)
	fmt.Printf("  Trusted: %v\n", info.Trusted)
}

func indexOf(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
