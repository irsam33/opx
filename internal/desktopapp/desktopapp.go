package desktopapp

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Connection represents a connection to the desktop app
type Connection struct {
	Pipe     *WindowsNamedPipe
	PipeName string
}

// DesktopAppSettings represents desktop app settings
type DesktopAppSettings struct {
	SystemAuthEnabled   bool   `json:"systemAuthEnabled"`
	DismissedSystemAuth bool   `json:"dismissedSystemAuthPrompt"`
	LastSignedInUser    string `json:"systemAuthLatestSignInUser"`
	DeviceUUID          string `json:"deviceUUID"`
}

// Message represents an IPC message
type Message struct {
	Type    string                 `json:"type"`
	Payload map[string]interface{} `json:"payload"`
}

// Response represents an IPC response
type Response struct {
	Type    string                 `json:"type"`
	Success bool                   `json:"success"`
	Payload map[string]interface{} `json:"payload"`
	Error   string                 `json:"error,omitempty"`
}

// PipeName generates the Named Pipe name
func PipeName() string {
	pid := os.Getpid()
	return fmt.Sprintf(`\\.\pipe\opx-%d`, pid)
}

// Connect connects to the desktop app via Named Pipe
func Connect(timeout time.Duration) (*Connection, error) {
	// Check if desktop app is installed
	if !IsDesktopAppInstalled() {
		return nil, fmt.Errorf("desktop app not installed")
	}

	// Find 1Password pipes
	pipes, err := FindOpPipes()
	pipeName := `\\.\pipe\opx-desktop`
	if err == nil && len(pipes) > 0 {
		pipeName = `\\.\pipe\` + pipes[0]
	}

	// Connect to the named pipe
	np, err := ConnectNamedPipe(pipeName, timeout)
	if err != nil {
		return nil, fmt.Errorf("connecting to desktop app: %w", err)
	}

	// Verify the peer executable
	exePath := DesktopAppPath()
	if exePath != "" {
		info, err := VerifyExecutableSignature(exePath)
		if err != nil {
			np.Close()
			return nil, fmt.Errorf("cannot verify desktop app: %w", err)
		}
		if !info.Valid {
			np.Close()
			return nil, fmt.Errorf("desktop app signature invalid: %s", info.Signer)
		}
	}

	return &Connection{
		Pipe:     np,
		PipeName: pipeName,
	}, nil
}

// Send sends a message to the desktop app
func (c *Connection) Send(msg *Message) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	length := uint32(len(data))
	lengthBytes := []byte{byte(length), byte(length >> 8), byte(length >> 16), byte(length >> 24)}
	if _, err := c.Pipe.Write(lengthBytes); err != nil {
		return err
	}
	if _, err := c.Pipe.Write(data); err != nil {
		return err
	}

	return nil
}

// Receive receives a message from the desktop app
func (c *Connection) Receive() (*Response, error) {
	lengthBytes := make([]byte, 4)
	if _, err := c.Pipe.Read(lengthBytes); err != nil {
		return nil, err
	}

	length := uint32(lengthBytes[0]) | uint32(lengthBytes[1])<<8 |
		uint32(lengthBytes[2])<<16 | uint32(lengthBytes[3])<<24

	data := make([]byte, length)
	if _, err := c.Pipe.Read(data); err != nil {
		return nil, err
	}

	var resp Response
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, err
	}

	return &resp, nil
}

// Close closes the connection
func (c *Connection) Close() error {
	return c.Pipe.Close()
}

// WaitForAuthorization waits for user authorization
func (c *Connection) WaitForAuthorization(timeout time.Duration) (*Response, error) {
	msg := &Message{
		Type: "request_authorization",
		Payload: map[string]interface{}{
			"client": "opx",
		},
	}
	if err := c.Send(msg); err != nil {
		return nil, err
	}

	c.Pipe.SetReadDeadline(time.Now().Add(timeout))
	resp, err := c.Receive()
	if err != nil {
		return nil, err
	}

	return resp, nil
}

// RequestAccounts requests list of accounts from desktop app
func (c *Connection) RequestAccounts() (*Response, error) {
	msg := &Message{
		Type:    "request_accounts",
		Payload: map[string]interface{}{},
	}
	if err := c.Send(msg); err != nil {
		return nil, err
	}
	return c.Receive()
}

// RequestDelegatedSession requests a delegated session
func (c *Connection) RequestDelegatedSession() (*Response, error) {
	msg := &Message{
		Type: "request_delegated_session",
		Payload: map[string]interface{}{
			"cli":           "opx",
			"tty":           true,
			"parentProcess": os.Getpid(),
		},
	}
	if err := c.Send(msg); err != nil {
		return nil, err
	}
	return c.Receive()
}

// RequestBiometricAuth requests biometric authentication from desktop app
func (c *Connection) RequestBiometricAuth(reason string) (*Response, error) {
	msg := &Message{
		Type: "request_biometric_auth",
		Payload: map[string]interface{}{
			"reason": reason,
			"client": "opx",
		},
	}
	if err := c.Send(msg); err != nil {
		return nil, err
	}
	return c.Receive()
}

// DesktopAppUserDataDir returns the desktop app user data directory
func DesktopAppUserDataDir() string {
	if val := os.Getenv("LOCALAPPDATA"); val != "" {
		return filepath.Join(val, "1Password")
	}
	if val := os.Getenv("APPDATA"); val != "" {
		return filepath.Join(val, "1Password")
	}
	return ""
}

// DesktopAppSettingsPath returns the path to desktop app settings
func DesktopAppSettingsPath() string {
	userDataDir := DesktopAppUserDataDir()
	if userDataDir == "" {
		return ""
	}
	return filepath.Join(userDataDir, "settings", "settings.json")
}

// LoadDesktopAppSettings loads desktop app settings
func LoadDesktopAppSettings() (*DesktopAppSettings, error) {
	path := DesktopAppSettingsPath()
	if path == "" {
		return nil, fmt.Errorf("cannot determine settings path")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read settings: %w", err)
	}

	var settings DesktopAppSettings
	if err := json.Unmarshal(data, &settings); err != nil {
		return nil, fmt.Errorf("cannot parse settings: %w", err)
	}

	return &settings, nil
}

// IsDesktopAppInstalled checks if the desktop app is installed
func IsDesktopAppInstalled() bool {
	settingsPath := DesktopAppSettingsPath()
	if settingsPath == "" {
		return false
	}
	_, err := os.Stat(settingsPath)
	return err == nil
}

// GetDesktopAppVersion returns the desktop app executable path
func GetDesktopAppVersion() (string, error) {
	paths := []string{
		filepath.Join(os.Getenv("LOCALAPPDATA"), "1Password", "app", "1Password.exe"),
		filepath.Join(os.Getenv("PROGRAMFILES"), "1Password", "app", "1Password.exe"),
		filepath.Join(os.Getenv("PROGRAMFILES(X86)"), "1Password", "app", "1Password.exe"),
	}

	for _, p := range paths {
		if info, err := os.Stat(p); err == nil && !info.IsDir() {
			return p, nil
		}
	}

	return "", fmt.Errorf("desktop app not found")
}

// VerifyPeerExecutable verifies the desktop app executable signature
func VerifyPeerExecutable(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("executable not found: %w", err)
	}
	if info.IsDir() {
		return fmt.Errorf("path is a directory")
	}

	result, err := VerifyExecutableSignature(path)
	if err != nil {
		return err
	}
	if !result.Valid {
		return fmt.Errorf("signature verification failed: %s", result.Signer)
	}

	return nil
}

// DesktopAppPath returns the path to the 1Password desktop app
func DesktopAppPath() string {
	paths := []string{
		filepath.Join(os.Getenv("LOCALAPPDATA"), "1Password", "app", "1Password.exe"),
		filepath.Join(os.Getenv("PROGRAMFILES"), "1Password", "app", "1Password.exe"),
		filepath.Join(os.Getenv("PROGRAMFILES(X86)"), "1Password", "app", "1Password.exe"),
	}

	for _, p := range paths {
		if info, err := os.Stat(p); err == nil && !info.IsDir() {
			return p
		}
	}

	return ""
}

// IsBiometricAvailable checks if biometric auth is available
func IsBiometricAvailable() bool {
	settings, err := LoadDesktopAppSettings()
	if err != nil {
		return false
	}
	return settings.SystemAuthEnabled
}

// GetBiometricType returns the type of biometric auth available
func GetBiometricType() string {
	return "Windows Hello"
}

// GetSystemInfo returns system information for IPC
func GetSystemInfo() map[string]interface{} {
	hostname, _ := os.Hostname()
	return map[string]interface{}{
		"hostname": hostname,
		"pid":      os.Getpid(),
		"os":       "windows",
		"arch":     "amd64",
	}
}

// CreateNamedPipe creates a named pipe for IPC (server side)
func CreateNamedPipe(name string) (interface{}, error) {
	np, err := CreateNamedPipeServer(name)
	if err != nil {
		return nil, err
	}
	return np, nil
}
