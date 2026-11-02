//go:build windows

package desktopapp

import (
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/windows"
)

// WindowsNamedPipe implements full Windows Named Pipe IPC
type WindowsNamedPipe struct {
	Handle windows.Handle
	Name   string
}

// CreateNamedPipeServer creates a Named Pipe server
func CreateNamedPipeServer(pipeName string) (*WindowsNamedPipe, error) {
	// Convert pipe name to UTF-16
	namePtr, err := windows.UTF16PtrFromString(pipeName)
	if err != nil {
		return nil, err
	}

	// Create named pipe
	handle, err := windows.CreateNamedPipe(
		namePtr,
		windows.PIPE_ACCESS_DUPLEX,
		windows.PIPE_TYPE_MESSAGE|windows.PIPE_READMODE_MESSAGE|windows.PIPE_WAIT,
		1,     // max instances
		65536, // out buffer size
		65536, // in buffer size
		0,     // default timeout
		nil,   // security attributes
	)
	if err != nil {
		return nil, fmt.Errorf("create named pipe failed: %w", err)
	}

	return &WindowsNamedPipe{
		Handle: handle,
		Name:   pipeName,
	}, nil
}

// ConnectNamedPipe connects to a named pipe (client side)
func ConnectNamedPipe(pipeName string, timeout time.Duration) (*WindowsNamedPipe, error) {
	// Wait for pipe to be available
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		// Try to open the pipe
		namePtr, err := windows.UTF16PtrFromString(pipeName)
		if err != nil {
			return nil, err
		}

		handle, err := windows.CreateFile(
			namePtr,
			windows.GENERIC_READ|windows.GENERIC_WRITE,
			0,
			nil,
			windows.OPEN_EXISTING,
			windows.FILE_ATTRIBUTE_NORMAL,
			0,
		)
		if err == nil {
			return &WindowsNamedPipe{
				Handle: handle,
				Name:   pipeName,
			}, nil
		}

		time.Sleep(100 * time.Millisecond)
	}

	return nil, fmt.Errorf("timeout connecting to named pipe: %s", pipeName)
}

// Read reads from the named pipe
func (np *WindowsNamedPipe) Read(buf []byte) (int, error) {
	var bytesRead uint32
	err := windows.ReadFile(np.Handle, buf, &bytesRead, nil)
	if err != nil {
		return 0, err
	}
	return int(bytesRead), nil
}

// Write writes to the named pipe
func (np *WindowsNamedPipe) Write(buf []byte) (int, error) {
	var bytesWritten uint32
	err := windows.WriteFile(np.Handle, buf, &bytesWritten, nil)
	if err != nil {
		return 0, err
	}
	return int(bytesWritten), nil
}

// Close closes the named pipe
func (np *WindowsNamedPipe) Close() error {
	return windows.CloseHandle(np.Handle)
}

// SetReadDeadline sets a read deadline (simplified - uses a timer)
func (np *WindowsNamedPipe) SetReadDeadline(t time.Time) error {
	// Windows named pipes don't support deadlines directly
	// This is a no-op for now
	return nil
}

// FlushPipe flushes the named pipe
func (np *WindowsNamedPipe) FlushPipe() error {
	return windows.FlushFileBuffers(np.Handle)
}

// DisconnectNamedPipe disconnects a client from the pipe
func (np *WindowsNamedPipe) DisconnectNamedPipe() error {
	return windows.DisconnectNamedPipe(np.Handle)
}

// WaitNamedPipe waits for a named pipe to become available
func WaitNamedPipe(pipeName string, timeout time.Duration) error {
	// Simplified: just try to connect
	_, err := ConnectNamedPipe(pipeName, timeout)
	return err
}

// GetPipeInfo returns information about a named pipe
func GetPipeInfo(pipeName string) (map[string]interface{}, error) {
	info := make(map[string]interface{})

	// Try to connect
	np, err := ConnectNamedPipe(pipeName, 1*time.Second)
	if err != nil {
		info["available"] = false
		info["error"] = err.Error()
		return info, nil
	}
	defer np.Close()

	info["available"] = true
	info["name"] = pipeName

	return info, nil
}

// ListNamedPipes lists all named pipes on the system
func ListNamedPipes() ([]string, error) {
	// Open the pipe directory
	dir, err := os.Open(`\\.\pipe\`)
	if err != nil {
		return nil, err
	}
	defer dir.Close()

	entries, err := dir.Readdirnames(-1)
	if err != nil {
		return nil, err
	}

	var pipes []string
	for _, entry := range entries {
		if len(entry) > 0 {
			pipes = append(pipes, entry)
		}
	}

	return pipes, nil
}

// FindOpPipes finds 1Password-related named pipes
func FindOpPipes() ([]string, error) {
	pipes, err := ListNamedPipes()
	if err != nil {
		return nil, err
	}

	var opPipes []string
	for _, pipe := range pipes {
		if len(pipe) > 0 && (contains(pipe, "1Password") || contains(pipe, "op-")) {
			opPipes = append(opPipes, pipe)
		}
	}

	return opPipes, nil
}

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// IsDesktopAppRunning checks if the desktop app is running
func IsDesktopAppRunning() bool {
	// Check for named pipes
	pipes, err := FindOpPipes()
	if err != nil {
		return false
	}
	return len(pipes) > 0
}
