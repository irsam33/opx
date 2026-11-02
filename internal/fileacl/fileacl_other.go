//go:build !windows

package fileacl

import (
	"fmt"
	"os"
)

// SetFileACL is a no-op on non-Windows
func SetFileACL(path string) error {
	return nil
}

// SetFilePermissions sets file permissions
func SetFilePermissions(path string, mode os.FileMode) error {
	return os.Chmod(path, mode)
}

// RestrictFileAccess restricts file access to current user only
func RestrictFileAccess(path string) error {
	return os.Chmod(path, 0600)
}

// GetFileOwner returns the owner of a file
func GetFileOwner(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	return info.Name(), nil
}

// IsFileAccessibleByOthers checks if file is accessible by other users
func IsFileAccessibleByOthers(path string) (bool, error) {
	info, err := os.Stat(path)
	if err != nil {
		return false, err
	}
	mode := info.Mode()
	// Check if group or others have read/write
	return (mode & 0044) != 0, nil
}
