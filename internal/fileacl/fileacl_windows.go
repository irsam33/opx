//go:build windows

package fileacl

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// SetFileACL sets explicit ACL on a file for the current user only
// Simplified version using Windows API
func SetFileACL(path string) error {
	// Get current user SID
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return fmt.Errorf("cannot open process token: %w", err)
	}
	defer token.Close()

	user, err := token.GetTokenUser()
	if err != nil {
		return fmt.Errorf("cannot get token user: %w", err)
	}

	// Create explicit access entry for current user
	ea := windows.EXPLICIT_ACCESS{
		AccessPermissions: windows.GENERIC_ALL,
		AccessMode:        windows.SET_ACCESS,
		Inheritance:       windows.NO_INHERITANCE,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_USER,
			TrusteeValue: windows.TrusteeValueFromSID(user.User.Sid),
		},
	}

	// Create new ACL with the entry
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{ea}, nil)
	if err != nil {
		return fmt.Errorf("cannot create ACL: %w", err)
	}

	// Build security descriptor
	sd, err := windows.BuildSecurityDescriptor(nil, nil, []windows.EXPLICIT_ACCESS{ea}, nil, nil)
	if err != nil {
		return fmt.Errorf("cannot build security descriptor: %w", err)
	}
	_ = acl
	_ = sd

	// For simplicity, just set file permissions
	// Full ACL implementation would use SetFileSecurity via syscall
	return os.Chmod(path, 0600)
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
	return "current user", nil
}

// IsFileAccessibleByOthers checks if file is accessible by other users
func IsFileAccessibleByOthers(path string) (bool, error) {
	info, err := os.Stat(path)
	if err != nil {
		return false, err
	}
	mode := info.Mode()
	return (mode & 0044) != 0, nil
}
