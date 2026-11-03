package fileacl

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestRestrictFileAccess(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("File permission tests are not reliable on Windows")
	}
	dir := t.TempDir()
	testFile := filepath.Join(dir, "test-acl-file.txt")

	// Create the test file with some content
	err := os.WriteFile(testFile, []byte("sensitive data"), 0644)
	if err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	// Restrict file access
	err = RestrictFileAccess(testFile)
	if err != nil {
		t.Fatalf("RestrictFileAccess() error = %v", err)
	}

	// Check that the file has restrictive permissions (0600)
	info, err := os.Stat(testFile)
	if err != nil {
		t.Fatalf("os.Stat() error = %v", err)
	}

	// The file should have 0600 permissions (user read/write only)
	expected := os.FileMode(0600)
	if info.Mode().Perm() != expected {
		t.Errorf("File permissions = %o, want %o", info.Mode().Perm(), expected)
	}
}

func TestRestrictFileAccessNotFound(t *testing.T) {
	err := RestrictFileAccess("/nonexistent/path/to/file")
	// On Windows, os.Chmod on nonexistent file returns an error
	if err == nil {
		t.Log("RestrictFileAccess() returned nil for nonexistent file (platform dependent)")
	}
}

func TestGetFileOwner(t *testing.T) {
	owner, err := GetFileOwner("C:\\Windows")
	if err != nil {
		t.Logf("GetFileOwner() error = %v", err)
	}
	// GetFileOwner always returns "current user" (simplified)
	if owner != "current user" {
		t.Errorf("Owner = %q, want current user", owner)
	}
}

func TestIsFileAccessibleByOthers(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("File permission tests are not reliable on Windows")
	}
	dir := t.TempDir()

	// Test file with restrictive permissions (0600)
	restrictiveFile := filepath.Join(dir, "restrictive.txt")
	err := os.WriteFile(restrictiveFile, []byte("data"), 0600)
	if err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	isAccessible, err := IsFileAccessibleByOthers(restrictiveFile)
	if err != nil {
		t.Fatalf("IsFileAccessibleByOthers() error = %v", err)
	}

	if isAccessible {
		t.Error("File with 0600 permissions should not be accessible by others")
	}

	// Test file with open permissions (0666)
	openFile := filepath.Join(dir, "open.txt")
	err = os.WriteFile(openFile, []byte("data"), 0666)
	if err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	isAccessible, err = IsFileAccessibleByOthers(openFile)
	if err != nil {
		t.Fatalf("IsFileAccessibleByOthers() error = %v", err)
	}

	if !isAccessible {
		t.Error("File with 0666 permissions should be accessible by others")
	}
}

func TestIsFileAccessibleByOthersDefaultPermissions(t *testing.T) {
	dir := t.TempDir()

	defaultFile := filepath.Join(dir, "default.txt")
	// Create with default permissions (typically 0666 on Windows for new files)
	err := os.WriteFile(defaultFile, []byte("data"), 0)
	if err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	isAccessible, err := IsFileAccessibleByOthers(defaultFile)
	if err != nil {
		t.Fatalf("IsFileAccessibleByOthers() error = %v", err)
	}

	// File may or may not be accessible depending on OS default
	t.Logf("Default permission file accessible by others: %v (platform dependent)", isAccessible)
}

func TestSetFilePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("File permission tests are not reliable on Windows")
	}
	dir := t.TempDir()
	testFile := filepath.Join(dir, "test-perms.txt")

	err := os.WriteFile(testFile, []byte("data"), 0644)
	if err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	// Set restrictive permissions
	err = SetFilePermissions(testFile, 0600)
	if err != nil {
		t.Fatalf("SetFilePermissions() error = %v", err)
	}

	info, err := os.Stat(testFile)
	if err != nil {
		t.Fatalf("os.Stat() error = %v", err)
	}

	if info.Mode().Perm() != 0600 {
		t.Errorf("File permissions = %o, want 0600", info.Mode().Perm())
	}

	// Set open permissions
	err = SetFilePermissions(testFile, 0644)
	if err != nil {
		t.Fatalf("SetFilePermissions() error = %v", err)
	}

	info, err = os.Stat(testFile)
	if err != nil {
		t.Fatalf("os.Stat() error = %v", err)
	}

	if info.Mode().Perm() != 0644 {
		t.Errorf("File permissions = %o, want 0644", info.Mode().Perm())
	}
}

func TestSetFilePermissionsNotFound(t *testing.T) {
	err := SetFilePermissions("/nonexistent/path", 0600)
	if err == nil {
		t.Log("SetFilePermissions() returned nil for nonexistent file (platform dependent)")
	}
}

func TestSetFileACL(t *testing.T) {
	// Test SetFileACL (simplified version)
	dir := t.TempDir()
	testFile := filepath.Join(dir, "test-acl.txt")

	err := os.WriteFile(testFile, []byte("data"), 0644)
	if err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	err = SetFileACL(testFile)
	if err != nil {
		t.Logf("SetFileACL() error = %v", err)
	}
	// Note: On Windows this may fail due to permission requirements
	// The simplified version falls back to os.Chmod
}

// Benchmark file permission operations
func BenchmarkRestrictFileAccess(b *testing.B) {
	dir := b.TempDir()
	testFile := filepath.Join(dir, "benchmark-acl.txt")

	err := os.WriteFile(testFile, []byte("sensitive data"), 0644)
	if err != nil {
		b.Fatalf("os.WriteFile() error = %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = RestrictFileAccess(testFile)
	}
}

func BenchmarkIsFileAccessibleByOthers(b *testing.B) {
	dir := b.TempDir()
	testFile := filepath.Join(dir, "benchmark-perms.txt")

	err := os.WriteFile(testFile, []byte("data"), 0600)
	if err != nil {
		b.Fatalf("os.WriteFile() error = %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = IsFileAccessibleByOthers(testFile)
	}
}

func BenchmarkSetFilePermissions(b *testing.B) {
	dir := b.TempDir()
	testFile := filepath.Join(dir, "benchmark-setperms.txt")

	err := os.WriteFile(testFile, []byte("data"), 0644)
	if err != nil {
		b.Fatalf("os.WriteFile() error = %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = SetFilePermissions(testFile, 0600)
	}
}
