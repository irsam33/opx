package update

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

// VersionInfo holds version information
type VersionInfo struct {
	Version      string    `json:"version"`
	DownloadURL  string    `json:"download_url"`
	ReleaseNotes string    `json:"release_notes"`
	PublishedAt  time.Time `json:"published_at"`
	Checksum     string    `json:"checksum"`
}

// UpdateChecker checks for updates
type UpdateChecker struct {
	CurrentVersion string
	UpdateURL      string
	AutoCheck      bool
	LastCheck      time.Time
	CheckInterval  time.Duration
}

// NewUpdateChecker creates a new update checker
func NewUpdateChecker(currentVersion string) *UpdateChecker {
	return &UpdateChecker{
		CurrentVersion: currentVersion,
		UpdateURL:      "https://api.github.com/repos/user/opx/releases/latest",
		AutoCheck:      true,
		CheckInterval:  24 * time.Hour,
	}
}

// CheckUpdate checks if an update is available
func (uc *UpdateChecker) CheckUpdate() (*VersionInfo, bool, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(uc.UpdateURL)
	if err != nil {
		return nil, false, fmt.Errorf("cannot check for updates: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, false, fmt.Errorf("update check failed: %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, false, err
	}

	var info VersionInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return nil, false, fmt.Errorf("invalid response: %w", err)
	}

	hasUpdate := info.Version != uc.CurrentVersion && info.Version != ""
	uc.LastCheck = time.Now()

	return &info, hasUpdate, nil
}

// ShouldCheck returns true if it's time to check for updates
func (uc *UpdateChecker) ShouldCheck() bool {
	if !uc.AutoCheck {
		return false
	}
	if uc.LastCheck.IsZero() {
		return true
	}
	return time.Since(uc.LastCheck) > uc.CheckInterval
}

// AutoCheckUpdate performs automatic update check
func (uc *UpdateChecker) AutoCheckUpdate() (*VersionInfo, bool, error) {
	if !uc.ShouldCheck() {
		return nil, false, nil
	}
	return uc.CheckUpdate()
}

// DownloadUpdate downloads the update
func (uc *UpdateChecker) DownloadUpdate(url, destPath string) error {
	fmt.Printf("Downloading update from %s...\n", url)

	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("download failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed: %s", resp.Status)
	}

	out, err := os.Create(destPath)
	if err != nil {
		return err
	}
	defer out.Close()

	written, err := io.Copy(out, resp.Body)
	if err != nil {
		return err
	}

	fmt.Printf("Downloaded %d bytes to %s\n", written, destPath)
	return nil
}

// ApplyUpdate applies the downloaded update
func (uc *UpdateChecker) ApplyUpdate(updatePath string) error {
	currentExe, err := os.Executable()
	if err != nil {
		return err
	}

	backupPath := currentExe + ".bak"
	if err := os.Rename(currentExe, backupPath); err != nil {
		return fmt.Errorf("cannot backup current binary: %w", err)
	}

	if err := os.Rename(updatePath, currentExe); err != nil {
		os.Rename(backupPath, currentExe)
		return fmt.Errorf("cannot apply update: %w", err)
	}

	os.Remove(backupPath)

	fmt.Println("Update applied successfully!")
	fmt.Println("Please restart the application.")
	return nil
}

// AutoUpdate performs automatic update (check + download + apply)
func (uc *UpdateChecker) AutoUpdate() error {
	info, hasUpdate, err := uc.AutoCheckUpdate()
	if err != nil {
		return err
	}

	if !hasUpdate {
		return nil
	}

	fmt.Printf("Update available: %s (current: %s)\n", info.Version, uc.CurrentVersion)
	fmt.Printf("Release notes: %s\n", info.ReleaseNotes)

	tmpDir := os.TempDir()
	updatePath := filepath.Join(tmpDir, "opx-update.exe")

	if err := uc.DownloadUpdate(info.DownloadURL, updatePath); err != nil {
		return err
	}

	if info.Checksum != "" {
		if err := verifyChecksum(updatePath, info.Checksum); err != nil {
			os.Remove(updatePath)
			return fmt.Errorf("checksum verification failed: %w", err)
		}
	}

	if err := uc.ApplyUpdate(updatePath); err != nil {
		return err
	}

	return nil
}

// verifyChecksum verifies a file's SHA256 checksum
func verifyChecksum(filePath, expectedChecksum string) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}

	hash := sha256.Sum256(data)
	actualChecksum := fmt.Sprintf("%x", hash)

	if actualChecksum != expectedChecksum {
		return fmt.Errorf("checksum mismatch: expected %s, got %s", expectedChecksum, actualChecksum)
	}

	return nil
}

// GetPlatformInfo returns platform-specific info
func GetPlatformInfo() string {
	return fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH)
}

// GetUpdateURL returns the update URL for the current platform
func GetUpdateURL(version string) string {
	return fmt.Sprintf("https://c.1password.com/dist/1P/opx/pkg/v%s/opx_%s_%s", version, runtime.GOOS, runtime.GOARCH)
}

// CheckForUpdates is a convenience function
func CheckForUpdates(currentVersion string) {
	uc := NewUpdateChecker(currentVersion)
	info, hasUpdate, err := uc.CheckUpdate()
	if err != nil {
		fmt.Printf("Update check failed: %v\n", err)
		return
	}

	if hasUpdate {
		fmt.Printf("Update available: %s (current: %s)\n", info.Version, currentVersion)
		fmt.Printf("Release notes: %s\n", info.ReleaseNotes)
		fmt.Printf("Download: %s\n", info.DownloadURL)
	} else {
		fmt.Printf("You are up to date (version %s)\n", currentVersion)
	}
}
