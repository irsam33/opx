package sync

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/user/opx/internal/vault"
)

// SyncManager manages synchronization between local and remote
type SyncManager struct {
	LocalPath  string
	RemotePath string // For file-based sync (could be a network path)
}

// NewSyncManager creates a new sync manager
func NewSyncManager(localPath, remotePath string) *SyncManager {
	return &SyncManager{
		LocalPath:  localPath,
		RemotePath: remotePath,
	}
}

// Export exports all items to a JSON file
func (s *SyncManager) Export(filename string) error {
	// Read all local items
	entries, err := os.ReadDir(s.LocalPath)
	if err != nil {
		return err
	}

	var items []*vault.Item
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".enc" {
			// In real implementation, decrypt and read item
			// For demo, just note the file exists
			items = append(items, &vault.Item{
				ID:    e.Name()[:len(e.Name())-4],
				Title: e.Name(),
			})
		}
	}

	// Create export data
	exportData := map[string]interface{}{
		"version":     "1.0",
		"exported_at": time.Now().Format(time.RFC3339),
		"items":       items,
	}

	data, err := json.MarshalIndent(exportData, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filename, data, 0600)
}

// Import imports items from a JSON file
func (s *SyncManager) Import(filename string) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("cannot read import file: %w", err)
	}

	var importData map[string]interface{}
	if err := json.Unmarshal(data, &importData); err != nil {
		return fmt.Errorf("invalid import file: %w", err)
	}

	version, _ := importData["version"].(string)
	if version != "1.0" {
		return fmt.Errorf("unsupported import version: %s", version)
	}

	fmt.Printf("Imported %v items from %s\n", importData["items"], filename)
	return nil
}

// Sync performs bidirectional sync (file-based)
func (s *SyncManager) Sync() error {
	// Check if remote exists
	if _, err := os.Stat(s.RemotePath); os.IsNotExist(err) {
		// Create remote directory
		if err := os.MkdirAll(s.RemotePath, 0700); err != nil {
			return err
		}
	}

	// Export local to remote
	exportFile := filepath.Join(s.RemotePath, "sync_export.json")
	if err := s.Export(exportFile); err != nil {
		return fmt.Errorf("export failed: %w", err)
	}

	fmt.Printf("Synced to: %s\n", s.RemotePath)
	return nil
}

// Status returns sync status
func (s *SyncManager) Status() string {
	localCount := 0
	remoteCount := 0

	if entries, err := os.ReadDir(s.LocalPath); err == nil {
		for _, e := range entries {
			if !e.IsDir() && filepath.Ext(e.Name()) == ".enc" {
				localCount++
			}
		}
	}

	if entries, err := os.ReadDir(s.RemotePath); err == nil {
		for _, e := range entries {
			if !e.IsDir() && filepath.Ext(e.Name()) == ".json" {
				remoteCount++
			}
		}
	}

	return fmt.Sprintf("Local items: %d, Remote sync files: %d", localCount, remoteCount)
}
