package storage

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/user/opx/internal/crypto"
	"github.com/user/opx/internal/fileacl"
	"github.com/user/opx/internal/vault"
)

// Storage manages local encrypted storage
type Storage struct {
	BasePath  string
	MasterKey []byte
}

// NewStorage creates a new storage instance
func NewStorage(basePath string, masterKey []byte) *Storage {
	return &Storage{
		BasePath:  basePath,
		MasterKey: masterKey,
	}
}

// DefaultPath returns the default storage path
func DefaultPath() string {
	if appData := os.Getenv("APPDATA"); appData != "" {
		return filepath.Join(appData, "opx")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".opx")
}

// SaveItem saves an item to storage (atomic write)
func (s *Storage) SaveItem(item *vault.Item) error {
	// Create directory if needed
	if err := os.MkdirAll(s.BasePath, 0700); err != nil {
		return err
	}

	// Encrypt item
	encData, err := crypto.EncryptJSON(item, s.MasterKey)
	if err != nil {
		return fmt.Errorf("encryption failed: %w", err)
	}

	// Save to file (atomic write)
	filename := filepath.Join(s.BasePath, item.ID+".enc")
	data, err := json.MarshalIndent(encData, "", "  ")
	if err != nil {
		return err
	}

	return atomicWriteFile(filename, data, 0600)
}

// LoadItem loads an item from storage
func (s *Storage) LoadItem(id string) (*vault.Item, error) {
	filename := filepath.Join(s.BasePath, id+".enc")
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("file not found: %w", err)
	}

	var encData crypto.EncryptedData
	if err := json.Unmarshal(data, &encData); err != nil {
		return nil, err
	}

	var item vault.Item
	if err := crypto.DecryptJSON(&encData, s.MasterKey, &item); err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return &item, nil
}

// ListItems returns all item IDs
func (s *Storage) ListItems() ([]string, error) {
	entries, err := os.ReadDir(s.BasePath)
	if err != nil {
		return nil, err
	}

	var ids []string
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".enc" {
			ids = append(ids, e.Name()[:len(e.Name())-4])
		}
	}
	return ids, nil
}

// DeleteItem deletes an item from storage (atomic)
func (s *Storage) DeleteItem(id string) error {
	filename := filepath.Join(s.BasePath, id+".enc")
	// Atomic delete (rename to .deleted, then remove)
	tmpPath := filename + ".deleted"
	if err := os.Rename(filename, tmpPath); err != nil {
		return err
	}
	return os.Remove(tmpPath)
}

// atomicWriteFile writes a file atomically using temp file + rename
func atomicWriteFile(filename string, data []byte, perm os.FileMode) error {
	// Write to temp file first
	tmpPath := filename + ".tmp"
	if err := os.WriteFile(tmpPath, data, perm); err != nil {
		return fmt.Errorf("failed to write temp file: %w", err)
	}

	// Apply file ACL
	fileacl.RestrictFileAccess(tmpPath)

	// Atomic rename
	if err := os.Rename(tmpPath, filename); err != nil {
		// Clean up temp file
		os.Remove(tmpPath)
		return fmt.Errorf("failed to rename file: %w", err)
	}

	return nil
}

// Backup creates a backup of the storage
func (s *Storage) Backup(backupPath string) error {
	if err := os.MkdirAll(backupPath, 0700); err != nil {
		return err
	}

	entries, err := os.ReadDir(s.BasePath)
	if err != nil {
		return err
	}

	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		src := filepath.Join(s.BasePath, e.Name())
		dst := filepath.Join(backupPath, e.Name())
		data, err := os.ReadFile(src)
		if err != nil {
			continue
		}
		os.WriteFile(dst, data, 0600)
	}

	return nil
}

// Restore restores storage from a backup
func (s *Storage) Restore(backupPath string) error {
	entries, err := os.ReadDir(backupPath)
	if err != nil {
		return err
	}

	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		src := filepath.Join(backupPath, e.Name())
		dst := filepath.Join(s.BasePath, e.Name())
		data, err := os.ReadFile(src)
		if err != nil {
			continue
		}
		os.WriteFile(dst, data, 0600)
	}

	return nil
}
