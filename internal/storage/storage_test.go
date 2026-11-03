package storage

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/user/opx/internal/vault"
)

func TestNewStorage(t *testing.T) {
	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(i)
	}

	s := NewStorage("/tmp/test-storage", masterKey)

	if s.BasePath != "/tmp/test-storage" {
		t.Errorf("BasePath = %q, want /tmp/test-storage", s.BasePath)
	}

	if len(s.MasterKey) != 32 {
		t.Errorf("MasterKey length = %d, want 32", len(s.MasterKey))
	}
}

func TestDefaultPath(t *testing.T) {
	path := DefaultPath()

	if path == "" {
		t.Error("DefaultPath() returned empty path")
	}

	// Should contain opx
	if !contains(path, "opx") {
		t.Errorf("DefaultPath() = %q, should contain opx", path)
	}

	// Should be an absolute path
	if !filepath.IsAbs(path) {
		t.Errorf("DefaultPath() = %q, should be absolute", path)
	}
}

func TestDefaultPathWithAppData(t *testing.T) {
	original := os.Getenv("APPDATA")
	os.Setenv("APPDATA", "/tmp/test-appdata")
	defer func() {
		if original != "" {
			os.Setenv("APPDATA", original)
		} else {
			os.Unsetenv("APPDATA")
		}
	}()

	path := DefaultPath()
	expected := filepath.Join("/tmp/test-appdata", "opx")

	if path != expected {
		t.Errorf("DefaultPath() = %q, want %q", path, expected)
	}
}

func TestStorageSaveAndLoadItem(t *testing.T) {
	dir := t.TempDir()

	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(i)
	}

	s := NewStorage(dir, masterKey)

	item := &vault.Item{
		ID:      "test-item-123",
		Title:   "Test Login",
		Category: "login",
		Vault:   "Personal",
		Fields: []vault.Field{
			{
				ID:     "field-1",
				Label:  "username",
				Type:   "text",
				Value:  "testuser@example.com",
			},
			{
				ID:     "field-2",
				Label:  "password",
				Type:   "password",
				Value:  "super-secret-password-123",
			},
		},
	}

	err := s.SaveItem(item)
	if err != nil {
		t.Fatalf("SaveItem() error = %v", err)
	}

	// Check file was created
	filename := filepath.Join(dir, "test-item-123.enc")
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		t.Error("SaveItem() did not create the .enc file")
	}

	// Load the item back
	loaded, err := s.LoadItem("test-item-123")
	if err != nil {
		t.Fatalf("LoadItem() error = %v", err)
	}

	if loaded.ID != item.ID {
		t.Errorf("Loaded ID = %q, want %q", loaded.ID, item.ID)
	}

	if loaded.Title != item.Title {
		t.Errorf("Loaded Title = %q, want %q", loaded.Title, item.Title)
	}

	if loaded.Category != item.Category {
		t.Errorf("Loaded Category = %q, want %q", loaded.Category, item.Category)
	}

	if loaded.Vault != item.Vault {
		t.Errorf("Loaded Vault = %q, want %q", loaded.Vault, item.Vault)
	}

	if len(loaded.Fields) != len(item.Fields) {
		t.Fatalf("Loaded Fields count = %d, want %d", len(loaded.Fields), len(item.Fields))
	}

	// Verify field values were preserved
	foundUsername := false
	foundPassword := false
	for _, f := range loaded.Fields {
		if f.Label == "username" && f.Value == "testuser@example.com" {
			foundUsername = true
		}
		if f.Label == "password" && f.Value == "super-secret-password-123" {
			foundPassword = true
		}
	}

	if !foundUsername {
		t.Error("Loaded username field is incorrect")
	}
	if !foundPassword {
		t.Error("Loaded password field is incorrect")
	}
}

func TestStorageLoadItemNotFound(t *testing.T) {
	dir := t.TempDir()

	masterKey := make([]byte, 32)
	s := NewStorage(dir, masterKey)

	_, err := s.LoadItem("nonexistent-item")
	if err == nil {
		t.Error("LoadItem() should return error for nonexistent item")
	}
}

func TestStorageListItems(t *testing.T) {
	dir := t.TempDir()

	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(i)
	}

	s := NewStorage(dir, masterKey)

	// Create some encrypted files directly
	item1 := &vault.Item{ID: "item-1", Title: "Item One", Category: "login"}
	item2 := &vault.Item{ID: "item-2", Title: "Item Two", Category: "login"}
	item3 := &vault.Item{ID: "item-3", Title: "Item Three", Category: "login"}

	_ = s.SaveItem(item1)
	_ = s.SaveItem(item2)
	_ = s.SaveItem(item3)

	ids, err := s.ListItems()
	if err != nil {
		t.Fatalf("ListItems() error = %v", err)
	}

	if len(ids) != 3 {
		t.Errorf("ListItems() returned %d items, want 3", len(ids))
	}

	expected := map[string]bool{
		"item-1": false,
		"item-2": false,
		"item-3": false,
	}

	for _, id := range ids {
		if _, ok := expected[id]; ok {
			expected[id] = true
		} else {
			t.Errorf("Unexpected item ID: %s", id)
		}
	}

	for id, found := range expected {
		if !found {
			t.Errorf("Item %s not found in list", id)
		}
	}
}

func TestStorageDeleteItem(t *testing.T) {
	dir := t.TempDir()

	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(i)
	}

	s := NewStorage(dir, masterKey)

	item := &vault.Item{ID: "item-to-delete", Title: "Delete Me", Category: "login"}
	err := s.SaveItem(item)
	if err != nil {
		t.Fatalf("SaveItem() error = %v", err)
	}

	// Verify it exists
	_, err = s.LoadItem("item-to-delete")
	if err != nil {
		t.Fatalf("Item should exist before delete")
	}

	// Delete it
	err = s.DeleteItem("item-to-delete")
	if err != nil {
		t.Fatalf("DeleteItem() error = %v", err)
	}

	// Verify it's gone
	_, err = s.LoadItem("item-to-delete")
	if err == nil {
		t.Error("DeleteItem() did not remove the item")
	}
}

func TestStorageEncryptJSON(t *testing.T) {
	dir := t.TempDir()

	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(i)
	}

	s := NewStorage(dir, masterKey)

	item := &vault.Item{
		ID:      "json-test",
		Title:   "JSON Test",
		Category: "login",
		Fields: []vault.Field{{Label: "data", Type: "text", Value: "some-data"}},
	}

	err := s.SaveItem(item)
	if err != nil {
		t.Fatalf("SaveItem() error = %v", err)
	}
}

func TestStorageWrongKey(t *testing.T) {
	dir := t.TempDir()

	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(i)
	}

	s := NewStorage(dir, masterKey)

	item := &vault.Item{ID: "wrong-key-test", Title: "Wrong Key Test", Category: "login"}
	err := s.SaveItem(item)
	if err != nil {
		t.Fatalf("SaveItem() error = %v", err)
	}

	// Try to load with a different key
	wrongKey := make([]byte, 32)
	for i := range wrongKey {
		wrongKey[i] = byte(i + 1)
	}

	s2 := NewStorage(dir, wrongKey)
	_, err = s2.LoadItem("wrong-key-test")
	if err == nil {
		t.Error("LoadItem() with wrong key should fail")
	}
}

func TestAtomicWrite(t *testing.T) {
	dir := t.TempDir()

	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(i)
	}

	s := NewStorage(dir, masterKey)

	item := &vault.Item{ID: "atomic-test", Title: "Atomic Test", Category: "login"}
	err := s.SaveItem(item)
	if err != nil {
		t.Fatalf("SaveItem() error = %v", err)
	}

	// Check no temp files remain
	tmpFiles, err := filepath.Glob(filepath.Join(dir, "*.tmp"))
	if err != nil {
		t.Fatalf("Glob() error = %v", err)
	}
	if len(tmpFiles) != 0 {
		t.Errorf("Temp files remain: %v", tmpFiles)
	}

	// Verify the actual file exists and has content
	encFiles, err := filepath.Glob(filepath.Join(dir, "*.enc"))
	if err != nil {
		t.Fatalf("Glob() error = %v", err)
	}
	if len(encFiles) != 1 {
		t.Errorf("Expected 1 .enc file, got %d", len(encFiles))
	}
}

func TestBackupAndRestore(t *testing.T) {
	dir := t.TempDir()
	backupDir := t.TempDir()

	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(i)
	}

	s := NewStorage(dir, masterKey)

	item1 := &vault.Item{ID: "backup-item-1", Title: "Backup Item One", Category: "login"}
	item2 := &vault.Item{ID: "backup-item-2", Title: "Backup Item Two", Category: "login"}

	_ = s.SaveItem(item1)
	_ = s.SaveItem(item2)

	// Create backup
	err := s.Backup(backupDir)
	if err != nil {
		t.Fatalf("Backup() error = %v", err)
	}

	// Verify backup files exist
	backupFiles, err := os.ReadDir(backupDir)
	if err != nil {
		t.Fatalf("ReadDir() error = %v", err)
	}
	if len(backupFiles) != 2 {
		t.Errorf("Backup has %d files, want 2", len(backupFiles))
	}

	// Restore to a new directory
	newDir := t.TempDir()
	s2 := NewStorage(newDir, masterKey)
	err = s2.Restore(backupDir)
	if err != nil {
		t.Fatalf("Restore() error = %v", err)
	}

	// Verify restored files
	newFiles, err := os.ReadDir(newDir)
	if err != nil {
		t.Fatalf("ReadDir() error = %v", err)
	}
	if len(newFiles) != 2 {
		t.Errorf("Restore has %d files, want 2", len(newFiles))
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || findSubstring(s, substr))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// Benchmark storage operations
func BenchmarkSaveItem(b *testing.B) {
	dir := b.TempDir()

	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(i)
	}

	s := NewStorage(dir, masterKey)
	item := &vault.Item{
		ID:      "benchmark-item",
		Title:   "Benchmark Item",
		Category: "login",
		Fields: []vault.Field{
			{Label: "username", Type: "text", Value: "benchmark@example.com"},
			{Label: "password", Type: "password", Value: "benchmark-password-123"},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		item.ID = "benchmark-item-" + string(rune('0'+i%10))
		if err := s.SaveItem(item); err != nil {
			b.Fatalf("SaveItem() error = %v", err)
		}
	}
}

func BenchmarkLoadItem(b *testing.B) {
	dir := b.TempDir()

	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(i)
	}

	s := NewStorage(dir, masterKey)
	item := &vault.Item{
		ID:      "benchmark-item",
		Title:   "Benchmark Item",
		Category: "login",
		Fields: []vault.Field{{Label: "password", Type: "password", Value: "benchmark-password-123"}},
	}
	_ = s.SaveItem(item)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		item.ID = "benchmark-item-" + string(rune('0'+i%10))
		err := s.SaveItem(item)
		if err != nil {
			b.Fatalf("SaveItem() error = %v", err)
		}
	}
}
