package vault

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestNewItem(t *testing.T) {
	item := NewItem("My Login", "login", "Personal")

	if item.Title != "My Login" {
		t.Errorf("Title = %q, want My Login", item.Title)
	}

	if item.Category != "login" {
		t.Errorf("Category = %q, want login", item.Category)
	}

	if item.Vault != "Personal" {
		t.Errorf("Vault = %q, want Personal", item.Vault)
	}

	if item.ID == "" {
		t.Error("Item ID should not be empty")
	}

	if len(item.Fields) != 0 {
		t.Errorf("Fields length = %d, want 0", len(item.Fields))
	}

	if len(item.Tags) != 0 {
		t.Errorf("Tags length = %d, want 0", len(item.Tags))
	}

	if item.CreatedAt.IsZero() {
		t.Error("CreatedAt should not be zero")
	}
}

func TestAddField(t *testing.T) {
	item := NewItem("My Login", "login", "Personal")

	item.AddField("username", "text", "testuser@example.com")
	item.AddField("password", "password", "super-secret-password")

	if len(item.Fields) != 2 {
		t.Errorf("Fields length = %d, want 2", len(item.Fields))
	}

	username := item.GetField("username")
	if username == nil || username.Value != "testuser@example.com" {
		t.Error("Username field not found or incorrect")
	}

	password := item.GetField("password")
	if password == nil || password.Value != "super-secret-password" {
		t.Error("Password field not found or incorrect")
	}

	// Verify UpdatedAt was updated
	if item.UpdatedAt.IsZero() {
		t.Error("UpdatedAt should be set")
	}
}

func TestAddMultipleFields(t *testing.T) {
	item := NewItem("My Login", "login", "Personal")

	fields := []struct {
		label string
		fieldType string
		value string
	}{
		{"username", "text", "testuser@example.com"},
		{"password", "password", "super-secret"},
		{"url", "text", "https://example.com"},
		{"notes", "text", "Some notes here"},
	}

	for _, f := range fields {
		item.AddField(f.label, f.fieldType, f.value)
	}

	if len(item.Fields) != len(fields) {
		t.Errorf("Fields length = %d, want %d", len(item.Fields), len(fields))
	}
}

func TestGetFieldNotFound(t *testing.T) {
	item := NewItem("My Login", "login", "Personal")
	item.AddField("username", "text", "testuser@example.com")

	field := item.GetField("nonexistent")
	if field != nil {
		t.Error("GetField should return nil for nonexistent field")
	}
}

func TestNewItemDefaultValues(t *testing.T) {
	item := NewItem("Test", "password", "Default Vault")

	if item.Fields == nil {
		t.Error("Fields should be initialized as empty slice, not nil")
	}

	if item.Tags == nil {
		t.Error("Tags should be initialized as empty slice, not nil")
	}
}

func TestToJSON(t *testing.T) {
	item := NewItem("My Login", "login", "Personal")
	item.AddField("username", "text", "testuser@example.com")
	item.AddField("password", "password", "super-secret")

	jsonStr, err := item.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON() error = %v", err)
	}

	if jsonStr == "" {
		t.Error("ToJSON() returned empty string")
	}

	// Verify JSON contains expected fields
	if !strings.Contains(jsonStr, "my-login") && !strings.Contains(jsonStr, "My Login") {
		t.Error("JSON should contain item title")
	}

	if !strings.Contains(jsonStr, "testuser@example.com") {
		t.Error("JSON should contain username")
	}
}

func TestFromJSON(t *testing.T) {
	item := NewItem("My Login", "login", "Personal")
	item.AddField("username", "text", "testuser@example.com")
	item.AddField("password", "password", "super-secret")

	jsonStr, err := item.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON() error = %v", err)
	}

	loaded, err := ItemFromJSON([]byte(jsonStr))
	if err != nil {
		t.Fatalf("ItemFromJSON() error = %v", err)
	}

	if loaded.Title != item.Title {
		t.Errorf("Loaded Title = %q, want %q", loaded.Title, item.Title)
	}

	if loaded.Category != item.Category {
		t.Errorf("Loaded Category = %q, want %q", loaded.Category, item.Category)
	}

	if len(loaded.Fields) != len(item.Fields) {
		t.Errorf("Loaded Fields = %d, want %d", len(loaded.Fields), len(item.Fields))
	}

	foundPassword := false
	for _, f := range loaded.Fields {
		if f.Type == "password" && f.Value == "super-secret" {
			foundPassword = true
		}
	}
	if !foundPassword {
		t.Error("Loaded password field not found")
	}
}

func TestFromJSONInvalid(t *testing.T) {
	_, err := ItemFromJSON([]byte("not-valid-json"))
	if err == nil {
		t.Error("ItemFromJSON should return error for invalid JSON")
	}
}

func TestFieldWithLabelDifferentFromName(t *testing.T) {
	item := NewItem("My Login", "login", "Personal")

	item.AddField("username", "text", "user@example.com")
	item.AddField("password", "password", "secret")
	item.AddField("notes", "text", "Notes about this login")

	// Get all fields
	for _, f := range item.Fields {
		if f.Type != "text" && f.Type != "password" {
			t.Errorf("Unexpected field type: %s", f.Type)
		}
	}

	// Verify we can find each by label
	labels := []string{"username", "password", "notes"}
	for _, label := range labels {
		f := item.GetField(label)
		if f == nil {
			t.Errorf("Field %s not found", label)
		}
	}
}

func TestVault(t *testing.T) {
	vault := Vault{
		ID:   "personal-vault-123",
		Name: "Personal",
	}

	if vault.ID != "personal-vault-123" {
		t.Errorf("Vault ID = %q, want personal-vault-123", vault.ID)
	}

	if vault.Name != "Personal" {
		t.Errorf("Vault Name = %q, want Personal", vault.Name)
	}
}

func TestVaultJSONSerialization(t *testing.T) {
	vault := Vault{
		ID:   "personal-vault-123",
		Name: "Personal",
	}

	data, err := json.Marshal(vault)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	var loaded Vault
	if err := json.Unmarshal(data, &loaded); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}

	if loaded.ID != vault.ID {
		t.Errorf("Loaded Vault ID = %q, want %q", loaded.ID, vault.ID)
	}
}

func TestNewItemJSONRoundTrip(t *testing.T) {
	original := NewItem("Round Trip Login", "login", "Test Vault")
	original.AddField("username", "text", "roundtrip@example.com")
	original.AddField("password", "password", "roundtrip-pass")

	jsonStr, err := original.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON() error = %v", err)
	}

	loaded, err := ItemFromJSON([]byte(jsonStr))
	if err != nil {
		t.Fatalf("ItemFromJSON() error = %v", err)
	}

	if loaded.ID == original.ID {
		t.Log("Note: ID generation may be deterministic")
	}

	if loaded.Title != original.Title {
		t.Errorf("Title mismatch")
	}

	foundUsername := false
	foundPassword := false
	for _, f := range loaded.Fields {
		if f.Label == "username" && f.Value == "roundtrip@example.com" {
			foundUsername = true
		}
		if f.Label == "password" && f.Value == "roundtrip-pass" {
			foundPassword = true
		}
	}

	if !foundUsername || !foundPassword {
		t.Error("Fields lost during round trip")
	}
}

// Benchmark item operations
func BenchmarkNewItem(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		NewItem("Test Item", "login", "Personal")
	}
}

func BenchmarkAddField(b *testing.B) {
	item := NewItem("Test Item", "login", "Personal")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		item.AddField("field", "text", "value")
	}
}

func BenchmarkGetField(b *testing.B) {
	item := NewItem("Test Item", "login", "Personal")
	for i := 0; i < 10; i++ {
		item.AddField(fmt.Sprintf("field-%d", i), "text", "value")
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		item.GetField("field-5")
	}
}

func BenchmarkToJSON(b *testing.B) {
	item := NewItem("Test Item", "login", "Personal")
	item.AddField("username", "text", "user@example.com")
	item.AddField("password", "password", "secret")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = item.ToJSON()
	}
}

func BenchmarkItemFromJSON(b *testing.B) {
	item := NewItem("Test Item", "login", "Personal")
	item.AddField("username", "text", "user@example.com")
	jsonStr, _ := item.ToJSON()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ItemFromJSON([]byte(jsonStr))
	}
}
