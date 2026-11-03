package auth

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/user/opx/internal/storage"
)

func TestNewAuth(t *testing.T) {
	a := NewAuth()
	if a == nil {
		t.Fatal("NewAuth() returned nil")
	}
	if a.Storage == nil {
		t.Error("NewAuth() returned nil Storage")
	}
	if a.MasterKey != nil {
		t.Error("NewAuth() should start with nil MasterKey")
	}
}

func TestAuthIsSignedIn(t *testing.T) {
	// Need to mock storage.DefaultPath - test with a fresh instance
	a := NewAuth()
	a.Storage.BasePath = t.TempDir()

	// Should not be signed in initially
	if a.IsSignedIn() {
		t.Error("New auth should not be signed in")
	}
}

func TestAuthSignIn(t *testing.T) {
	a := NewAuth()
	a.Account = "test@example.com"

	// Use a proper password (not the removed default)
	password := "test-password-secure-123!"

	err := a.SignIn(password)
	if err != nil {
		t.Fatalf("SignIn() error = %v", err)
	}

	if !a.IsSignedIn() {
		t.Error("Auth should be signed in after SignIn")
	}

	if a.Account != "test@example.com" {
		t.Errorf("Account = %q, want %q", a.Account, "test@example.com")
	}

	if a.MasterKey == nil || a.MasterKey.Len() == 0 {
		t.Error("MasterKey should be set after SignIn")
	}
}

func TestAuthDifferentPasswords(t *testing.T) {
	a1 := NewAuth()
	a1.Account = "test@example.com"
	password1 := "password-one"

	a2 := NewAuth()
	a2.Account = "test@example.com"
	password2 := "password-two"

	err1 := a1.SignIn(password1)
	if err1 != nil {
		t.Fatalf("SignIn() error = %v", err1)
	}

	err2 := a2.SignIn(password2)
	if err2 != nil {
		t.Fatalf("SignIn() error = %v", err2)
	}

	if a1.MasterKey == nil || a2.MasterKey == nil {
		t.Fatal("Both MasterKeys should be set")
	}

	// Different passwords should derive different keys
	if string(a1.MasterKey.Bytes()) == string(a2.MasterKey.Bytes()) {
		t.Error("Different passwords should produce different master keys")
	}
}

func TestAuthSignOut(t *testing.T) {
	a := NewAuth()
	a.Account = "test@example.com"

	// Create temp storage dir
	a.Storage.BasePath = t.TempDir()

	err := a.SignIn("test-password")
	if err != nil {
		t.Fatalf("SignIn() error = %v", err)
	}

	if !a.IsSignedIn() {
		t.Error("Should be signed in before SignOut")
	}

	err = a.SignOut()
	if err != nil {
		t.Fatalf("SignOut() error = %v", err)
	}

	if a.IsSignedIn() {
		t.Error("Should not be signed in after SignOut")
	}

	if a.MasterKey != nil {
		t.Error("MasterKey should be nil after SignOut")
	}
}

func TestAuthGetMasterKey(t *testing.T) {
	a := NewAuth()
	a.Account = "test@example.com"
	a.Storage.BasePath = t.TempDir()

	err := a.SignIn("test-password")
	if err != nil {
		t.Fatalf("SignIn() error = %v", err)
	}

	key, err := a.GetMasterKey()
	if err != nil {
		t.Errorf("GetMasterKey() error = %v", err)
	}

	if len(key) == 0 {
		t.Error("GetMasterKey() returned empty key")
	}
}

func TestAuthGetMasterKeyNotSignedIn(t *testing.T) {
	a := NewAuth()
	a.Storage.BasePath = t.TempDir()

	_, err := a.GetMasterKey()
	if err == nil {
		t.Error("GetMasterKey() should fail when not signed in")
	}
}

func TestAuthDestroy(t *testing.T) {
	a := NewAuth()
	a.Account = "test@example.com"
	a.Storage.BasePath = t.TempDir()

	err := a.SignIn("test-password")
	if err != nil {
		t.Fatalf("SignIn() error = %v", err)
	}

	if a.MasterKey == nil {
		t.Fatal("MasterKey should be set before Destroy")
	}

	a.Destroy()

	if a.MasterKey != nil {
		t.Error("MasterKey should be nil after Destroy")
	}
}

func TestAuthConfigFileCreation(t *testing.T) {
	storageDir := t.TempDir()

	// Create auth instance directly with the storage dir
	a := &Auth{
		Account: "test@example.com",
		Storage: &storage.Storage{
			BasePath: storageDir,
		},
	}

	err := a.SignIn("test-password")
	if err != nil {
		t.Fatalf("SignIn() error = %v", err)
	}

	// Check that config file was created
	configPath := filepath.Join(storageDir, "opx_config.json")
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		t.Error("Config file should be created after SignIn")
	}

	// Clean up
	os.Remove(configPath)
}

// Benchmark authentication
func BenchmarkAuthSignIn(b *testing.B) {
	storageDir := b.TempDir()
	a := &Auth{
		Account: "test@example.com",
		Storage: &storage.Storage{
			BasePath: storageDir,
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = a.SignIn("benchmark-password-123!")
		a.Destroy()
	}
}

// Test SecureBytes operations
func TestSecureBytesOperations(t *testing.T) {
	// Test SecureBytes creation
	password := "test-password-secure-123!"
	a := &Auth{
		Account: "test@example.com",
		Storage: &storage.Storage{
			BasePath: t.TempDir(),
		},
	}
	a.SignIn(password)

	// Verify key length is 32 bytes
	key := a.MasterKey.Bytes()
	if len(key) != 32 {
		t.Errorf("MasterKey length = %d, want 32", len(key))
	}

	// Clean up
	a.Destroy()
}
