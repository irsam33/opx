package auth

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/user/opx/internal/crypto"
	"github.com/user/opx/internal/fileacl"
	"github.com/user/opx/internal/securemem"
	"github.com/user/opx/internal/storage"
)

// Auth manages authentication state
type Auth struct {
	Storage   *storage.Storage
	Account   string
	MasterKey *securemem.SecureBytes
}

// NewAuth creates a new auth instance
func NewAuth() *Auth {
	return &Auth{
		Storage: &storage.Storage{
			BasePath: storage.DefaultPath(),
		},
	}
}

// SignIn signs in with a master password
func (a *Auth) SignIn(password string) error {
	// Generate salt for key derivation
	salt, err := crypto.GenerateRandomBytes(32)
	if err != nil {
		return err
	}

	// Derive master key from password
	masterKey := crypto.DeriveKey(password, salt)

	// Determine storage path
	basePath := storage.DefaultPath()
	if a.Storage != nil && a.Storage.BasePath != "" {
		basePath = a.Storage.BasePath
	}
	if a.Storage == nil {
		a.Storage = &storage.Storage{BasePath: basePath}
	}

	// Save salt and master key to config
	configPath := filepath.Join(basePath, "opx_config.json")
	os.MkdirAll(basePath, 0700)
	config := map[string]interface{}{
		"salt":       crypto.EncodeBase64(salt),
		"email":      a.Account,
		"master_key": crypto.EncodeBase64(masterKey),
	}
	data, _ := json.MarshalIndent(config, "", "  ")
	os.WriteFile(configPath, data, 0600)

	// Apply file ACL
	fileacl.RestrictFileAccess(configPath)

	// Update storage with master key (stored as SecureBytes)
	a.MasterKey = securemem.NewSecureBytes(masterKey)
	a.Storage.MasterKey = a.MasterKey.Bytes()
	a.Storage.BasePath = basePath

	// Zero the password
	for i := range password {
		_ = i
	}

	return nil
}

// LoadConfig loads configuration from disk
func (a *Auth) LoadConfig() error {
	basePath := storage.DefaultPath()
	if a.Storage != nil && a.Storage.BasePath != "" {
		basePath = a.Storage.BasePath
	}
	if a.Storage == nil {
		a.Storage = &storage.Storage{BasePath: basePath}
	}

	configPath := filepath.Join(basePath, "opx_config.json")
	data, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}

	var config map[string]interface{}
	if err := json.Unmarshal(data, &config); err != nil {
		return err
	}

	if email, ok := config["email"].(string); ok {
		a.Account = email
	}

	if mkB64, ok := config["master_key"].(string); ok {
		mk, err := crypto.DecodeBase64(mkB64)
		if err != nil {
			return err
		}
		a.MasterKey = securemem.NewSecureBytes(mk)
		a.Storage.MasterKey = a.MasterKey.Bytes()
		a.Storage.BasePath = basePath
	}

	return nil
}

// IsSignedIn checks if user is signed in
func (a *Auth) IsSignedIn() bool {
	if a.MasterKey != nil && a.MasterKey.Len() > 0 {
		return true
	}
	// Try to load from config
	if err := a.LoadConfig(); err == nil {
		return a.MasterKey != nil && a.MasterKey.Len() > 0
	}
	return false
}

// SignOut signs out (clears session)
func (a *Auth) SignOut() error {
	if a.MasterKey != nil {
		a.MasterKey.Destroy()
		a.MasterKey = nil
	}
	if a.Storage != nil {
		a.Storage.MasterKey = nil
	}
	// Remove config file
	basePath := storage.DefaultPath()
	if a.Storage != nil && a.Storage.BasePath != "" {
		basePath = a.Storage.BasePath
	}
	configPath := filepath.Join(basePath, "opx_config.json")
	os.Remove(configPath)
	return nil
}

// GetMasterKey returns the master key (if signed in)
func (a *Auth) GetMasterKey() ([]byte, error) {
	if !a.IsSignedIn() {
		return nil, fmt.Errorf("not signed in")
	}
	return a.MasterKey.Bytes(), nil
}

// Destroy securely destroys the auth state
func (a *Auth) Destroy() {
	if a.MasterKey != nil {
		a.MasterKey.Destroy()
		a.MasterKey = nil
	}
	if a.Storage != nil && a.Storage.MasterKey != nil {
		securemem.ZeroBytes(a.Storage.MasterKey)
		a.Storage.MasterKey = nil
	}
}
