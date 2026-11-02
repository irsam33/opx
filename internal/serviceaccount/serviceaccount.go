package serviceaccount

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/user/opx/internal/auth"
	"github.com/user/opx/internal/storage"
)

// ServiceAccount represents a 1Password-like service account
type ServiceAccount struct {
	Token     string    `json:"token"`
	Name      string    `json:"name"`
	Email     string    `json:"email"`
	Vaults    []string  `json:"vaults"` // Allowed vaults
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// ServiceAccountToken represents a parsed token
type ServiceAccountToken struct {
	AccountUUID string   `json:"account_uuid"`
	UserUUID    string   `json:"user_uuid"`
	VaultUUIDs  []string `json:"vault_uuids"`
	Scopes      []string `json:"scopes"`
	ExpiresAt   int64    `json:"exp"`
	IssuedAt    int64    `json:"iat"`
}

// NewServiceAccount creates a new service account
func NewServiceAccount(name, email string, vaults []string) *ServiceAccount {
	return &ServiceAccount{
		Name:      name,
		Email:     email,
		Vaults:    vaults,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(365 * 24 * time.Hour), // 1 year
	}
}

// GenerateToken generates a service account token (JWT-like)
func (sa *ServiceAccount) GenerateToken() (string, error) {
	// Create token payload
	token := ServiceAccountToken{
		AccountUUID: "account-uuid-" + sa.Name,
		UserUUID:    "user-uuid-" + sa.Name,
		VaultUUIDs:  sa.Vaults,
		Scopes:      []string{"vaults:read", "items:read", "items:write"},
		ExpiresAt:   sa.ExpiresAt.Unix(),
		IssuedAt:    sa.CreatedAt.Unix(),
	}

	// Marshal to JSON
	data, err := json.Marshal(token)
	if err != nil {
		return "", err
	}

	// Base64 encode (simplified JWT - no signature for demo)
	encoded := base64.URLEncoding.EncodeToString(data)
	sa.Token = "ops_" + encoded

	return sa.Token, nil
}

// ParseToken parses a service account token
func ParseToken(token string) (*ServiceAccountToken, error) {
	if !strings.HasPrefix(token, "ops_") {
		return nil, fmt.Errorf("invalid token format: must start with 'ops_'")
	}

	encoded := token[4:] // Remove "ops_" prefix
	data, err := base64.URLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("invalid token encoding: %w", err)
	}

	var tokenData ServiceAccountToken
	if err := json.Unmarshal(data, &tokenData); err != nil {
		return nil, fmt.Errorf("invalid token data: %w", err)
	}

	// Check expiration
	if time.Now().Unix() > tokenData.ExpiresAt {
		return nil, fmt.Errorf("token expired")
	}

	return &tokenData, nil
}

// ValidateToken validates a service account token
func ValidateToken(token string) bool {
	_, err := ParseToken(token)
	return err == nil
}

// GetAllowedVaults returns the vaults this service account can access
func (sa *ServiceAccount) GetAllowedVaults() []string {
	return sa.Vaults
}

// HasVaultAccess checks if the service account has access to a vault
func (sa *ServiceAccount) HasVaultAccess(vault string) bool {
	for _, v := range sa.Vaults {
		if v == vault || v == "*" {
			return true
		}
	}
	return false
}

// Save saves the service account to storage
func (sa *ServiceAccount) Save() error {
	configPath := filepath.Join(storage.DefaultPath(), "service_accounts.json")

	// Load existing accounts
	var accounts []ServiceAccount
	data, err := os.ReadFile(configPath)
	if err == nil {
		json.Unmarshal(data, &accounts)
	}

	// Add new account
	accounts = append(accounts, *sa)

	// Save
	data, err = json.MarshalIndent(accounts, "", "  ")
	if err != nil {
		return err
	}

	os.MkdirAll(storage.DefaultPath(), 0700)
	return os.WriteFile(configPath, data, 0600)
}

// LoadServiceAccounts loads all service accounts
func LoadServiceAccounts() ([]ServiceAccount, error) {
	configPath := filepath.Join(storage.DefaultPath(), "service_accounts.json")
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}

	var accounts []ServiceAccount
	if err := json.Unmarshal(data, &accounts); err != nil {
		return nil, err
	}

	return accounts, nil
}

// FindServiceAccount finds a service account by name
func FindServiceAccount(name string) (*ServiceAccount, error) {
	accounts, err := LoadServiceAccounts()
	if err != nil {
		return nil, err
	}

	for i := range accounts {
		if accounts[i].Name == name {
			return &accounts[i], nil
		}
	}

	return nil, fmt.Errorf("service account not found: %s", name)
}

// DeleteServiceAccount deletes a service account
func DeleteServiceAccount(name string) error {
	accounts, err := LoadServiceAccounts()
	if err != nil {
		return err
	}

	var newAccounts []ServiceAccount
	for _, acc := range accounts {
		if acc.Name != name {
			newAccounts = append(newAccounts, acc)
		}
	}

	configPath := filepath.Join(storage.DefaultPath(), "service_accounts.json")
	data, err := json.MarshalIndent(newAccounts, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(configPath, data, 0600)
}

// SignInWithToken signs in using a service account token
func SignInWithToken(token string) (*auth.Auth, error) {
	tokenData, err := ParseToken(token)
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	// Create auth instance
	a := auth.NewAuth()
	a.Account = "service-account"

	// Derive master key from token (simplified)
	// In real implementation, this would use the token to fetch account details
	_ = tokenData

	return a, nil
}

// GetTokenInfo returns information about a token
func GetTokenInfo(token string) (*ServiceAccountToken, error) {
	return ParseToken(token)
}

// ListServiceAccounts lists all service accounts
func ListServiceAccounts() error {
	accounts, err := LoadServiceAccounts()
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Println("No service accounts found.")
			return nil
		}
		return err
	}

	if len(accounts) == 0 {
		fmt.Println("No service accounts found.")
		return nil
	}

	fmt.Println("Service Accounts:")
	for _, acc := range accounts {
		status := "active"
		if time.Now().After(acc.ExpiresAt) {
			status = "expired"
		}
		fmt.Printf("  - %s (%s) - Vaults: %v [%s]\n", acc.Name, acc.Email, acc.Vaults, status)
		fmt.Printf("    Token: %s...\n", acc.Token[:20])
		fmt.Printf("    Created: %s, Expires: %s\n", acc.CreatedAt.Format("2006-01-02"), acc.ExpiresAt.Format("2006-01-02"))
	}

	return nil
}
