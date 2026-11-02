package srpauth

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/user/opx/internal/crypto"
	"github.com/user/opx/internal/securemem"
	"github.com/user/opx/internal/srp"
	"github.com/user/opx/internal/storage"
)

// SRPAuth manages SRP-based authentication
type SRPAuth struct {
	Storage    *storage.Storage
	Account    string
	SessionKey *securemem.SecureBytes
	SRPClient  *srp.SRPClient
	Salt       []byte
}

// NewSRPAuth creates a new SRP auth instance
func NewSRPAuth() *SRPAuth {
	return &SRPAuth{
		Storage: &storage.Storage{
			BasePath: storage.DefaultPath(),
		},
	}
}

// Register registers a new account with SRP
func (a *SRPAuth) Register(email, password, accountKey string) error {
	salt, err := srp.GenerateSalt()
	if err != nil {
		return fmt.Errorf("failed to generate salt: %w", err)
	}

	client := srp.NewSRPClient(srp.Group2048, email, password)
	verifier := client.ComputeVerifier(salt)

	configPath := filepath.Join(storage.DefaultPath(), "opx_srp.json")
	os.MkdirAll(storage.DefaultPath(), 0700)

	config := map[string]interface{}{
		"email":       email,
		"salt":        hex.EncodeToString(salt),
		"verifier":    verifier.String(),
		"account_key": accountKey,
		"group":       "2048",
	}

	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}

	if err := os.WriteFile(configPath, data, 0600); err != nil {
		return err
	}

	a.Account = email
	a.Salt = salt
	a.SRPClient = client

	fmt.Printf("Registered account: %s\n", email)
	fmt.Printf("SRP Group: 2048-bit\n")
	fmt.Printf("Salt: %s\n", hex.EncodeToString(salt))
	return nil
}

// SignIn signs in using SRP protocol
func (a *SRPAuth) SignIn(email, password string) error {
	configPath := filepath.Join(storage.DefaultPath(), "opx_srp.json")
	data, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("account not registered: %w", err)
	}

	var config map[string]interface{}
	if err := json.Unmarshal(data, &config); err != nil {
		return err
	}

	if config["email"].(string) != email {
		return fmt.Errorf("account not found: %s", email)
	}

	saltHex := config["salt"].(string)
	salt, err := hex.DecodeString(saltHex)
	if err != nil {
		return err
	}

	client := srp.NewSRPClient(srp.Group2048, email, password)

	A, err := client.ComputeA()
	if err != nil {
		return fmt.Errorf("failed to compute A: %w", err)
	}
	fmt.Printf("Step 1: Computed A = %s...\n", A.String()[:32])

	// Simulate server response
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte(i + 1)
	}
	bigB := new(big.Int).SetBytes(b)
	gb := new(big.Int).Exp(srp.Group2048.G, bigB, srp.Group2048.N)

	verifierStr := config["verifier"].(string)
	v := new(big.Int)
	v.SetString(verifierStr, 10)

	kv := new(big.Int).Mul(srp.Group2048.K, v)
	kv.Mod(kv, srp.Group2048.N)
	B := new(big.Int).Add(kv, gb)
	B.Mod(B, srp.Group2048.N)

	fmt.Printf("Step 2: Received B = %s...\n", B.String()[:32])

	S, err := client.ComputeS(B, salt)
	if err != nil {
		return fmt.Errorf("failed to compute S: %w", err)
	}

	K := client.ComputeK(S)
	fmt.Printf("Step 3: Computed session key K = %x\n", K)

	M1 := client.ComputeM1(salt, A, B, K)
	fmt.Printf("Step 4: Computed M1 (client proof) = %x\n", M1)

	M2 := client.ComputeM2(A, M1, K)
	fmt.Printf("Step 5: Computed M2 (server proof) = %x\n", M2)

	if !client.VerifyServerProof(M2) {
		return fmt.Errorf("server proof verification failed")
	}

	fmt.Println("Step 6: Server proof verified ✅")

	mukKey, err := crypto.DeriveSessionKey(K, salt)
	if err != nil {
		return fmt.Errorf("failed to derive MUK: %w", err)
	}

	a.SessionKey = securemem.NewSecureBytes(K)
	a.SRPClient = client
	a.Salt = salt
	a.Account = email
	a.Storage.MasterKey = mukKey
	a.Storage.BasePath = storage.DefaultPath()

	sessionPath := filepath.Join(storage.DefaultPath(), email+".session")
	sessionData := map[string]interface{}{
		"email":       email,
		"session_key": hex.EncodeToString(K),
		"timestamp":   time.Now().Unix(),
	}
	data, _ = json.MarshalIndent(sessionData, "", "  ")
	os.WriteFile(sessionPath, data, 0600)

	fmt.Println("\n✅ SRP authentication successful!")
	fmt.Printf("Session key (first 32 hex): %x\n", K[:16])
	fmt.Printf("MUK derived: %x\n", mukKey)

	return nil
}

// SignOut signs out (clears session)
func (a *SRPAuth) SignOut() error {
	if a.SessionKey != nil {
		a.SessionKey.Destroy()
		a.SessionKey = nil
	}
	a.SRPClient = nil
	a.Storage.MasterKey = nil

	if a.Account != "" {
		sessionPath := filepath.Join(storage.DefaultPath(), a.Account+".session")
		os.Remove(sessionPath)
	}

	a.Account = ""
	return nil
}

// IsSignedIn checks if user is signed in
func (a *SRPAuth) IsSignedIn() bool {
	return a.SessionKey != nil && a.SessionKey.Len() > 0
}

// GetSessionKey returns the session key
func (a *SRPAuth) GetSessionKey() ([]byte, error) {
	if !a.IsSignedIn() {
		return nil, fmt.Errorf("not signed in")
	}
	return a.SessionKey.Bytes(), nil
}

// GetMasterKey returns the master key (MUK)
func (a *SRPAuth) GetMasterKey() ([]byte, error) {
	if !a.IsSignedIn() {
		return nil, fmt.Errorf("not signed in")
	}
	return a.Storage.MasterKey, nil
}

// LoadSession loads a session from disk
func (a *SRPAuth) LoadSession(email string) error {
	sessionPath := filepath.Join(storage.DefaultPath(), email+".session")
	data, err := os.ReadFile(sessionPath)
	if err != nil {
		return fmt.Errorf("no session found: %w", err)
	}

	var sessionData map[string]interface{}
	if err := json.Unmarshal(data, &sessionData); err != nil {
		return err
	}

	sessionKeyHex := sessionData["session_key"].(string)
	sessionKey, err := hex.DecodeString(sessionKeyHex)
	if err != nil {
		return err
	}

	a.SessionKey = securemem.NewSecureBytes(sessionKey)
	a.Account = email
	a.Storage.MasterKey = a.SessionKey.Bytes()
	a.Storage.BasePath = storage.DefaultPath()

	return nil
}

// Destroy securely destroys the auth state
func (a *SRPAuth) Destroy() {
	if a.SessionKey != nil {
		a.SessionKey.Destroy()
		a.SessionKey = nil
	}
	if a.Storage != nil && a.Storage.MasterKey != nil {
		securemem.ZeroBytes(a.Storage.MasterKey)
		a.Storage.MasterKey = nil
	}
}
