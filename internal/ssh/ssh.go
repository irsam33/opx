package ssh

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
)

// KeyType represents an SSH key type
type KeyType string

const (
	KeyTypeEd25519 KeyType = "ed25519"
	KeyTypeRSA     KeyType = "rsa"
)

// SSHKey represents an SSH key
type SSHKey struct {
	Type        KeyType `json:"type"`
	Name        string  `json:"name"`
	PublicKey   string  `json:"public_key"`
	PrivateKey  string  `json:"private_key"`
	Fingerprint string  `json:"fingerprint"`
	CreatedAt   string  `json:"created_at"`
}

// GenerateKey generates a new SSH key
func GenerateKey(keyType KeyType, name string) (*SSHKey, error) {
	switch keyType {
	case KeyTypeEd25519:
		return generateEd25519Key(name)
	case KeyTypeRSA:
		return generateRSAKey(name, 4096)
	default:
		return nil, fmt.Errorf("unsupported key type: %s", keyType)
	}
}

func generateEd25519Key(name string) (*SSHKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	// Marshal private key
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}

	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privBytes,
	})

	// Marshal public key
	pubSSH, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil, err
	}

	pubBytes := ssh.MarshalAuthorizedKey(pubSSH)
	fingerprint := ssh.FingerprintSHA256(pubSSH)

	return &SSHKey{
		Type:        KeyTypeEd25519,
		Name:        name,
		PublicKey:   string(pubBytes),
		PrivateKey:  string(privPEM),
		Fingerprint: fingerprint,
	}, nil
}

func generateRSAKey(name string, bits int) (*SSHKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}

	// Marshal private key
	privBytes := x509.MarshalPKCS1PrivateKey(priv)
	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privBytes,
	})

	// Marshal public key
	pubSSH, err := ssh.NewPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, err
	}

	pubBytes := ssh.MarshalAuthorizedKey(pubSSH)
	fingerprint := ssh.FingerprintSHA256(pubSSH)

	return &SSHKey{
		Type:        KeyTypeRSA,
		Name:        name,
		PublicKey:   string(pubBytes),
		PrivateKey:  string(privPEM),
		Fingerprint: fingerprint,
	}, nil
}

// SaveKey saves an SSH key to a file
func SaveKey(key *SSHKey, dir string) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	// Save private key
	privPath := filepath.Join(dir, key.Name)
	if err := os.WriteFile(privPath, []byte(key.PrivateKey), 0600); err != nil {
		return err
	}

	// Save public key
	pubPath := filepath.Join(dir, key.Name+".pub")
	if err := os.WriteFile(pubPath, []byte(key.PublicKey), 0644); err != nil {
		return err
	}

	return nil
}

// LoadKey loads an SSH key from a file
func LoadKey(name, dir string) (*SSHKey, error) {
	privPath := filepath.Join(dir, name)
	pubPath := filepath.Join(dir, name+".pub")

	privData, err := os.ReadFile(privPath)
	if err != nil {
		return nil, fmt.Errorf("cannot read private key: %w", err)
	}

	pubData, err := os.ReadFile(pubPath)
	if err != nil {
		return nil, fmt.Errorf("cannot read public key: %w", err)
	}

	// Parse private key to determine type
	block, _ := pem.Decode(privData)
	if block == nil {
		return nil, fmt.Errorf("invalid PEM")
	}

	keyType := KeyTypeRSA
	if block.Type == "PRIVATE KEY" {
		keyType = KeyTypeEd25519
	}

	// Calculate fingerprint
	pubSSH, _, _, _, err := ssh.ParseAuthorizedKey(pubData)
	if err != nil {
		return nil, err
	}
	fingerprint := ssh.FingerprintSHA256(pubSSH)

	return &SSHKey{
		Type:        keyType,
		Name:        name,
		PublicKey:   string(pubData),
		PrivateKey:  string(privData),
		Fingerprint: fingerprint,
	}, nil
}

// ListKeys lists all SSH keys in a directory
func ListKeys(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	var keys []string
	for _, e := range entries {
		if !e.IsDir() && !strings.HasSuffix(e.Name(), ".pub") {
			keys = append(keys, e.Name())
		}
	}
	return keys, nil
}

// DeleteKey deletes an SSH key
func DeleteKey(name, dir string) error {
	os.Remove(filepath.Join(dir, name))
	os.Remove(filepath.Join(dir, name+".pub"))
	return nil
}

// GetSSHDir returns the SSH directory path
func GetSSHDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".ssh")
}
