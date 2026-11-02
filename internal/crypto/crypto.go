package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

// EncryptedData holds encrypted data with nonce and salt
type EncryptedData struct {
	KDFSalt []byte `json:"kdf_salt"`
	Nonce   []byte `json:"nonce"`
	Cipher  []byte `json:"cipher"`
}

// DeriveKey derives a key from password using Argon2id
func DeriveKey(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt, 3, 64*1024, 4, 32)
}

// DeriveSessionKey derives a session encryption key using HKDF
func DeriveSessionKey(muk []byte, kdfSalt []byte) ([]byte, error) {
	hkdfReader := hkdf.New(sha256.New, muk, []byte("session encryption key"), kdfSalt)
	key := make([]byte, 16)
	if _, err := io.ReadFull(hkdfReader, key); err != nil {
		return nil, fmt.Errorf("HKDF failed: %w", err)
	}
	return key, nil
}

// Encrypt encrypts plaintext with AES-256-GCM
func Encrypt(plaintext []byte, key []byte) (*EncryptedData, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	kdfSalt := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, kdfSalt); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	return &EncryptedData{
		KDFSalt: kdfSalt,
		Nonce:   nonce,
		Cipher:  ciphertext,
	}, nil
}

// Decrypt decrypts ciphertext with AES-256-GCM
func Decrypt(data *EncryptedData, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintext, err := gcm.Open(nil, data.Nonce, data.Cipher, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}

// EncryptJSON encrypts a JSON-serializable object
func EncryptJSON(v interface{}, key []byte) (*EncryptedData, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return Encrypt(data, key)
}

// DecryptJSON decrypts and unmarshals a JSON object
func DecryptJSON(data *EncryptedData, key []byte, v interface{}) error {
	plaintext, err := Decrypt(data, key)
	if err != nil {
		return err
	}
	return json.Unmarshal(plaintext, v)
}

// GenerateRandomBytes generates cryptographically secure random bytes
func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	return b, err
}

// EncodeBase64 encodes bytes to base64
func EncodeBase64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// DecodeBase64 decodes base64 to bytes
func DecodeBase64(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}
