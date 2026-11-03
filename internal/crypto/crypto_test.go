package crypto

import (
	"bytes"
	"testing"
)

func TestDeriveKey(t *testing.T) {
	password := "test-password-123"
	salt := make([]byte, 32)

	key := DeriveKey(password, salt)
	if len(key) != 32 {
		t.Errorf("Derived key length = %d, want 32", len(key))
	}

	// Same inputs should produce the same key
	key2 := DeriveKey(password, salt)
	if !bytes.Equal(key, key2) {
		t.Error("Same inputs produced different keys")
	}

	// Different password should produce different key
	key3 := DeriveKey("different-password", salt)
	if bytes.Equal(key, key3) {
		t.Error("Different passwords produced the same key")
	}
}

func TestDeriveSessionKey(t *testing.T) {
	muk := make([]byte, 32)
	for i := range muk {
		muk[i] = byte(i)
	}
	kdfSalt := make([]byte, 32)

	key, err := DeriveSessionKey(muk, kdfSalt)
	if err != nil {
		t.Fatalf("DeriveSessionKey() error = %v", err)
	}

	if len(key) != 16 {
		t.Errorf("Session key length = %d, want 16", len(key))
	}
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	plaintext := []byte("Hello, World! This is a secret message.")

	encrypted, err := Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	if encrypted.Nonce == nil || len(encrypted.Nonce) == 0 {
		t.Error("Encrypted data has empty nonce")
	}

	if encrypted.KDFSalt == nil || len(encrypted.KDFSalt) == 0 {
		t.Error("Encrypted data has empty KDF salt")
	}

	if len(encrypted.Cipher) == 0 {
		t.Error("Encrypted cipher is empty")
	}

	decrypted, err := Decrypt(encrypted, key)
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("Decrypted = %s, want %s", decrypted, plaintext)
	}
}

func TestEncryptDifferentOutputs(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	plaintext := []byte("Same message")

	encrypted1, err := Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	encrypted2, err := Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	// Each encryption should use a different nonce
	if bytes.Equal(encrypted1.Nonce, encrypted2.Nonce) {
		t.Error("Same plaintext encrypted twice should produce different nonces")
	}

	if bytes.Equal(encrypted1.Cipher, encrypted2.Cipher) {
		t.Error("Same plaintext encrypted twice should produce different ciphers")
	}
}

func TestEncryptDecryptInvalidKey(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	plaintext := []byte("Secret message")

	encrypted, err := Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	// Try to decrypt with wrong key
	wrongKey := make([]byte, 32)
	for i := range wrongKey {
		wrongKey[i] = byte(i + 1)
	}

	_, err = Decrypt(encrypted, wrongKey)
	if err == nil {
		t.Error("Decrypting with wrong key should fail")
	}
}

func TestEncryptJSON(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	data := map[string]interface{}{
		"username": "testuser",
		"password": "super-secret",
		"vault":    "Personal",
	}

	encrypted, err := EncryptJSON(data, key)
	if err != nil {
		t.Fatalf("EncryptJSON() error = %v", err)
	}

	var decrypted map[string]interface{}
	err = DecryptJSON(encrypted, key, &decrypted)
	if err != nil {
		t.Fatalf("DecryptJSON() error = %v", err)
	}

	if decrypted["username"] != "testuser" {
		t.Errorf("Decrypted username = %v, want testuser", decrypted["username"])
	}
	if decrypted["password"] != "super-secret" {
		t.Errorf("Decrypted password = %v, want super-secret", decrypted["password"])
	}
}

func TestGenerateRandomBytes(t *testing.T) {
	// Test with small size
	b1, err := GenerateRandomBytes(16)
	if err != nil {
		t.Fatalf("GenerateRandomBytes() error = %v", err)
	}
	if len(b1) != 16 {
		t.Errorf("Random bytes length = %d, want 16", len(b1))
	}

	// Test with larger size
	b2, err := GenerateRandomBytes(1024)
	if err != nil {
		t.Fatalf("GenerateRandomBytes() error = %v", err)
	}
	if len(b2) != 1024 {
		t.Errorf("Random bytes length = %d, want 1024", len(b2))
	}

	// Test uniqueness
	b3, err := GenerateRandomBytes(32)
	if err != nil {
		t.Fatalf("GenerateRandomBytes() error = %v", err)
	}
	if bytes.Equal(b1, b3) {
		t.Error("Random bytes should be unique")
	}
}

func TestBase64EncodeDecode(t *testing.T) {
	original := []byte("Hello, World!")

	encoded := EncodeBase64(original)
	decoded, err := DecodeBase64(encoded)
	if err != nil {
		t.Fatalf("DecodeBase64() error = %v", err)
	}

	if !bytes.Equal(decoded, original) {
		t.Errorf("DecodeBase64() = %s, want %s", decoded, original)
	}
}

func TestBase64InvalidInput(t *testing.T) {
	_, err := DecodeBase64("not-valid-base64!!!")
	if err == nil {
		t.Error("DecodeBase64() should fail with invalid input")
	}
}

// Benchmark encryption/decryption
func BenchmarkEncrypt(b *testing.B) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	plaintext := []byte("Secret message that needs encryption for benchmarking purposes")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := Encrypt(plaintext, key)
		if err != nil {
			b.Fatalf("Encrypt() error = %v", err)
		}
	}
}

func BenchmarkDecrypt(b *testing.B) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	plaintext := []byte("Secret message that needs encryption for benchmarking purposes")

	encrypted, err := Encrypt(plaintext, key)
	if err != nil {
		b.Fatalf("Encrypt() error = %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := Decrypt(encrypted, key)
		if err != nil {
			b.Fatalf("Decrypt() error = %v", err)
		}
	}
}

// Benchmark key derivation
func BenchmarkDeriveKey(b *testing.B) {
	password := "test-password-123"
	salt := make([]byte, 32)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = DeriveKey(password, salt)
	}
}
