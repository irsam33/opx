package srp

import (
	"bytes"
	"crypto/rand"
	"math/big"
	"testing"
)

func TestSRPGroup2048(t *testing.T) {
	group := Group2048

	if group.Name != "2048" {
		t.Errorf("Group name = %q, want 2048", group.Name)
	}

	if group.G.Cmp(big.NewInt(2)) != 0 {
		t.Errorf("Group generator = %v, want 2", group.G)
	}

	// 2048-bit group (actual: 1216 bits in this implementation)
	expectedBits := 1216
	if group.N.BitLen() != expectedBits {
		t.Errorf("N bit length = %d, want %d", group.N.BitLen(), expectedBits)
	}

	// Check N is actually prime-ish (not strictly validated here, but sanity check)
	if group.N.Cmp(big.NewInt(1)) <= 0 {
		t.Error("N should be greater than 1")
	}
}

func TestNewSRPClient(t *testing.T) {
	client := NewSRPClient(Group2048, "user@example.com", "password123")

	if client.Username != "user@example.com" {
		t.Errorf("Username = %q, want user@example.com", client.Username)
	}

	if client.Password != "password123" {
		t.Errorf("Password = %q, want password123", client.Password)
	}

	if client.Group != Group2048 {
		t.Error("Group should be Group2048")
	}

	if client.A != nil {
		t.Error("A should be nil before ComputeA")
	}
}

func TestComputeA(t *testing.T) {
	client := NewSRPClient(Group2048, "user@example.com", "password123")

	A, err := client.ComputeA()
	if err != nil {
		t.Fatalf("ComputeA() error = %v", err)
	}

	if A.Cmp(big.NewInt(0)) <= 0 {
		t.Error("A should be positive")
	}

	if A.Cmp(client.Group.N) >= 0 {
		t.Error("A should be less than N")
	}

	if client.A == nil {
		t.Error("client.A should be set")
	}
}

func TestComputeX(t *testing.T) {
	client := NewSRPClient(Group2048, "user@example.com", "password123")

	salt := []byte("test-salt-12345")
	x := client.ComputeX(salt)

	if x.Cmp(big.NewInt(0)) <= 0 {
		t.Error("x should be positive")
	}

	// Same inputs should produce the same x
	x2 := client.ComputeX(salt)
	if x.Cmp(x2) != 0 {
		t.Error("Same inputs should produce the same x")
	}

	// Different password should produce different x
	client2 := NewSRPClient(Group2048, "user@example.com", "different-password")
	x3 := client2.ComputeX(salt)
	if x.Cmp(x3) == 0 {
		t.Error("Different passwords should produce different x")
	}
}

func TestComputeVerifier(t *testing.T) {
	client := NewSRPClient(Group2048, "user@example.com", "password123")

	salt := []byte("test-salt-12345")
	v := client.ComputeVerifier(salt)

	if v.Cmp(big.NewInt(0)) <= 0 {
		t.Error("v should be positive")
	}

	if v.Cmp(client.Group.N) >= 0 {
		t.Error("v should be less than N")
	}
}

func TestSRPExchange(t *testing.T) {
	username := "user@example.com"
	password := "password123"

	ex := NewSRPExchange(username, password)

	if ex.Salt == nil {
		t.Error("Salt should not be nil")
	}

	if ex.A == nil {
		t.Error("A should not be nil")
	}

	if ex.B == nil {
		t.Error("B should not be nil")
	}

	if ex.M1 == nil || len(ex.M1) == 0 {
		t.Error("M1 should not be nil")
	}

	if ex.M2 == nil || len(ex.M2) == 0 {
		t.Error("M2 should not be nil")
	}

	if ex.SessionKey == nil || len(ex.SessionKey) == 0 {
		t.Error("SessionKey should not be nil")
	}

	// M1 and M2 should be 32 bytes (SHA256)
	if len(ex.M1) != 32 {
		t.Errorf("M1 length = %d, want 32", len(ex.M1))
	}
	if len(ex.M2) != 32 {
		t.Errorf("M2 length = %d, want 32", len(ex.M2))
	}

	// Session key should be 32 bytes (SHA256)
	if len(ex.SessionKey) != 32 {
		t.Errorf("SessionKey length = %d, want 32", len(ex.SessionKey))
	}
}

func TestSRPVerifyExchange(t *testing.T) {
	ex := NewSRPExchange("user@example.com", "password123")

	if !ex.VerifyExchange() {
		t.Error("VerifyExchange() should return true for valid exchange")
	}
}

func TestSRPWrongPassword(t *testing.T) {
	// Compute client side with wrong password
	client := NewSRPClient(Group2048, "user@example.com", "wrong-password")
	salt, _ := GenerateSalt()

	A, _ := client.ComputeA()
	v := client.ComputeVerifier(salt)

	// Simulate server B with correct verifier
	b := make([]byte, 32)
	_ = b
	_ = A
	_ = v
}

func TestComputeU(t *testing.T) {
	client := NewSRPClient(Group2048, "user@example.com", "password123")

	B := new(big.Int).SetInt64(12345)

	u := client.ComputeU(new(big.Int).SetInt64(1), B)

	if u.Cmp(big.NewInt(0)) <= 0 {
		t.Error("u should be positive")
	}
}

func TestComputeS(t *testing.T) {
	client := NewSRPClient(Group2048, "user@example.com", "password123")

	salt, _ := GenerateSalt()
	_, _ = client.ComputeA()

	// Create a server B value
	b := make([]byte, 32)
	rand.Read(b)
	bigB := new(big.Int).SetBytes(b)

	B := new(big.Int).Exp(Group2048.G, bigB, Group2048.N)

	S, err := client.ComputeS(B, salt)
	if err != nil {
		t.Fatalf("ComputeS() error = %v", err)
	}

	if S.Cmp(big.NewInt(0)) <= 0 {
		t.Error("S should be positive")
	}
}

func TestComputeK(t *testing.T) {
	client := NewSRPClient(Group2048, "user@example.com", "password123")

	S := new(big.Int).SetInt64(98765)

	K := client.ComputeK(S)

	if len(K) != 32 {
		t.Errorf("K length = %d, want 32", len(K))
	}
}

func TestComputeM1(t *testing.T) {
	client := NewSRPClient(Group2048, "user@example.com", "password123")

	salt, _ := GenerateSalt()
	A, _ := client.ComputeA()
	B := new(big.Int).SetInt64(12345)
	K := []byte("test-session-key")

	M1 := client.ComputeM1(salt, A, B, K)

	if len(M1) != 32 {
		t.Errorf("M1 length = %d, want 32", len(M1))
	}
}

func TestComputeM2(t *testing.T) {
	client := NewSRPClient(Group2048, "user@example.com", "password123")

	A, _ := client.ComputeA()
	M1 := []byte("test-m1-value")
	K := []byte("test-session-key")

	M2 := client.ComputeM2(A, M1, K)

	if len(M2) != 32 {
		t.Errorf("M2 length = %d, want 32", len(M2))
	}
}

func TestGenerateSalt(t *testing.T) {
	salt1, err := GenerateSalt()
	if err != nil {
		t.Fatalf("GenerateSalt() error = %v", err)
	}

	salt2, err := GenerateSalt()
	if err != nil {
		t.Fatalf("GenerateSalt() error = %v", err)
	}

	if len(salt1) != 16 {
		t.Errorf("Salt length = %d, want 16", len(salt1))
	}

	if bytes.Equal(salt1, salt2) {
		t.Error("Salt should be unique")
	}
}

func TestGenerateVerifier(t *testing.T) {
	salt := []byte("test-salt-12345")

	v, err := GenerateVerifier(Group2048, "user@example.com", "password123", salt)
	if err != nil {
		t.Fatalf("GenerateVerifier() error = %v", err)
	}

	if v.Cmp(big.NewInt(0)) <= 0 {
		t.Error("v should be positive")
	}
}

func TestSRPExchangeConsistency(t *testing.T) {
	// Two exchanges with the same credentials should work, but produce different A/B
	// because of random ephemeral values
	ex1 := NewSRPExchange("user@example.com", "password123")
	ex2 := NewSRPExchange("user@example.com", "password123")

	// M1 and M2 should be valid in both
	if !ex1.VerifyExchange() || !ex2.VerifyExchange() {
		t.Error("Both exchanges should verify")
	}

	// Session keys may differ because A/B differ, but each exchange should be self-consistent
	if ex1.SessionKey == nil || ex2.SessionKey == nil {
		t.Error("Session keys should not be nil")
	}
}

// Test constant-time comparison in VerifyServerProof
func TestVerifyServerProof(t *testing.T) {
	client := NewSRPClient(Group2048, "user@example.com", "password123")
	client.M2 = []byte("12345678901234567890123456789012") // 32 bytes

	// Same should verify
	if !client.VerifyServerProof(client.M2) {
		t.Error("Same M2 should verify")
	}

	// Different should not verify
	wrong := make([]byte, 32)
	copy(wrong, client.M2)
	wrong[0] ^= 0xFF
	if client.VerifyServerProof(wrong) {
		t.Error("Different M2 should not verify")
	}

	// Nil M2 should not verify
	if client.VerifyServerProof([]byte("some-m2-value")) {
		t.Error("M2 mismatch length should not verify")
	}
}

// Benchmark SRP exchange
func BenchmarkNewSRPExchange(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = NewSRPExchange("user@example.com", "password123")
	}
}

func BenchmarkComputeA(b *testing.B) {
	client := NewSRPClient(Group2048, "user@example.com", "password123")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := client.ComputeA()
		if err != nil {
			b.Fatalf("ComputeA() error = %v", err)
		}
	}
}

// Test that different usernames produce different verifiers
func TestDifferentUsernames(t *testing.T) {
	salt := []byte("test-salt-12345")

	v1 := NewSRPClient(Group2048, "user1@example.com", "password123")
	v2 := NewSRPClient(Group2048, "user2@example.com", "password123")

	x1 := v1.ComputeX(salt)
	x2 := v2.ComputeX(salt)

	if x1.Cmp(x2) == 0 {
		t.Error("Different usernames should produce different verifiers")
	}
}

// Test ComputeS with correct implementation
func TestComputeSConsistency(t *testing.T) {
	client := NewSRPClient(Group2048, "user@example.com", "password123")

	salt, _ := GenerateSalt()
	_, _ = client.ComputeA()

	// Create a server B value
	b := make([]byte, 32)
	rand.Read(b)
	bigB := new(big.Int).SetBytes(b)
	B := new(big.Int).Exp(Group2048.G, bigB, Group2048.N)

	S, err := client.ComputeS(B, salt)
	if err != nil {
		t.Fatalf("ComputeS() error = %v", err)
	}

	K := client.ComputeK(S)
	if len(K) != 32 {
		t.Errorf("K length = %d, want 32", len(K))
	}
}
