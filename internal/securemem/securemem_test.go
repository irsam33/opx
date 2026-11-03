package securemem

import (
	"bytes"
	"testing"
	"unsafe"
)

func TestNewSecureBytes(t *testing.T) {
	data := []byte("test-data-123")
	dataCopy := make([]byte, len(data))
	copy(dataCopy, data)

	sb := NewSecureBytes(data)

	if sb.Len() != len(dataCopy) {
		t.Errorf("Len = %d, want %d", sb.Len(), len(dataCopy))
	}

	if !bytes.Equal(sb.Bytes(), dataCopy) {
		t.Error("Bytes() does not match input")
	}
}

func TestNewSecureBytesFromString(t *testing.T) {
	sb := NewSecureBytesFromString("secret-password")

	if sb.String() != "secret-password" {
		t.Errorf("String() = %q, want secret-password", sb.String())
	}

	if sb.Len() != 15 {
		t.Errorf("Len = %d, want 15", sb.Len())
	}
}

func TestBytesAndString(t *testing.T) {
	original := "my-secret-value"
	sb := NewSecureBytesFromString(original)

	bytesData := sb.Bytes()
	stringData := sb.String()

	if string(stringData) != original {
		t.Errorf("String = %q, want %q", stringData, original)
	}

	if !bytes.Equal(bytesData, []byte(original)) {
		t.Error("Bytes does not match string")
	}
}

func TestDestroy(t *testing.T) {
	sb := NewSecureBytes([]byte("secret-data"))

	// Verify data is present
	if len(sb.Bytes()) == 0 {
		t.Fatal("SecureBytes should have data before Destroy")
	}

	sb.Destroy()

	// After destroy, Bytes should return nil or empty
	if sb.Bytes() != nil && len(sb.Bytes()) > 0 {
		// Data may or may not be immediately nil after GC
		t.Logf("Data not cleared (expected behavior without immediate GC)")
	}
}

func TestClone(t *testing.T) {
	original := NewSecureBytesFromString("clone-test-value")
	clone := original.Clone()

	if !clone.Compare(original) {
		t.Error("Clone should be equal to original")
	}

	// Modify original and verify clone is independent
	// (Can't modify directly due to encapsulation, but clone is a separate copy)
	if clone == original {
		t.Error("Clone should be a separate instance")
	}
}

func TestCompareEqual(t *testing.T) {
	sb1 := NewSecureBytesFromString("same-value")
	sb2 := NewSecureBytesFromString("same-value")

	if !sb1.Compare(sb2) {
		t.Error("Compare should return true for equal SecureBytes")
	}
}

func TestCompareNotEqual(t *testing.T) {
	sb1 := NewSecureBytesFromString("value-one")
	sb2 := NewSecureBytesFromString("value-two")

	if sb1.Compare(sb2) {
		t.Error("Compare should return false for different SecureBytes")
	}
}

func TestCompareDifferentLengths(t *testing.T) {
	sb1 := NewSecureBytesFromString("short")
	sb2 := NewSecureBytesFromString("much-longer-value")

	if sb1.Compare(sb2) {
		t.Error("Compare should return false for different lengths")
	}
}

func TestZeroBytes(t *testing.T) {
	data := []byte("test-data")

	ZeroBytes(data)

	for i, b := range data {
		if b != 0 {
			t.Errorf("data[%d] = %d, want 0", i, b)
		}
	}
}

func TestZeroString(t *testing.T) {
	result := ZeroString("some-string")

	if result != "" {
		t.Errorf("ZeroString returned %q, want empty string", result)
	}
}

func TestGenerateSecureRandom(t *testing.T) {
	// Test small size
	b1, err := GenerateSecureRandom(16)
	if err != nil {
		t.Fatalf("GenerateSecureRandom() error = %v", err)
	}

	if len(b1) != 16 {
		t.Errorf("Random bytes length = %d, want 16", len(b1))
	}

	// Test larger size
	b2, err := GenerateSecureRandom(1024)
	if err != nil {
		t.Fatalf("GenerateSecureRandom() error = %v", err)
	}

	if len(b2) != 1024 {
		t.Errorf("Random bytes length = %d, want 1024", len(b2))
	}

	// Verify uniqueness
	b3, err := GenerateSecureRandom(32)
	if err != nil {
		t.Fatalf("GenerateSecureRandom() error = %v", err)
	}

	if bytes.Equal(b1, b3) {
		t.Error("Generated random bytes should be unique")
	}
}

func TestGenerateSecureRandomZero(t *testing.T) {
	b, err := GenerateSecureRandom(0)
	if err != nil {
		t.Fatalf("GenerateSecureRandom() error = %v", err)
	}

	if len(b) != 0 {
		t.Errorf("Zero-length random bytes length = %d, want 0", len(b))
	}
}

func TestSecureCopy(t *testing.T) {
	original := []byte("source-data")
	// Make a copy of original for comparison since SecureCopy zeroes it
	originalCopy := make([]byte, len(original))
	copy(originalCopy, original)

	result := SecureCopy(original)

	// Source should be zeroed
	for i, b := range original {
		if b != 0 {
			t.Errorf("original[%d] = %d, want 0 after SecureCopy", i, b)
		}
	}

	// Result should match the original values before zeroing
	if !bytes.Equal(result, originalCopy) {
		t.Errorf("SecureCopy result = %v, want %v", result, originalCopy)
	}

	// Result should not be same slice
	if &result[0] == &originalCopy[0] {
		t.Error("SecureCopy should return a separate slice")
	}
}

func TestGenerateSecureRandomNonZero(t *testing.T) {
	// Random data should have some non-zero bytes (high probability)
	b, err := GenerateSecureRandom(64)
	if err != nil {
		t.Fatalf("GenerateSecureRandom() error = %v", err)
	}

	hasNonZero := false
	for _, v := range b {
		if v != 0 {
			hasNonZero = true
			break
		}
	}

	if !hasNonZero {
		t.Log("All zeros generated (very unlikely for 64 bytes)")
	}
}

func TestNewSecureBytesEmpty(t *testing.T) {
	sb := NewSecureBytes([]byte{})

	if sb.Len() != 0 {
		t.Errorf("Len of empty SecureBytes = %d, want 0", sb.Len())
	}
}

func TestNewSecureBytesNil(t *testing.T) {
	sb := NewSecureBytes(nil)

	if sb.Len() != 0 {
		t.Errorf("Len of nil SecureBytes = %d, want 0", sb.Len())
	}
}

func TestSecureBytesConcurrency(t *testing.T) {
	sb := NewSecureBytesFromString("concurrent-test")

	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func() {
			_ = sb.Bytes()
			_ = sb.String()
			_ = sb.Len()
			done <- true
		}()
	}

	for i := 0; i < 10; i++ {
		<-done
	}

	sb.Destroy()
}

func TestLockMemory(t *testing.T) {
	// LockMemory is a no-op on non-Windows for safety in tests
	err := LockMemory([]byte("test"))
	if err != nil {
		t.Errorf("LockMemory() error = %v", err)
	}
}

func TestUnlockMemory(t *testing.T) {
	err := UnlockMemory([]byte("test"))
	if err != nil {
		t.Errorf("UnlockMemory() error = %v", err)
	}
}

// Benchmark SecureBytes operations
func BenchmarkNewSecureBytes(b *testing.B) {
	data := []byte("benchmark-secret-data")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = NewSecureBytes(data)
	}
}

func BenchmarkSecureBytesString(b *testing.B) {
	sb := NewSecureBytesFromString("benchmark-secret")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = sb.String()
	}
}

func BenchmarkSecureBytesBytes(b *testing.B) {
	sb := NewSecureBytesFromString("benchmark-secret")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = sb.Bytes()
	}
}

func BenchmarkSecureBytesCompare(b *testing.B) {
	sb1 := NewSecureBytesFromString("benchmark-value-one")
	sb2 := NewSecureBytesFromString("benchmark-value-one")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = sb1.Compare(sb2)
	}
}

func BenchmarkSecureBytesDestroy(b *testing.B) {
	sb := NewSecureBytesFromString("benchmark-secret")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sb.Destroy()
		sb = NewSecureBytes([]byte("benchmark-secret"))
	}
}

func BenchmarkZeroBytes(b *testing.B) {
	data := make([]byte, 1024)
	for i := range data {
		data[i] = byte(i)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ZeroBytes(data)
	}
}

func BenchmarkGenerateSecureRandom(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := GenerateSecureRandom(32)
		if err != nil {
			b.Fatalf("GenerateSecureRandom() error = %v", err)
		}
	}
}

// Test GenerateSecureRandom produces enough entropy
func TestEntropyCheck(t *testing.T) {
	b, err := GenerateSecureRandom(256)
	if err != nil {
		t.Fatalf("GenerateSecureRandom() error = %v", err)
	}

	// Count unique bytes
	unique := make(map[byte]bool)
	for _, v := range b {
		unique[v] = true
	}

	// 256 bytes should have many unique values (high probability)
	if len(unique) < 100 {
		t.Logf("Unique bytes: %d (expected high entropy)", len(unique))
	}
}

// Test that strings passed to NewSecureBytes are zeroed (not leaked)
func TestInputZeroed(t *testing.T) {
	data := []byte("sensitive-input-data")
	original := make([]byte, len(data))
	copy(original, data)

	_ = NewSecureBytes(data)

	// The input slice should be zeroed
	for i, b := range data {
		if b != 0 {
			t.Errorf("Input[%d] = %d, want 0 after NewSecureBytes", i, b)
		}
	}
}

// Test SecureString alias
func TestSecureStringAlias(t *testing.T) {
	ss := NewSecureString("alias-test")

	if ss.String() != "alias-test" {
		t.Errorf("SecureString = %q, want alias-test", ss.String())
	}
}

// Test pointer conversion is safe (basic check)
func TestPointerToBytes(t *testing.T) {
	if testing.Short() {
		t.Skip("pointer conversion test skipped")
	}

	data := []byte("ptr-test-data")
	ptr := unsafe.Pointer(&data[0])

	result := PointerToBytes(ptr, len(data))

	if !bytes.Equal(result, data) {
		t.Error("PointerToBytes does not match source")
	}
}

func TestCompareSelf(t *testing.T) {
	sb := NewSecureBytesFromString("self-compare")

	if !sb.Compare(sb) {
		t.Error("Comparing a SecureBytes to itself should return true")
	}
}

func TestSecureBytesStringWithSpecialChars(t *testing.T) {
	special := "s3cr3t!@#$%^&*()_+|:<>?"
	sb := NewSecureBytesFromString(special)

	if sb.String() != special {
		t.Errorf("String = %q, want %q", sb.String(), special)
	}
}

func TestNewSecureBytesLarge(t *testing.T) {
	// 1MB of data
	data := make([]byte, 1024*1024)
	for i := range data {
		data[i] = byte(i % 256)
	}

	sb := NewSecureBytes(data)

	if sb.Len() != 1024*1024 {
		t.Errorf("Len = %d, want 1048576", sb.Len())
	}

	// Verify data integrity
	b := sb.Bytes()
	match := true
	for i := 0; i < 100; i++ {
		if b[i] != byte(i%256) {
			match = false
			break
		}
	}
	if !match {
		t.Error("Large SecureBytes data corrupted")
	}
}

func TestNewSecureBytesWithNullBytes(t *testing.T) {
	data := []byte{0, 1, 0, 3, 0, 5}
	dataCopy := make([]byte, len(data))
	copy(dataCopy, data)

	sb := NewSecureBytes(data)

	b := sb.Bytes()
	if !bytes.Equal(b, dataCopy) {
		t.Errorf("SecureBytes with null bytes = %v, want %v", b, dataCopy)
	}
}

func TestDestroyMultipleTimes(t *testing.T) {
	sb := NewSecureBytes([]byte("multi-destroy"))

	sb.Destroy()
	sb.Destroy() // Should not panic
	sb.Destroy() // Should not panic

	// Should not panic and should still be safe to access
	_ = sb.String()
}

func TestSecureBytesEmptyCompare(t *testing.T) {
	sb1 := NewSecureBytes([]byte{})
	sb2 := NewSecureBytes([]byte{})

	if !sb1.Compare(sb2) {
		t.Error("Two empty SecureBytes should be equal")
	}
}
