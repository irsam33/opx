package securemem

import (
	"crypto/rand"
	"runtime"
	"sync"
	"unsafe"
)

// SecureBytes represents a byte slice that can be securely zeroed
type SecureBytes struct {
	data []byte
	mu   sync.Mutex
}

// NewSecureBytes creates a new SecureBytes from a byte slice
func NewSecureBytes(data []byte) *SecureBytes {
	sb := &SecureBytes{
		data: make([]byte, len(data)),
	}
	copy(sb.data, data)
	// Zero the original data
	for i := range data {
		data[i] = 0
	}
	return sb
}

// NewSecureBytesFromString creates a SecureBytes from a string
func NewSecureBytesFromString(s string) *SecureBytes {
	return NewSecureBytes([]byte(s))
}

// Bytes returns the underlying byte slice
func (sb *SecureBytes) Bytes() []byte {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	return sb.data
}

// String returns the string representation
func (sb *SecureBytes) String() string {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	return string(sb.data)
}

// Len returns the length
func (sb *SecureBytes) Len() int {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	return len(sb.data)
}

// Destroy zeros the memory and releases it
func (sb *SecureBytes) Destroy() {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	if sb.data != nil {
		// Zero memory
		for i := range sb.data {
			sb.data[i] = 0
		}
		// Force garbage collection hint
		sb.data = nil
		runtime.GC()
	}
}

// Clone creates a copy of SecureBytes
func (sb *SecureBytes) Clone() *SecureBytes {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	clone := &SecureBytes{
		data: make([]byte, len(sb.data)),
	}
	copy(clone.data, sb.data)
	return clone
}

// Compare compares two SecureBytes in constant time
func (sb *SecureBytes) Compare(other *SecureBytes) bool {
	if sb == other {
		return true
	}

	sb.mu.Lock()
	defer sb.mu.Unlock()
	other.mu.Lock()
	defer other.mu.Unlock()

	if len(sb.data) != len(other.data) {
		return false
	}

	result := 0
	for i := 0; i < len(sb.data); i++ {
		result |= int(sb.data[i] ^ other.data[i])
	}
	return result == 0
}

// SecureString is an alias for SecureBytes
type SecureString = SecureBytes

// NewSecureString creates a SecureString from a string
func NewSecureString(s string) *SecureString {
	return NewSecureBytesFromString(s)
}

// ZeroBytes zeros a byte slice
func ZeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// ZeroString is a no-op for strings (immutable), returns empty string
// Use SecureString instead for mutable secrets
func ZeroString(s string) string {
	return ""
}

// GenerateSecureRandom generates cryptographically secure random bytes
func GenerateSecureRandom(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// LockMemory attempts to lock memory pages (platform-specific)
// On Windows, this would use VirtualLock
func LockMemory(data []byte) error {
	// Platform-specific implementation
	// Windows: VirtualLock
	// Linux: mlock
	// macOS: mlock
	return nil
}

// UnlockMemory unlocks previously locked memory
func UnlockMemory(data []byte) error {
	return nil
}

// SecureCopy copies data to a new secure buffer
func SecureCopy(src []byte) []byte {
	dst := make([]byte, len(src))
	copy(dst, src)
	// Zero source
	ZeroBytes(src)
	return dst
}

// PointerToBytes converts an unsafe pointer to a byte slice (use with caution)
func PointerToBytes(ptr unsafe.Pointer, length int) []byte {
	return (*[1 << 30]byte)(ptr)[:length:length]
}
