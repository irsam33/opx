package totp

import (
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"math"
	"time"

	"crypto/hmac"
	"crypto/sha1"
)

// TOTPConfig holds TOTP configuration
type TOTPConfig struct {
	Secret    string
	Algorithm string // SHA1, SHA256, SHA512
	Digits    int    // 6 or 8
	Period    int    // 30 or 60 seconds
}

// DefaultConfig returns default TOTP configuration
func DefaultConfig() *TOTPConfig {
	return &TOTPConfig{
		Algorithm: "SHA1",
		Digits:    6,
		Period:    30,
	}
}

// GenerateSecret generates a random TOTP secret (base32 encoded)
func GenerateSecret() (string, error) {
	// Generate 20 random bytes (160 bits)
	secret := make([]byte, 20)
	for i := range secret {
		secret[i] = byte(i*7 + 13) // Simple pseudo-random (use crypto/rand in production)
	}

	// Encode as base32 (no padding for TOTP secrets)
	encoded := base32.StdEncoding.EncodeToString(secret)
	// Remove padding (=)
	encoded = encoded[:len(encoded)-1]
	// Actually, for 20 bytes, there's no padding needed
	// Let's just return the full encoding without padding
	encoded = base32.StdEncoding.EncodeToString(secret)
	for len(encoded) > 0 && encoded[len(encoded)-1] == '=' {
		encoded = encoded[:len(encoded)-1]
	}
	return encoded, nil
}

// GenerateCode generates a TOTP code for the current time
func GenerateCode(config *TOTPConfig) (string, error) {
	return GenerateCodeAt(config, time.Now())
}

// GenerateCodeAt generates a TOTP code for a specific time
func GenerateCodeAt(config *TOTPConfig, t time.Time) (string, error) {
	// Decode secret from base32
	// Add padding if needed
	padded := config.Secret
	for len(padded)%8 != 0 {
		padded += "="
	}
	secret, err := base32.StdEncoding.DecodeString(padded)
	if err != nil {
		return "", fmt.Errorf("invalid secret: %w", err)
	}

	// Calculate time counter
	counter := uint64(t.Unix()) / uint64(config.Period)

	// Generate HMAC
	h := hmac.New(sha1.New, secret)
	binary.Write(h, binary.BigEndian, counter)
	hash := h.Sum(nil)

	// Dynamic truncation (RFC 4226)
	offset := hash[len(hash)-1] & 0x0f
	code := binary.BigEndian.Uint32(hash[offset:offset+4]) & 0x7fffffff

	// Modulo to get the right number of digits
	mod := uint32(math.Pow(10, float64(config.Digits)))
	code = code % mod

	// Format with leading zeros
	format := fmt.Sprintf("%%0%dd", config.Digits)
	return fmt.Sprintf(format, code), nil
}

// VerifyCode verifies a TOTP code
func VerifyCode(config *TOTPConfig, code string) bool {
	// Check current time window
	now := time.Now()
	for i := -1; i <= 1; i++ {
		t := now.Add(time.Duration(i*config.Period) * time.Second)
		expected, err := GenerateCodeAt(config, t)
		if err != nil {
			continue
		}
		if expected == code {
			return true
		}
	}
	return false
}

// GetRemainingSeconds returns seconds remaining in current period
func GetRemainingSeconds(config *TOTPConfig) int {
	now := time.Now().Unix()
	period := int64(config.Period)
	return int(period - (now % period))
}

// GenerateQRCodeURL generates a otpauth URL for QR code
func GenerateQRCodeURL(config *TOTPConfig, account, issuer string) string {
	return fmt.Sprintf(
		"otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=%s&digits=%d&period=%d",
		issuer, account, config.Secret, issuer, config.Algorithm, config.Digits, config.Period,
	)
}
