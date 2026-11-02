package retry

import (
	"fmt"
	"time"
)

// RetryConfig holds retry configuration
type RetryConfig struct {
	MaxRetries   int
	InitialDelay time.Duration
	MaxDelay     time.Duration
	Multiplier   float64
}

// DefaultConfig returns default retry configuration
func DefaultConfig() *RetryConfig {
	return &RetryConfig{
		MaxRetries:   3,
		InitialDelay: 1 * time.Second,
		MaxDelay:     30 * time.Second,
		Multiplier:   2.0,
	}
}

// Do executes a function with retry logic
func Do(config *RetryConfig, fn func() error) error {
	var lastErr error
	delay := config.InitialDelay

	for i := 0; i <= config.MaxRetries; i++ {
		err := fn()
		if err == nil {
			return nil
		}
		lastErr = err

		if i < config.MaxRetries {
			time.Sleep(delay)
			delay = time.Duration(float64(delay) * config.Multiplier)
			if delay > config.MaxDelay {
				delay = config.MaxDelay
			}
		}
	}

	return fmt.Errorf("max retries (%d) exceeded: %w", config.MaxRetries, lastErr)
}

// DoWithResult executes a function with retry and returns a result
func DoWithResult[T any](config *RetryConfig, fn func() (T, error)) (T, error) {
	var lastErr error
	var result T
	delay := config.InitialDelay

	for i := 0; i <= config.MaxRetries; i++ {
		r, err := fn()
		if err == nil {
			return r, nil
		}
		lastErr = err
		result = r

		if i < config.MaxRetries {
			time.Sleep(delay)
			delay = time.Duration(float64(delay) * config.Multiplier)
			if delay > config.MaxDelay {
				delay = config.MaxDelay
			}
		}
	}

	return result, fmt.Errorf("max retries (%d) exceeded: %w", config.MaxRetries, lastErr)
}

// IsRetryable checks if an error is retryable
func IsRetryable(err error) bool {
	// Network errors, timeouts, and temporary failures are retryable
	if err == nil {
		return false
	}
	errStr := err.Error()
	retryableErrors := []string{
		"connection refused",
		"timeout",
		"temporary failure",
		"network unreachable",
		"connection reset",
	}
	for _, re := range retryableErrors {
		if contains(errStr, re) {
			return true
		}
	}
	return false
}

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
