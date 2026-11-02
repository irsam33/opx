package ctxutil

import (
	"context"
	"time"
)

// WithTimeout creates a context with timeout
func WithTimeout(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, timeout)
}

// WithCancel creates a cancellable context
func WithCancel(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithCancel(parent)
}

// WithValue adds a value to context
func WithValue(parent context.Context, key, val interface{}) context.Context {
	return context.WithValue(parent, key, val)
}

// GetValue retrieves a value from context
func GetValue(ctx context.Context, key interface{}) interface{} {
	return ctx.Value(key)
}

// CheckContext checks if context is cancelled
func CheckContext(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

// DefaultTimeout returns a default timeout duration
func DefaultTimeout() time.Duration {
	return 30 * time.Second
}

// ShortTimeout returns a short timeout for quick operations
func ShortTimeout() time.Duration {
	return 5 * time.Second
}

// LongTimeout returns a long timeout for heavy operations
func LongTimeout() time.Duration {
	return 5 * time.Minute
}
