package graceful

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

// ShutdownManager manages graceful shutdown
type ShutdownManager struct {
	handlers []ShutdownHandler
	mu       sync.Mutex
	timeout  time.Duration
}

// ShutdownHandler is a function called during shutdown
type ShutdownHandler func() error

// NewShutdownManager creates a new shutdown manager
func NewShutdownManager(timeout time.Duration) *ShutdownManager {
	return &ShutdownManager{
		timeout: timeout,
	}
}

// Register registers a shutdown handler
func (sm *ShutdownManager) Register(handler ShutdownHandler) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.handlers = append(sm.handlers, handler)
}

// Shutdown executes all shutdown handlers
func (sm *ShutdownManager) Shutdown(ctx context.Context) error {
	sm.mu.Lock()
	handlers := sm.handlers
	sm.mu.Unlock()

	// Create timeout context
	ctx, cancel := context.WithTimeout(ctx, sm.timeout)
	defer cancel()

	var wg sync.WaitGroup
	errCh := make(chan error, len(handlers))

	for _, handler := range handlers {
		wg.Add(1)
		go func(h ShutdownHandler) {
			defer wg.Done()
			if err := h(); err != nil {
				errCh <- err
			}
		}(handler)
	}

	// Wait for all handlers or timeout
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// All handlers completed
	case <-ctx.Done():
		return fmt.Errorf("shutdown timeout exceeded")
	}

	// Collect errors
	close(errCh)
	var errs []error
	for err := range errCh {
		errs = append(errs, err)
	}

	if len(errs) > 0 {
		return fmt.Errorf("shutdown errors: %v", errs)
	}

	return nil
}

// WaitForSignal waits for an interrupt signal
func WaitForSignal() os.Signal {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	return <-sigCh
}

// RunWithGracefulShutdown runs a function with graceful shutdown support
func RunWithGracefulShutdown(run func() error, handlers ...ShutdownHandler) error {
	sm := NewShutdownManager(10 * time.Second)
	for _, h := range handlers {
		sm.Register(h)
	}

	// Start the main function in a goroutine
	errCh := make(chan error, 1)
	go func() {
		errCh <- run()
	}()

	// Wait for signal or completion
	select {
	case err := <-errCh:
		return err
	case sig := <-func() chan os.Signal {
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
		return ch
	}():
		fmt.Printf("\nReceived signal: %v. Shutting down gracefully...\n", sig)
		ctx := context.Background()
		if err := sm.Shutdown(ctx); err != nil {
			return err
		}
		return nil
	}
}
