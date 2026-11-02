package apperror

import (
	"fmt"
)

// ErrorCode represents an error code
type ErrorCode string

const (
	ErrNotSignedIn      ErrorCode = "NOT_SIGNED_IN"
	ErrItemNotFound     ErrorCode = "ITEM_NOT_FOUND"
	ErrVaultNotFound    ErrorCode = "VAULT_NOT_FOUND"
	ErrInvalidInput     ErrorCode = "INVALID_INPUT"
	ErrPermissionDenied ErrorCode = "PERMISSION_DENIED"
	ErrNetworkError     ErrorCode = "NETWORK_ERROR"
	ErrStorageError     ErrorCode = "STORAGE_ERROR"
	ErrCryptoError      ErrorCode = "CRYPTO_ERROR"
	ErrConfigError      ErrorCode = "CONFIG_ERROR"
	ErrPluginError      ErrorCode = "PLUGIN_ERROR"
	ErrSyncError        ErrorCode = "SYNC_ERROR"
	ErrUnknown          ErrorCode = "UNKNOWN_ERROR"
)

// AppError represents a standardized application error
type AppError struct {
	Code    ErrorCode
	Message string
	Cause   error
	Hint    string
}

// New creates a new AppError
func New(code ErrorCode, message string) *AppError {
	return &AppError{
		Code:    code,
		Message: message,
	}
}

// Wrap wraps an existing error
func Wrap(code ErrorCode, message string, cause error) *AppError {
	return &AppError{
		Code:    code,
		Message: message,
		Cause:   cause,
	}
}

// WithHint adds a hint to the error
func (e *AppError) WithHint(hint string) *AppError {
	e.Hint = hint
	return e
}

// Error implements the error interface
func (e *AppError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("[%s] %s: %v", e.Code, e.Message, e.Cause)
	}
	return fmt.Sprintf("[%s] %s", e.Code, e.Message)
}

// Unwrap returns the underlying error
func (e *AppError) Unwrap() error {
	return e.Cause
}

// Is checks if the error is of a specific code
func (e *AppError) Is(code ErrorCode) bool {
	return e.Code == code
}

// UserMessage returns a user-friendly message
func (e *AppError) UserMessage() string {
	msg := e.Message
	if e.Hint != "" {
		msg += "\n  Hint: " + e.Hint
	}
	return msg
}

// Common errors
var (
	ErrNotSignedInError = New(ErrNotSignedIn, "not signed in")
	ErrItemNotFoundErr  = New(ErrItemNotFound, "item not found")
	ErrVaultNotFoundErr = New(ErrVaultNotFound, "vault not found")
	ErrInvalidInputErr  = New(ErrInvalidInput, "invalid input")
)

// IsAppError checks if an error is an AppError
func IsAppError(err error) bool {
	_, ok := err.(*AppError)
	return ok
}

// GetCode extracts the error code from an error
func GetCode(err error) ErrorCode {
	if ae, ok := err.(*AppError); ok {
		return ae.Code
	}
	return ErrUnknown
}
