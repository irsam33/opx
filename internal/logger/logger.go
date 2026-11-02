package logger

import (
	"fmt"
	"os"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// Logger wraps zerolog.Logger
type Logger struct {
	zerolog.Logger
}

// New creates a new logger
func New(level string, output string) *Logger {
	lvl, err := zerolog.ParseLevel(level)
	if err != nil {
		lvl = zerolog.InfoLevel
	}

	var out *os.File
	switch output {
	case "stderr":
		out = os.Stderr
	case "stdout":
		out = os.Stdout
	default:
		out = os.Stderr
	}

	logger := zerolog.New(out).With().Timestamp().Logger().Level(lvl)
	return &Logger{Logger: logger}
}

// Default returns a default logger
func Default() *Logger {
	return New("info", "stderr")
}

// Debug logs a debug message
func (l *Logger) Debug(msg string, fields ...interface{}) {
	l.Logger.Debug().Fields(fields).Msg(msg)
}

// Info logs an info message
func (l *Logger) Info(msg string, fields ...interface{}) {
	l.Logger.Info().Fields(fields).Msg(msg)
}

// Warn logs a warning message
func (l *Logger) Warn(msg string, fields ...interface{}) {
	l.Logger.Warn().Fields(fields).Msg(msg)
}

// Error logs an error message
func (l *Logger) Error(msg string, err error, fields ...interface{}) {
	l.Logger.Error().Err(err).Fields(fields).Msg(msg)
}

// Fatal logs a fatal message and exits
func (l *Logger) Fatal(msg string, err error, fields ...interface{}) {
	l.Logger.Fatal().Err(err).Fields(fields).Msg(msg)
}

// WithField adds a field to the logger
func (l *Logger) WithField(key string, value interface{}) *Logger {
	newLogger := l.Logger.With().Interface(key, value).Logger()
	return &Logger{Logger: newLogger}
}

// Init initializes the global logger
func Init(level string) {
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	if lvl, err := zerolog.ParseLevel(level); err == nil {
		zerolog.SetGlobalLevel(lvl)
	}
	log.Logger = zerolog.New(os.Stderr).With().Timestamp().Logger()
}

// Global logger instance
var globalLogger = Default()

// SetGlobal sets the global logger
func SetGlobal(l *Logger) {
	globalLogger = l
}

// GetGlobal returns the global logger
func GetGlobal() *Logger {
	return globalLogger
}

// Convenience functions using global logger
func Debug(msg string, fields ...interface{}) {
	globalLogger.Debug(msg, fields...)
}

func Info(msg string, fields ...interface{}) {
	globalLogger.Info(msg, fields...)
}

func Warn(msg string, fields ...interface{}) {
	globalLogger.Warn(msg, fields...)
}

func Error(msg string, err error, fields ...interface{}) {
	globalLogger.Error(msg, err, fields...)
}

func Fatal(msg string, err error, fields ...interface{}) {
	globalLogger.Fatal(msg, err, fields...)
}

// FormatDuration formats a duration for logging
func FormatDuration(d time.Duration) string {
	return d.String()
}

var _ = fmt.Sprintf
