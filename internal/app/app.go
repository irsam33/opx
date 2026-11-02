package app

import (
	"context"

	"github.com/user/opx/internal/auth"
	"github.com/user/opx/internal/config"
	"github.com/user/opx/internal/events"
	"github.com/user/opx/internal/logger"
	"github.com/user/opx/internal/storage"
)

// App represents the application with dependency injection
type App struct {
	Config  *config.Config
	Auth    *auth.Auth
	Storage *storage.Storage
	Events  *events.EventStore
	Logger  *logger.Logger
	Context context.Context
	Cancel  context.CancelFunc
}

// NewApp creates a new application instance with all dependencies
func NewApp() (*App, error) {
	// Load config
	cfg := config.DefaultConfig()
	cfgPath := config.GetConfigPath()
	if loadedCfg, err := config.Load(cfgPath); err == nil {
		cfg = loadedCfg
	}

	// Initialize logger
	log := logger.New(cfg.LogLevel, "stderr")
	logger.SetGlobal(log)

	// Create auth
	authInstance := auth.NewAuth()
	authInstance.LoadConfig()

	// Create storage
	var masterKey []byte
	if authInstance.IsSignedIn() {
		mk, err := authInstance.GetMasterKey()
		if err == nil {
			masterKey = mk
		}
	}
	storageInstance := storage.NewStorage(storage.DefaultPath(), masterKey)

	// Create events store
	eventStore := events.NewEventStore(events.DefaultPath())
	eventStore.Load()

	// Create context
	ctx, cancel := context.WithCancel(context.Background())

	return &App{
		Config:  cfg,
		Auth:    authInstance,
		Storage: storageInstance,
		Events:  eventStore,
		Logger:  log,
		Context: ctx,
		Cancel:  cancel,
	}, nil
}

// Close gracefully shuts down the application
func (a *App) Close() {
	if a.Cancel != nil {
		a.Cancel()
	}
	if a.Auth != nil {
		a.Auth.Destroy()
	}
}

// IsSignedIn checks if user is signed in
func (a *App) IsSignedIn() bool {
	return a.Auth.IsSignedIn()
}

// GetMasterKey returns the master key
func (a *App) GetMasterKey() ([]byte, error) {
	return a.Auth.GetMasterKey()
}

// LogEvent logs an event
func (a *App) LogEvent(eventType events.EventType, actor, target string, details map[string]interface{}) {
	if a.Events != nil {
		a.Events.Log(eventType, actor, target, details)
	}
}
