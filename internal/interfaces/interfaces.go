package interfaces

import (
	"context"

	"github.com/user/opx/internal/vault"
)

// Storage defines the storage interface
type Storage interface {
	SaveItem(item *vault.Item) error
	LoadItem(id string) (*vault.Item, error)
	ListItems() ([]string, error)
	DeleteItem(id string) error
	Backup(path string) error
	Restore(path string) error
}

// Authenticator defines the authentication interface
type Authenticator interface {
	SignIn(password string) error
	SignOut() error
	IsSignedIn() bool
	GetMasterKey() ([]byte, error)
	LoadConfig() error
	Destroy()
}

// EventLogger defines the event logging interface
type EventLogger interface {
	Log(eventType string, actor, target string, details map[string]interface{}) error
	Query(eventType string, actor string, since interface{}, limit int) []interface{}
	GetRecent(n int) []interface{}
	Clear() error
	Count() int
}

// ItemManager defines the item management interface
type ItemManager interface {
	Create(title, category, vault string) (*vault.Item, error)
	Get(id string) (*vault.Item, error)
	Update(id string, fields map[string]string) error
	Delete(id string) error
	Search(query string) ([]*vault.Item, error)
	List() ([]*vault.Item, error)
}

// VaultManager defines the vault management interface
type VaultManager interface {
	List() ([]string, error)
	Get(name string) (*vault.Vault, error)
	Create(name string) error
	Delete(name string) error
}

// SSHKeyManager defines the SSH key management interface
type SSHKeyManager interface {
	Generate(keyType, name string) (string, error)
	List() ([]string, error)
	Get(name string) (string, error)
	Delete(name string) error
}

// SyncManager defines the sync interface
type SyncManager interface {
	Push() error
	Pull() error
	Sync() error
	Status() string
}

// PluginManager defines the plugin interface
type PluginManager interface {
	Discover() error
	List() []interface{}
	Get(name string) (interface{}, error)
	Execute(name string, args []string) error
	Install(source, name string) error
	Remove(name string) error
}

// ConnectServer defines the Connect server interface
type ConnectServer interface {
	Start() error
	Stop() error
	IsRunning() bool
}

// ContextAware defines context-aware operations
type ContextAware interface {
	WithContext(ctx context.Context) interface{}
}
