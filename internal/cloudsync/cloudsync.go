package cloudsync

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/gorilla/websocket"
	"github.com/user/opx/internal/storage"
	"github.com/user/opx/internal/vault"
)

// CloudSyncConfig holds cloud sync configuration
type CloudSyncConfig struct {
	ServerURL string    `json:"server_url"`
	APIKey    string    `json:"api_key"`
	SyncDir   string    `json:"sync_dir"`
	LastSync  time.Time `json:"last_sync"`
}

// CloudSync manages cloud synchronization
type CloudSync struct {
	Config  *CloudSyncConfig
	Storage *storage.Storage
	WSConn  *websocket.Conn
}

// NewCloudSync creates a new cloud sync instance
func NewCloudSync(serverURL, apiKey string, storage *storage.Storage) *CloudSync {
	return &CloudSync{
		Config: &CloudSyncConfig{
			ServerURL: serverURL,
			APIKey:    apiKey,
			SyncDir:   storage.BasePath,
		},
		Storage: storage,
	}
}

// DefaultConfig returns default cloud sync config
func DefaultConfig() *CloudSyncConfig {
	return &CloudSyncConfig{
		ServerURL: "wss://sync.opx.example.com",
		SyncDir:   storage.DefaultPath(),
	}
}

// LoadConfig loads cloud sync config from disk
func LoadConfig() (*CloudSyncConfig, error) {
	configPath := filepath.Join(storage.DefaultPath(), "opx_cloud_sync.json")
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}

	var config CloudSyncConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	return &config, nil
}

// SaveConfig saves cloud sync config to disk
func SaveConfig(config *CloudSyncConfig) error {
	configPath := filepath.Join(storage.DefaultPath(), "opx_cloud_sync.json")
	os.MkdirAll(storage.DefaultPath(), 0700)

	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(configPath, data, 0600)
}

// Push pushes local items to the cloud
func (cs *CloudSync) Push() error {
	fmt.Println("Pushing local items to cloud...")

	ids, err := cs.Storage.ListItems()
	if err != nil {
		return fmt.Errorf("cannot list items: %w", err)
	}

	var items []*vault.Item
	for _, id := range ids {
		item, err := cs.Storage.LoadItem(id)
		if err != nil {
			continue
		}
		items = append(items, item)
	}

	data, err := json.Marshal(items)
	if err != nil {
		return err
	}

	url := cs.Config.ServerURL + "/api/v1/sync/push"
	req, err := http.NewRequest("POST", url, bytes.NewReader(data))
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "Bearer "+cs.Config.APIKey)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("push failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("push failed: %s - %s", resp.Status, string(body))
	}

	cs.Config.LastSync = time.Now()
	SaveConfig(cs.Config)

	fmt.Printf("Pushed %d items to cloud.\n", len(items))
	return nil
}

// Pull pulls items from the cloud
func (cs *CloudSync) Pull() error {
	fmt.Println("Pulling items from cloud...")

	url := cs.Config.ServerURL + "/api/v1/sync/pull"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "Bearer "+cs.Config.APIKey)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("pull failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("pull failed: %s - %s", resp.Status, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var items []*vault.Item
	if err := json.Unmarshal(body, &items); err != nil {
		return fmt.Errorf("invalid response: %w", err)
	}

	for _, item := range items {
		if err := cs.Storage.SaveItem(item); err != nil {
			fmt.Printf("  Warning: failed to save %s: %v\n", item.Title, err)
		}
	}

	cs.Config.LastSync = time.Now()
	SaveConfig(cs.Config)

	fmt.Printf("Pulled %d items from cloud.\n", len(items))
	return nil
}

// Sync performs bidirectional sync
func (cs *CloudSync) Sync() error {
	fmt.Println("Performing bidirectional sync...")

	if err := cs.Pull(); err != nil {
		fmt.Printf("  Pull warning: %v\n", err)
	}

	if err := cs.Push(); err != nil {
		fmt.Printf("  Push warning: %v\n", err)
	}

	fmt.Println("Sync complete.")
	return nil
}

// Status returns sync status
func (cs *CloudSync) Status() string {
	status := "Not configured"
	if cs.Config != nil && cs.Config.ServerURL != "" {
		status = "Configured"
		if !cs.Config.LastSync.IsZero() {
			status += fmt.Sprintf(" (last sync: %s)", cs.Config.LastSync.Format("2006-01-02 15:04:05"))
		}
	}
	return status
}

// ConnectWebSocket connects to the WebSocket sync server
func (cs *CloudSync) ConnectWebSocket() error {
	fmt.Println("Connecting to WebSocket sync server...")

	dialer := websocket.Dialer{
		HandshakeTimeout: 10 * time.Second,
	}

	headers := http.Header{}
	headers.Set("Authorization", "Bearer "+cs.Config.APIKey)

	conn, _, err := dialer.Dial(cs.Config.ServerURL, headers)
	if err != nil {
		return fmt.Errorf("WebSocket connection failed: %w", err)
	}

	cs.WSConn = conn
	fmt.Println("✅ Connected to WebSocket sync server")
	return nil
}

// DisconnectWebSocket disconnects from the WebSocket server
func (cs *CloudSync) DisconnectWebSocket() error {
	if cs.WSConn != nil {
		return cs.WSConn.Close()
	}
	return nil
}

// WatchForChanges watches for real-time changes via WebSocket
func (cs *CloudSync) WatchForChanges(handler func(*vault.Item)) error {
	if cs.WSConn == nil {
		return fmt.Errorf("not connected to WebSocket server")
	}

	fmt.Println("Watching for real-time changes...")

	for {
		_, message, err := cs.WSConn.ReadMessage()
		if err != nil {
			return fmt.Errorf("WebSocket read error: %w", err)
		}

		var msg struct {
			Type string      `json:"type"`
			Item *vault.Item `json:"item"`
		}
		if err := json.Unmarshal(message, &msg); err != nil {
			fmt.Printf("  Warning: invalid message: %v\n", err)
			continue
		}

		switch msg.Type {
		case "item_created":
			fmt.Printf("  [WS] Item created: %s\n", msg.Item.Title)
			if handler != nil {
				handler(msg.Item)
			}
		case "item_updated":
			fmt.Printf("  [WS] Item updated: %s\n", msg.Item.Title)
			if handler != nil {
				handler(msg.Item)
			}
		case "item_deleted":
			fmt.Printf("  [WS] Item deleted: %s\n", msg.Item.ID)
		case "sync_complete":
			fmt.Println("  [WS] Sync complete")
			cs.Config.LastSync = time.Now()
			SaveConfig(cs.Config)
		default:
			fmt.Printf("  [WS] Unknown message type: %s\n", msg.Type)
		}
	}
}

// SendChange sends a change notification to the server
func (cs *CloudSync) SendChange(changeType string, item *vault.Item) error {
	if cs.WSConn == nil {
		return fmt.Errorf("not connected to WebSocket server")
	}

	msg := map[string]interface{}{
		"type":      changeType,
		"item":      item,
		"timestamp": time.Now().Unix(),
	}

	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	return cs.WSConn.WriteMessage(websocket.TextMessage, data)
}

// RealtimeSync performs real-time bidirectional sync
func (cs *CloudSync) RealtimeSync(duration time.Duration) error {
	if err := cs.ConnectWebSocket(); err != nil {
		return err
	}
	defer cs.DisconnectWebSocket()

	go func() {
		cs.WatchForChanges(func(item *vault.Item) {
			cs.Storage.SaveItem(item)
		})
	}()

	ids, _ := cs.Storage.ListItems()
	for _, id := range ids {
		item, err := cs.Storage.LoadItem(id)
		if err != nil {
			continue
		}
		cs.SendChange("item_created", item)
	}

	time.Sleep(duration)

	fmt.Println("Real-time sync complete.")
	return nil
}
