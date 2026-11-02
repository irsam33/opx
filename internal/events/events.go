package events

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// EventType represents the type of event
type EventType string

const (
	EventSignIn      EventType = "signin"
	EventSignOut     EventType = "signout"
	EventItemCreate  EventType = "item_create"
	EventItemRead    EventType = "item_read"
	EventItemUpdate  EventType = "item_update"
	EventItemDelete  EventType = "item_delete"
	EventVaultCreate EventType = "vault_create"
	EventVaultAccess EventType = "vault_access"
	EventSSHKeyGen   EventType = "ssh_key_generate"
	EventTOTPVerify  EventType = "totp_verify"
	EventPluginRun   EventType = "plugin_run"
	EventServiceAcct EventType = "service_account"
	EventConnectAPI  EventType = "connect_api"
	EventSync        EventType = "sync"
	EventUpdate      EventType = "update"
)

// Event represents an audit event
type Event struct {
	ID        string                 `json:"id"`
	Type      EventType              `json:"type"`
	Timestamp time.Time              `json:"timestamp"`
	Actor     string                 `json:"actor"`
	Target    string                 `json:"target"`
	Details   map[string]interface{} `json:"details"`
	SourceIP  string                 `json:"source_ip"`
	UserAgent string                 `json:"user_agent"`
	Severity  string                 `json:"severity"`
}

// EventStore manages event storage
type EventStore struct {
	BasePath string
	Events   []Event
}

// NewEventStore creates a new event store
func NewEventStore(basePath string) *EventStore {
	return &EventStore{
		BasePath: basePath,
		Events:   []Event{},
	}
}

// DefaultPath returns the default event store path
func DefaultPath() string {
	return filepath.Join(os.TempDir(), "opx", "events")
}

// Log logs a new event
func (es *EventStore) Log(eventType EventType, actor, target string, details map[string]interface{}) error {
	return es.LogWithSeverity(eventType, actor, target, details, "info")
}

// LogWithSeverity logs a new event with severity
func (es *EventStore) LogWithSeverity(eventType EventType, actor, target string, details map[string]interface{}, severity string) error {
	event := Event{
		ID:        generateEventID(),
		Type:      eventType,
		Timestamp: time.Now(),
		Actor:     actor,
		Target:    target,
		Details:   details,
		SourceIP:  "127.0.0.1",
		UserAgent: "opx/1.0",
		Severity:  severity,
	}

	es.Events = append(es.Events, event)

	wm := NewWebhookManager(es.BasePath)
	wm.Load()
	queue := NewWebhookDeliveryQueue(es.BasePath)
	queue.Load()
	wm.TriggerWebhooksWithDelivery(event, queue)

	es.ApplyRetention(DefaultRetentionPolicy())

	return es.save()
}

// save persists events to disk
func (es *EventStore) save() error {
	if err := os.MkdirAll(es.BasePath, 0700); err != nil {
		return err
	}

	filename := filepath.Join(es.BasePath, "opx_events.json")
	data, err := json.MarshalIndent(es.Events, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filename, data, 0600)
}

// Load loads events from disk
func (es *EventStore) Load() error {
	filename := filepath.Join(es.BasePath, "opx_events.json")
	data, err := os.ReadFile(filename)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	return json.Unmarshal(data, &es.Events)
}

// Query queries events with filters
func (es *EventStore) Query(eventType EventType, actor string, since time.Time, limit int) []Event {
	return es.FilterEvents([]EventType{eventType}, []string{actor}, since, time.Time{})
}

// FilterEvents filters events by multiple criteria
func (es *EventStore) FilterEvents(types []EventType, actors []string, since, until time.Time) []Event {
	var results []Event

	for _, e := range es.Events {
		if len(types) > 0 {
			found := false
			for _, t := range types {
				if e.Type == t {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		if len(actors) > 0 {
			found := false
			for _, a := range actors {
				if e.Actor == a {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		if !since.IsZero() && e.Timestamp.Before(since) {
			continue
		}
		if !until.IsZero() && e.Timestamp.After(until) {
			continue
		}

		results = append(results, e)
	}

	return results
}

// GetRecent returns the most recent N events
func (es *EventStore) GetRecent(n int) []Event {
	if n > len(es.Events) {
		n = len(es.Events)
	}
	start := len(es.Events) - n
	if start < 0 {
		start = 0
	}
	return es.Events[start:]
}

// GetPaginated returns events with pagination
func (es *EventStore) GetPaginated(offset, limit int) ([]Event, int) {
	total := len(es.Events)
	if offset >= total {
		return []Event{}, total
	}

	end := offset + limit
	if end > total {
		end = total
	}

	return es.Events[offset:end], total
}

// Clear clears all events
func (es *EventStore) Clear() error {
	es.Events = []Event{}
	return es.save()
}

// Count returns the number of events
func (es *EventStore) Count() int {
	return len(es.Events)
}

// CountByType returns event counts by type
func (es *EventStore) CountByType() map[EventType]int {
	counts := make(map[EventType]int)
	for _, e := range es.Events {
		counts[e.Type]++
	}
	return counts
}

// CountByActor returns event counts by actor
func (es *EventStore) CountByActor() map[string]int {
	counts := make(map[string]int)
	for _, e := range es.Events {
		counts[e.Actor]++
	}
	return counts
}

// Export exports events to a file
func (es *EventStore) Export(filename string) error {
	data, err := json.MarshalIndent(es.Events, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filename, data, 0600)
}

// Import imports events from a file
func (es *EventStore) Import(filename string) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return err
	}

	var events []Event
	if err := json.Unmarshal(data, &events); err != nil {
		return err
	}

	es.Events = append(es.Events, events...)
	return es.save()
}

// generateEventID generates a unique event ID
func generateEventID() string {
	return fmt.Sprintf("evt_%d", time.Now().UnixNano())
}

// FormatEvent formats an event for display
func FormatEvent(e Event) string {
	details := ""
	if len(e.Details) > 0 {
		detailsBytes, _ := json.Marshal(e.Details)
		details = string(detailsBytes)
	}

	severityIcon := "ℹ️"
	switch e.Severity {
	case "warning":
		severityIcon = "⚠️"
	case "error":
		severityIcon = "❌"
	case "critical":
		severityIcon = "🔴"
	}

	return fmt.Sprintf("[%s] %s %s | %s | %s | %s",
		e.Timestamp.Format("2006-01-02 15:04:05"),
		severityIcon,
		e.Type,
		e.Actor,
		e.Target,
		details,
	)
}

// EventSummary provides a summary of events
type EventSummary struct {
	TotalEvents  int            `json:"total_events"`
	ByType       map[string]int `json:"by_type"`
	ByActor      map[string]int `json:"by_actor"`
	BySeverity   map[string]int `json:"by_severity"`
	FirstEvent   time.Time      `json:"first_event"`
	LastEvent    time.Time      `json:"last_event"`
	UniqueActors int            `json:"unique_actors"`
}

// GetSummary returns an event summary
func (es *EventStore) GetSummary() EventSummary {
	summary := EventSummary{
		TotalEvents: len(es.Events),
		ByType:      make(map[string]int),
		ByActor:     make(map[string]int),
		BySeverity:  make(map[string]int),
	}

	actors := make(map[string]bool)
	for _, e := range es.Events {
		summary.ByType[string(e.Type)]++
		summary.ByActor[e.Actor]++
		summary.BySeverity[e.Severity]++
		actors[e.Actor] = true

		if summary.FirstEvent.IsZero() || e.Timestamp.Before(summary.FirstEvent) {
			summary.FirstEvent = e.Timestamp
		}
		if e.Timestamp.After(summary.LastEvent) {
			summary.LastEvent = e.Timestamp
		}
	}

	summary.UniqueActors = len(actors)
	return summary
}

// RetentionPolicy holds event retention policy
type RetentionPolicy struct {
	MaxEvents   int           `json:"max_events"`
	MaxAge      time.Duration `json:"max_age"`
	AutoCleanup bool          `json:"auto_cleanup"`
}

// DefaultRetentionPolicy returns default retention policy
func DefaultRetentionPolicy() RetentionPolicy {
	return RetentionPolicy{
		MaxEvents:   1000,
		MaxAge:      30 * 24 * time.Hour,
		AutoCleanup: true,
	}
}

// ApplyRetention applies retention policy to event store
func (es *EventStore) ApplyRetention(policy RetentionPolicy) int {
	removed := 0
	now := time.Now()

	var newEvents []Event
	for _, e := range es.Events {
		if policy.MaxAge > 0 && now.Sub(e.Timestamp) > policy.MaxAge {
			removed++
			continue
		}
		newEvents = append(newEvents, e)
	}

	if policy.MaxEvents > 0 && len(newEvents) > policy.MaxEvents {
		removed += len(newEvents) - policy.MaxEvents
		newEvents = newEvents[len(newEvents)-policy.MaxEvents:]
	}

	es.Events = newEvents
	if removed > 0 {
		es.save()
	}

	return removed
}

// WebhookConfig holds webhook configuration
type WebhookConfig struct {
	URL     string   `json:"url"`
	Events  []string `json:"events"`
	Enabled bool     `json:"enabled"`
	Retries int      `json:"retries"`
}

// WebhookManager manages webhooks
type WebhookManager struct {
	Configs []WebhookConfig `json:"webhooks"`
	Path    string
}

// NewWebhookManager creates a new webhook manager
func NewWebhookManager(basePath string) *WebhookManager {
	return &WebhookManager{
		Path: filepath.Join(basePath, "opx_webhooks.json"),
	}
}

// Load loads webhooks from disk
func (wm *WebhookManager) Load() error {
	data, err := os.ReadFile(wm.Path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	return json.Unmarshal(data, &wm.Configs)
}

// Save saves webhooks to disk
func (wm *WebhookManager) Save() error {
	os.MkdirAll(filepath.Dir(wm.Path), 0700)
	data, err := json.MarshalIndent(wm.Configs, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(wm.Path, data, 0600)
}

// AddWebhook adds a new webhook
func (wm *WebhookManager) AddWebhook(url string, events []string, retries int) error {
	if retries <= 0 {
		retries = 3
	}
	wm.Configs = append(wm.Configs, WebhookConfig{
		URL:     url,
		Events:  events,
		Enabled: true,
		Retries: retries,
	})
	return wm.Save()
}

// RemoveWebhook removes a webhook
func (wm *WebhookManager) RemoveWebhook(url string) error {
	var newConfigs []WebhookConfig
	for _, c := range wm.Configs {
		if c.URL != url {
			newConfigs = append(newConfigs, c)
		}
	}
	wm.Configs = newConfigs
	return wm.Save()
}

// TriggerWebhooks triggers webhooks for an event
// TestWebhook tests a webhook
func (wm *WebhookManager) TestWebhook(url string) error {
	testEvent := Event{
		ID:        "test_event",
		Type:      EventSignIn,
		Timestamp: time.Now(),
		Actor:     "test",
		Target:    "test",
		Details:   map[string]interface{}{"test": true},
		Severity:  "info",
	}

	data, _ := json.Marshal(testEvent)
	resp, err := http.Post(url, "application/json", bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}

	return nil
}
