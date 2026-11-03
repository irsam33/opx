package events

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewEventStore(t *testing.T) {
	es := NewEventStore("/tmp/test-events")

	if es.BasePath != "/tmp/test-events" {
		t.Errorf("BasePath = %q, want /tmp/test-events", es.BasePath)
	}

	if len(es.Events) != 0 {
		t.Errorf("Events length = %d, want 0", len(es.Events))
	}
}

func TestDefaultPath(t *testing.T) {
	path := DefaultPath()

	if path == "" {
		t.Error("DefaultPath() returned empty path")
	}

	// Should contain opx/events
	if !contains(path, "opx") || !contains(path, "events") {
		t.Errorf("DefaultPath() = %q, should contain opx and events", path)
	}
}

func TestLogEvent(t *testing.T) {
	dir := t.TempDir()
	es := NewEventStore(dir)

	err := es.Log(EventSignIn, "testuser@example.com", "vault/Personal", map[string]interface{}{
		"method": "password",
	})
	if err != nil {
		t.Fatalf("Log() error = %v", err)
	}

	if es.Count() != 1 {
		t.Errorf("Count = %d, want 1", es.Count())
	}

	event := es.Events[0]
	if event.Type != EventSignIn {
		t.Errorf("Type = %q, want signin", event.Type)
	}

	if event.Actor != "testuser@example.com" {
		t.Errorf("Actor = %q, want testuser@example.com", event.Actor)
	}

	if event.Target != "vault/Personal" {
		t.Errorf("Target = %q, want vault/Personal", event.Target)
	}

	if event.Details["method"] != "password" {
		t.Errorf("Details method = %v, want password", event.Details["method"])
	}

	if event.Severity != "info" {
		t.Errorf("Severity = %q, want info", event.Severity)
	}

	// Verify file was created
	filename := filepath.Join(dir, "opx_events.json")
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		t.Error("Events file not created")
	}
}

func TestLogWithSeverity(t *testing.T) {
	dir := t.TempDir()
	es := NewEventStore(dir)

	severities := []string{"info", "warning", "error", "critical"}

	for i, sev := range severities {
		err := es.LogWithSeverity(EventItemCreate, "user", "item", map[string]interface{}{}, sev)
		if err != nil {
			t.Fatalf("LogWithSeverity() error = %v", err)
		}
		if es.Events[i].Severity != sev {
			t.Errorf("Severity[%d] = %q, want %q", i, es.Events[i].Severity, sev)
		}
	}
}

func TestLoadEvents(t *testing.T) {
	dir := t.TempDir()

	// Create some events first
	es1 := NewEventStore(dir)
	_ = es1.Log(EventSignIn, "user1", "vault", map[string]interface{}{})
	_ = es1.Log(EventSignOut, "user2", "session", map[string]interface{}{})

	// Load them in a new store
	es2 := NewEventStore(dir)
	err := es2.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if es2.Count() != 2 {
		t.Errorf("Loaded count = %d, want 2", es2.Count())
	}
}

func TestQueryEvents(t *testing.T) {
	dir := t.TempDir()
	es := NewEventStore(dir)

	_ = es.Log(EventSignIn, "user1", "vault", map[string]interface{}{})
	_ = es.Log(EventItemCreate, "user1", "item-1", map[string]interface{}{})
	_ = es.Log(EventSignIn, "user2", "vault", map[string]interface{}{})
	_ = es.Log(EventItemDelete, "user1", "item-2", map[string]interface{}{})

	results := es.Query(EventSignIn, "", time.Time{}, 0)
	if len(results) != 2 {
		t.Errorf("Query(signin) = %d results, want 2", len(results))
	}

	results = es.Query(EventItemCreate, "", time.Time{}, 0)
	if len(results) != 1 {
		t.Errorf("Query(item_create) = %d results, want 1", len(results))
	}
}

func TestFilterEvents(t *testing.T) {
	dir := t.TempDir()
	es := NewEventStore(dir)

	_ = es.Log(EventSignIn, "user1", "vault", map[string]interface{}{})
	_ = es.Log(EventItemCreate, "user1", "item-1", map[string]interface{}{})
	_ = es.Log(EventSignIn, "user2", "vault", map[string]interface{}{})

	// Filter by type
	results := es.FilterEvents([]EventType{EventSignIn}, nil, time.Time{}, time.Time{})
	if len(results) != 2 {
		t.Errorf("Filter by type = %d results, want 2", len(results))
	}

	// Filter by actor
	results = es.FilterEvents(nil, []string{"user1"}, time.Time{}, time.Time{})
	if len(results) != 2 {
		t.Errorf("Filter by actor = %d results, want 2", len(results))
	}

	// Filter by both
	results = es.FilterEvents([]EventType{EventSignIn}, []string{"user1"}, time.Time{}, time.Time{})
	if len(results) != 1 {
		t.Errorf("Filter by both = %d results, want 1", len(results))
	}
}

func TestGetRecent(t *testing.T) {
	dir := t.TempDir()
	es := NewEventStore(dir)

	for i := 0; i < 5; i++ {
		_ = es.Log(EventSignIn, fmt.Sprintf("user%d", i), "vault", map[string]interface{}{})
	}

	recent := es.GetRecent(3)
	if len(recent) != 3 {
		t.Errorf("GetRecent(3) = %d events, want 3", len(recent))
	}

	// Get more than available
	all := es.GetRecent(10)
	if len(all) != 5 {
		t.Errorf("GetRecent(10) = %d events, want 5", len(all))
	}
}

func TestGetPaginated(t *testing.T) {
	dir := t.TempDir()
	es := NewEventStore(dir)

	for i := 0; i < 10; i++ {
		_ = es.Log(EventSignIn, "user", "vault", map[string]interface{}{})
	}

	events, total := es.GetPaginated(0, 3)
	if len(events) != 3 {
		t.Errorf("Page 1 = %d events, want 3", len(events))
	}
	if total != 10 {
		t.Errorf("Total = %d, want 10", total)
	}

	events, _ = es.GetPaginated(8, 3)
	if len(events) != 2 {
		t.Errorf("Last page = %d events, want 2", len(events))
	}

	events, _ = es.GetPaginated(15, 3)
	if len(events) != 0 {
		t.Errorf("Beyond end = %d events, want 0", len(events))
	}
}

func TestClear(t *testing.T) {
	dir := t.TempDir()
	es := NewEventStore(dir)

	_ = es.Log(EventSignIn, "user", "vault", map[string]interface{}{})
	_ = es.Log(EventItemCreate, "user", "item", map[string]interface{}{})

	err := es.Clear()
	if err != nil {
		t.Fatalf("Clear() error = %v", err)
	}

	if es.Count() != 0 {
		t.Errorf("After clear: Count = %d, want 0", es.Count())
	}
}

func TestExportImport(t *testing.T) {
	dir := t.TempDir()
	exportFile := filepath.Join(dir, "exported_events.json")

	es1 := NewEventStore(dir)
	_ = es1.Log(EventSignIn, "user1", "vault", map[string]interface{}{"ip": "1.2.3.4"})
	_ = es1.Log(EventItemCreate, "user2", "item-1", map[string]interface{}{"type": "login"})

	err := es1.Export(exportFile)
	if err != nil {
		t.Fatalf("Export() error = %v", err)
	}

	// Import into a new store
	es2 := NewEventStore(dir)
	err = es2.Import(exportFile)
	if err != nil {
		t.Fatalf("Import() error = %v", err)
	}

	if es2.Count() != 2 {
		t.Errorf("Imported count = %d, want 2", es2.Count())
	}
}

func TestGetSummary(t *testing.T) {
	dir := t.TempDir()
	es := NewEventStore(dir)

	_ = es.Log(EventSignIn, "user1", "vault", map[string]interface{}{})
	_ = es.Log(EventSignIn, "user2", "vault", map[string]interface{}{})
	_ = es.Log(EventItemCreate, "user1", "item-1", map[string]interface{}{})
	_ = es.Log(EventItemDelete, "user1", "item-2", map[string]interface{}{})

	summary := es.GetSummary()

	if summary.TotalEvents != 4 {
		t.Errorf("TotalEvents = %d, want 4", summary.TotalEvents)
	}

	if summary.ByType[string(EventSignIn)] != 2 {
		t.Errorf("ByType[signin] = %d, want 2", summary.ByType[string(EventSignIn)])
	}

	if summary.UniqueActors != 2 {
		t.Errorf("UniqueActors = %d, want 2", summary.UniqueActors)
	}
}

func TestApplyRetention(t *testing.T) {
	dir := t.TempDir()
	es := NewEventStore(dir)

	policy := RetentionPolicy{
		MaxEvents:   5,
		MaxAge:      0, // No age limit for this test
		AutoCleanup: true,
	}

	for i := 0; i < 10; i++ {
		_ = es.Log(EventSignIn, "user", "vault", map[string]interface{}{})
	}

	removed := es.ApplyRetention(policy)
	if removed != 5 {
		t.Errorf("Removed = %d, want 5", removed)
	}

	if es.Count() != 5 {
		t.Errorf("Count after retention = %d, want 5", es.Count())
	}
}

func TestApplyRetentionByAge(t *testing.T) {
	dir := t.TempDir()
	es := NewEventStore(dir)

	// Add old events manually
	oldTime := time.Now().Add(-60 * time.Minute)
	es.Events = append(es.Events, Event{
		ID:        "old-event",
		Type:      EventSignIn,
		Timestamp: oldTime,
		Actor:     "user",
		Severity:  "info",
	})

	// Add recent event
	_ = es.Log(EventSignIn, "user", "vault", map[string]interface{}{})

	policy := RetentionPolicy{
		MaxEvents:   0, // No count limit
		MaxAge:      30 * time.Minute,
		AutoCleanup: true,
	}

	removed := es.ApplyRetention(policy)
	if removed != 1 {
		t.Errorf("Removed = %d, want 1", removed)
	}
}

func TestFormatEvent(t *testing.T) {
	event := Event{
		ID:        "evt_123",
		Type:      EventSignIn,
		Timestamp: time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC),
		Actor:     "testuser@example.com",
		Target:    "vault/Personal",
		Details:   map[string]interface{}{"method": "password"},
		Severity:  "info",
	}

	formatted := FormatEvent(event)

	if formatted == "" {
		t.Error("FormatEvent() returned empty string")
	}

	if !contains(formatted, "signin") {
		t.Error("Formatted event should contain type")
	}

	if !contains(formatted, "testuser@example.com") {
		t.Error("Formatted event should contain actor")
	}
}

func TestWebhookManager(t *testing.T) {
	dir := t.TempDir()
	wm := NewWebhookManager(dir)

	err := wm.AddWebhook("https://example.com/webhook", []string{"signin", "signout"}, 3)
	if err != nil {
		t.Fatalf("AddWebhook() error = %v", err)
	}

	if len(wm.Configs) != 1 {
		t.Errorf("Configs count = %d, want 1", len(wm.Configs))
	}

	// Save and reload
	err = wm.Save()
	if err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	wm2 := NewWebhookManager(dir)
	err = wm2.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if len(wm2.Configs) != 1 {
		t.Errorf("Reloaded configs = %d, want 1", len(wm2.Configs))
	}
}

func TestRemoveWebhook(t *testing.T) {
	dir := t.TempDir()
	wm := NewWebhookManager(dir)

	_ = wm.AddWebhook("https://example.com/hook1", []string{"signin"}, 3)
	_ = wm.AddWebhook("https://example.com/hook2", []string{"signout"}, 3)

	err := wm.RemoveWebhook("https://example.com/hook1")
	if err != nil {
		t.Fatalf("RemoveWebhook() error = %v", err)
	}

	if len(wm.Configs) != 1 {
		t.Errorf("Configs after remove = %d, want 1", len(wm.Configs))
	}
}

func TestCountByType(t *testing.T) {
	dir := t.TempDir()
	es := NewEventStore(dir)

	_ = es.Log(EventSignIn, "user1", "vault", map[string]interface{}{})
	_ = es.Log(EventSignIn, "user2", "vault", map[string]interface{}{})
	_ = es.Log(EventItemCreate, "user1", "item", map[string]interface{}{})

	counts := es.CountByType()

	if counts[EventSignIn] != 2 {
		t.Errorf("CountByType[signin] = %d, want 2", counts[EventSignIn])
	}

	if counts[EventItemCreate] != 1 {
		t.Errorf("CountByType[item_create] = %d, want 1", counts[EventItemCreate])
	}
}

func TestCountByActor(t *testing.T) {
	dir := t.TempDir()
	es := NewEventStore(dir)

	_ = es.Log(EventSignIn, "user1", "vault", map[string]interface{}{})
	_ = es.Log(EventSignIn, "user1", "vault", map[string]interface{}{})
	_ = es.Log(EventItemCreate, "user2", "item", map[string]interface{}{})

	counts := es.CountByActor()

	if counts["user1"] != 2 {
		t.Errorf("CountByActor[user1] = %d, want 2", counts["user1"])
	}

	if counts["user2"] != 1 {
		t.Errorf("CountByActor[user2] = %d, want 1", counts["user2"])
	}
}

func TestEventJSONSerialization(t *testing.T) {
	event := Event{
		ID:        "evt_test",
		Type:      EventSignIn,
		Timestamp: time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC),
		Actor:     "test@example.com",
		Target:    "vault/Personal",
		Details:   map[string]interface{}{"key": "value"},
		Severity:  "info",
	}

	data, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	var loaded Event
	err = json.Unmarshal(data, &loaded)
	if err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}

	if loaded.ID != event.ID {
		t.Errorf("ID mismatch")
	}

	if loaded.Type != event.Type {
		t.Errorf("Type mismatch")
	}
}

func TestAllEventTypes(t *testing.T) {
	types := []EventType{
		EventSignIn,
		EventSignOut,
		EventItemCreate,
		EventItemRead,
		EventItemUpdate,
		EventItemDelete,
		EventVaultCreate,
		EventVaultAccess,
		EventSSHKeyGen,
		EventTOTPVerify,
		EventPluginRun,
		EventServiceAcct,
		EventConnectAPI,
		EventSync,
		EventUpdate,
	}

	dir := t.TempDir()
	es := NewEventStore(dir)

	for _, et := range types {
		err := es.Log(et, "testuser", "test-target", map[string]interface{}{})
		if err != nil {
			t.Errorf("Log(%s) error = %v", et, err)
		}
	}

	if es.Count() != len(types) {
		t.Errorf("Logged %d events, want %d", es.Count(), len(types))
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || findSubstring(s, substr))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// Benchmark event logging
func BenchmarkLogEvent(b *testing.B) {
	dir := b.TempDir()
	es := NewEventStore(dir)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = es.Log(EventSignIn, "user", "vault", map[string]interface{}{})
	}
}

func BenchmarkFilterEvents(b *testing.B) {
	dir := b.TempDir()
	es := NewEventStore(dir)

	for i := 0; i < 1000; i++ {
		_ = es.Log(EventSignIn, "user", "vault", map[string]interface{}{})
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = es.FilterEvents([]EventType{EventSignIn}, nil, time.Time{}, time.Time{})
	}
}
