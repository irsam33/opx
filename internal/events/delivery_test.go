package events

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewWebhookDeliveryQueue(t *testing.T) {
	q := NewWebhookDeliveryQueue("/tmp/test-deliveries")

	if q.BasePath != "/tmp/test-deliveries" {
		t.Errorf("BasePath = %q, want /tmp/test-deliveries", q.BasePath)
	}

	if len(q.Deliveries) != 0 {
		t.Errorf("Deliveries length = %d, want 0", len(q.Deliveries))
	}
}

func TestEnqueue(t *testing.T) {
	dir := t.TempDir()
	q := NewWebhookDeliveryQueue(dir)

	event := Event{
		ID:        "evt-test",
		Type:      EventSignIn,
		Timestamp: time.Now(),
		Actor:     "test@example.com",
		Target:    "vault/Personal",
	}

	q.Enqueue("https://example.com/webhook", event, 3)

	if len(q.Deliveries) != 1 {
		t.Errorf("Deliveries length = %d, want 1", len(q.Deliveries))
	}

	delivery := q.Deliveries[0]
	if delivery.Status != "pending" {
		t.Errorf("Status = %q, want pending", delivery.Status)
	}

	if delivery.WebhookURL != "https://example.com/webhook" {
		t.Errorf("WebhookURL = %q, want https://example.com/webhook", delivery.WebhookURL)
	}

	if delivery.MaxRetries != 3 {
		t.Errorf("MaxRetries = %d, want 3", delivery.MaxRetries)
	}

	// Verify file was created
	filename := filepath.Join(dir, "opx_webhook_deliveries.json")
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		t.Error("Deliveries file not created")
	}
}

func TestGetRetryDelay(t *testing.T) {
	tests := []struct {
		attempt int
		want    time.Duration
	}{
		{1, 2 * time.Second},
		{2, 4 * time.Second},
		{3, 8 * time.Second},
		{4, 16 * time.Second},
		{7, 60 * time.Second},
		{10, 60 * time.Second},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("attempt-%d", tt.attempt), func(t *testing.T) {
			delay := GetRetryDelay(tt.attempt)
			if delay != tt.want {
				t.Errorf("GetRetryDelay(%d) = %v, want %v", tt.attempt, delay, tt.want)
			}
		})
	}
}

func TestGetStats(t *testing.T) {
	dir := t.TempDir()
	q := NewWebhookDeliveryQueue(dir)

	event := Event{
		ID:        "evt-test",
		Type:      EventSignIn,
		Timestamp: time.Now(),
		Actor:     "test@example.com",
	}

	q.Enqueue("https://example.com/hook1", event, 3)
	q.Enqueue("https://example.com/hook1", event, 3)
	q.Enqueue("https://example.com/hook2", event, 3)

	stats := q.GetStats()

	if stats.Total != 3 {
		t.Errorf("Total = %d, want 3", stats.Total)
	}

	if stats.ByWebhook["https://example.com/hook1"] != 2 {
		t.Errorf("hook1 count = %d, want 2", stats.ByWebhook["https://example.com/hook1"])
	}

	if stats.ByWebhook["https://example.com/hook2"] != 1 {
		t.Errorf("hook2 count = %d, want 1", stats.ByWebhook["https://example.com/hook2"])
	}

	if stats.Pending != 3 {
		t.Errorf("Pending = %d, want 3", stats.Pending)
	}
}

func TestDeliveryQueueWithHTTPServer(t *testing.T) {
	dir := t.TempDir()
	q := NewWebhookDeliveryQueue(dir)

	received := make(chan bool, 10)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- true

		sig := r.Header.Get("X-Webhook-Signature")
		if sig == "" {
			t.Error("X-Webhook-Signature header missing")
		}

		deliveryID := r.Header.Get("X-Webhook-Delivery")
		if deliveryID == "" {
			t.Error("X-Webhook-Delivery header missing")
		}

		eventType := r.Header.Get("X-Webhook-Event")
		if eventType == "" {
			t.Error("X-Webhook-Event header missing")
		}

		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	event := Event{
		ID:        "evt-delivery-test",
		Type:      EventItemCreate,
		Timestamp: time.Now(),
		Actor:     "test@example.com",
		Target:    "item-123",
		Details:   map[string]interface{}{"field": "value"},
	}

	q.Enqueue(ts.URL, event, 3)
	q.Process()

	time.Sleep(500 * time.Millisecond)

	select {
	case <-received:
	default:
		t.Error("Webhook was not delivered to test server")
	}

	stats := q.GetStats()
	if stats.Delivered != 1 {
		t.Errorf("Delivered = %d, want 1", stats.Delivered)
	}
}

func TestDeliveryWithFailedServer(t *testing.T) {
	dir := t.TempDir()
	q := NewWebhookDeliveryQueue(dir)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	event := Event{
		ID:        "evt-failed-test",
		Type:      EventItemDelete,
		Timestamp: time.Now(),
		Actor:     "test@example.com",
	}

	q.Enqueue(ts.URL, event, 1)

	go q.ProcessWithBackoff()

	time.Sleep(2 * GetRetryDelay(1))

	stats := q.GetStats()
	if stats.Failed != 1 {
		t.Errorf("Failed = %d, want 1", stats.Failed)
	}

	if stats.Delivered != 0 {
		t.Errorf("Delivered = %d, want 0", stats.Delivered)
	}
}

func TestGetPending(t *testing.T) {
	dir := t.TempDir()
	q := NewWebhookDeliveryQueue(dir)

	event := Event{
		ID:        "evt-test",
		Type:      EventSignIn,
		Timestamp: time.Now(),
	}

	q.Enqueue("https://example.com/hook1", event, 3)
	q.Enqueue("https://example.com/hook2", event, 3)

	pending := q.GetPending()
	if len(pending) != 2 {
		t.Errorf("Pending = %d, want 2", len(pending))
	}
}

func TestGetDelivered(t *testing.T) {
	dir := t.TempDir()
	q := NewWebhookDeliveryQueue(dir)

	event := Event{
		ID:        "evt-test",
		Type:      EventSignIn,
		Timestamp: time.Now(),
	}

	q.Enqueue("https://example.com/hook1", event, 3)
	q.Enqueue("https://example.com/hook2", event, 3)

	for i := range q.Deliveries {
		q.Deliveries[i].Status = "delivered"
		q.Deliveries[i].DeliveredAt = time.Now()
	}

	delivered := q.GetDelivered()
	if len(delivered) != 2 {
		t.Errorf("Delivered = %d, want 2", len(delivered))
	}

	pending := q.GetPending()
	if len(pending) != 0 {
		t.Errorf("Pending = %d, want 0", len(pending))
	}
}

func TestGetFailed(t *testing.T) {
	dir := t.TempDir()
	q := NewWebhookDeliveryQueue(dir)

	event := Event{
		ID:        "evt-test",
		Type:      EventSignIn,
		Timestamp: time.Now(),
	}

	q.Enqueue("https://example.com/hook1", event, 3)
	q.Enqueue("https://example.com/hook2", event, 3)

	for i := range q.Deliveries {
		q.Deliveries[i].Status = "failed"
		q.Deliveries[i].LastError = "test error"
	}

	failed := q.GetFailed()
	if len(failed) != 2 {
		t.Errorf("Failed = %d, want 2", len(failed))
	}

	if failed[0].LastError != "test error" {
		t.Errorf("LastError = %q, want test error", failed[0].LastError)
	}
}

func TestRetryFailed(t *testing.T) {
	dir := t.TempDir()
	q := NewWebhookDeliveryQueue(dir)

	event := Event{
		ID:        "evt-test",
		Type:      EventSignIn,
		Timestamp: time.Now(),
	}

	q.Enqueue("https://example.com/hook1", event, 3)
	q.Enqueue("https://example.com/hook2", event, 3)

	q.Deliveries[0].Status = "failed"
	q.Deliveries[1].Status = "failed"

	retried := q.RetryFailed()
	if retried != 2 {
		t.Errorf("Retried = %d, want 2", retried)
	}

	pending := q.GetPending()
	if len(pending) != 2 {
		t.Errorf("Pending after retry = %d, want 2", len(pending))
	}
}

func TestRetryWithBackoff(t *testing.T) {
	dir := t.TempDir()
	q := NewWebhookDeliveryQueue(dir)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	event := Event{
		ID:        "evt-retry-backoff",
		Type:      EventSignIn,
		Timestamp: time.Now(),
	}

	q.Enqueue(ts.URL, event, 3)
	q.Deliveries[0].Status = "failed"

	if !q.RetryWithBackoff(&q.Deliveries[0]) {
		t.Error("RetryWithBackoff() should return true for successful delivery")
	}

	stats := q.GetStats()
	if stats.Delivered != 1 {
		t.Errorf("Delivered = %d, want 1", stats.Delivered)
	}
}

func TestSignPayload(t *testing.T) {
	data := []byte("test-payload-data")
	secret := "my-secret-key"

	signature := signPayload(data, secret)

	if len(signature) < 7 || signature[:7] != "sha256=" {
		t.Errorf("Signature = %q, should start with sha256=", signature)
	}

	signature2 := signPayload(data, secret)
	if signature != signature2 {
		t.Error("Same payload and secret should produce the same signature")
	}

	signature3 := signPayload(data, "different-secret")
	if signature == signature3 {
		t.Error("Different secret should produce different signature")
	}
}

func TestVerifyHMACSignature(t *testing.T) {
	data := []byte("test-payload-data")
	secret := "my-secret-key"

	expected := signPayload(data, secret)

	h := hmac.New(sha256.New, []byte(secret))
	h.Write(data)
	expectedMAC := "sha256=" + hex.EncodeToString(h.Sum(nil))

	if expected != expectedMAC {
		t.Error("signPayload does not match manual HMAC computation")
	}
}

func TestWebhookManagerTrigger(t *testing.T) {
	dir := t.TempDir()
	q := NewWebhookDeliveryQueue(dir)

	received := make(chan bool, 10)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- true
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	event := Event{
		ID:        "evt-trigger-test",
		Type:      EventSignIn,
		Timestamp: time.Now(),
		Actor:     "test@example.com",
	}

	q.Enqueue(ts.URL, event, 3)
	q.Process()

	time.Sleep(500 * time.Millisecond)

	select {
	case <-received:
	default:
		t.Error("Webhook not triggered")
	}
}

func TestLoadDeliveries(t *testing.T) {
	dir := t.TempDir()

	q1 := NewWebhookDeliveryQueue(dir)
	event := Event{
		ID:        "evt-test",
		Type:      EventSignIn,
		Timestamp: time.Now(),
	}
	q1.Enqueue("https://example.com/hook1", event, 3)

	q2 := NewWebhookDeliveryQueue(dir)
	err := q2.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if len(q2.Deliveries) != 1 {
		t.Errorf("Loaded deliveries = %d, want 1", len(q2.Deliveries))
	}
}

func TestClearDeliveries(t *testing.T) {
	dir := t.TempDir()
	q := NewWebhookDeliveryQueue(dir)

	event := Event{
		ID:        "evt-test",
		Type:      EventSignIn,
		Timestamp: time.Now(),
	}

	q.Enqueue("https://example.com/hook1", event, 3)
	q.Enqueue("https://example.com/hook2", event, 3)

	err := q.Clear()
	if err != nil {
		t.Fatalf("Clear() error = %v", err)
	}

	if len(q.Deliveries) != 0 {
		t.Errorf("After clear, deliveries = %d, want 0", len(q.Deliveries))
	}
}

func TestDeliveryJSONSerialization(t *testing.T) {
	delivery := WebhookDelivery{
		ID:          "del_test",
		WebhookURL:  "https://example.com/webhook",
		Status:      "pending",
		Attempts:    0,
		MaxRetries:  3,
	}

	data, err := json.Marshal(delivery)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	var loaded WebhookDelivery
	err = json.Unmarshal(data, &loaded)
	if err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}

	if loaded.WebhookURL != delivery.WebhookURL {
		t.Errorf("WebhookURL mismatch")
	}

	if loaded.Status != delivery.Status {
		t.Errorf("Status mismatch")
	}

	if loaded.MaxRetries != delivery.MaxRetries {
		t.Errorf("MaxRetries mismatch")
	}
}

func TestDeliveryPayloadMarshaling(t *testing.T) {
	event := Event{
		ID:        "evt-test",
		Type:      EventSignIn,
		Timestamp: time.Now(),
		Actor:     "test@example.com",
		Target:    "vault",
		Details: map[string]interface{}{
			"username": "testuser",
			"success":  true,
		},
	}

	data, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}

	if parsed["type"] != "signin" {
		t.Errorf("Event type = %v, want signin", parsed["type"])
	}

	if parsed["actor"] != "test@example.com" {
		t.Errorf("Event actor = %v, want test@example.com", parsed["actor"])
	}
}

func TestProcessPendingWebhooks(t *testing.T) {
	dir := t.TempDir()

	received := make(chan bool, 10)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- true
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	event := Event{
		ID:        "evt-process-test",
		Type:      EventSignIn,
		Timestamp: time.Now(),
	}

	q := NewWebhookDeliveryQueue(dir)
	q.Enqueue(ts.URL, event, 3)

	ProcessPendingWebhooks(dir)

	select {
	case <-received:
	default:
		t.Error("Webhook not processed")
	}
}

func BenchmarkEnqueue(b *testing.B) {
	dir := b.TempDir()
	q := NewWebhookDeliveryQueue(dir)
	event := Event{
		ID:        "evt-bench",
		Type:      EventSignIn,
		Timestamp: time.Now(),
		Actor:     "test@example.com",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		q.Enqueue("https://example.com/webhook", event, 3)
	}
}

func BenchmarkGetStats(b *testing.B) {
	dir := b.TempDir()
	q := NewWebhookDeliveryQueue(dir)

	event := Event{
		ID:        "evt-bench",
		Type:      EventSignIn,
		Timestamp: time.Now(),
	}

	for i := 0; i < 1000; i++ {
		q.Enqueue(fmt.Sprintf("https://example.com/hook-%d", i%10), event, 3)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = q.GetStats()
	}
}

func BenchmarkSignPayload(b *testing.B) {
	data := []byte("benchmark-payload-data")
	secret := "benchmark-secret-key"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = signPayload(data, secret)
	}
}

func BenchmarkGetRetryDelay(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = GetRetryDelay(i % 10)
	}
}
