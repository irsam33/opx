package events

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// WebhookDelivery represents a webhook delivery attempt
type WebhookDelivery struct {
	ID          string    `json:"id"`
	WebhookURL  string    `json:"webhook_url"`
	Event       Event     `json:"event"`
	Status      string    `json:"status"` // pending, delivered, failed
	Attempts    int       `json:"attempts"`
	MaxRetries  int       `json:"max_retries"`
	LastError   string    `json:"last_error,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	DeliveredAt time.Time `json:"delivered_at,omitempty"`
}

// WebhookDeliveryQueue manages webhook deliveries
type WebhookDeliveryQueue struct {
	BasePath   string
	Deliveries []WebhookDelivery
}

// NewWebhookDeliveryQueue creates a new delivery queue
func NewWebhookDeliveryQueue(basePath string) *WebhookDeliveryQueue {
	return &WebhookDeliveryQueue{
		BasePath:   basePath,
		Deliveries: []WebhookDelivery{},
	}
}

// Enqueue adds a delivery to the queue
func (q *WebhookDeliveryQueue) Enqueue(webhookURL string, event Event, maxRetries int) {
	delivery := WebhookDelivery{
		ID:         fmt.Sprintf("del_%d", time.Now().UnixNano()),
		WebhookURL: webhookURL,
		Event:      event,
		Status:     "pending",
		Attempts:   0,
		MaxRetries: maxRetries,
		CreatedAt:  time.Now(),
	}
	q.Deliveries = append(q.Deliveries, delivery)
	q.save()
}

// Process processes pending deliveries
func (q *WebhookDeliveryQueue) Process() {
	for i := range q.Deliveries {
		if q.Deliveries[i].Status != "pending" {
			continue
		}

		q.deliver(&q.Deliveries[i])
	}

	q.save()
}

// deliver attempts to deliver a single webhook with exponential backoff
func (q *WebhookDeliveryQueue) deliver(d *WebhookDelivery) {
	d.Attempts++

	data, _ := json.Marshal(d.Event)

	// Sign the payload with HMAC
	signature := signPayload(data, d.WebhookURL)

	req, err := http.NewRequest("POST", d.WebhookURL, bytes.NewReader(data))
	if err != nil {
		d.Status = "failed"
		d.LastError = err.Error()
		return
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Webhook-Signature", signature)
	req.Header.Set("X-Webhook-Delivery", d.ID)
	req.Header.Set("X-Webhook-Event", string(d.Event.Type))
	req.Header.Set("X-Webhook-Attempt", fmt.Sprintf("%d", d.Attempts))

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)

	if err != nil {
		d.LastError = err.Error()
		if d.Attempts >= d.MaxRetries {
			d.Status = "failed"
		} else {
			// Exponential backoff: wait 2^attempt seconds
			backoff := time.Duration(1<<uint(d.Attempts)) * time.Second
			if backoff > 60*time.Second {
				backoff = 60 * time.Second
			}
			time.Sleep(backoff)
		}
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		d.Status = "delivered"
		d.DeliveredAt = time.Now()
	} else {
		d.LastError = fmt.Sprintf("HTTP %d", resp.StatusCode)
		if d.Attempts >= d.MaxRetries {
			d.Status = "failed"
		} else {
			// Exponential backoff for HTTP errors too
			backoff := time.Duration(1<<uint(d.Attempts)) * time.Second
			if backoff > 60*time.Second {
				backoff = 60 * time.Second
			}
			time.Sleep(backoff)
		}
	}
}

// RetryWithBackoff retries a failed delivery with exponential backoff
func (q *WebhookDeliveryQueue) RetryWithBackoff(d *WebhookDelivery) bool {
	if d.Status != "failed" {
		return false
	}

	// Reset status to pending
	d.Status = "pending"
	d.Attempts = 0
	d.LastError = ""

	q.deliver(d)
	q.save()

	return d.Status == "delivered"
}

// ProcessWithBackoff processes pending deliveries with exponential backoff
func (q *WebhookDeliveryQueue) ProcessWithBackoff() {
	for i := range q.Deliveries {
		if q.Deliveries[i].Status != "pending" {
			continue
		}

		q.deliver(&q.Deliveries[i])
	}

	q.save()
}

// GetRetryDelay calculates the retry delay for a given attempt
func GetRetryDelay(attempt int) time.Duration {
	delay := time.Duration(1<<uint(attempt)) * time.Second
	if delay > 60*time.Second {
		delay = 60 * time.Second
	}
	return delay
}

// DeliveryStats holds delivery statistics
type DeliveryStats struct {
	Total     int            `json:"total"`
	Pending   int            `json:"pending"`
	Delivered int            `json:"delivered"`
	Failed    int            `json:"failed"`
	ByWebhook map[string]int `json:"by_webhook"`
}

// GetStats returns detailed delivery statistics
func (q *WebhookDeliveryQueue) GetStats() DeliveryStats {
	stats := DeliveryStats{
		Total:     len(q.Deliveries),
		ByWebhook: make(map[string]int),
	}

	for _, d := range q.Deliveries {
		switch d.Status {
		case "pending":
			stats.Pending++
		case "delivered":
			stats.Delivered++
		case "failed":
			stats.Failed++
		}
		stats.ByWebhook[d.WebhookURL]++
	}

	return stats
}

// signPayload signs a payload with HMAC-SHA256
func signPayload(data []byte, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write(data)
	return "sha256=" + hex.EncodeToString(h.Sum(nil))
}

// save persists deliveries to disk
func (q *WebhookDeliveryQueue) save() error {
	if err := os.MkdirAll(q.BasePath, 0700); err != nil {
		return err
	}

	filename := filepath.Join(q.BasePath, "opx_webhook_deliveries.json")
	data, err := json.MarshalIndent(q.Deliveries, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filename, data, 0600)
}

// Load loads deliveries from disk
func (q *WebhookDeliveryQueue) Load() error {
	filename := filepath.Join(q.BasePath, "opx_webhook_deliveries.json")
	data, err := os.ReadFile(filename)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	return json.Unmarshal(data, &q.Deliveries)
}

// GetPending returns pending deliveries
func (q *WebhookDeliveryQueue) GetPending() []WebhookDelivery {
	var pending []WebhookDelivery
	for _, d := range q.Deliveries {
		if d.Status == "pending" {
			pending = append(pending, d)
		}
	}
	return pending
}

// GetFailed returns failed deliveries
func (q *WebhookDeliveryQueue) GetFailed() []WebhookDelivery {
	var failed []WebhookDelivery
	for _, d := range q.Deliveries {
		if d.Status == "failed" {
			failed = append(failed, d)
		}
	}
	return failed
}

// GetDelivered returns delivered deliveries
func (q *WebhookDeliveryQueue) GetDelivered() []WebhookDelivery {
	var delivered []WebhookDelivery
	for _, d := range q.Deliveries {
		if d.Status == "delivered" {
			delivered = append(delivered, d)
		}
	}
	return delivered
}

// RetryFailed retries all failed deliveries
func (q *WebhookDeliveryQueue) RetryFailed() int {
	count := 0
	for i := range q.Deliveries {
		if q.Deliveries[i].Status == "failed" {
			q.Deliveries[i].Status = "pending"
			q.Deliveries[i].Attempts = 0
			count++
		}
	}
	q.save()
	return count
}

// Clear clears all deliveries
func (q *WebhookDeliveryQueue) Clear() error {
	q.Deliveries = []WebhookDelivery{}
	return q.save()
}

// Stats returns delivery statistics
func (q *WebhookDeliveryQueue) Stats() map[string]int {
	stats := map[string]int{
		"total":     len(q.Deliveries),
		"pending":   0,
		"delivered": 0,
		"failed":    0,
	}

	for _, d := range q.Deliveries {
		stats[d.Status]++
	}

	return stats
}

// ProcessPendingWebhooks processes all pending webhook deliveries
func ProcessPendingWebhooks(basePath string) {
	q := NewWebhookDeliveryQueue(basePath)
	q.Load()
	q.Process()
}

// TriggerWebhooksWithDelivery triggers webhooks with delivery tracking
func (wm *WebhookManager) TriggerWebhooksWithDelivery(event Event, queue *WebhookDeliveryQueue) {
	for _, config := range wm.Configs {
		if !config.Enabled {
			continue
		}

		if len(config.Events) > 0 {
			found := false
			for _, e := range config.Events {
				if e == string(event.Type) || e == "*" {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		queue.Enqueue(config.URL, event, config.Retries)
	}

	queue.Process()
}
