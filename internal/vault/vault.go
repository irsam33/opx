package vault

import (
	"encoding/json"
	"fmt"
	"time"
)

// Item represents a 1Password-like item
type Item struct {
	ID        string    `json:"id"`
	Title     string    `json:"title"`
	Category  string    `json:"category"` // login, password, document, etc.
	Vault     string    `json:"vault"`
	Fields    []Field   `json:"fields"`
	Tags      []string  `json:"tags"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Field represents an item field
type Field struct {
	ID    string `json:"id"`
	Label string `json:"label"`
	Type  string `json:"type"` // text, concealed, password, etc.
	Value string `json:"value"`
}

// Vault represents a vault
type Vault struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

// NewItem creates a new item
func NewItem(title, category, vault string) *Item {
	now := time.Now()
	return &Item{
		ID:        generateID(),
		Title:     title,
		Category:  category,
		Vault:     vault,
		Fields:    []Field{},
		Tags:      []string{},
		CreatedAt: now,
		UpdatedAt: now,
	}
}

// AddField adds a field to an item
func (i *Item) AddField(label, fieldType, value string) {
	i.Fields = append(i.Fields, Field{
		ID:    generateID(),
		Label: label,
		Type:  fieldType,
		Value: value,
	})
	i.UpdatedAt = time.Now()
}

// GetField returns a field by label
func (i *Item) GetField(label string) *Field {
	for idx := range i.Fields {
		if i.Fields[idx].Label == label {
			return &i.Fields[idx]
		}
	}
	return nil
}

// ToJSON serializes item to JSON
func (i *Item) ToJSON() (string, error) {
	data, err := json.MarshalIndent(i, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// FromJSON deserializes item from JSON
func ItemFromJSON(data []byte) (*Item, error) {
	var item Item
	if err := json.Unmarshal(data, &item); err != nil {
		return nil, err
	}
	return &item, nil
}

func generateID() string {
	b := make([]byte, 16)
	// Simple ID generation (use crypto/rand in production)
	for i := range b {
		b[i] = byte(i + 1)
	}
	return fmt.Sprintf("%x", b)
}
