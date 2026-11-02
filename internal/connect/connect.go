package connect

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/user/opx/internal/ratelimit"
	"github.com/user/opx/internal/storage"
	"github.com/user/opx/internal/vault"
)

// ConnectServer represents a 1Password Connect-like server
type ConnectServer struct {
	Host    string
	Port    int
	Token   string
	Storage *storage.Storage
	Running bool
}

// ConnectToken represents a Connect server token
type ConnectToken struct {
	Token     string    `json:"token"`
	Name      string    `json:"name"`
	Vaults    []string  `json:"vaults"`
	Scopes    []string  `json:"scopes"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// NewConnectServer creates a new Connect server
func NewConnectServer(host string, port int, token string, storage *storage.Storage) *ConnectServer {
	return &ConnectServer{
		Host:    host,
		Port:    port,
		Token:   token,
		Storage: storage,
	}
}

// DefaultHost returns the default host
func DefaultHost() string {
	return "127.0.0.1"
}

// DefaultPort returns the default port
func DefaultPort() int {
	return 8080
}

// GenerateToken generates a Connect token
func GenerateToken(name string, vaults []string) (*ConnectToken, error) {
	token := &ConnectToken{
		Token:     generateTokenString(),
		Name:      name,
		Vaults:    vaults,
		Scopes:    []string{"vaults:read", "items:read", "items:write", "items:delete"},
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(365 * 24 * time.Hour),
	}
	return token, nil
}

func generateTokenString() string {
	// Simple token generation (use crypto/rand in production)
	return fmt.Sprintf("ops_connect_%d", time.Now().UnixNano())
}

// SaveToken saves a Connect token
func SaveToken(token *ConnectToken) error {
	configPath := filepath.Join(storage.DefaultPath(), "opx_connect_tokens.json")

	var tokens []ConnectToken
	data, err := os.ReadFile(configPath)
	if err == nil {
		json.Unmarshal(data, &tokens)
	}

	tokens = append(tokens, *token)

	data, err = json.MarshalIndent(tokens, "", "  ")
	if err != nil {
		return err
	}

	os.MkdirAll(storage.DefaultPath(), 0700)
	return os.WriteFile(configPath, data, 0600)
}

// LoadTokens loads all Connect tokens
func LoadTokens() ([]ConnectToken, error) {
	configPath := filepath.Join(storage.DefaultPath(), "opx_connect_tokens.json")
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}

	var tokens []ConnectToken
	if err := json.Unmarshal(data, &tokens); err != nil {
		return nil, err
	}

	return tokens, nil
}

// ValidateToken validates a Connect token
func ValidateToken(token string) (*ConnectToken, error) {
	tokens, err := LoadTokens()
	if err != nil {
		return nil, err
	}

	for i := range tokens {
		if tokens[i].Token == token {
			if time.Now().After(tokens[i].ExpiresAt) {
				return nil, fmt.Errorf("token expired")
			}
			return &tokens[i], nil
		}
	}

	return nil, fmt.Errorf("invalid token")
}

// Start starts the Connect server
func (cs *ConnectServer) Start() error {
	mux := http.NewServeMux()

	// Rate limiter: 10 requests per second, burst of 20
	rateLimiter := ratelimit.NewIPRateLimiter(10, 20)

	// Health check
	mux.HandleFunc("/health", cs.handleHealth)

	// Vaults
	mux.HandleFunc("/v1/vaults", cs.authMiddleware(rateLimiter, cs.handleVaults))

	// Vault items
	mux.HandleFunc("/v1/vaults/", cs.authMiddleware(rateLimiter, cs.handleVaultItems))

	cs.Running = true
	fmt.Printf("Connect server starting on %s:%d\n", cs.Host, cs.Port)
	fmt.Printf("Token: %s\n", cs.Token)
	fmt.Println("Rate limit: 10 req/s, burst 20")
	fmt.Println("Press Ctrl+C to stop")

	return http.ListenAndServe(fmt.Sprintf("%s:%d", cs.Host, cs.Port), mux)
}

// authMiddleware checks Connect token and rate limit
func (cs *ConnectServer) authMiddleware(rateLimiter *ratelimit.IPRateLimiter, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Rate limiting
		ip := r.RemoteAddr
		if !rateLimiter.Allow(ip) {
			w.Header().Set("Retry-After", "1")
			http.Error(w, "Rate limit exceeded", 429)
			return
		}

		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Missing authorization header", http.StatusUnauthorized)
			return
		}

		token := strings.TrimPrefix(authHeader, "Bearer ")
		ct, err := ValidateToken(token)
		if err != nil {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		r.Header.Set("X-Connect-Token", ct.Token)
		next(w, r)
	}
}

func (cs *ConnectServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "ok",
		"version": "1.0.0",
	})
}

func (cs *ConnectServer) handleVaults(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		// List vaults
		vaults := []map[string]string{
			{"id": "personal", "name": "Personal"},
		}
		json.NewEncoder(w).Encode(vaults)
	case http.MethodPost:
		// Create vault
		var vault map[string]string
		json.NewDecoder(r.Body).Decode(&vault)
		vault["id"] = "vault-" + time.Now().Format("20060102150405")
		json.NewEncoder(w).Encode(vault)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (cs *ConnectServer) handleVaultItems(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/v1/vaults/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		http.Error(w, "Invalid vault ID", http.StatusBadRequest)
		return
	}

	vaultID := parts[0]

	// If path is /v1/vaults/{id}/items
	if len(parts) >= 2 && parts[1] == "items" {
		switch r.Method {
		case http.MethodGet:
			ids, err := cs.Storage.ListItems()
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			var items []map[string]string
			for _, id := range ids {
				item, err := cs.Storage.LoadItem(id)
				if err != nil {
					continue
				}
				items = append(items, map[string]string{
					"id":    item.ID,
					"title": item.Title,
					"vault": vaultID,
				})
			}
			json.NewEncoder(w).Encode(items)

		case http.MethodPost:
			var item vault.Item
			if err := json.NewDecoder(r.Body).Decode(&item); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			item.ID = generateItemID()
			item.CreatedAt = time.Now()
			item.UpdatedAt = time.Now()

			if err := cs.Storage.SaveItem(&item); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(item)

		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
		return
	}

	// If path is /v1/vaults/{id}
	json.NewEncoder(w).Encode(map[string]string{
		"id":   vaultID,
		"name": "Vault " + vaultID,
	})
}

func generateItemID() string {
	return fmt.Sprintf("item_%d", time.Now().UnixNano())
}

// ListTokens lists all Connect tokens
func ListTokens() error {
	tokens, err := LoadTokens()
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Println("No Connect tokens found.")
			return nil
		}
		return err
	}

	if len(tokens) == 0 {
		fmt.Println("No Connect tokens found.")
		return nil
	}

	fmt.Println("Connect Tokens:")
	for _, t := range tokens {
		status := "active"
		if time.Now().After(t.ExpiresAt) {
			status = "expired"
		}
		fmt.Printf("  - %s [%s]\n", t.Name, status)
		fmt.Printf("    Token: %s...\n", t.Token[:20])
		fmt.Printf("    Vaults: %v\n", t.Vaults)
		fmt.Printf("    Scopes: %v\n", t.Scopes)
		fmt.Printf("    Created: %s, Expires: %s\n", t.CreatedAt.Format("2006-01-02"), t.ExpiresAt.Format("2006-01-02"))
	}

	return nil
}

// DeleteToken deletes a Connect token
func DeleteToken(name string) error {
	tokens, err := LoadTokens()
	if err != nil {
		return err
	}

	var newTokens []ConnectToken
	for _, t := range tokens {
		if t.Name != name {
			newTokens = append(newTokens, t)
		}
	}

	configPath := filepath.Join(storage.DefaultPath(), "opx_connect_tokens.json")
	data, err := json.MarshalIndent(newTokens, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(configPath, data, 0600)
}
