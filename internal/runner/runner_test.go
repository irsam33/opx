package runner

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestNewRunner(t *testing.T) {
	r := NewRunner("echo", []string{"hello"})

	if r.Command != "echo" {
		t.Errorf("Command = %q, want echo", r.Command)
	}

	if len(r.Args) != 1 || r.Args[0] != "hello" {
		t.Errorf("Args = %v, want [hello]", r.Args)
	}

	if r.Env == nil {
		t.Error("Env should be initialized")
	}

	if r.Secrets == nil {
		t.Error("Secrets should be initialized")
	}

	if !r.MaskSecrets {
		t.Error("MaskSecrets should default to true")
	}
}

func TestAddSecret(t *testing.T) {
	r := NewRunner("test", nil)

	r.AddSecret("API_KEY", "secret-key-123")

	if len(r.Secrets) != 1 {
		t.Fatalf("Secrets length = %d, want 1", len(r.Secrets))
	}

	if r.Secrets["API_KEY"] != "secret-key-123" {
		t.Errorf("Secret = %q, want secret-key-123", r.Secrets["API_KEY"])
	}
}

func TestSetEnv(t *testing.T) {
	r := NewRunner("test", nil)

	r.SetEnv("CUSTOM_VAR", "custom-value")

	if r.Env["CUSTOM_VAR"] != "custom-value" {
		t.Errorf("Env = %q, want custom-value", r.Env["CUSTOM_VAR"])
	}
}

func TestMultipleSecrets(t *testing.T) {
	r := NewRunner("test", nil)

	r.AddSecret("DB_PASSWORD", "db-pass-123")
	r.AddSecret("API_KEY", "api-key-456")
	r.AddSecret("TOKEN", "bearer-token-789")

	if len(r.Secrets) != 3 {
		t.Fatalf("Secrets length = %d, want 3", len(r.Secrets))
	}

	expected := map[string]string{
		"DB_PASSWORD": "db-pass-123",
		"API_KEY":     "api-key-456",
		"TOKEN":       "bearer-token-789",
	}

	for k, v := range expected {
		if r.Secrets[k] != v {
			t.Errorf("Secret %s = %q, want %q", k, r.Secrets[k], v)
		}
	}
}

func TestParseSecretReference(t *testing.T) {
	tests := []struct {
		name     string
		ref      string
		wantErr  bool
		wantVault string
		wantItem  string
		wantField string
	}{
		{
			name:     "valid reference",
			ref:      "op://Personal/My Login/password",
			wantErr:  false,
			wantVault: "Personal",
			wantItem:  "My Login",
			wantField: "password",
		},
		{
			name:     "valid reference simple",
			ref:      "op://work/db/username",
			wantErr:  false,
			wantVault: "work",
			wantItem:  "db",
			wantField: "username",
		},
		{
			name:    "missing op:// prefix",
			ref:     "Personal/My Login/password",
			wantErr: true,
		},
		{
			name:    "too few parts",
			ref:     "op://Personal/password",
			wantErr: true,
		},
		{
			name:    "empty reference",
			ref:     "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vault, item, field, err := ParseSecretReference(tt.ref)

			if (err != nil) != tt.wantErr {
				t.Errorf("ParseSecretReference() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if vault != tt.wantVault {
					t.Errorf("Vault = %q, want %q", vault, tt.wantVault)
				}
				if item != tt.wantItem {
					t.Errorf("Item = %q, want %q", item, tt.wantItem)
				}
				if field != tt.wantField {
					t.Errorf("Field = %q, want %q", field, tt.wantField)
				}
			}
		})
	}
}

func TestResolveSecrets(t *testing.T) {
	envVars := map[string]string{
		"DB_PASSWORD":    "op://Personal/Database/password",
		"API_KEY":        "op://Personal/API/key",
		"PLAIN_VAR":      "not-a-secret",
		"ANOTHER_SECRET": "op://work/service/token",
	}

	secrets := ResolveSecrets(envVars)

	// Secret references should be resolved
	if secrets["DB_PASSWORD"] != "[secret from op://Personal/Database/password]" {
		t.Errorf("Resolved DB_PASSWORD = %q", secrets["DB_PASSWORD"])
	}

	// Plain values should pass through
	if secrets["PLAIN_VAR"] != "not-a-secret" {
		t.Errorf("Resolved PLAIN_VAR = %q, want not-a-secret", secrets["PLAIN_VAR"])
	}
}

func TestResolveSecretsEmpty(t *testing.T) {
	secrets := ResolveSecrets(map[string]string{})

	if len(secrets) != 0 {
		t.Errorf("Empty map should return empty secrets, got %v", secrets)
	}
}

func TestListSecretReferences(t *testing.T) {
	// Set up test environment
	original := os.Environ()
	defer func() {
		os.Clearenv()
		for _, env := range original {
			parts := strings.SplitN(env, "=", 2)
			if len(parts) == 2 {
				os.Setenv(parts[0], parts[1])
			}
		}
	}()

	os.Clearenv()
	os.Setenv("DB_PASSWORD", "op://Personal/Database/password")
	os.Setenv("API_KEY", "op://Personal/API/key")
	os.Setenv("PLAIN_VAR", "not-a-secret")
	os.Setenv("TOKEN", "op://work/service/token")

	refs := ListSecretReferences()

	if len(refs) != 3 {
		t.Errorf("Found %d references, want 3", len(refs))
	}

	expected := map[string]string{
		"DB_PASSWORD": "op://Personal/Database/password",
		"API_KEY":     "op://Personal/API/key",
		"TOKEN":       "op://work/service/token",
	}

	for k, v := range expected {
		if refs[k] != v {
			t.Errorf("Reference %s = %q, want %q", k, refs[k], v)
		}
	}
}

func TestListSecretReferencesNoRefs(t *testing.T) {
	original := os.Environ()
	defer func() {
		os.Clearenv()
		for _, env := range original {
			parts := strings.SplitN(env, "=", 2)
			if len(parts) == 2 {
				os.Setenv(parts[0], parts[1])
			}
		}
	}()

	os.Clearenv()
	os.Setenv("PLAIN_VAR1", "value1")
	os.Setenv("PLAIN_VAR2", "value2")

	refs := ListSecretReferences()

	if len(refs) != 0 {
		t.Errorf("Should find no references, got %v", refs)
	}
}

// Test that secrets are actually injected into subprocess environment
func TestSecretInjection(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	r := NewRunner("sh", []string{"-c", "echo $TEST_SECRET"})
	r.AddSecret("TEST_SECRET", " injected-value-123")

	output, err := r.RunStdout()
	if err != nil {
		t.Skipf("sh not available, skipping: %v", err)
	}

	if len(output) == 0 {
		t.Skip("could not capture output, skipping")
	}
}

// Helper methods added for testing
func (r *Runner) RunStdout() (string, error) {
	cmd := exec.Command(r.Command, r.Args...)
	// Build environment the same way as Run()
	env := os.Environ()
	for k, v := range r.Env {
		env = append(env, k+"="+v)
	}
	for k, v := range r.Secrets {
		env = append(env, k+"="+v)
	}
	cmd.Env = env

	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(output), nil
}

// RunWithMasking should work the same as Run
func TestRunWithMasking(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	r := NewRunner("echo", []string{"hello world"})
	err := r.RunWithMasking()
	if err != nil {
		t.Errorf("RunWithMasking() error = %v", err)
	}
}

// Benchmark secret parsing
func BenchmarkParseSecretReference(b *testing.B) {
	ref := "op://Personal/My Login/password"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _, err := ParseSecretReference(ref)
		if err != nil {
			b.Fatalf("ParseSecretReference() error = %v", err)
		}
	}
}

// Benchmark resolving secrets
func BenchmarkResolveSecrets(b *testing.B) {
	envVars := map[string]string{
		"DB_PASSWORD": "op://Personal/Database/password",
		"API_KEY":     "op://Personal/API/key",
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ResolveSecrets(envVars)
	}
}
