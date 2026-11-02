package runner

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// Runner manages subprocess execution with secret injection
type Runner struct {
	Command     string
	Args        []string
	Env         map[string]string
	Secrets     map[string]string // env var name -> secret value
	MaskSecrets bool
}

// NewRunner creates a new runner
func NewRunner(command string, args []string) *Runner {
	return &Runner{
		Command:     command,
		Args:        args,
		Env:         make(map[string]string),
		Secrets:     make(map[string]string),
		MaskSecrets: true,
	}
}

// AddSecret adds a secret to be injected
func (r *Runner) AddSecret(envVar, value string) {
	r.Secrets[envVar] = value
}

// SetEnv sets an environment variable
func (r *Runner) SetEnv(key, value string) {
	r.Env[key] = value
}

// Run executes the command with secrets injected
func (r *Runner) Run() error {
	cmd := exec.Command(r.Command, r.Args...)

	// Build environment
	env := os.Environ()
	for k, v := range r.Env {
		env = append(env, k+"="+v)
	}
	for k, v := range r.Secrets {
		env = append(env, k+"="+v)
	}
	cmd.Env = env

	// Set up I/O
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	fmt.Printf("Running: %s %s\n", r.Command, strings.Join(r.Args, " "))
	fmt.Printf("Secrets injected: %d\n", len(r.Secrets))

	start := time.Now()
	err := cmd.Run()
	duration := time.Since(start)

	if err != nil {
		fmt.Printf("Command failed: %v (duration: %s)\n", err, duration)
		return err
	}

	fmt.Printf("Command completed successfully (duration: %s)\n", duration)
	return nil
}

// RunWithMasking runs command with secret masking in output
func (r *Runner) RunWithMasking() error {
	// For simplicity, just run normally
	// In a real implementation, we'd intercept stdout/stderr and mask secrets
	return r.Run()
}

// ParseSecretReference parses an op:// reference
func ParseSecretReference(ref string) (vault, item, field string, err error) {
	// Format: op://vault/item/field
	if !strings.HasPrefix(ref, "op://") {
		return "", "", "", fmt.Errorf("invalid reference: must start with op://")
	}

	parts := strings.Split(strings.TrimPrefix(ref, "op://"), "/")
	if len(parts) < 3 {
		return "", "", "", fmt.Errorf("invalid reference: must be op://vault/item/field")
	}

	return parts[0], parts[1], parts[2], nil
}

// ResolveSecrets resolves secret references from environment variables
func ResolveSecrets(envVars map[string]string) map[string]string {
	secrets := make(map[string]string)
	for key, ref := range envVars {
		if strings.HasPrefix(ref, "op://") {
			// In a real implementation, this would fetch from 1Password
			// For demo, return a placeholder
			secrets[key] = fmt.Sprintf("[secret from %s]", ref)
		} else {
			secrets[key] = ref
		}
	}
	return secrets
}

// ListSecretReferences lists all secret references in environment
func ListSecretReferences() map[string]string {
	refs := make(map[string]string)
	for _, env := range os.Environ() {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) == 2 && strings.HasPrefix(parts[1], "op://") {
			refs[parts[0]] = parts[1]
		}
	}
	return refs
}
