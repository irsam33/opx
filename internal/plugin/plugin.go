package plugin

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Plugin represents a plugin definition
type Plugin struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Path        string   `json:"path"`
	Version     string   `json:"version"`
	Commands    []string `json:"commands"`
}

// PluginManager manages plugins
type PluginManager struct {
	PluginDir string
	Plugins   map[string]*Plugin
}

// NewPluginManager creates a new plugin manager
func NewPluginManager() *PluginManager {
	home, _ := os.UserHomeDir()
	pluginDir := filepath.Join(home, ".opx", "plugins")

	return &PluginManager{
		PluginDir: pluginDir,
		Plugins:   make(map[string]*Plugin),
	}
}

// Discover discovers plugins in the plugin directory
func (pm *PluginManager) Discover() error {
	if err := os.MkdirAll(pm.PluginDir, 0700); err != nil {
		return err
	}

	entries, err := os.ReadDir(pm.PluginDir)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		// Check if executable
		info, err := entry.Info()
		if err != nil {
			continue
		}
		_ = info

		// On Windows, check .exe or .bat extension
		if !strings.HasSuffix(entry.Name(), ".exe") && !strings.HasSuffix(entry.Name(), ".bat") && !strings.HasSuffix(entry.Name(), ".sh") {
			continue
		}

		// Try to get plugin info
		pluginPath := filepath.Join(pm.PluginDir, entry.Name())
		// Use filename without extension as plugin name
		pluginName := entry.Name()
		if idx := strings.LastIndex(pluginName, "."); idx > 0 {
			pluginName = pluginName[:idx]
		}
		plugin, err := pm.getPluginInfo(pluginPath, pluginName)
		if err != nil {
			continue
		}

		pm.Plugins[plugin.Name] = plugin
	}

	return nil
}

func (pm *PluginManager) getPluginInfo(path, name string) (*Plugin, error) {
	// Run plugin with --info flag to get metadata
	cmd := exec.Command(path, "--info")
	output, err := cmd.Output()
	if err != nil {
		// If --info fails, create a basic plugin entry
		return &Plugin{
			Name:        name,
			Description: "Plugin: " + name,
			Path:        path,
			Version:     "1.0.0",
			Commands:    []string{},
		}, nil
	}

	var plugin Plugin
	if err := json.Unmarshal(output, &plugin); err != nil {
		return nil, err
	}

	plugin.Path = path
	return &plugin, nil
}

// ListPlugins lists all discovered plugins
func (pm *PluginManager) ListPlugins() []*Plugin {
	var plugins []*Plugin
	for _, p := range pm.Plugins {
		plugins = append(plugins, p)
	}
	return plugins
}

// GetPlugin gets a plugin by name
func (pm *PluginManager) GetPlugin(name string) (*Plugin, error) {
	plugin, ok := pm.Plugins[name]
	if !ok {
		return nil, fmt.Errorf("plugin not found: %s", name)
	}
	return plugin, nil
}

// ExecutePlugin executes a plugin command
func (pm *PluginManager) ExecutePlugin(name string, args []string) error {
	plugin, err := pm.GetPlugin(name)
	if err != nil {
		return err
	}

	// Execute the plugin
	cmd := exec.Command(plugin.Path, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("plugin execution failed: %w", err)
	}

	return nil
}

// InstallPlugin installs a plugin from a path
func (pm *PluginManager) InstallPlugin(sourcePath, name string) error {
	if err := os.MkdirAll(pm.PluginDir, 0700); err != nil {
		return err
	}

	destPath := filepath.Join(pm.PluginDir, name)
	if !strings.HasSuffix(destPath, ".exe") && !strings.HasSuffix(destPath, ".bat") && !strings.HasSuffix(destPath, ".sh") {
		destPath += ".exe"
	}

	// Copy file
	data, err := os.ReadFile(sourcePath)
	if err != nil {
		return fmt.Errorf("cannot read source: %w", err)
	}

	if err := os.WriteFile(destPath, data, 0755); err != nil {
		return fmt.Errorf("cannot write plugin: %w", err)
	}

	fmt.Printf("Installed plugin: %s\n", destPath)
	return nil
}

// RemovePlugin removes a plugin
func (pm *PluginManager) RemovePlugin(name string) error {
	plugin, err := pm.GetPlugin(name)
	if err != nil {
		return err
	}

	if err := os.Remove(plugin.Path); err != nil {
		return fmt.Errorf("cannot remove plugin: %w", err)
	}

	delete(pm.Plugins, name)
	fmt.Printf("Removed plugin: %s\n", name)
	return nil
}

// CreateExamplePlugin creates an example plugin script
func CreateExamplePlugin(dir string) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	// Create a simple batch script plugin (Windows compatible)
	script := `@echo off
if "%1"=="--info" (
    echo {"name":"example","description":"Example plugin","version":"1.0.0","commands":["hello","status"]}
    exit /b 0
)

if "%1"=="hello" (
    echo Hello from example plugin!
    exit /b 0
)

if "%1"=="status" (
    echo Plugin is working!
    exit /b 0
)

echo Unknown command: %1
echo Available: hello, status
`

	path := filepath.Join(dir, "example.bat")
	return os.WriteFile(path, []byte(script), 0755)
}
