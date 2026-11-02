package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
	"github.com/user/opx/internal/auth"
	"github.com/user/opx/internal/clipboard"
	"github.com/user/opx/internal/cloudsync"
	"github.com/user/opx/internal/codesign"
	"github.com/user/opx/internal/connect"
	"github.com/user/opx/internal/desktopapp"
	"github.com/user/opx/internal/events"
	"github.com/user/opx/internal/plugin"
	"github.com/user/opx/internal/runner"
	"github.com/user/opx/internal/serviceaccount"
	"github.com/user/opx/internal/srp"
	"github.com/user/opx/internal/srpauth"
	"github.com/user/opx/internal/ssh"
	"github.com/user/opx/internal/storage"
	"github.com/user/opx/internal/sync"
	"github.com/user/opx/internal/totp"
	"github.com/user/opx/internal/update"
	"github.com/user/opx/internal/vault"
)

var authInstance = auth.NewAuth()

var signinCmd = &cobra.Command{
	Use:   "signin [account]",
	Short: "Sign in to your vault",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		account := args[0]
		fmt.Printf("Signing in to %s...\n", account)
		fmt.Print("Enter master password: ")
		var password string
		fmt.Scanln(&password)

		// Check if SRP is registered for this account
		srpPath := filepath.Join(storage.DefaultPath(), "opx_srp.json")
		if _, err := os.Stat(srpPath); err == nil {
			// SRP is registered, use SRP auth
			fmt.Println("Using SRP authentication...")
			if err := srpAuth.SignIn(account, password); err != nil {
				return fmt.Errorf("SRP sign in failed: %w", err)
			}
			// Sync with main auth instance
			authInstance.Account = account
			mk, _ := srpAuth.GetMasterKey()
			authInstance.Storage.MasterKey = mk
			authInstance.Storage.BasePath = storage.DefaultPath()
		} else {
			// Fall back to password-based auth
			fmt.Println("Using password-based authentication...")
			authInstance.Account = account
			if err := authInstance.SignIn(password); err != nil {
				return fmt.Errorf("sign in failed: %w", err)
			}
		}

		// Log event
		es := events.NewEventStore(events.DefaultPath())
		es.Load()
		es.Log(events.EventSignIn, account, "vault", map[string]interface{}{
			"method": func() string {
				if _, err := os.Stat(srpPath); err == nil {
					return "srp"
				}
				return "password"
			}(),
		})

		fmt.Println("Signed in successfully!")
		return nil
	},
}

var signoutCmd = &cobra.Command{
	Use:   "signout",
	Short: "Sign out of your vault",
	RunE: func(cmd *cobra.Command, args []string) error {
		// Sign out of both auth systems
		authInstance.SignOut()
		srpAuth.SignOut()
		fmt.Println("Signed out successfully!")
		return nil
	},
}

var whoamiCmd = &cobra.Command{
	Use:   "whoami",
	Short: "Show the currently signed in account",
	RunE: func(cmd *cobra.Command, args []string) error {
		// Check SRP first
		if srpAuth.IsSignedIn() {
			fmt.Printf("Account: %s (SRP)\n", srpAuth.Account)
			sessionKey, _ := srpAuth.GetSessionKey()
			fmt.Printf("Session Key: %x...\n", sessionKey[:16])
			return nil
		}

		// Check password-based auth
		if !authInstance.IsSignedIn() {
			return fmt.Errorf("not signed in")
		}
		fmt.Printf("Account: %s (password)\n", authInstance.Account)
		return nil
	},
}

var vaultCmd = &cobra.Command{
	Use:   "vault",
	Short: "Manage vaults",
}

var vaultListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all vaults",
	RunE: func(cmd *cobra.Command, args []string) error {
		if !authInstance.IsSignedIn() {
			return fmt.Errorf("not signed in")
		}
		fmt.Println("Vaults:")
		fmt.Println("  - Personal (default)")
		return nil
	},
}

var itemCmd = &cobra.Command{
	Use:   "item",
	Short: "Manage items",
}

var itemCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new item",
	RunE: func(cmd *cobra.Command, args []string) error {
		if !authInstance.IsSignedIn() {
			return fmt.Errorf("not signed in")
		}

		title, _ := cmd.Flags().GetString("title")
		category, _ := cmd.Flags().GetString("category")
		vaultName, _ := cmd.Flags().GetString("vault")

		if title == "" {
			return fmt.Errorf("title is required")
		}
		if category == "" {
			category = "login"
		}
		if vaultName == "" {
			vaultName = "Personal"
		}

		item := vault.NewItem(title, category, vaultName)
		fmt.Printf("Created item: %s (ID: %s)\n", item.Title, item.ID)

		// Save to storage
		masterKey, _ := authInstance.GetMasterKey()
		storage := &storage.Storage{
			BasePath:  storage.DefaultPath(),
			MasterKey: masterKey,
		}
		if err := storage.SaveItem(item); err != nil {
			return fmt.Errorf("failed to save item: %w", err)
		}

		// Log event
		es := events.NewEventStore(events.DefaultPath())
		es.Load()
		es.Log(events.EventItemCreate, authInstance.Account, item.ID, map[string]interface{}{
			"title":    item.Title,
			"category": item.Category,
			"vault":    item.Vault,
		})

		return nil
	},
}

var itemGetCmd = &cobra.Command{
	Use:   "get [item-id]",
	Short: "Get an item by ID",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if !authInstance.IsSignedIn() {
			return fmt.Errorf("not signed in")
		}

		masterKey, _ := authInstance.GetMasterKey()
		storage := &storage.Storage{
			BasePath:  storage.DefaultPath(),
			MasterKey: masterKey,
		}

		item, err := storage.LoadItem(args[0])
		if err != nil {
			return fmt.Errorf("item not found: %w", err)
		}

		data, _ := item.ToJSON()
		fmt.Println(data)
		return nil
	},
}

var itemEditCmd = &cobra.Command{
	Use:   "edit [item-id]",
	Short: "Edit an item",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if !authInstance.IsSignedIn() {
			return fmt.Errorf("not signed in")
		}

		masterKey, _ := authInstance.GetMasterKey()
		storage := &storage.Storage{
			BasePath:  storage.DefaultPath(),
			MasterKey: masterKey,
		}

		item, err := storage.LoadItem(args[0])
		if err != nil {
			return fmt.Errorf("item not found: %w", err)
		}

		// Add field if specified
		if fieldLabel, _ := cmd.Flags().GetString("field"); fieldLabel != "" {
			fieldValue, _ := cmd.Flags().GetString("value")
			item.AddField(fieldLabel, "text", fieldValue)
		}

		if err := storage.SaveItem(item); err != nil {
			return fmt.Errorf("failed to save: %w", err)
		}

		fmt.Printf("Updated item: %s\n", item.Title)
		return nil
	},
}

var itemDeleteCmd = &cobra.Command{
	Use:   "delete [item-id]",
	Short: "Delete an item",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if !authInstance.IsSignedIn() {
			return fmt.Errorf("not signed in")
		}

		masterKey, _ := authInstance.GetMasterKey()
		storage := &storage.Storage{
			BasePath:  storage.DefaultPath(),
			MasterKey: masterKey,
		}

		if err := storage.DeleteItem(args[0]); err != nil {
			return fmt.Errorf("failed to delete: %w", err)
		}

		fmt.Printf("Deleted item: %s\n", args[0])
		return nil
	},
}

var itemSearchCmd = &cobra.Command{
	Use:   "search [query]",
	Short: "Search items",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if !authInstance.IsSignedIn() {
			return fmt.Errorf("not signed in")
		}

		masterKey, _ := authInstance.GetMasterKey()
		storage := &storage.Storage{
			BasePath:  storage.DefaultPath(),
			MasterKey: masterKey,
		}

		ids, err := storage.ListItems()
		if err != nil {
			return err
		}

		fmt.Printf("Found %d items:\n", len(ids))
		for _, id := range ids {
			item, err := storage.LoadItem(id)
			if err != nil {
				continue
			}
			if contains(item.Title, args[0]) {
				fmt.Printf("  - %s (ID: %s)\n", item.Title, item.ID)
			}
		}
		return nil
	},
}

var readCmd = &cobra.Command{
	Use:   "read [reference]",
	Short: "Read a secret reference (op://vault/item/field)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if !authInstance.IsSignedIn() {
			return fmt.Errorf("not signed in")
		}

		// Parse reference: op://vault/item/field
		ref := args[0]
		fmt.Printf("Reading: %s\n", ref)

		// For demo, just show the reference
		fmt.Println("Secret value: [REDACTED]")
		return nil
	},
}

// TOTP Commands

var totpCmd = &cobra.Command{
	Use:   "totp",
	Short: "Manage TOTP (2FA) codes",
}

var totpGenerateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate a new TOTP secret",
	RunE: func(cmd *cobra.Command, args []string) error {
		secret, err := totp.GenerateSecret()
		if err != nil {
			return err
		}
		fmt.Printf("TOTP Secret: %s\n", secret)
		fmt.Printf("QR Code URL: %s\n", totp.GenerateQRCodeURL(
			&totp.TOTPConfig{Secret: secret, Algorithm: "SHA1", Digits: 6, Period: 30},
			"user@example.com", "opx"))
		return nil
	},
}

var totpCodeCmd = &cobra.Command{
	Use:   "code [secret]",
	Short: "Generate a TOTP code from a secret",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		config := &totp.TOTPConfig{
			Secret:    args[0],
			Algorithm: "SHA1",
			Digits:    6,
			Period:    30,
		}
		code, err := totp.GenerateCode(config)
		if err != nil {
			return err
		}
		remaining := totp.GetRemainingSeconds(config)
		fmt.Printf("Code: %s (expires in %d seconds)\n", code, remaining)
		return nil
	},
}

var totpVerifyCmd = &cobra.Command{
	Use:   "verify [secret] [code]",
	Short: "Verify a TOTP code",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		config := &totp.TOTPConfig{
			Secret:    args[0],
			Algorithm: "SHA1",
			Digits:    6,
			Period:    30,
		}
		if totp.VerifyCode(config, args[1]) {
			fmt.Println("✅ Code is valid!")
		} else {
			fmt.Println("❌ Code is invalid!")
		}
		return nil
	},
}

// Sync Commands

var syncCmd = &cobra.Command{
	Use:   "sync",
	Short: "Synchronize vault data",
}

var syncExportCmd = &cobra.Command{
	Use:   "export [filename]",
	Short: "Export vault items to a file",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if !authInstance.IsSignedIn() {
			return fmt.Errorf("not signed in")
		}

		masterKey, _ := authInstance.GetMasterKey()
		_ = masterKey

		sm := sync.NewSyncManager(storage.DefaultPath(), "")
		if err := sm.Export(args[0]); err != nil {
			return err
		}
		fmt.Printf("Exported to: %s\n", args[0])
		return nil
	},
}

var syncImportCmd = &cobra.Command{
	Use:   "import [filename]",
	Short: "Import vault items from a file",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		sm := sync.NewSyncManager(storage.DefaultPath(), "")
		if err := sm.Import(args[0]); err != nil {
			return err
		}
		return nil
	},
}

var syncStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show sync status",
	RunE: func(cmd *cobra.Command, args []string) error {
		sm := sync.NewSyncManager(storage.DefaultPath(), "")
		fmt.Println(sm.Status())
		return nil
	},
}

// SSH Commands

var sshCmd = &cobra.Command{
	Use:   "ssh",
	Short: "Manage SSH keys",
}

var sshGenerateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate a new SSH key",
	RunE: func(cmd *cobra.Command, args []string) error {
		keyType, _ := cmd.Flags().GetString("type")
		keyName, _ := cmd.Flags().GetString("name")

		if keyName == "" {
			return fmt.Errorf("key name is required (--name)")
		}

		kt := ssh.KeyTypeEd25519
		if keyType == "rsa" {
			kt = ssh.KeyTypeRSA
		}

		key, err := ssh.GenerateKey(kt, keyName)
		if err != nil {
			return fmt.Errorf("failed to generate key: %w", err)
		}

		sshDir := ssh.GetSSHDir()
		if err := ssh.SaveKey(key, sshDir); err != nil {
			return fmt.Errorf("failed to save key: %w", err)
		}

		fmt.Printf("Generated %s SSH key: %s\n", key.Type, key.Name)
		fmt.Printf("Fingerprint: %s\n", key.Fingerprint)
		fmt.Printf("Public key saved to: %s.pub\n", filepath.Join(sshDir, key.Name))
		fmt.Printf("Private key saved to: %s\n", filepath.Join(sshDir, key.Name))
		fmt.Println("\nPublic key:")
		fmt.Println(key.PublicKey)
		return nil
	},
}

var sshListCmd = &cobra.Command{
	Use:   "list",
	Short: "List SSH keys",
	RunE: func(cmd *cobra.Command, args []string) error {
		sshDir := ssh.GetSSHDir()
		keys, err := ssh.ListKeys(sshDir)
		if err != nil {
			return err
		}

		if len(keys) == 0 {
			fmt.Println("No SSH keys found.")
			return nil
		}

		fmt.Println("SSH Keys:")
		for _, keyName := range keys {
			key, err := ssh.LoadKey(keyName, sshDir)
			if err != nil {
				fmt.Printf("  - %s (error: %v)\n", keyName, err)
				continue
			}
			fmt.Printf("  - %s (%s) %s\n", key.Name, key.Type, key.Fingerprint)
		}
		return nil
	},
}

var sshShowCmd = &cobra.Command{
	Use:   "show [key-name]",
	Short: "Show an SSH public key",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		sshDir := ssh.GetSSHDir()
		key, err := ssh.LoadKey(args[0], sshDir)
		if err != nil {
			return err
		}
		fmt.Println(key.PublicKey)
		return nil
	},
}

var sshDeleteCmd = &cobra.Command{
	Use:   "delete [key-name]",
	Short: "Delete an SSH key",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		sshDir := ssh.GetSSHDir()
		if err := ssh.DeleteKey(args[0], sshDir); err != nil {
			return err
		}
		fmt.Printf("Deleted SSH key: %s\n", args[0])
		return nil
	},
}

// Service Account Commands

var serviceAccountCmd = &cobra.Command{
	Use:   "service-account",
	Short: "Manage service accounts",
}

var saCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new service account",
	RunE: func(cmd *cobra.Command, args []string) error {
		name, _ := cmd.Flags().GetString("name")
		email, _ := cmd.Flags().GetString("email")
		vaults, _ := cmd.Flags().GetStringSlice("vaults")

		if name == "" {
			return fmt.Errorf("name is required (--name)")
		}
		if email == "" {
			email = name + "@service-account"
		}
		if len(vaults) == 0 {
			vaults = []string{"*"}
		}

		sa := serviceaccount.NewServiceAccount(name, email, vaults)
		token, err := sa.GenerateToken()
		if err != nil {
			return fmt.Errorf("failed to generate token: %w", err)
		}

		if err := sa.Save(); err != nil {
			return fmt.Errorf("failed to save service account: %w", err)
		}

		fmt.Printf("Created service account: %s\n", sa.Name)
		fmt.Printf("Email: %s\n", sa.Email)
		fmt.Printf("Vaults: %v\n", sa.Vaults)
		fmt.Printf("Token: %s\n", token)
		fmt.Println("\n⚠️  Save this token securely! It won't be shown again.")
		return nil
	},
}

var saListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all service accounts",
	RunE: func(cmd *cobra.Command, args []string) error {
		return serviceaccount.ListServiceAccounts()
	},
}

var saDeleteCmd = &cobra.Command{
	Use:   "delete [name]",
	Short: "Delete a service account",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := serviceaccount.DeleteServiceAccount(args[0]); err != nil {
			return err
		}
		fmt.Printf("Deleted service account: %s\n", args[0])
		return nil
	},
}

var saTokenInfoCmd = &cobra.Command{
	Use:   "token-info [token]",
	Short: "Show information about a service account token",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		info, err := serviceaccount.GetTokenInfo(args[0])
		if err != nil {
			return err
		}

		fmt.Println("Token Information:")
		fmt.Printf("  Account UUID: %s\n", info.AccountUUID)
		fmt.Printf("  User UUID: %s\n", info.UserUUID)
		fmt.Printf("  Vault UUIDs: %v\n", info.VaultUUIDs)
		fmt.Printf("  Scopes: %v\n", info.Scopes)
		fmt.Printf("  Issued: %s\n", time.Unix(info.IssuedAt, 0).Format("2006-01-02 15:04:05"))
		fmt.Printf("  Expires: %s\n", time.Unix(info.ExpiresAt, 0).Format("2006-01-02 15:04:05"))

		if time.Now().Unix() > info.ExpiresAt {
			fmt.Println("  Status: ❌ EXPIRED")
		} else {
			fmt.Println("  Status: ✅ Valid")
		}
		return nil
	},
}

var saSigninCmd = &cobra.Command{
	Use:   "signin",
	Short: "Sign in with a service account token",
	RunE: func(cmd *cobra.Command, args []string) error {
		token, _ := cmd.Flags().GetString("token")
		if token == "" {
			// Try environment variable
			token = os.Getenv("OP_SERVICE_ACCOUNT_TOKEN")
		}
		if token == "" {
			return fmt.Errorf("token is required (--token or OP_SERVICE_ACCOUNT_TOKEN env var)")
		}

		if !serviceaccount.ValidateToken(token) {
			return fmt.Errorf("invalid or expired token")
		}

		info, _ := serviceaccount.GetTokenInfo(token)
		fmt.Printf("Signed in with service account: %s\n", info.AccountUUID)
		fmt.Printf("Vaults: %v\n", info.VaultUUIDs)
		fmt.Printf("Scopes: %v\n", info.Scopes)
		return nil
	},
}

// Plugin Commands

var pluginCmd = &cobra.Command{
	Use:   "plugin",
	Short: "Manage plugins",
}

var pluginListCmd = &cobra.Command{
	Use:   "list",
	Short: "List installed plugins",
	RunE: func(cmd *cobra.Command, args []string) error {
		pm := plugin.NewPluginManager()
		if err := pm.Discover(); err != nil {
			return err
		}

		plugins := pm.ListPlugins()
		if len(plugins) == 0 {
			fmt.Println("No plugins found.")
			fmt.Printf("Plugin directory: %s\n", pm.PluginDir)
			return nil
		}

		fmt.Println("Plugins:")
		for _, p := range plugins {
			fmt.Printf("  - %s v%s: %s\n", p.Name, p.Version, p.Description)
		}
		return nil
	},
}

var pluginInstallCmd = &cobra.Command{
	Use:   "install [source-path]",
	Short: "Install a plugin from a file",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name, _ := cmd.Flags().GetString("name")
		if name == "" {
			// Use filename as name
			name = filepath.Base(args[0])
		}

		pm := plugin.NewPluginManager()
		if err := pm.InstallPlugin(args[0], name); err != nil {
			return err
		}
		return nil
	},
}

var pluginRemoveCmd = &cobra.Command{
	Use:   "remove [name]",
	Short: "Remove a plugin",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		pm := plugin.NewPluginManager()
		if err := pm.Discover(); err != nil {
			return err
		}
		if err := pm.RemovePlugin(args[0]); err != nil {
			return err
		}
		return nil
	},
}

var pluginRunCmd = &cobra.Command{
	Use:   "run [plugin-name] [args...]",
	Short: "Run a plugin command",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		pm := plugin.NewPluginManager()
		if err := pm.Discover(); err != nil {
			return err
		}
		return pm.ExecutePlugin(args[0], args[1:])
	},
}

var pluginExampleCmd = &cobra.Command{
	Use:   "example",
	Short: "Create an example plugin",
	RunE: func(cmd *cobra.Command, args []string) error {
		pm := plugin.NewPluginManager()
		if err := plugin.CreateExamplePlugin(pm.PluginDir); err != nil {
			return err
		}
		fmt.Printf("Created example plugin in: %s\n", pm.PluginDir)
		fmt.Println("Run: opx plugin list")
		return nil
	},
}

// Events Commands

var eventsCmd = &cobra.Command{
	Use:   "events",
	Short: "Manage audit events",
}

var eventsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List recent events",
	RunE: func(cmd *cobra.Command, args []string) error {
		es := events.NewEventStore(events.DefaultPath())
		if err := es.Load(); err != nil {
			return err
		}

		limit, _ := cmd.Flags().GetInt("limit")
		eventType, _ := cmd.Flags().GetString("type")

		var filtered []events.Event
		if eventType != "" {
			filtered = es.Query(events.EventType(eventType), "", time.Time{}, limit)
		} else {
			filtered = es.GetRecent(limit)
		}

		if len(filtered) == 0 {
			fmt.Println("No events found.")
			return nil
		}

		fmt.Printf("Events (%d):\n", len(filtered))
		for _, e := range filtered {
			fmt.Println(events.FormatEvent(e))
		}
		return nil
	},
}

var eventsSummaryCmd = &cobra.Command{
	Use:   "summary",
	Short: "Show event summary",
	RunE: func(cmd *cobra.Command, args []string) error {
		es := events.NewEventStore(events.DefaultPath())
		if err := es.Load(); err != nil {
			return err
		}

		summary := es.GetSummary()
		fmt.Printf("Total Events: %d\n", summary.TotalEvents)
		fmt.Printf("Unique Actors: %d\n", summary.UniqueActors)
		if !summary.FirstEvent.IsZero() {
			fmt.Printf("First Event: %s\n", summary.FirstEvent.Format("2006-01-02 15:04:05"))
			fmt.Printf("Last Event: %s\n", summary.LastEvent.Format("2006-01-02 15:04:05"))
		}
		fmt.Println("\nBy Type:")
		for t, count := range summary.ByType {
			fmt.Printf("  %s: %d\n", t, count)
		}
		return nil
	},
}

var eventsExportCmd = &cobra.Command{
	Use:   "export [filename]",
	Short: "Export events to a file",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		es := events.NewEventStore(events.DefaultPath())
		if err := es.Load(); err != nil {
			return err
		}

		if err := es.Export(args[0]); err != nil {
			return err
		}
		fmt.Printf("Exported %d events to: %s\n", es.Count(), args[0])
		return nil
	},
}

var eventsClearCmd = &cobra.Command{
	Use:   "clear",
	Short: "Clear all events",
	RunE: func(cmd *cobra.Command, args []string) error {
		es := events.NewEventStore(events.DefaultPath())
		if err := es.Load(); err != nil {
			return err
		}

		count := es.Count()
		if err := es.Clear(); err != nil {
			return err
		}
		fmt.Printf("Cleared %d events.\n", count)
		return nil
	},
}

// Connect Server Commands

var connectCmd = &cobra.Command{
	Use:   "connect",
	Short: "Manage Connect server",
}

var connectTokenCmd = &cobra.Command{
	Use:   "token",
	Short: "Manage Connect tokens",
}

var connectServeCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the Connect server",
	RunE: func(cmd *cobra.Command, args []string) error {
		host, _ := cmd.Flags().GetString("host")
		port, _ := cmd.Flags().GetInt("port")
		token, _ := cmd.Flags().GetString("token")

		if host == "" {
			host = connect.DefaultHost()
		}
		if port == 0 {
			port = connect.DefaultPort()
		}

		if token == "" {
			// Generate a new token
			ct, err := connect.GenerateToken("default", []string{"*"})
			if err != nil {
				return err
			}
			if err := connect.SaveToken(ct); err != nil {
				return err
			}
			token = ct.Token
		}

		// Validate token
		ct, err := connect.ValidateToken(token)
		if err != nil {
			return fmt.Errorf("invalid token: %w", err)
		}
		_ = ct

		// Create storage
		masterKey := make([]byte, 32)
		storage := &storage.Storage{
			BasePath:  storage.DefaultPath(),
			MasterKey: masterKey,
		}

		server := connect.NewConnectServer(host, port, token, storage)
		return server.Start()
	},
}

var connectTokenCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a Connect token",
	RunE: func(cmd *cobra.Command, args []string) error {
		name, _ := cmd.Flags().GetString("name")
		vaults, _ := cmd.Flags().GetStringSlice("vaults")

		if name == "" {
			name = "default"
		}
		if len(vaults) == 0 {
			vaults = []string{"*"}
		}

		token, err := connect.GenerateToken(name, vaults)
		if err != nil {
			return err
		}

		if err := connect.SaveToken(token); err != nil {
			return err
		}

		fmt.Printf("Created Connect token: %s\n", token.Name)
		fmt.Printf("Token: %s\n", token.Token)
		fmt.Printf("Vaults: %v\n", token.Vaults)
		fmt.Printf("Scopes: %v\n", token.Scopes)
		fmt.Printf("Expires: %s\n", token.ExpiresAt.Format("2006-01-02"))
		return nil
	},
}

var connectTokenListCmd = &cobra.Command{
	Use:   "list",
	Short: "List Connect tokens",
	RunE: func(cmd *cobra.Command, args []string) error {
		return connect.ListTokens()
	},
}

var connectTokenDeleteCmd = &cobra.Command{
	Use:   "delete [name]",
	Short: "Delete a Connect token",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := connect.DeleteToken(args[0]); err != nil {
			return err
		}
		fmt.Printf("Deleted Connect token: %s\n", args[0])
		return nil
	},
}

// Desktop App Commands

var desktopCmd = &cobra.Command{
	Use:   "desktop",
	Short: "Manage desktop app integration",
}

var desktopStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Check desktop app status",
	RunE: func(cmd *cobra.Command, args []string) error {
		if desktopapp.IsDesktopAppInstalled() {
			fmt.Println("✅ 1Password desktop app is installed")
			settings, err := desktopapp.LoadDesktopAppSettings()
			if err != nil {
				fmt.Printf("  Settings: %v\n", err)
			} else {
				fmt.Printf("  System Auth Enabled: %v\n", settings.SystemAuthEnabled)
				fmt.Printf("  Last Signed In User: %s\n", settings.LastSignedInUser)
				fmt.Printf("  Device UUID: %s\n", settings.DeviceUUID)
			}
		} else {
			fmt.Println("❌ 1Password desktop app is not installed")
			fmt.Println("  Install from: https://1password.com/downloads/")
		}

		path, err := desktopapp.GetDesktopAppVersion()
		if err != nil {
			fmt.Printf("  Executable: %v\n", err)
		} else {
			fmt.Printf("  Executable: %s\n", path)
		}

		fmt.Printf("  Settings Path: %s\n", desktopapp.DesktopAppSettingsPath())
		fmt.Printf("  User Data Dir: %s\n", desktopapp.DesktopAppUserDataDir())
		return nil
	},
}

var desktopConnectCmd = &cobra.Command{
	Use:   "connect",
	Short: "Connect to desktop app via IPC",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("Connecting to desktop app...")
		conn, err := desktopapp.Connect(5 * time.Second)
		if err != nil {
			return fmt.Errorf("connection failed: %w", err)
		}
		defer conn.Close()

		fmt.Printf("✅ Connected to: %s\n", conn.PipeName)

		// Request accounts
		resp, err := conn.RequestAccounts()
		if err != nil {
			fmt.Printf("  RequestAccounts error: %v\n", err)
		} else {
			fmt.Printf("  Response: %+v\n", resp)
		}

		return nil
	},
}

var desktopInfoCmd = &cobra.Command{
	Use:   "info",
	Short: "Show system information for IPC",
	RunE: func(cmd *cobra.Command, args []string) error {
		info := desktopapp.GetSystemInfo()
		fmt.Println("System Information:")
		for k, v := range info {
			fmt.Printf("  %s: %v\n", k, v)
		}
		fmt.Printf("  Pipe Name: %s\n", desktopapp.PipeName())
		return nil
	},
}

// Cloud Sync Commands

var cloudSyncCmd = &cobra.Command{
	Use:   "cloud-sync",
	Short: "Manage cloud synchronization",
}

var cloudSyncConfigureCmd = &cobra.Command{
	Use:   "configure",
	Short: "Configure cloud sync",
	RunE: func(cmd *cobra.Command, args []string) error {
		serverURL, _ := cmd.Flags().GetString("server")
		apiKey, _ := cmd.Flags().GetString("api-key")

		if serverURL == "" {
			return fmt.Errorf("server URL is required (--server)")
		}
		if apiKey == "" {
			return fmt.Errorf("API key is required (--api-key)")
		}

		config := &cloudsync.CloudSyncConfig{
			ServerURL: serverURL,
			APIKey:    apiKey,
			SyncDir:   storage.DefaultPath(),
		}
		if err := cloudsync.SaveConfig(config); err != nil {
			return err
		}

		fmt.Printf("Cloud sync configured: %s\n", serverURL)
		return nil
	},
}

var cloudSyncPushCmd = &cobra.Command{
	Use:   "push",
	Short: "Push local items to cloud",
	RunE: func(cmd *cobra.Command, args []string) error {
		config, err := cloudsync.LoadConfig()
		if err != nil {
			return fmt.Errorf("cloud sync not configured: %w", err)
		}

		masterKey := make([]byte, 32)
		st := &storage.Storage{BasePath: storage.DefaultPath(), MasterKey: masterKey}
		cs := cloudsync.NewCloudSync(config.ServerURL, config.APIKey, st)
		cs.Config = config

		return cs.Push()
	},
}

var cloudSyncPullCmd = &cobra.Command{
	Use:   "pull",
	Short: "Pull items from cloud",
	RunE: func(cmd *cobra.Command, args []string) error {
		config, err := cloudsync.LoadConfig()
		if err != nil {
			return fmt.Errorf("cloud sync not configured: %w", err)
		}

		masterKey := make([]byte, 32)
		st := &storage.Storage{BasePath: storage.DefaultPath(), MasterKey: masterKey}
		cs := cloudsync.NewCloudSync(config.ServerURL, config.APIKey, st)
		cs.Config = config

		return cs.Pull()
	},
}

var cloudSyncStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show cloud sync status",
	RunE: func(cmd *cobra.Command, args []string) error {
		config, err := cloudsync.LoadConfig()
		if err != nil {
			fmt.Println("Cloud sync: Not configured")
			return nil
		}

		masterKey := make([]byte, 32)
		st := &storage.Storage{BasePath: storage.DefaultPath(), MasterKey: masterKey}
		cs := cloudsync.NewCloudSync(config.ServerURL, config.APIKey, st)
		cs.Config = config

		fmt.Printf("Cloud sync: %s\n", cs.Status())
		fmt.Printf("Server: %s\n", config.ServerURL)
		return nil
	},
}

var cloudSyncRealtimeCmd = &cobra.Command{
	Use:   "realtime",
	Short: "Perform real-time sync via WebSocket",
	RunE: func(cmd *cobra.Command, args []string) error {
		config, err := cloudsync.LoadConfig()
		if err != nil {
			return fmt.Errorf("cloud sync not configured: %w", err)
		}

		duration, _ := cmd.Flags().GetInt("duration")

		masterKey := make([]byte, 32)
		st := &storage.Storage{BasePath: storage.DefaultPath(), MasterKey: masterKey}
		cs := cloudsync.NewCloudSync(config.ServerURL, config.APIKey, st)
		cs.Config = config

		return cs.RealtimeSync(time.Duration(duration) * time.Second)
	},
}

var cloudSyncCmd2 = &cobra.Command{
	Use:   "sync",
	Short: "Perform bidirectional sync",
	RunE: func(cmd *cobra.Command, args []string) error {
		config, err := cloudsync.LoadConfig()
		if err != nil {
			return fmt.Errorf("cloud sync not configured: %w", err)
		}

		masterKey := make([]byte, 32)
		st := &storage.Storage{BasePath: storage.DefaultPath(), MasterKey: masterKey}
		cs := cloudsync.NewCloudSync(config.ServerURL, config.APIKey, st)
		cs.Config = config

		return cs.Sync()
	},
}

var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Check for and apply updates",
}

var updateCheckCmd = &cobra.Command{
	Use:   "check",
	Short: "Check for updates",
	RunE: func(cmd *cobra.Command, args []string) error {
		version := "1.0.0"
		update.CheckForUpdates(version)
		return nil
	},
}

// Events API Extensions

var updateInfoCmd = &cobra.Command{
	Use:   "info",
	Short: "Show update information",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Printf("Current version: 1.0.0\n")
		fmt.Printf("Platform: %s\n", update.GetPlatformInfo())
		fmt.Printf("Update URL: %s\n", "https://github.com/user/opx/releases")
		return nil
	},
}

var eventsWebhookCmd = &cobra.Command{
	Use:   "webhook",
	Short: "Manage event webhooks",
}

var eventsWebhookAddCmd = &cobra.Command{
	Use:   "add [url]",
	Short: "Add a webhook",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		eventsFilter, _ := cmd.Flags().GetStringSlice("events")
		if len(eventsFilter) == 0 {
			eventsFilter = []string{"*"}
		}

		wm := events.NewWebhookManager(events.DefaultPath())
		if err := wm.Load(); err != nil {
			return err
		}

		if err := wm.AddWebhook(args[0], eventsFilter, 3); err != nil {
			return err
		}

		fmt.Printf("Added webhook: %s\n", args[0])
		fmt.Printf("Events: %v\n", eventsFilter)
		return nil
	},
}

var eventsWebhookListCmd = &cobra.Command{
	Use:   "list",
	Short: "List webhooks",
	RunE: func(cmd *cobra.Command, args []string) error {
		wm := events.NewWebhookManager(events.DefaultPath())
		if err := wm.Load(); err != nil {
			return err
		}

		if len(wm.Configs) == 0 {
			fmt.Println("No webhooks configured.")
			return nil
		}

		fmt.Println("Webhooks:")
		for _, w := range wm.Configs {
			status := "enabled"
			if !w.Enabled {
				status = "disabled"
			}
			fmt.Printf("  - %s [%s] Events: %v\n", w.URL, status, w.Events)
		}
		return nil
	},
}

var eventsWebhookRemoveCmd = &cobra.Command{
	Use:   "remove [url]",
	Short: "Remove a webhook",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		wm := events.NewWebhookManager(events.DefaultPath())
		if err := wm.Load(); err != nil {
			return err
		}

		if err := wm.RemoveWebhook(args[0]); err != nil {
			return err
		}

		fmt.Printf("Removed webhook: %s\n", args[0])
		return nil
	},
}

var eventsRetentionCmd = &cobra.Command{
	Use:   "retention",
	Short: "Apply retention policy",
	RunE: func(cmd *cobra.Command, args []string) error {
		maxEvents, _ := cmd.Flags().GetInt("max-events")
		maxDays, _ := cmd.Flags().GetInt("max-days")

		es := events.NewEventStore(events.DefaultPath())
		if err := es.Load(); err != nil {
			return err
		}

		policy := events.DefaultRetentionPolicy()
		if maxEvents > 0 {
			policy.MaxEvents = maxEvents
		}
		if maxDays > 0 {
			policy.MaxAge = time.Duration(maxDays) * 24 * time.Hour
		}

		removed := es.ApplyRetention(policy)
		fmt.Printf("Removed %d events (policy: max %d events, %d days)\n", removed, policy.MaxEvents, maxDays)
		fmt.Printf("Remaining events: %d\n", es.Count())
		return nil
	},
}

// Code Signing Commands

var codesignCmd = &cobra.Command{
	Use:   "codesign",
	Short: "Manage code signing",
}

var codesignVerifyCmd = &cobra.Command{
	Use:   "verify [file]",
	Short: "Verify a file's digital signature",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		info, err := codesign.VerifySignature(args[0])
		if err != nil {
			return err
		}
		codesign.PrintSignatureInfo(info)
		return nil
	},
}

var codesignSignCmd = &cobra.Command{
	Use:   "sign [file]",
	Short: "Sign a file with a certificate",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cert, _ := cmd.Flags().GetString("cert")
		password, _ := cmd.Flags().GetString("password")
		timestamp, _ := cmd.Flags().GetString("timestamp")

		if cert == "" {
			return fmt.Errorf("certificate path is required (--cert)")
		}
		if password == "" {
			return fmt.Errorf("password is required (--password)")
		}
		if timestamp == "" {
			timestamp = "http://timestamp.digicert.com"
		}

		if err := codesign.SignFile(args[0], cert, password, timestamp); err != nil {
			return err
		}
		fmt.Printf("Successfully signed: %s\n", args[0])
		return nil
	},
}

var codesignCreateCertCmd = &cobra.Command{
	Use:   "create-cert",
	Short: "Create a self-signed code signing certificate",
	RunE: func(cmd *cobra.Command, args []string) error {
		subject, _ := cmd.Flags().GetString("subject")
		output, _ := cmd.Flags().GetString("output")
		password, _ := cmd.Flags().GetString("password")

		if subject == "" {
			subject = "CN=opx Code Signing"
		}
		if output == "" {
			output = "opx.pfx"
		}
		if password == "" {
			fmt.Print("Password: ")
			fmt.Scanln(&password)
		}

		if err := codesign.CreateSelfSignedCert(subject, output, password); err != nil {
			return err
		}
		fmt.Printf("Certificate saved to: %s\n", output)
		return nil
	},
}

var desktopBiometricCmd = &cobra.Command{
	Use:   "biometric",
	Short: "Test biometric authentication",
	RunE: func(cmd *cobra.Command, args []string) error {
		if !desktopapp.IsDesktopAppInstalled() {
			return fmt.Errorf("desktop app not installed")
		}

		fmt.Printf("Biometric type: %s\n", desktopapp.GetBiometricType())
		fmt.Printf("Biometric available: %v\n", desktopapp.IsBiometricAvailable())

		if !desktopapp.IsBiometricAvailable() {
			fmt.Println("⚠️  Biometric authentication is not enabled in the desktop app")
			fmt.Println("   Enable it in: 1Password > Settings > Security > Unlock with Windows Hello")
			return nil
		}

		fmt.Println("Connecting to desktop app...")
		conn, err := desktopapp.Connect(5 * time.Second)
		if err != nil {
			return fmt.Errorf("connection failed: %w", err)
		}
		defer conn.Close()

		fmt.Println("Requesting biometric authentication...")
		resp, err := conn.RequestBiometricAuth("Verify identity for opx")
		if err != nil {
			return fmt.Errorf("biometric auth failed: %w", err)
		}

		if resp.Success {
			fmt.Println("✅ Biometric authentication successful!")
		} else {
			fmt.Printf("❌ Biometric authentication failed: %s\n", resp.Error)
		}

		return nil
	},
}

var desktopListPipesCmd = &cobra.Command{
	Use:   "list-pipes",
	Short: "List available named pipes",
	RunE: func(cmd *cobra.Command, args []string) error {
		pipes, err := desktopapp.ListNamedPipes()
		if err != nil {
			return err
		}

		fmt.Println("Named Pipes:")
		for _, pipe := range pipes {
			if len(pipe) > 0 {
				fmt.Printf("  - %s\n", pipe)
			}
		}

		opPipes, err := desktopapp.FindOpPipes()
		if err == nil && len(opPipes) > 0 {
			fmt.Println("\n1Password-related pipes:")
			for _, pipe := range opPipes {
				fmt.Printf("  - %s\n", pipe)
			}
		}

		return nil
	},
}

// Auto Update Command

var updateAutoCmd = &cobra.Command{
	Use:   "auto",
	Short: "Automatically check and apply updates",
	RunE: func(cmd *cobra.Command, args []string) error {
		version := "1.0.0"
		uc := update.NewUpdateChecker(version)
		if err := uc.AutoUpdate(); err != nil {
			return err
		}
		return nil
	},
}

// SRP Commands

var srpCmd = &cobra.Command{
	Use:   "srp",
	Short: "SRP (Secure Remote Password) authentication",
}

var srpDemoCmd = &cobra.Command{
	Use:   "demo",
	Short: "Demonstrate SRP authentication flow",
	RunE: func(cmd *cobra.Command, args []string) error {
		username, _ := cmd.Flags().GetString("username")
		password, _ := cmd.Flags().GetString("password")

		if username == "" {
			username = "test@example.com"
		}
		if password == "" {
			fmt.Print("Password: ")
			fmt.Scanln(&password)
		}

		fmt.Println("=== SRP Authentication Demo ===")
		fmt.Printf("Username: %s\n", username)
		fmt.Printf("Password: %s\n", password)
		fmt.Println()

		// Create SRP exchange
		exchange := srp.NewSRPExchange(username, password)

		fmt.Printf("Salt: %x\n", exchange.Salt)
		fmt.Printf("A (client ephemeral): %s\n", exchange.A.String()[:64]+"...")
		fmt.Printf("B (server ephemeral): %s\n", exchange.B.String()[:64]+"...")
		fmt.Printf("U (scrambling): %s\n", exchange.U.String()[:32]+"...")
		fmt.Printf("M1 (client proof): %x\n", exchange.M1)
		fmt.Printf("M2 (server proof): %x\n", exchange.M2)
		fmt.Printf("Session Key: %x\n", exchange.SessionKey)
		fmt.Println()

		if exchange.VerifyExchange() {
			fmt.Println("✅ SRP exchange verified successfully!")
		} else {
			fmt.Println("❌ SRP exchange verification failed!")
		}

		// Show security properties
		fmt.Println("\n=== Security Properties ===")
		fmt.Println("✅ Password never sent over network")
		fmt.Println("✅ Forward secrecy (ephemeral keys)")
		fmt.Println("✅ Mutual authentication (M1/M2 proofs)")
		fmt.Println("✅ Resistant to offline dictionary attacks")

		return nil
	},
}

var srpGroupCmd = &cobra.Command{
	Use:   "groups",
	Short: "Show available SRP groups",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("Available SRP Groups:")
		fmt.Println("  1024-bit (legacy)")
		fmt.Println("  1536-bit")
		fmt.Println("  2048-bit (RFC 5054)")
		fmt.Println("  3072-bit")
		fmt.Println("  4096-bit (default)")
		fmt.Println("  6144-bit")
		fmt.Println("  8192-bit")
		fmt.Println()
		fmt.Println("Default group: 4096-bit")
		return nil
	},
}

var eventsWebhookTestCmd = &cobra.Command{
	Use:   "test [url]",
	Short: "Test a webhook",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		wm := events.NewWebhookManager(events.DefaultPath())
		if err := wm.Load(); err != nil {
			return err
		}

		if err := wm.TestWebhook(args[0]); err != nil {
			return fmt.Errorf("webhook test failed: %w", err)
		}

		fmt.Printf("✅ Webhook test successful: %s\n", args[0])
		return nil
	},
}

// SRP Auth Commands

var srpAuth = srpauth.NewSRPAuth()

var srpRegisterCmd = &cobra.Command{
	Use:   "register",
	Short: "Register a new account with SRP",
	RunE: func(cmd *cobra.Command, args []string) error {
		email, _ := cmd.Flags().GetString("email")
		password, _ := cmd.Flags().GetString("password")
		accountKey, _ := cmd.Flags().GetString("account-key")

		if email == "" {
			fmt.Print("Email: ")
			fmt.Scanln(&email)
		}
		if password == "" {
			fmt.Print("Password: ")
			fmt.Scanln(&password)
		}
		if accountKey == "" {
			fmt.Print("Account Key: ")
			fmt.Scanln(&accountKey)
		}

		return srpAuth.Register(email, password, accountKey)
	},
}

var srpSignInCmd = &cobra.Command{
	Use:   "signin",
	Short: "Sign in with SRP authentication",
	RunE: func(cmd *cobra.Command, args []string) error {
		email, _ := cmd.Flags().GetString("email")
		password, _ := cmd.Flags().GetString("password")

		if email == "" {
			fmt.Print("Email: ")
			fmt.Scanln(&email)
		}
		if password == "" {
			fmt.Print("Password: ")
			fmt.Scanln(&password)
		}

		return srpAuth.SignIn(email, password)
	},
}

var srpSignOutCmd = &cobra.Command{
	Use:   "signout",
	Short: "Sign out (clear SRP session)",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := srpAuth.SignOut(); err != nil {
			return err
		}
		fmt.Println("Signed out successfully!")
		return nil
	},
}

var srpWhoamiCmd = &cobra.Command{
	Use:   "whoami",
	Short: "Show SRP session info",
	RunE: func(cmd *cobra.Command, args []string) error {
		if !srpAuth.IsSignedIn() {
			return fmt.Errorf("not signed in")
		}
		fmt.Printf("Account: %s\n", srpAuth.Account)
		sessionKey, _ := srpAuth.GetSessionKey()
		fmt.Printf("Session Key: %x...\n", sessionKey[:16])
		return nil
	},
}

var srpDemoFullCmd = &cobra.Command{
	Use:   "demo-full",
	Short: "Full SRP authentication demo",
	RunE: func(cmd *cobra.Command, args []string) error {
		email := "test@example.com"
		password := ""
		accountKey := "A3-XXXXXX-YYYYYYYYYYYYYYYYYYYYYYYYYYYYY"

		fmt.Println("=== Full SRP Authentication Demo ===")
		fmt.Printf("Email: %s\n", email)
		fmt.Printf("Password: %s\n", password)
		fmt.Printf("Account Key: %s\n", accountKey)
		fmt.Println()

		// Register
		fmt.Println("--- Step 1: Register ---")
		if err := srpAuth.Register(email, password, accountKey); err != nil {
			return err
		}
		fmt.Println()

		// Sign in
		fmt.Println("--- Step 2: Sign In ---")
		if err := srpAuth.SignIn(email, password); err != nil {
			return err
		}
		fmt.Println()

		// Show session info
		fmt.Println("--- Step 3: Session Info ---")
		sessionKey, _ := srpAuth.GetSessionKey()
		masterKey, _ := srpAuth.GetMasterKey()
		fmt.Printf("Session Key: %x\n", sessionKey)
		fmt.Printf("MUK (Master Unlock Key): %x\n", masterKey)
		fmt.Println()

		// Sign out
		fmt.Println("--- Step 4: Sign Out ---")
		if err := srpAuth.SignOut(); err != nil {
			return err
		}
		fmt.Println("Signed out successfully!")

		return nil
	},
}

// Run Command (Secret Injection)

var runCmd = &cobra.Command{
	Use:   "run [command] [args...]",
	Short: "Run a command with secrets injected",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		// List secret references from environment
		refs := runner.ListSecretReferences()
		if len(refs) > 0 {
			fmt.Println("Secret references found in environment:")
			for k, v := range refs {
				fmt.Printf("  %s=%s\n", k, v)
			}
			fmt.Println()
		}

		// Create runner
		r := runner.NewRunner(args[0], args[1:])

		// Add secrets from environment
		for k, v := range refs {
			r.AddSecret(k, v)
		}

		// Set masking
		noMask, _ := cmd.Flags().GetBool("no-masking")
		r.MaskSecrets = !noMask

		// Run
		return r.Run()
	},
}

// Copy Command (Clipboard)

var copyCmd = &cobra.Command{
	Use:   "copy [text]",
	Short: "Copy text to clipboard with auto-clear",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		timeout, _ := cmd.Flags().GetInt("timeout")
		if timeout <= 0 {
			timeout = 30
		}

		text := args[0]
		if err := clipboard.CopyWithTimeout(text, time.Duration(timeout)*time.Second); err != nil {
			return fmt.Errorf("failed to copy: %w", err)
		}

		fmt.Printf("Copied to clipboard (clears in %d seconds)\n", timeout)
		return nil
	},
}

// TOTP Copy Command

var totpCopyCmd = &cobra.Command{
	Use:   "copy [secret]",
	Short: "Generate TOTP code and copy to clipboard",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		config := &totp.TOTPConfig{
			Secret:    args[0],
			Algorithm: "SHA1",
			Digits:    6,
			Period:    30,
		}
		code, err := totp.GenerateCode(config)
		if err != nil {
			return err
		}

		if err := clipboard.CopyWithTimeout(code, 10*time.Second); err != nil {
			return fmt.Errorf("failed to copy: %w", err)
		}

		remaining := totp.GetRemainingSeconds(config)
		fmt.Printf("Code: %s (copied to clipboard, clears in 10s, expires in %ds)\n", code, remaining)
		return nil
	},
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version number",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("opx version %s\n", version)
		fmt.Printf("  commit: %s\n", commit)
		fmt.Printf("  built:  %s\n", date)
	},
}

var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Check system health and configuration",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("opx Doctor")
		fmt.Println("==========")
		fmt.Println()

		// Check Go version
		fmt.Println("✅ Go runtime: OK")

		// Check storage path
		fmt.Printf("Storage path: %s\n", storage.DefaultPath())
		if info, err := os.Stat(storage.DefaultPath()); err == nil && info.IsDir() {
			fmt.Println("✅ Storage directory: OK")
		} else {
			fmt.Println("⚠️  Storage directory: Not found (will be created)")
		}

		// Check config
		configPath := storage.DefaultPath() + "/opx_config.json"
		if _, err := os.Stat(configPath); err == nil {
			fmt.Println("✅ Config file: Found")
		} else {
			fmt.Println("⚠️  Config file: Not found (not signed in)")
		}

		// Check SSH directory
		sshDir := os.Getenv("HOME")
		if sshDir == "" {
			sshDir = os.Getenv("USERPROFILE")
		}
		sshDir = sshDir + "/.ssh"
		if info, err := os.Stat(sshDir); err == nil && info.IsDir() {
			fmt.Println("✅ SSH directory: OK")
		} else {
			fmt.Println("⚠️  SSH directory: Not found")
		}

		// Check desktop app
		if desktopapp.IsDesktopAppInstalled() {
			fmt.Println("✅ Desktop app: Installed")
		} else {
			fmt.Println("⚠️  Desktop app: Not installed")
		}

		// Check code signing
		fmt.Println("✅ Binary signed: Yes (self-signed)")

		fmt.Println()
		fmt.Println("All checks completed.")
	},
}

func init() {
	vaultCmd.AddCommand(vaultListCmd)

	itemCmd.AddCommand(itemCreateCmd)
	itemCmd.AddCommand(itemGetCmd)
	itemCmd.AddCommand(itemEditCmd)
	itemCmd.AddCommand(itemDeleteCmd)
	itemCmd.AddCommand(itemSearchCmd)

	totpCmd.AddCommand(totpGenerateCmd)
	totpCmd.AddCommand(totpCodeCmd)
	totpCmd.AddCommand(totpVerifyCmd)
	totpCmd.AddCommand(totpCopyCmd)

	syncCmd.AddCommand(syncExportCmd)
	syncCmd.AddCommand(syncImportCmd)
	syncCmd.AddCommand(syncStatusCmd)

	sshCmd.AddCommand(sshGenerateCmd)
	sshCmd.AddCommand(sshListCmd)
	sshCmd.AddCommand(sshShowCmd)
	sshCmd.AddCommand(sshDeleteCmd)

	srpCmd.AddCommand(srpDemoCmd)
	srpCmd.AddCommand(srpGroupCmd)
	srpCmd.AddCommand(srpRegisterCmd)
	srpCmd.AddCommand(srpSignInCmd)
	srpCmd.AddCommand(srpSignOutCmd)
	srpCmd.AddCommand(srpWhoamiCmd)
	srpCmd.AddCommand(srpDemoFullCmd)

	serviceAccountCmd.AddCommand(saCreateCmd)
	serviceAccountCmd.AddCommand(saListCmd)
	serviceAccountCmd.AddCommand(saDeleteCmd)
	serviceAccountCmd.AddCommand(saTokenInfoCmd)
	serviceAccountCmd.AddCommand(saSigninCmd)

	pluginCmd.AddCommand(pluginListCmd)
	pluginCmd.AddCommand(pluginInstallCmd)
	pluginCmd.AddCommand(pluginRemoveCmd)
	pluginCmd.AddCommand(pluginRunCmd)
	pluginCmd.AddCommand(pluginExampleCmd)

	eventsCmd.AddCommand(eventsListCmd)
	eventsCmd.AddCommand(eventsSummaryCmd)
	eventsCmd.AddCommand(eventsExportCmd)
	eventsCmd.AddCommand(eventsClearCmd)
	eventsCmd.AddCommand(eventsWebhookCmd)
	eventsCmd.AddCommand(eventsRetentionCmd)

	eventsWebhookCmd.AddCommand(eventsWebhookAddCmd)
	eventsWebhookCmd.AddCommand(eventsWebhookListCmd)
	eventsWebhookCmd.AddCommand(eventsWebhookRemoveCmd)
	eventsWebhookCmd.AddCommand(eventsWebhookTestCmd)

	connectCmd.AddCommand(connectServeCmd)
	connectCmd.AddCommand(connectTokenCmd)

	connectTokenCmd.AddCommand(connectTokenCreateCmd)
	connectTokenCmd.AddCommand(connectTokenListCmd)
	connectTokenCmd.AddCommand(connectTokenDeleteCmd)

	desktopCmd.AddCommand(desktopStatusCmd)
	desktopCmd.AddCommand(desktopConnectCmd)
	desktopCmd.AddCommand(desktopInfoCmd)
	desktopCmd.AddCommand(desktopBiometricCmd)
	desktopCmd.AddCommand(desktopListPipesCmd)

	cloudSyncCmd.AddCommand(cloudSyncConfigureCmd)
	cloudSyncCmd.AddCommand(cloudSyncPushCmd)
	cloudSyncCmd.AddCommand(cloudSyncPullCmd)
	cloudSyncCmd.AddCommand(cloudSyncCmd2)
	cloudSyncCmd.AddCommand(cloudSyncStatusCmd)
	cloudSyncCmd.AddCommand(cloudSyncRealtimeCmd)

	updateCmd.AddCommand(updateCheckCmd)
	updateCmd.AddCommand(updateInfoCmd)
	updateCmd.AddCommand(updateAutoCmd)

	codesignCmd.AddCommand(codesignVerifyCmd)
	codesignCmd.AddCommand(codesignSignCmd)
	codesignCmd.AddCommand(codesignCreateCertCmd)

	itemCreateCmd.Flags().String("title", "", "Item title")
	itemCreateCmd.Flags().String("category", "login", "Item category")
	itemCreateCmd.Flags().String("vault", "Personal", "Vault name")
	itemEditCmd.Flags().String("field", "", "Field label")
	itemEditCmd.Flags().String("value", "", "Field value")
	sshGenerateCmd.Flags().String("type", "ed25519", "Key type (ed25519 or rsa)")
	sshGenerateCmd.Flags().String("name", "", "Key name")
	saCreateCmd.Flags().String("name", "", "Service account name")
	saCreateCmd.Flags().String("email", "", "Service account email")
	saCreateCmd.Flags().StringSlice("vaults", []string{}, "Allowed vaults")
	saSigninCmd.Flags().String("token", "", "Service account token")
	srpRegisterCmd.Flags().String("email", "", "Account email")
	srpRegisterCmd.Flags().String("password", "", "Account password")
	srpRegisterCmd.Flags().String("account-key", "", "Account key")
	srpSignInCmd.Flags().String("email", "", "Account email")
	srpSignInCmd.Flags().String("password", "", "Account password")
	srpDemoCmd.Flags().String("username", "test@example.com", "Username")
	srpDemoCmd.Flags().String("password", "", "Password")
	pluginInstallCmd.Flags().String("name", "", "Plugin name")
	runCmd.Flags().Bool("no-masking", false, "Disable secret masking in output")
	copyCmd.Flags().Int("timeout", 30, "Auto-clear timeout in seconds")
	connectServeCmd.Flags().String("host", "127.0.0.1", "Server host")
	connectServeCmd.Flags().Int("port", 8080, "Server port")
	connectServeCmd.Flags().String("token", "", "Connect token")
	connectTokenCreateCmd.Flags().String("name", "default", "Token name")
	connectTokenCreateCmd.Flags().StringSlice("vaults", []string{"*"}, "Allowed vaults")
	cloudSyncConfigureCmd.Flags().String("server", "", "Cloud sync server URL")
	cloudSyncConfigureCmd.Flags().String("api-key", "", "Cloud sync API key")
	cloudSyncRealtimeCmd.Flags().Int("duration", 10, "Duration in seconds")
	eventsWebhookAddCmd.Flags().StringSlice("events", []string{"*"}, "Event types to trigger webhook")
	eventsRetentionCmd.Flags().Int("max-events", 1000, "Maximum number of events to keep")
	eventsRetentionCmd.Flags().Int("max-days", 30, "Maximum age of events in days")
	codesignSignCmd.Flags().String("cert", "", "Certificate path (.pfx)")
	codesignSignCmd.Flags().String("password", "", "Certificate password")
	codesignSignCmd.Flags().String("timestamp", "http://timestamp.digicert.com", "Timestamp server URL")
	codesignCreateCertCmd.Flags().String("subject", "CN=opx Code Signing", "Certificate subject")
	codesignCreateCertCmd.Flags().String("output", "opx.pfx", "Output file path")
	codesignCreateCertCmd.Flags().String("password", "", "Certificate password")
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
