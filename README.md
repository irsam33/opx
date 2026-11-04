# opx

<p align="left">
  <img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License" />
  <img src="https://img.shields.io/badge/Go-1.23+-00ADD8?style=flat-square&logo=go" alt="Go Version" />
  <img src="https://img.shields.io/badge/build-passing-brightgreen.svg" alt="Build Status" />
</p>
**opx** is a simplified, zero-knowledge secret manager CLI inspired by 1Password CLI. Built in Go, it handles secrets securely with password-based and SRP (Secure Remote Password) authentication, encrypted local storage, and a secure memory model.

> **Note:** This is a reverse-engineered educational clone for learning purposes. It is not affiliated with 1Password.

## ✨ Features

| Feature | Description |
|---------|-------------|
| **Password Manager** | Securely store and retrieve vault items, fields, and secrets |
| **TOTP (2FA)** | Generate and copy TOTP codes with auto-clear clipboard |
| **SRP Authentication** | Secure Remote Password protocol (SRP-2048) for zero-knowledge auth |
| **Encrypted Storage** | AES-256-GCM + Argon2id key derivation |
| **SSH Keys** | Generate and manage Ed25519 / RSA keys |
| **Service Accounts** | JWT-based service accounts for automation |
| **Sync** | Export / import vault data |
| **Events API** | Audit events with webhook delivery, HMAC signing, and exponential backoff |
| **Connect Server** | REST API server for integrating with other tools |
| **Desktop IPC** | Secure integration with desktop apps via Named Pipes |
| **Cloud Sync** | Real-time sync via HTTP + WebSocket |
| **Auto-update** | Check for and apply updates |
| **Code Signing** | Authenticode code signing with self-signed certificates |
| **Plugins** | Extensible plugin system via subprocess |
| **Secure Memory** | Zeroed sensitive data from memory |
| **Clipboard Auto-Clear** | Copy secrets that auto-clear after a timeout |
| **Run Command** | Run commands with secrets injected from `op://` references |

## 🚀 Quick Start

### Download

Prebuilt binaries are available on the [releases page](https://github.com/user/opx/releases).

### Build from Source

Requires [Go 1.22+](https://go.dev/dl/):

```bash
git clone https://github.com/irsam33/opx
cd opx
go build -buildvcs=false -o opx.exe ./cmd/op
```

### Signing (Windows)

Build with version metadata:

```powershell
$commit = "local"
$date = Get-Date -Format 'yyyy-MM-dd'
& "C:\Program Files\Go\bin\go.exe" build `
  -buildvcs=false `
  -ldflags "-s -w -X main.version=1.0.0 -X main.commit=$commit -X main.date=$date" `
  -o opx.exe ./cmd/op
```

Sign with a self-signed certificate:

```powershell
$cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject "CN=opx Development" `
  -KeyAlgorithm RSA -KeyLength 2048 -CertStoreLocation "Cert:\CurrentUser\My" `
  -NotAfter (Get-Date).AddYears(5)
$password = ConvertTo-SecureString -String "your-pfx-password" -Force -AsPlainText
Export-PfxCertificate -Cert $cert -FilePath "opx.pfx" -Password $password
& "C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe" sign `
  /f "opx.pfx" /p "your-pfx-password" /tr "http://timestamp.digicert.com" /td sha256 /fd sha256 opx.exe
```

Tip: set `OPX_SIGNTOOL` environment variable to point to your `signtool.exe` path.

## 📖 Usage

```bash
# Sign in (SRP if configured, otherwise password-based)
opx signin

# Register for SRP authentication (1Password Connect-style)
opx srp register --account-key <key> --email <email> --password <password>
opx signin <account>

# Store a secret
opx item create login --url "https://example.com" --username "user" --password "secret"

# Read a secret (copied to clipboard)
opx read op://Personal/Login/password

# Generate a TOTP code
opx totp code <secret>

# Copy to clipboard with auto-clear (default 30s)
opx copy "my-password" --timeout 30

# Copy TOTP code (clears in 10s)
opx totp copy <secret>

# Run a command with secrets injected
$env:DB_PASSWORD = "op://Personal/Database/password"
opx run -- python app.py

# List vaults and items
opx vault list
opx item list

# Manage SSH keys
opx ssh add id_ed25519

# Sync vault data
opx sync export > vault.json
opx sync import vault.json

# Connect API server
opx connect start

# Check health
opx doctor

# Show version
opx version
```

## 🔐 Configuration

opx stores its configuration in `~/.opx/`:

- `opx_config.json` — user configuration
- `opx_srp.json` — SRP credentials (if using SRP auth)
- `opx_connect_tokens.json` — Connect server tokens
- `opx_events.json` — audit events
- `opx_webhooks.json` — webhook configuration
- `opx_webhook_deliveries.json` — delivery history

## 🛡 Security

- Secrets are encrypted at rest using AES-256-GCM with Argon2id key derivation.
- Sensitive memory is zeroed after use via the `securemem` package.
- Clipboard content auto-clears after a configurable timeout to reduce exposure.
- Secrets injected into subprocesses are masked in logs.
- Desktop IPC uses Named Pipes with Authenticode signature verification.
- Webhook events are signed with HMAC-SHA256.

## 📁 Project Structure

```
opx/
├── cmd/op/                # CLI entry point
│   ├── main.go
│   ├── root.go
│   └── commands.go
├── internal/              # 31 application packages
│   ├── auth/              # Authentication (password + SRP)
│   ├── clipboard/         # Clipboard with auto-clear
│   ├── cloudsync/         # Cloud sync (HTTP + WebSocket)
│   ├── codesign/          # Code signing
│   ├── connect/           # Connect API server
│   ├── config/            # Configuration validation
│   ├── crypto/            # AES-256-GCM, HKDF, Argon2id
│   ├── ctxutil/           # Context propagation
│   ├── desktopapp/        # Desktop IPC (Named Pipes)
│   ├── events/            # Audit events + webhooks
│   ├── graceful/          # Graceful shutdown
│   ├── interfaces/        # Interface definitions
│   ├── logger/            # Structured logging
│   ├── plugin/            # Plugin system
│   ├── ratelimit/         # Rate limiting
│   ├── retry/             # Retry logic
│   ├── runner/            # Subprocess with secret injection
│   ├── securemem/         # Secure memory management
│   ├── serviceaccount/    # Service accounts (JWT)
│   ├── srp/               # SRP protocol
│   ├── srpauth/           # SRP authentication
│   ├── ssh/               # SSH key management
│   ├── storage/           # Encrypted storage
│   ├── sync/              # Vault sync (export/import)
│   ├── totp/              # TOTP (2FA)
│   ├── update/            # Auto-updates
│   ├── ux/                # UX helpers
│   ├── vault/             # Data models
│   └── apperror/          # Error standardization
├── .gitignore
├── go.mod
├── go.sum
├── LICENSE
└── README.md
```

## ⚙️ Build Flags & Metadata

The build injects runtime metadata:

```bash
go build -ldflags "-s -w -X main.version=1.0.0 -X main.commit=$(git rev-parse --short HEAD) -X main.date=$(Get-Date -Format 'yyyy-MM-dd')" -o opx.exe ./cmd/op
```

- `-s -w` — Strip debug symbols and DWARF.
- `main.version` — Semantic version.
- `main.commit` — Git commit SHA.
- `main.date` — Build date.

## 🧪 Testing

```bash
go test ./...
```

## 📜 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This project was created as an educational reverse-engineering exercise of the 1Password CLI. It is not affiliated with, endorsed by, or connected to AgileBits Inc. or 1Password. Do not rely on this tool for production-grade security; use the official 1Password CLI for sensitive workloads.
