# NotifyGate API 🚪

A centralized notification hub that receives webhooks and distributes notifications across multiple providers with user-configurable preferences, scheduling, and channel management.

## 🚀 Features

- **Multi-Provider Notifications**: Discord, Slack, Telegram, Email, SMS, and generic webhooks
- **OAuth2 Authentication**: Google and GitHub login support
- **Token-Based Webhooks**: Unique tokens for secure notification endpoints
- **Flexible Scheduling**: Time windows, timezone support, and delayed delivery
- **Rich Content Support**: Images, attachments, links, and priority levels
- **Status Tracking**: Read/unread/deleted/forwarded notification states
- **Rate Limiting**: Configurable rate limits per endpoint
- **Extensible Architecture**: Easy to add new notification providers

## 🏗️ Architecture

```
cmd/apisrv/           # API Server entrypoint
pkg/
├── models/           # GORM database models
├── webserver/        # HTTP server and routing
├── db/              # Database connection and repository
├── config/          # Configuration management
├── utils/           # Utility functions (crypto, JWT, validation)
└── log/             # Structured logging
```

## 📋 Prerequisites

- Go 1.21 or higher
- SQLite (default) or PostgreSQL
- OAuth2 credentials (Google/GitHub)

## 🔧 Setup

### 1. Clone and Setup

```bash
git clone <repository-url>
cd notifygate
go mod download
```

### 2. Configuration

Copy the example environment file and configure it:

```bash
cp .env.example .env
```

**Required Configuration:**

1. **Generate JWT Secret** (32+ characters):
```bash
# Example secure JWT secret
JWT_SECRET=your_very_secure_jwt_secret_key_here_32plus_chars
```

2. **Generate Encryption Key** (32 bytes for AES-256):
```bash
# Generate with OpenSSL
openssl rand -hex 32
# Set in .env
ENCRYPTION_KEY=generated_32_byte_hex_key
```

3. **OAuth2 Setup:**
   - **Google**: Create app at [Google Cloud Console](https://console.cloud.google.com/)
   - **GitHub**: Create app at [GitHub Developer Settings](https://github.com/settings/developers)

### 3. Database Setup

**SQLite (Default):**
```bash
# No additional setup required - will create notifygate.db automatically
```

**PostgreSQL (Optional):**
```bash
# Create database
createdb notifygate

# Update .env
DB_DRIVER=postgres
DB_NAME=notifygate
DB_USERNAME=your_username
DB_PASSWORD=your_password
```

### 4. Run the Server

```bash
# Development
go run cmd/apisrv/main.go

# Production build
go build -o bin/notifygate cmd/apisrv/main.go
./bin/notifygate
```

Server will start on `http://localhost:8080`

## 📡 API Endpoints

### Authentication
- `GET /api/v1/auth/login/{provider}` - OAuth2 login
- `GET /api/v1/auth/callback/{provider}` - OAuth2 callback
- `POST /api/v1/auth/logout` - Logout

### Webhooks (Public)
- `POST /webhook/{token}` - Receive JSON notifications
- `GET /webhook/{token}` - Receive URL parameter notifications

### Destinations (Protected)
- `GET /api/v1/destinations` - List destinations
- `POST /api/v1/destinations` - Create destination
- `PUT /api/v1/destinations/{id}` - Update destination
- `DELETE /api/v1/destinations/{id}` - Delete destination
- `POST /api/v1/destinations/{id}/regenerate-token` - Regenerate token

### Travelers (Notifications)
- `GET /api/v1/travelers` - List notifications
- `PUT /api/v1/travelers/{id}/status` - Update status
- `POST /api/v1/travelers/{id}/forward` - Forward notification
- `DELETE /api/v1/travelers/{id}` - Delete notification

### Endpoints & Settings
- `GET /api/v1/endpoints` - List available endpoints
- `GET /api/v1/settings/endpoints` - Get user endpoint settings
- `PUT /api/v1/settings/endpoints/{endpoint_id}` - Update settings
- `POST /api/v1/settings/endpoints/{endpoint_id}/test` - Test endpoint

## 🔗 Webhook Usage

### JSON POST Example
```bash
curl -X POST "http://localhost:8080/webhook/your_destination_token" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Alert: System Status",
    "body": "Database connection restored",
    "priority": "high",
    "image_url": "https://example.com/status.png",
    "link": "https://dashboard.example.com"
  }'
```

### URL Parameters Example
```bash
curl "http://localhost:8080/webhook/your_destination_token?title=Alert&body=System%20is%20down&priority=critical"
```

## 🛠️ Development

### Project Structure
```
notifygate/
├── cmd/apisrv/main.go           # Server entrypoint
├── pkg/
│   ├── models/models.go         # Database models
│   ├── webserver/
│   │   ├── server.go           # HTTP server setup
│   │   └── routes.go           # Route definitions
│   ├── db/db.go                # Database layer
│   ├── config/config.go        # Configuration
│   ├── utils/utils.go          # Utilities
│   └── log/log.go              # Logging
├── .env.example                # Environment template
├── go.mod                      # Go dependencies
└── README.md                   # This file
```

### Adding New Endpoints

1. **Add Endpoint Config**: Update the seed data in `pkg/db/db.go`
2. **Implement Provider**: Create endpoint-specific logic
3. **Add Tests**: Create comprehensive tests
4. **Update Documentation**: Add endpoint docs

## 🔒 Security Features

- **JWT Authentication**: Secure user sessions
- **AES-256 Encryption**: Encrypted credential storage
- **Rate Limiting**: Configurable request limits
- **CORS Protection**: Cross-origin request security
- **Input Validation**: Comprehensive input sanitization
- **Audit Logging**: Security event tracking

## 📊 Monitoring

### Health Check
```bash
curl http://localhost:8080/health
```

## 🐳 Docker (Coming Soon)

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request


## 🆘 Support

- **Issues**: Create GitHub issues for bugs
- **Discussions**: Use GitHub discussions for questions
- **Documentation**: Check the `/docs` directory for detailed guides

