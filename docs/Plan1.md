# NotifyGate Project Plan

## Project Overview
A centralized notification hub that receives webhooks and distributes notifications across multiple providers with user-configurable preferences, scheduling, and channel management.

## Phase 1: Foundation & Database Design

### 1.1 Core Database Entities
- **Users**: OAuth2 authentication, profile data
- **Channels**: Named destinations with unique tokens
- **Notifications**: Messages with metadata, status tracking
- **Providers**: Extensible provider configuration
- **User Provider Settings**: Encrypted credentials per user/provider
- **Delivery Preferences**: Scheduling, time windows, timezone support
- **Notification Queue**: Delayed/scheduled delivery

### 1.2 Database Schema Design
- Primary keys, foreign keys, indexes
- Encryption strategy for sensitive data
- Audit trails and timestamps
- Status enums and constraints

## Phase 2: Backend API (Go)

### 2.1 Core Infrastructure
- **Authentication**: OAuth2 middleware (Google, GitHub)
- **Database**: GORM with PostgreSQL/SQLite
- **Router**: Gin or Fiber framework
- **Encryption**: AES encryption for provider credentials
- **Queue**: Background job processing (Redis/memory)

### 2.2 API Endpoints

#### Authentication & Users
- `POST /auth/login/{provider}` - OAuth2 login
- `GET /auth/callback/{provider}` - OAuth2 callback
- `GET /auth/user` - Get current user
- `POST /auth/logout` - Logout

#### Channels & Tokens
- `GET /channels` - List user channels
- `POST /channels` - Create channel
- `PUT /channels/{id}` - Update channel
- `DELETE /channels/{id}` - Delete channel
- `POST /channels/{id}/regenerate-token` - Regenerate token

#### Webhooks (Public)
- `POST /webhook/{token}` - Receive JSON notifications
- `GET /webhook/{token}` - Receive URL parameter notifications

#### Notifications
- `GET /notifications` - List notifications (paginated, filtered)
- `PUT /notifications/{id}/status` - Update status (read/unread/deleted)
- `POST /notifications/{id}/forward` - Forward notification

#### Providers & Settings
- `GET /providers` - List available providers
- `GET /providers/settings` - Get user provider settings
- `PUT /providers/{provider}/settings` - Update provider settings
- `POST /providers/{provider}/test` - Test provider connection

#### Delivery Preferences
- `GET /preferences` - Get delivery preferences
- `PUT /preferences` - Update delivery preferences

### 2.3 Background Services
- **Notification Processor**: Validate, parse, store incoming notifications
- **Delivery Engine**: Send notifications based on preferences
- **Queue Worker**: Process scheduled/delayed notifications
- **Cleanup Service**: Archive old notifications

## Phase 3: Provider System

### 3.1 Provider Interface
```go
type Provider interface {
    Send(notification *Notification, settings *ProviderSettings) error
    ValidateSettings(settings map[string]interface{}) error
    GetRequiredFields() []string
}
```

### 3.2 Initial Providers
- **Discord**: Webhook URL
- **Slack**: Webhook URL or Bot token
- **Telegram**: Bot token + chat ID
- **Email**: SMTP or service API
- **SMS**: Twilio/similar API
- **Push**: Firebase/APNs

### 3.3 Provider Features
- Rich content support (images, attachments, links)
- Rate limiting and retry logic
- Error handling and fallback

## Phase 4: Frontend (Svelte 5)

### 4.1 Core Components
- **Auth**: Login page with OAuth2 buttons
- **Layout**: Navigation, user menu, responsive design
- **Dashboard**: Overview cards, recent notifications
- **Channels**: CRUD operations, token management
- **Notifications**: List view with filtering, status updates
- **Providers**: Configuration forms, test connections
- **Settings**: Preferences, time windows, timezone

### 4.2 State Management
```javascript
// Using Svelte 5 runes
let user = $state(null);
let channels = $state([]);
let notifications = $state([]);
let providers = $state([]);
```

### 4.3 Key Features
- Real-time updates (WebSocket/SSE)
- Notification status management
- Bulk operations
- Export/import settings
- Dark/light theme

## Phase 5: Advanced Features

### 5.1 Scheduling System
- **Time Windows**: User-defined delivery hours
- **Timezone Support**: Per-user timezone settings
- **Queue Management**: Automatic off-hours queueing
- **Delivery Strategies**: Immediate, batched, digest

### 5.2 Analytics & Monitoring
- Delivery success rates
- Provider performance metrics
- User engagement tracking
- Error rate monitoring

### 5.3 Security & Compliance
- Rate limiting per token/user
- Input validation and sanitization
- Audit logging
- GDPR compliance features

## Implementation Order

1. **Database schema and models**
2. **Basic authentication and user management**
3. **Channel and token management**
4. **Simple webhook receiver**
5. **Basic notification storage**
6. **Frontend authentication and dashboard**
7. **Provider system foundation**
8. **First provider implementations**
9. **Delivery preferences and scheduling**
10. **Advanced features and optimization**

## Technology Stack

### Backend
- **Language**: Go 1.21+
- **Framework**: Gin or Fiber
- **Database**: PostgreSQL with GORM
- **Cache/Queue**: Redis
- **Authentication**: OAuth2 libraries

### Frontend
- **Framework**: Svelte 5 with Vite
- **Styling**: Tailwind CSS
- **HTTP Client**: Fetch API with custom wrapper
- **State**: Svelte 5 runes ($state, $derived, $effect)

### Infrastructure
- **Deployment**: Docker containers
- **Database**: PostgreSQL or SQLite for development
- **Monitoring**: Basic logging and metrics

## Next Steps

Ready to proceed with **Phase 1: Database Design**. We'll design the complete schema with all entities, relationships, and constraints.