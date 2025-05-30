
NotifyGate: A gate that notifications flow through

The goal is to create a centralized Notification Hub that allows users to:

    Authenticate via OAuth2 (Google, GitHub).

    Create and manage notification channels (Named Destinations).

    Generate unique tokens (named codes) for each channel to receive notifications.

    Receive notifications via webhooks (JSON POST or URL parameters).

    View and manage notifications through a dashboard.

    Configure notification delivery preferences and scheduling.

    Send notifications through various providers (Discord, Slack, Telegram, Twitter/X, WhatsApp, Email, SMS, Google, GitHub).
    Provider-specific configuration system. Extensible architecture for adding new providers

    Customize notification delivery preferences (e.g., email, SMS, push notifications).
    Schedule notifications for future delivery. User-defined notification time windows. Automatic queueing for off-hours notifications. Timezone support

    A notification should be able to have an image, title, body, and link and attachment.
    notifcations have received,read,unread,deleted,forwarded statuses


Backend API (Go)

The backend will be a Go application responsible for user authentication, token management, webhook processing, notification storage, and dispatching notifications to various providers.
Core Functionality:

    User Management: Handle user registration (via OAuth2) and profile information.

    Token Generation & Management: Securely generate, store, and validate unique notification tokens.

    Channel Management: Allow users to create, update, and delete notification channels. A channel represents a specific source or type of notification. (Named Destinations)

    Webhook Ingestion: Receive incoming notifications via HTTP POST (JSON body) or GET (URL parameters).

    Notification Processing & Storage: Validate, parse, and store incoming notifications.

    Notification Dispatching: Send notifications to configured providers based on user preferences.

    Notification Queueing: Implement a queue for notifications that need to be sent during allowed times.

    Authentication & Authorization: Secure API endpoints.

    Database Schema (GORM with SQL - e.g., PostgreSQL, SQLLite)
    GORM Models: Define Go structs corresponding to these tables.
    Encryption: Sensitive data in user_provider_settings.credentials should be encrypted at rest.

    Rest endpoints for handling of incoming notification posts.
    Webhooks for receiving notifications
    Web hooks must be able to receive JSON posts and variables via url
    Token must be specific in the url to make it easy for webhooks



Frontend in Svelte 5, Svelte 5 with latest syntax ($state runes):
    Login page with oauth2 google or github
    Dashboard for users, tokens, channels, etc
    Users must be able to have multiple tokens with different notification preferences.
    Users must be able to set to what channels they want to receive notifications on and well as times to received them on.
    Notifications page that shows all the notifications from a specific channel
    Add channels page that allows users to add channels for a specific token.
    Settings page that allows users to set their notification preferences.
    Notifications should have a way to mark them as read or unread and deleted





Old:
* Backend API in go.
** Rest endpoints for handling of incoming notification posts.
** Token must be specific in the url to make it easy for webhooks
** Webhooks for receiving notifications
** Web hooks must be able to receive JSON posts and variables via url
** GORM with sql for storing tokens, users, channels, and notifications

* Frontend in Svelte 5
** Login page with oauth2 google or github
** Dashboard for users, tokens, channels, etc
** Notifications page that shows all the notifications from a specific channel
** Add tokens page that allows users to add tokens for a specific channel.
** Add channels page that allows users to add channels for a specific token.
** Settings page that allows users to set their notification preferences.

* Notification Design
** A notification should be able to have an image, title, body, and link.
** Notifications should have a way to mark them as read or unread and deleted
** Settings for allowed notification times (And queue for them to be sent when in the available times)
** These notification providers must be supported: 
	- Discord
    - Slack
    - Telegram
    - Twitter / X
    - Whatsapp and/or (https://github.com/tulir/whatsmeow)
    - Google
	- Github
    - Email

