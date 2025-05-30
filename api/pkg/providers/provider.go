package providers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/Warky-Devs/NotifyGate/api/pkg/config"
	"github.com/Warky-Devs/NotifyGate/api/pkg/log"
	"github.com/Warky-Devs/NotifyGate/api/pkg/models"
)

// Provider interface for notification providers
type Provider interface {
	Send(notification *NotificationData, credentials map[string]interface{}, settings models.JSON) (bool, string)
	GetName() string
	ValidateCredentials(credentials map[string]interface{}) error
}

// NotificationData represents the data to be sent
type NotificationData struct {
	Title      string      `json:"title"`
	Body       string      `json:"body"`
	ImageURL   string      `json:"image_url,omitempty"`
	Link       string      `json:"link,omitempty"`
	Attachment string      `json:"attachment,omitempty"`
	Priority   string      `json:"priority"`
	Metadata   models.JSON `json:"metadata,omitempty"`
}

// ProviderManager manages all notification providers
type ProviderManager struct {
	providers map[string]Provider
	logger    *log.Logger
	config    *config.Config
}

// NewProviderManager creates a new provider manager
func NewProviderManager(cfg *config.Config, logger *log.Logger) (ProviderManager, error) {
	manager := ProviderManager{
		providers: make(map[string]Provider),
		logger:    logger,
		config:    cfg,
	}

	// Register providers
	manager.registerProvider(NewDiscordProvider(logger))
	manager.registerProvider(NewSlackProvider(logger))
	manager.registerProvider(NewTelegramProvider(logger))
	manager.registerProvider(NewEmailProvider(logger))
	manager.registerProvider(NewWebhookProvider(logger))

	return manager, nil
}

// registerProvider registers a provider
func (pm *ProviderManager) registerProvider(provider Provider) {
	pm.providers[provider.GetName()] = provider
	pm.logger.WithField("provider", provider.GetName()).Debug("Registered provider")
}

// GetProvider returns a provider by name
func (pm *ProviderManager) GetProvider(name string) Provider {
	return pm.providers[name]
}

// GetProviders returns all registered providers
func (pm *ProviderManager) GetProviders() map[string]Provider {
	return pm.providers
}

// BaseProvider provides common functionality for providers
type BaseProvider struct {
	name   string
	logger *log.Logger
	client *http.Client
}

// NewBaseProvider creates a new base provider
func NewBaseProvider(name string, logger *log.Logger) *BaseProvider {
	return &BaseProvider{
		name:   name,
		logger: logger,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// GetName returns the provider name
func (bp *BaseProvider) GetName() string {
	return bp.name
}

// makeHTTPRequest makes an HTTP request
func (bp *BaseProvider) makeHTTPRequest(method, url string, headers map[string]string, body interface{}) (*http.Response, error) {
	var bodyReader io.Reader

	if body != nil {
		bodyBytes, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal body: %w", err)
		}
		bodyReader = bytes.NewReader(bodyBytes)
	}

	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set default headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "NotifyGate/1.0")

	// Set custom headers
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	resp, err := bp.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}

	return resp, nil
}

// handleHTTPResponse handles HTTP response
func (bp *BaseProvider) handleHTTPResponse(resp *http.Response, successCodes []int) (bool, string) {
	defer resp.Body.Close()

	// Read response body for error details
	bodyBytes, _ := io.ReadAll(resp.Body)
	bodyString := string(bodyBytes)

	// Check if status code is in success codes
	for _, code := range successCodes {
		if resp.StatusCode == code {
			bp.logger.WithFields(map[string]interface{}{
				"provider":    bp.name,
				"status_code": resp.StatusCode,
			}).Debug("Notification sent successfully")
			return true, ""
		}
	}

	// Log error
	bp.logger.WithFields(map[string]interface{}{
		"provider":      bp.name,
		"status_code":   resp.StatusCode,
		"response_body": bodyString,
	}).Error("Failed to send notification")

	return false, fmt.Sprintf("HTTP %d: %s", resp.StatusCode, bodyString)
}

// Discord Provider
type DiscordProvider struct {
	*BaseProvider
}

// NewDiscordProvider creates a new Discord provider
func NewDiscordProvider(logger *log.Logger) *DiscordProvider {
	return &DiscordProvider{
		BaseProvider: NewBaseProvider("discord", logger),
	}
}

// Send sends notification to Discord
func (dp *DiscordProvider) Send(notification *NotificationData, credentials map[string]interface{}, settings models.JSON) (bool, string) {
	webhookURL, ok := credentials["webhook_url"].(string)
	if !ok || webhookURL == "" {
		return false, "Discord webhook URL not configured"
	}

	// Prepare Discord webhook payload
	payload := map[string]interface{}{
		"content": notification.Title,
		"embeds": []map[string]interface{}{
			{
				"title":       notification.Title,
				"description": notification.Body,
				"color":       dp.getPriorityColor(notification.Priority),
				"timestamp":   time.Now().Format(time.RFC3339),
			},
		},
	}

	// Add image if provided
	if notification.ImageURL != "" {
		payload["embeds"].([]map[string]interface{})[0]["image"] = map[string]string{
			"url": notification.ImageURL,
		}
	}

	// Add link if provided
	if notification.Link != "" {
		payload["embeds"].([]map[string]interface{})[0]["url"] = notification.Link
	}

	resp, err := dp.makeHTTPRequest("POST", webhookURL, nil, payload)
	if err != nil {
		return false, err.Error()
	}

	return dp.handleHTTPResponse(resp, []int{200, 204})
}

// ValidateCredentials validates Discord credentials
func (dp *DiscordProvider) ValidateCredentials(credentials map[string]interface{}) error {
	webhookURL, ok := credentials["webhook_url"].(string)
	if !ok || webhookURL == "" {
		return fmt.Errorf("webhook_url is required")
	}
	return nil
}

// getPriorityColor returns color based on priority
func (dp *DiscordProvider) getPriorityColor(priority string) int {
	switch priority {
	case "critical":
		return 0xFF0000 // Red
	case "high":
		return 0xFF8000 // Orange
	case "normal":
		return 0x0080FF // Blue
	case "low":
		return 0x808080 // Gray
	default:
		return 0x0080FF // Blue
	}
}

// Slack Provider
type SlackProvider struct {
	*BaseProvider
}

// NewSlackProvider creates a new Slack provider
func NewSlackProvider(logger *log.Logger) *SlackProvider {
	return &SlackProvider{
		BaseProvider: NewBaseProvider("slack", logger),
	}
}

// Send sends notification to Slack
func (sp *SlackProvider) Send(notification *NotificationData, credentials map[string]interface{}, settings models.JSON) (bool, string) {
	webhookURL, ok := credentials["webhook_url"].(string)
	if !ok || webhookURL == "" {
		return false, "Slack webhook URL not configured"
	}

	// Prepare Slack webhook payload
	payload := map[string]interface{}{
		"text": notification.Title,
		"attachments": []map[string]interface{}{
			{
				"color":  sp.getPriorityColor(notification.Priority),
				"title":  notification.Title,
				"text":   notification.Body,
				"footer": "NotifyGate",
				"ts":     time.Now().Unix(),
			},
		},
	}

	// Add image if provided
	if notification.ImageURL != "" {
		payload["attachments"].([]map[string]interface{})[0]["image_url"] = notification.ImageURL
	}

	// Add link if provided
	if notification.Link != "" {
		payload["attachments"].([]map[string]interface{})[0]["title_link"] = notification.Link
	}

	resp, err := sp.makeHTTPRequest("POST", webhookURL, nil, payload)
	if err != nil {
		return false, err.Error()
	}

	return sp.handleHTTPResponse(resp, []int{200})
}

// ValidateCredentials validates Slack credentials
func (sp *SlackProvider) ValidateCredentials(credentials map[string]interface{}) error {
	webhookURL, ok := credentials["webhook_url"].(string)
	if !ok || webhookURL == "" {
		return fmt.Errorf("webhook_url is required")
	}
	return nil
}

// getPriorityColor returns color based on priority
func (sp *SlackProvider) getPriorityColor(priority string) string {
	switch priority {
	case "critical":
		return "danger"
	case "high":
		return "warning"
	case "normal":
		return "good"
	case "low":
		return "#808080"
	default:
		return "good"
	}
}

// Telegram Provider
type TelegramProvider struct {
	*BaseProvider
}

// NewTelegramProvider creates a new Telegram provider
func NewTelegramProvider(logger *log.Logger) *TelegramProvider {
	return &TelegramProvider{
		BaseProvider: NewBaseProvider("telegram", logger),
	}
}

// Send sends notification to Telegram
func (tp *TelegramProvider) Send(notification *NotificationData, credentials map[string]interface{}, settings models.JSON) (bool, string) {
	botToken, ok := credentials["bot_token"].(string)
	if !ok || botToken == "" {
		return false, "Telegram bot token not configured"
	}

	chatID, ok := credentials["chat_id"].(string)
	if !ok || chatID == "" {
		return false, "Telegram chat ID not configured"
	}

	// Prepare message text
	text := fmt.Sprintf("*%s*\n\n%s", notification.Title, notification.Body)
	if notification.Link != "" {
		text += fmt.Sprintf("\n\n[Open Link](%s)", notification.Link)
	}

	// Prepare Telegram API payload
	payload := map[string]interface{}{
		"chat_id":    chatID,
		"text":       text,
		"parse_mode": "Markdown",
	}

	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", botToken)

	resp, err := tp.makeHTTPRequest("POST", url, nil, payload)
	if err != nil {
		return false, err.Error()
	}

	return tp.handleHTTPResponse(resp, []int{200})
}

// ValidateCredentials validates Telegram credentials
func (tp *TelegramProvider) ValidateCredentials(credentials map[string]interface{}) error {
	botToken, ok := credentials["bot_token"].(string)
	if !ok || botToken == "" {
		return fmt.Errorf("bot_token is required")
	}

	chatID, ok := credentials["chat_id"].(string)
	if !ok || chatID == "" {
		return fmt.Errorf("chat_id is required")
	}

	return nil
}

// Email Provider
type EmailProvider struct {
	*BaseProvider
}

// NewEmailProvider creates a new Email provider
func NewEmailProvider(logger *log.Logger) *EmailProvider {
	return &EmailProvider{
		BaseProvider: NewBaseProvider("email", logger),
	}
}

// Send sends notification via email
func (ep *EmailProvider) Send(notification *NotificationData, credentials map[string]interface{}, settings models.JSON) (bool, string) {
	// This is a placeholder implementation
	// In a real implementation, you would use SMTP to send emails
	ep.logger.WithFields(map[string]interface{}{
		"provider": "email",
		"title":    notification.Title,
	}).Info("Email notification (placeholder)")

	return true, ""
}

// ValidateCredentials validates Email credentials
func (ep *EmailProvider) ValidateCredentials(credentials map[string]interface{}) error {
	required := []string{"smtp_host", "smtp_port", "username", "password", "from_email", "to_email"}
	for _, field := range required {
		if _, ok := credentials[field]; !ok {
			return fmt.Errorf("%s is required", field)
		}
	}
	return nil
}

// Webhook Provider
type WebhookProvider struct {
	*BaseProvider
}

// NewWebhookProvider creates a new generic webhook provider
func NewWebhookProvider(logger *log.Logger) *WebhookProvider {
	return &WebhookProvider{
		BaseProvider: NewBaseProvider("webhook", logger),
	}
}

// Send sends notification to a generic webhook
func (wp *WebhookProvider) Send(notification *NotificationData, credentials map[string]interface{}, settings models.JSON) (bool, string) {
	url, ok := credentials["url"].(string)
	if !ok || url == "" {
		return false, "Webhook URL not configured"
	}

	method := "POST"
	if m, ok := credentials["method"].(string); ok && m != "" {
		method = m
	}

	// Prepare headers
	headers := make(map[string]string)
	if h, ok := credentials["headers"].(map[string]interface{}); ok {
		for key, value := range h {
			if strValue, ok := value.(string); ok {
				headers[key] = strValue
			}
		}
	}

	// Prepare payload
	payload := map[string]interface{}{
		"title":      notification.Title,
		"body":       notification.Body,
		"image_url":  notification.ImageURL,
		"link":       notification.Link,
		"attachment": notification.Attachment,
		"priority":   notification.Priority,
		"timestamp":  time.Now().Format(time.RFC3339),
	}

	if notification.Metadata != nil {
		payload["metadata"] = notification.Metadata
	}

	resp, err := wp.makeHTTPRequest(method, url, headers, payload)
	if err != nil {
		return false, err.Error()
	}

	return wp.handleHTTPResponse(resp, []int{200, 201, 202, 204})
}

// ValidateCredentials validates webhook credentials
func (wp *WebhookProvider) ValidateCredentials(credentials map[string]interface{}) error {
	url, ok := credentials["url"].(string)
	if !ok || url == "" {
		return fmt.Errorf("url is required")
	}
	return nil
}
