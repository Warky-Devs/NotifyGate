package webserver

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/Warky-Devs/NotifyGate/api/pkg/db"
	"github.com/Warky-Devs/NotifyGate/api/pkg/models"
	"github.com/Warky-Devs/NotifyGate/api/pkg/utils"
)

// UpdateUserEndpointSettingRequest represents the request to update endpoint settings
type UpdateUserEndpointSettingRequest struct {
	IsEnabled          bool                   `json:"is_enabled"`
	Credentials        map[string]interface{} `json:"credentials"`
	Settings           map[string]interface{} `json:"settings"`
	RateLimitPerMinute int                    `json:"rate_limit_per_minute"`
}

// TestEndpointRequest represents the request to test an endpoint
type TestEndpointRequest struct {
	Title    string `json:"title" binding:"required"`
	Body     string `json:"body"`
	Priority string `json:"priority"`
}

// getEndpoints returns all available endpoints
func (s *Server) getEndpoints(c *gin.Context) {
	repo := db.NewRepository(s.db)
	endpoints, err := repo.GetEndpoints()
	if err != nil {
		s.logger.WithError(err).Error("Failed to get endpoints")
		c.JSON(http.StatusInternalServerError, utils.NewErrorResponse("Failed to get endpoints"))
		return
	}

	c.JSON(http.StatusOK, utils.NewSuccessResponse(endpoints, "Endpoints retrieved successfully"))
}

// getEndpoint returns a specific endpoint by name
func (s *Server) getEndpoint(c *gin.Context) {
	name := c.Param("name")

	repo := db.NewRepository(s.db)
	endpoint, err := repo.GetEndpointByName(name)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, utils.NewErrorResponse("Endpoint not found"))
			return
		}
		s.logger.WithError(err).Error("Failed to get endpoint")
		c.JSON(http.StatusInternalServerError, utils.NewErrorResponse("Failed to get endpoint"))
		return
	}

	c.JSON(http.StatusOK, utils.NewSuccessResponse(endpoint, "Endpoint retrieved successfully"))
}

// getUserEndpointSettings returns user's endpoint settings
func (s *Server) getUserEndpointSettings(c *gin.Context) {
	user, err := s.getCurrentUser(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, utils.NewErrorResponse("Unauthorized"))
		return
	}

	repo := db.NewRepository(s.db)
	settings, err := repo.GetUserEndpointSettings(user.ID)
	if err != nil {
		s.logger.WithError(err).Error("Failed to get user endpoint settings")
		c.JSON(http.StatusInternalServerError, utils.NewErrorResponse("Failed to get endpoint settings"))
		return
	}

	// Remove sensitive credentials from response
	for i := range settings {
		settings[i].EncryptedCredentials = nil
		settings[i].CredentialsHash = ""
	}

	c.JSON(http.StatusOK, utils.NewSuccessResponse(settings, "Endpoint settings retrieved successfully"))
}

// updateUserEndpointSetting updates or creates user endpoint setting
func (s *Server) updateUserEndpointSetting(c *gin.Context) {
	user, err := s.getCurrentUser(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, utils.NewErrorResponse("Unauthorized"))
		return
	}

	endpointIDParam := c.Param("endpoint_id")
	endpointID, err := strconv.ParseUint(endpointIDParam, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, utils.NewErrorResponse("Invalid endpoint ID"))
		return
	}

	var req UpdateUserEndpointSettingRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, utils.NewErrorResponse("Invalid request data"))
		return
	}

	repo := db.NewRepository(s.db)

	// Verify endpoint exists
	endpoint, err := repo.GetEndpointByID(uint(endpointID))
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, utils.NewErrorResponse("Endpoint not found"))
			return
		}
		s.logger.WithError(err).Error("Failed to get endpoint")
		c.JSON(http.StatusInternalServerError, utils.NewErrorResponse("Failed to get endpoint"))
		return
	}

	// Validate credentials against endpoint schema
	if err := s.validateEndpointCredentials(endpoint, req.Credentials); err != nil {
		c.JSON(http.StatusBadRequest, utils.NewErrorResponse("Invalid credentials: "+err.Error()))
		return
	}

	// Encrypt credentials
	var encryptedCredentials []byte
	var credentialsHash string
	if len(req.Credentials) > 0 {
		credentialsJSON, err := json.Marshal(req.Credentials)
		if err != nil {
			s.logger.WithError(err).Error("Failed to marshal credentials")
			c.JSON(http.StatusInternalServerError, utils.NewErrorResponse("Failed to process credentials"))
			return
		}

		encryptedData, err := s.encryption.Encrypt(string(credentialsJSON))
		if err != nil {
			s.logger.WithError(err).Error("Failed to encrypt credentials")
			c.JSON(http.StatusInternalServerError, utils.NewErrorResponse("Failed to encrypt credentials"))
			return
		}

		encryptedCredentials = []byte(encryptedData)
		credentialsHash = s.encryption.Hash(string(credentialsJSON))
	}

	// Validate rate limit
	if req.RateLimitPerMinute <= 0 {
		req.RateLimitPerMinute = 10
	}
	if req.RateLimitPerMinute > 100 {
		req.RateLimitPerMinute = 100
	}

	// Create or update setting
	setting := &models.UserEndpointSetting{
		UserID:               user.ID,
		EndpointID:           uint(endpointID),
		IsEnabled:            req.IsEnabled,
		EncryptedCredentials: encryptedCredentials,
		CredentialsHash:      credentialsHash,
		Settings:             models.JSON(req.Settings),
		RateLimitPerMinute:   req.RateLimitPerMinute,
	}

	if err := repo.CreateOrUpdateUserEndpointSetting(setting); err != nil {
		s.logger.WithError(err).Error("Failed to update user endpoint setting")
		c.JSON(http.StatusInternalServerError, utils.NewErrorResponse("Failed to update endpoint setting"))
		return
	}

	s.logger.LogEndpoint(endpoint.Name, user.ID, "settings_updated", true, "")

	// Return setting without sensitive data
	setting.EncryptedCredentials = nil
	setting.CredentialsHash = ""

	c.JSON(http.StatusOK, utils.NewSuccessResponse(setting, "Endpoint setting updated successfully"))
}

// testEndpoint tests an endpoint configuration
func (s *Server) testEndpoint(c *gin.Context) {
	user, err := s.getCurrentUser(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, utils.NewErrorResponse("Unauthorized"))
		return
	}

	endpointIDParam := c.Param("endpoint_id")
	endpointID, err := strconv.ParseUint(endpointIDParam, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, utils.NewErrorResponse("Invalid endpoint ID"))
		return
	}

	var req TestEndpointRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, utils.NewErrorResponse("Invalid request data"))
		return
	}

	repo := db.NewRepository(s.db)

	// Get user endpoint setting
	setting, err := repo.GetUserEndpointSetting(user.ID, uint(endpointID))
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, utils.NewErrorResponse("Endpoint setting not found"))
			return
		}
		s.logger.WithError(err).Error("Failed to get user endpoint setting")
		c.JSON(http.StatusInternalServerError, utils.NewErrorResponse("Failed to get endpoint setting"))
		return
	}

	if !setting.IsEnabled {
		c.JSON(http.StatusBadRequest, utils.NewErrorResponse("Endpoint is not enabled"))
		return
	}

	// Get endpoint
	endpoint, err := repo.GetEndpointByID(setting.EndpointID)
	if err != nil {
		s.logger.WithError(err).Error("Failed to get endpoint")
		c.JSON(http.StatusInternalServerError, utils.NewErrorResponse("Failed to get endpoint"))
		return
	}

	// Decrypt credentials
	credentials, err := s.decryptCredentials(setting.EncryptedCredentials)
	if err != nil {
		s.logger.WithError(err).Error("Failed to decrypt credentials")
		c.JSON(http.StatusInternalServerError, utils.NewErrorResponse("Failed to decrypt credentials"))
		return
	}

	// Validate priority
	priority := models.PriorityNormal
	if req.Priority != "" {
		switch req.Priority {
		case "low":
			priority = models.PriorityLow
		case "normal":
			priority = models.PriorityNormal
		case "high":
			priority = models.PriorityHigh
		case "critical":
			priority = models.PriorityCritical
		default:
			c.JSON(http.StatusBadRequest, utils.NewErrorResponse("Invalid priority"))
			return
		}
	}

	// Create test traveler
	testTraveler := &models.Traveler{
		Title:    req.Title,
		Body:     req.Body,
		Priority: priority,
	}

	// Send test notification
	success, errorMsg := s.sendTestNotification(endpoint, setting, credentials, testTraveler)

	if success {
		s.logger.LogEndpoint(endpoint.Name, user.ID, "test_success", true, "")
		c.JSON(http.StatusOK, utils.NewSuccessResponse(nil, "Test notification sent successfully"))
	} else {
		s.logger.LogEndpoint(endpoint.Name, user.ID, "test_failed", false, errorMsg)
		c.JSON(http.StatusBadRequest, utils.NewErrorResponse("Test failed: "+errorMsg))
	}
}

// validateEndpointCredentials validates credentials against endpoint schema
func (s *Server) validateEndpointCredentials(endpoint *models.Endpoint, credentials map[string]interface{}) error {
	if endpoint.ConfigSchema == nil {
		return nil
	}

	// Basic validation - check required fields
	for fieldName, fieldConfig := range endpoint.ConfigSchema {
		if config, ok := fieldConfig.(map[string]interface{}); ok {
			if required, exists := config["required"]; exists && required.(bool) {
				if _, hasField := credentials[fieldName]; !hasField {
					return fmt.Errorf("required field '%s' is missing", fieldName)
				}
			}

			// Validate field type
			if fieldType, exists := config["type"]; exists {
				value, hasField := credentials[fieldName]
				if hasField {
					switch fieldType.(string) {
					case "string":
						if _, ok := value.(string); !ok {
							return fmt.Errorf("field '%s' must be a string", fieldName)
						}
					case "integer":
						if _, ok := value.(float64); !ok { // JSON numbers are float64
							return fmt.Errorf("field '%s' must be an integer", fieldName)
						}
					case "boolean":
						if _, ok := value.(bool); !ok {
							return fmt.Errorf("field '%s' must be a boolean", fieldName)
						}
					}
				}
			}

			// Validate URL pattern if specified
			if pattern, exists := config["pattern"]; exists {
				value, hasField := credentials[fieldName]
				if hasField {
					if valueStr, ok := value.(string); ok && pattern.(string) != "" {
						if !s.validator.ValidateURL(valueStr) {
							return fmt.Errorf("field '%s' must be a valid URL", fieldName)
						}
					}
				}
			}
		}
	}

	return nil
}

// decryptCredentials decrypts encrypted credentials
func (s *Server) decryptCredentials(encryptedCredentials []byte) (map[string]interface{}, error) {
	if len(encryptedCredentials) == 0 {
		return make(map[string]interface{}), nil
	}

	decryptedData, err := s.encryption.Decrypt(string(encryptedCredentials))
	if err != nil {
		return nil, err
	}

	var credentials map[string]interface{}
	if err := json.Unmarshal([]byte(decryptedData), &credentials); err != nil {
		return nil, err
	}

	return credentials, nil
}

// sendTestNotification sends a test notification (placeholder implementation)
func (s *Server) sendTestNotification(endpoint *models.Endpoint, setting *models.UserEndpointSetting, credentials map[string]interface{}, traveler *models.Traveler) (bool, string) {
	// This is a placeholder implementation
	// In a real implementation, you would have specific logic for each endpoint type
	switch endpoint.Name {
	case "discord":
		return s.sendDiscordTest(credentials, traveler)
	case "slack":
		return s.sendSlackTest(credentials, traveler)
	case "telegram":
		return s.sendTelegramTest(credentials, traveler)
	case "email":
		return s.sendEmailTest(credentials, traveler)
	case "webhook":
		return s.sendWebhookTest(credentials, traveler)
	default:
		return false, "Endpoint type not implemented"
	}
}

// Placeholder test implementations
func (s *Server) sendDiscordTest(credentials map[string]interface{}, traveler *models.Traveler) (bool, string) {
	// Placeholder - implement Discord webhook
	return true, ""
}

func (s *Server) sendSlackTest(credentials map[string]interface{}, traveler *models.Traveler) (bool, string) {
	// Placeholder - implement Slack webhook
	return true, ""
}

func (s *Server) sendTelegramTest(credentials map[string]interface{}, traveler *models.Traveler) (bool, string) {
	// Placeholder - implement Telegram bot
	return true, ""
}

func (s *Server) sendEmailTest(credentials map[string]interface{}, traveler *models.Traveler) (bool, string) {
	// Placeholder - implement SMTP email
	return true, ""
}

func (s *Server) sendWebhookTest(credentials map[string]interface{}, traveler *models.Traveler) (bool, string) {
	// Placeholder - implement generic webhook
	return true, ""
}
