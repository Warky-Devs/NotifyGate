package webserver

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/Warky-Devs/NotifyGate/api/pkg/db"
	"github.com/Warky-Devs/NotifyGate/api/pkg/models"
	"github.com/Warky-Devs/NotifyGate/api/pkg/utils"
)

// WebhookPayload represents the incoming webhook data
type WebhookPayload struct {
	Title      string                 `json:"title" form:"title" binding:"required"`
	Body       string                 `json:"body" form:"body"`
	ImageURL   string                 `json:"image_url" form:"image_url"`
	Link       string                 `json:"link" form:"link"`
	Attachment string                 `json:"attachment" form:"attachment"`
	Priority   string                 `json:"priority" form:"priority"`
	Metadata   map[string]interface{} `json:"metadata" form:"-"`
}

// handleWebhookPost handles incoming JSON POST webhooks
func (s *Server) handleWebhookPost(c *gin.Context) {
	token := c.Param("token")

	// Validate token format
	if !s.validator.ValidateToken(token) {
		s.logger.LogWebhook(token, c.ClientIP(), c.Request.UserAgent(), false, "invalid_token_format", nil)
		c.JSON(http.StatusBadRequest, utils.NewErrorResponse("Invalid token format"))
		return
	}

	// Get destination by token
	repo := db.NewRepository(s.db)
	destination, err := repo.GetDestinationByToken(token)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			s.logger.LogWebhook(token, c.ClientIP(), c.Request.UserAgent(), false, "destination_not_found", nil)
			c.JSON(http.StatusNotFound, utils.NewErrorResponse("Destination not found"))
			return
		}
		s.logger.LogWebhook(token, c.ClientIP(), c.Request.UserAgent(), false, err.Error(), nil)
		c.JSON(http.StatusInternalServerError, utils.NewErrorResponse("Internal server error"))
		return
	}

	// Parse JSON payload
	var payload WebhookPayload
	if err := c.ShouldBindJSON(&payload); err != nil {
		s.logger.LogWebhook(token, c.ClientIP(), c.Request.UserAgent(), false, "invalid_json_payload", nil)
		c.JSON(http.StatusBadRequest, utils.NewErrorResponse("Invalid JSON payload"))
		return
	}

	// Get raw JSON for storage
	rawPayload, _ := c.GetRawData()

	// Process the webhook
	traveler, err := s.processTraveler(destination, payload, rawPayload, c)
	if err != nil {
		s.logger.LogWebhook(token, c.ClientIP(), c.Request.UserAgent(), false, err.Error(), string(rawPayload))
		c.JSON(http.StatusInternalServerError, utils.NewErrorResponse("Failed to process notification"))
		return
	}

	s.logger.LogWebhook(token, c.ClientIP(), c.Request.UserAgent(), true, "", string(rawPayload))
	s.logger.LogTraveler(traveler.ID, destination.ID, "received_via_post", true, "webhook")

	c.JSON(http.StatusOK, utils.NewSuccessResponse(map[string]interface{}{
		"traveler_id": traveler.ID,
		"status":      "received",
	}, "Notification received successfully"))
}

// handleWebhookGet handles incoming GET webhooks with URL parameters
func (s *Server) handleWebhookGet(c *gin.Context) {
	token := c.Param("token")

	// Validate token format
	if !s.validator.ValidateToken(token) {
		s.logger.LogWebhook(token, c.ClientIP(), c.Request.UserAgent(), false, "invalid_token_format", nil)
		c.JSON(http.StatusBadRequest, utils.NewErrorResponse("Invalid token format"))
		return
	}

	// Get destination by token
	repo := db.NewRepository(s.db)
	destination, err := repo.GetDestinationByToken(token)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			s.logger.LogWebhook(token, c.ClientIP(), c.Request.UserAgent(), false, "destination_not_found", nil)
			c.JSON(http.StatusNotFound, utils.NewErrorResponse("Destination not found"))
			return
		}
		s.logger.LogWebhook(token, c.ClientIP(), c.Request.UserAgent(), false, err.Error(), nil)
		c.JSON(http.StatusInternalServerError, utils.NewErrorResponse("Internal server error"))
		return
	}

	// Extract payload from query parameters
	payload := WebhookPayload{
		Title:      c.Query("title"),
		Body:       c.Query("body"),
		ImageURL:   c.Query("image_url"),
		Link:       c.Query("link"),
		Attachment: c.Query("attachment"),
		Priority:   c.Query("priority"),
	}

	// Validate required fields
	if payload.Title == "" {
		s.logger.LogWebhook(token, c.ClientIP(), c.Request.UserAgent(), false, "missing_title", nil)
		c.JSON(http.StatusBadRequest, utils.NewErrorResponse("Title is required"))
		return
	}

	// Create metadata from all query parameters
	metadata := make(map[string]interface{})
	for key, values := range c.Request.URL.Query() {
		if len(values) == 1 {
			metadata[key] = values[0]
		} else {
			metadata[key] = values
		}
	}
	payload.Metadata = metadata

	// Convert to JSON for raw payload storage
	rawPayload, _ := json.Marshal(payload)

	// Process the webhook
	traveler, err := s.processTraveler(destination, payload, rawPayload, c)
	if err != nil {
		s.logger.LogWebhook(token, c.ClientIP(), c.Request.UserAgent(), false, err.Error(), string(rawPayload))
		c.JSON(http.StatusInternalServerError, utils.NewErrorResponse("Failed to process notification"))
		return
	}

	s.logger.LogWebhook(token, c.ClientIP(), c.Request.UserAgent(), true, "", string(rawPayload))
	s.logger.LogTraveler(traveler.ID, destination.ID, "received_via_get", true, "webhook")

	c.JSON(http.StatusOK, utils.NewSuccessResponse(map[string]interface{}{
		"traveler_id": traveler.ID,
		"status":      "received",
	}, "Notification received successfully"))
}

// processTraveler processes and stores a traveler (notification)
func (s *Server) processTraveler(destination *models.Destination, payload WebhookPayload, rawPayload []byte, c *gin.Context) (*models.Traveler, error) {
	repo := db.NewRepository(s.db)

	// Sanitize input
	payload.Title = s.validator.SanitizeInput(payload.Title)
	payload.Body = s.validator.SanitizeInput(payload.Body)
	payload.ImageURL = s.validator.SanitizeInput(payload.ImageURL)
	payload.Link = s.validator.SanitizeInput(payload.Link)
	payload.Attachment = s.validator.SanitizeInput(payload.Attachment)
	payload.Priority = s.validator.SanitizeInput(payload.Priority)

	// Validate URLs if provided
	if payload.ImageURL != "" && !s.validator.ValidateURL(payload.ImageURL) {
		return nil, fmt.Errorf("invalid image URL")
	}
	if payload.Link != "" && !s.validator.ValidateURL(payload.Link) {
		return nil, fmt.Errorf("invalid link URL")
	}

	// Validate and set priority
	priority := models.PriorityNormal
	if payload.Priority != "" {
		switch strings.ToLower(payload.Priority) {
		case "low":
			priority = models.PriorityLow
		case "normal":
			priority = models.PriorityNormal
		case "high":
			priority = models.PriorityHigh
		case "critical":
			priority = models.PriorityCritical
		default:
			return nil, fmt.Errorf("invalid priority: %s", payload.Priority)
		}
	}

	// Convert raw payload to JSON
	var rawPayloadJSON models.JSON
	if len(rawPayload) > 0 {
		if err := json.Unmarshal(rawPayload, &rawPayloadJSON); err != nil {
			// If JSON parsing fails, store as string
			rawPayloadJSON = models.JSON{"raw": string(rawPayload)}
		}
	}

	// Create traveler
	traveler := &models.Traveler{
		UserID:        destination.UserID,
		DestinationID: destination.ID,
		Title:         payload.Title,
		Body:          payload.Body,
		ImageURL:      payload.ImageURL,
		Link:          payload.Link,
		Attachment:    payload.Attachment,
		Priority:      priority,
		Status:        models.StatusReceived,
		SourceIP:      c.ClientIP(),
		UserAgent:     c.Request.UserAgent(),
		RawPayload:    rawPayloadJSON,
	}

	// Save to database
	if err := repo.CreateTraveler(traveler); err != nil {
		return nil, err
	}

	// Queue for delivery
	go s.queueTravelerForDelivery(traveler)

	return traveler, nil
}

// queueTravelerForDelivery queues a traveler for delivery to configured endpoints
func (s *Server) queueTravelerForDelivery(traveler *models.Traveler) {
	repo := db.NewRepository(s.db)

	// Get user's delivery preferences
	preferences, err := repo.GetDeliveryPreferences(traveler.UserID)
	if err != nil {
		s.logger.WithError(err).Error("Failed to get delivery preferences")
		return
	}

	// Get user for timezone
	user, err := repo.GetUserByID(traveler.UserID)
	if err != nil {
		s.logger.WithError(err).Error("Failed to get user for delivery")
		return
	}

	// Process each enabled delivery preference
	for _, pref := range preferences {
		if !pref.IsEnabled {
			continue
		}

		// Check if destination matches (if destination-specific preference)
		if pref.DestinationID != nil && *pref.DestinationID != traveler.DestinationID {
			continue
		}

		// Check priority threshold
		if s.comparePriority(traveler.Priority, pref.MinPriority) < 0 {
			continue
		}

		// Calculate delivery time based on preferences
		deliveryTime := s.calculateDeliveryTime(&pref, user.Timezone)

		// Create queue item
		queueItem := &models.TravelerQueue{
			TravelerID:   traveler.ID,
			EndpointID:   pref.EndpointID,
			Status:       models.QueueStatusPending,
			ScheduledFor: deliveryTime,
			MaxAttempts:  3,
		}

		if err := repo.CreateTravelerQueue(queueItem); err != nil {
			s.logger.WithError(err).Error("Failed to create queue item")
			continue
		}

		s.logger.LogQueue(queueItem.ID, traveler.ID, "", "queued", true, 0, deliveryTime.Format(time.RFC3339))
	}
}

// comparePriority compares two priority levels (-1 if p1 < p2, 0 if equal, 1 if p1 > p2)
func (s *Server) comparePriority(p1, p2 models.Priority) int {
	priorityValues := map[models.Priority]int{
		models.PriorityLow:      1,
		models.PriorityNormal:   2,
		models.PriorityHigh:     3,
		models.PriorityCritical: 4,
	}

	v1, v2 := priorityValues[p1], priorityValues[p2]
	if v1 < v2 {
		return -1
	} else if v1 > v2 {
		return 1
	}
	return 0
}

// calculateDeliveryTime calculates when a traveler should be delivered based on preferences
func (s *Server) calculateDeliveryTime(pref *models.DeliveryPreference, timezone string) time.Time {
	now := time.Now()

	// If no time restrictions, deliver immediately
	if pref.TimeWindow == "00:00-23:59" && len(pref.DaysOfWeek) == 7 {
		return now
	}

	// Check if current time is within allowed window
	withinTime, _ := s.timeUtils.IsWithinTimeWindow(pref.TimeWindow, timezone)
	withinDays := s.timeUtils.IsWithinDaysOfWeek(s.extractDaysOfWeek(pref.DaysOfWeek), timezone)

	if withinTime && withinDays {
		return now
	}

	// Calculate next allowed time
	return s.timeUtils.CalculateNextAllowedTime(
		pref.TimeWindow,
		s.extractDaysOfWeek(pref.DaysOfWeek),
		timezone,
	)
}

// extractDaysOfWeek extracts days of week from JSON field
func (s *Server) extractDaysOfWeek(daysJSON models.JSON) []string {
	if daysJSON == nil {
		return []string{"monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"}
	}

	// Try to extract as array of strings
	if daysArray, ok := daysJSON["days"]; ok {
		if days, ok := daysArray.([]interface{}); ok {
			result := make([]string, len(days))
			for i, day := range days {
				if dayStr, ok := day.(string); ok {
					result[i] = strings.ToLower(dayStr)
				}
			}
			return result
		}
	}

	// Try to extract directly as array
	// if days, ok := daysJSON.([]interface{}); ok {
	// 	result := make([]string, len(days))
	// 	for i, day := range days {
	// 		if dayStr, ok := day.(string); ok {
	// 			result[i] = strings.ToLower(dayStr)
	// 		}
	// 	}
	// 	return result
	// }

	// Fallback to all days
	return []string{"monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"}
}
