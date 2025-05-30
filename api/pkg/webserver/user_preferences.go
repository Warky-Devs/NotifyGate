package webserver

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/Warky-Devs/NotifyGate/api/pkg/db"
	"github.com/Warky-Devs/NotifyGate/api/pkg/models"
	"github.com/Warky-Devs/NotifyGate/api/pkg/utils"
)

// UpdateUserRequest represents the request to update user information
type UpdateUserRequest struct {
	Name              string `json:"name" binding:"required,min=1,max=100"`
	Timezone          string `json:"timezone"`
	DefaultTimeWindow string `json:"default_time_window"`
}

// DeliveryPreferenceRequest represents the request to update delivery preferences
type DeliveryPreferenceRequest struct {
	EndpointID     uint     `json:"endpoint_id" binding:"required"`
	DestinationID  *uint    `json:"destination_id"` // Optional for destination-specific preferences
	IsEnabled      bool     `json:"is_enabled"`
	MinPriority    string   `json:"min_priority"`
	TimeWindow     string   `json:"time_window"`
	DaysOfWeek     []string `json:"days_of_week"`
	EnableDigest   bool     `json:"enable_digest"`
	DigestInterval int      `json:"digest_interval"`
}

// updateUser updates user information
func (s *Server) updateUser(c *gin.Context) {
	user, err := s.getCurrentUser(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, utils.NewErrorResponse("Unauthorized"))
		return
	}

	var req UpdateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, utils.NewErrorResponse("Invalid request data"))
		return
	}

	// Sanitize input
	req.Name = s.validator.SanitizeInput(req.Name)
	req.Timezone = s.validator.SanitizeInput(req.Timezone)
	req.DefaultTimeWindow = s.validator.SanitizeInput(req.DefaultTimeWindow)

	// Validate timezone (basic validation)
	if req.Timezone == "" {
		req.Timezone = "UTC"
	}

	// Validate time window format
	if req.DefaultTimeWindow != "" && !s.validator.ValidateTimeWindow(req.DefaultTimeWindow) {
		c.JSON(http.StatusBadRequest, utils.NewErrorResponse("Invalid time window format. Use HH:MM-HH:MM"))
		return
	}

	// Update user
	user.Name = req.Name
	user.Timezone = req.Timezone
	if req.DefaultTimeWindow != "" {
		user.DefaultTimeWindow = req.DefaultTimeWindow
	}

	repo := db.NewRepository(s.db)
	if err := repo.UpdateUser(user); err != nil {
		s.logger.WithError(err).Error("Failed to update user")
		c.JSON(http.StatusInternalServerError, utils.NewErrorResponse("Failed to update user"))
		return
	}

	s.logger.WithFields(map[string]interface{}{
		"user_id":  user.ID,
		"name":     user.Name,
		"timezone": user.Timezone,
	}).Info("User updated")

	c.JSON(http.StatusOK, utils.NewSuccessResponse(user, "User updated successfully"))
}

// deleteUser deletes the current user and all associated data
func (s *Server) deleteUser(c *gin.Context) {
	user, err := s.getCurrentUser(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, utils.NewErrorResponse("Unauthorized"))
		return
	}

	repo := db.NewRepository(s.db)

	// Delete user (soft delete with cascade)
	if err := repo.DeleteUser(user.ID); err != nil {
		s.logger.WithError(err).Error("Failed to delete user")
		c.JSON(http.StatusInternalServerError, utils.NewErrorResponse("Failed to delete user"))
		return
	}

	s.logger.WithFields(map[string]interface{}{
		"user_id": user.ID,
		"email":   user.Email,
	}).Info("User deleted")

	c.JSON(http.StatusOK, utils.NewSuccessResponse(nil, "User deleted successfully"))
}

// getDeliveryPreferences returns all delivery preferences for the current user
func (s *Server) getDeliveryPreferences(c *gin.Context) {
	user, err := s.getCurrentUser(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, utils.NewErrorResponse("Unauthorized"))
		return
	}

	repo := db.NewRepository(s.db)
	preferences, err := repo.GetAllDeliveryPreferences(user.ID)
	if err != nil {
		s.logger.WithError(err).Error("Failed to get delivery preferences")
		c.JSON(http.StatusInternalServerError, utils.NewErrorResponse("Failed to get delivery preferences"))
		return
	}

	c.JSON(http.StatusOK, utils.NewSuccessResponse(preferences, "Delivery preferences retrieved successfully"))
}

// updateDeliveryPreferences updates delivery preferences
func (s *Server) updateDeliveryPreferences(c *gin.Context) {
	user, err := s.getCurrentUser(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, utils.NewErrorResponse("Unauthorized"))
		return
	}

	var req []DeliveryPreferenceRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, utils.NewErrorResponse("Invalid request data"))
		return
	}

	repo := db.NewRepository(s.db)

	// Process each preference
	for _, prefReq := range req {
		if err := s.updateSingleDeliveryPreference(repo, user.ID, prefReq); err != nil {
			s.logger.WithError(err).Error("Failed to update delivery preference")
			c.JSON(http.StatusBadRequest, utils.NewErrorResponse("Failed to update preference: "+err.Error()))
			return
		}
	}

	// Get updated preferences
	updatedPreferences, err := repo.GetAllDeliveryPreferences(user.ID)
	if err != nil {
		s.logger.WithError(err).Error("Failed to get updated delivery preferences")
		c.JSON(http.StatusInternalServerError, utils.NewErrorResponse("Failed to get updated preferences"))
		return
	}

	s.logger.WithFields(map[string]interface{}{
		"user_id":           user.ID,
		"preferences_count": len(req),
	}).Info("Delivery preferences updated")

	c.JSON(http.StatusOK, utils.NewSuccessResponse(updatedPreferences, "Delivery preferences updated successfully"))
}

// getDestinationPreferences returns delivery preferences for a specific destination
func (s *Server) getDestinationPreferences(c *gin.Context) {
	user, err := s.getCurrentUser(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, utils.NewErrorResponse("Unauthorized"))
		return
	}

	destinationIDParam := c.Param("destination_id")
	destinationID, err := strconv.ParseUint(destinationIDParam, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, utils.NewErrorResponse("Invalid destination ID"))
		return
	}

	repo := db.NewRepository(s.db)

	// Verify destination belongs to user
	destination, err := repo.GetDestinationByID(uint(destinationID))
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, utils.NewErrorResponse("Destination not found"))
			return
		}
		s.logger.WithError(err).Error("Failed to get destination")
		c.JSON(http.StatusInternalServerError, utils.NewErrorResponse("Failed to get destination"))
		return
	}

	if destination.UserID != user.ID {
		c.JSON(http.StatusForbidden, utils.NewErrorResponse("Access denied"))
		return
	}

	preferences, err := repo.GetDestinationDeliveryPreferences(user.ID, uint(destinationID))
	if err != nil {
		s.logger.WithError(err).Error("Failed to get destination delivery preferences")
		c.JSON(http.StatusInternalServerError, utils.NewErrorResponse("Failed to get destination preferences"))
		return
	}

	c.JSON(http.StatusOK, utils.NewSuccessResponse(preferences, "Destination preferences retrieved successfully"))
}

// updateDestinationPreferences updates delivery preferences for a specific destination
func (s *Server) updateDestinationPreferences(c *gin.Context) {
	user, err := s.getCurrentUser(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, utils.NewErrorResponse("Unauthorized"))
		return
	}

	destinationIDParam := c.Param("destination_id")
	destinationID, err := strconv.ParseUint(destinationIDParam, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, utils.NewErrorResponse("Invalid destination ID"))
		return
	}

	var req []DeliveryPreferenceRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, utils.NewErrorResponse("Invalid request data"))
		return
	}

	repo := db.NewRepository(s.db)

	// Verify destination belongs to user
	destination, err := repo.GetDestinationByID(uint(destinationID))
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, utils.NewErrorResponse("Destination not found"))
			return
		}
		s.logger.WithError(err).Error("Failed to get destination")
		c.JSON(http.StatusInternalServerError, utils.NewErrorResponse("Failed to get destination"))
		return
	}

	if destination.UserID != user.ID {
		c.JSON(http.StatusForbidden, utils.NewErrorResponse("Access denied"))
		return
	}

	// Process each preference with destination ID
	for _, prefReq := range req {
		prefReq.DestinationID = &[]uint{uint(destinationID)}[0]
		if err := s.updateSingleDeliveryPreference(repo, user.ID, prefReq); err != nil {
			s.logger.WithError(err).Error("Failed to update destination delivery preference")
			c.JSON(http.StatusBadRequest, utils.NewErrorResponse("Failed to update preference: "+err.Error()))
			return
		}
	}

	// Get updated preferences
	updatedPreferences, err := repo.GetDestinationDeliveryPreferences(user.ID, uint(destinationID))
	if err != nil {
		s.logger.WithError(err).Error("Failed to get updated destination delivery preferences")
		c.JSON(http.StatusInternalServerError, utils.NewErrorResponse("Failed to get updated preferences"))
		return
	}

	s.logger.WithFields(map[string]interface{}{
		"user_id":           user.ID,
		"destination_id":    destinationID,
		"preferences_count": len(req),
	}).Info("Destination delivery preferences updated")

	c.JSON(http.StatusOK, utils.NewSuccessResponse(updatedPreferences, "Destination preferences updated successfully"))
}

// updateSingleDeliveryPreference updates a single delivery preference
func (s *Server) updateSingleDeliveryPreference(repo *db.Repository, userID uint, req DeliveryPreferenceRequest) error {
	// Validate endpoint exists
	_, err := repo.GetEndpointByID(req.EndpointID)
	if err != nil {
		return fmt.Errorf("endpoint not found")
	}

	// Validate destination if specified
	if req.DestinationID != nil {
		destination, err := repo.GetDestinationByID(*req.DestinationID)
		if err != nil {
			return fmt.Errorf("destination not found")
		}
		if destination.UserID != userID {
			return fmt.Errorf("destination access denied")
		}
	}

	// Validate priority
	var priority models.Priority
	switch strings.ToLower(req.MinPriority) {
	case "low":
		priority = models.PriorityLow
	case "normal":
		priority = models.PriorityNormal
	case "high":
		priority = models.PriorityHigh
	case "critical":
		priority = models.PriorityCritical
	default:
		priority = models.PriorityLow
	}

	// Validate time window
	if req.TimeWindow != "" && !s.validator.ValidateTimeWindow(req.TimeWindow) {
		return fmt.Errorf("invalid time window format")
	}
	if req.TimeWindow == "" {
		req.TimeWindow = "00:00-23:59"
	}

	// Validate days of week
	if len(req.DaysOfWeek) == 0 {
		req.DaysOfWeek = []string{"monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"}
	}

	// Convert days of week to JSON
	daysOfWeekJSON := map[string]interface{}{"values": req.DaysOfWeek}

	// Validate digest interval
	if req.DigestInterval <= 0 {
		req.DigestInterval = 60
	}

	// Create or update preference
	preference := &models.DeliveryPreference{
		UserID:         userID,
		DestinationID:  req.DestinationID,
		EndpointID:     req.EndpointID,
		IsEnabled:      req.IsEnabled,
		MinPriority:    priority,
		TimeWindow:     req.TimeWindow,
		DaysOfWeek:     daysOfWeekJSON,
		EnableDigest:   req.EnableDigest,
		DigestInterval: req.DigestInterval,
	}

	return repo.CreateOrUpdateDeliveryPreference(preference)
}
