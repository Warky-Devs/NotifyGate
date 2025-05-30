package webserver

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/Warky-Devs/NotifyGate/api/pkg/db"
	"github.com/Warky-Devs/NotifyGate/api/pkg/models"
	"github.com/Warky-Devs/NotifyGate/api/pkg/utils"
)

// CreateDestinationRequest represents the request to create a destination
type CreateDestinationRequest struct {
	Name        string `json:"name" binding:"required,min=1,max=100"`
	Description string `json:"description" binding:"max=500"`
}

// UpdateDestinationRequest represents the request to update a destination
type UpdateDestinationRequest struct {
	Name        string `json:"name" binding:"required,min=1,max=100"`
	Description string `json:"description" binding:"max=500"`
	IsActive    *bool  `json:"is_active"`
}

// getDestinations returns all destinations for the current user
func (s *Server) getDestinations(c *gin.Context) {
	user, err := s.getCurrentUser(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, utils.NewErrorResponse("Unauthorized"))
		return
	}

	repo := db.NewRepository(s.db)
	destinations, err := repo.GetDestinationsByUserID(user.ID)
	if err != nil {
		s.logger.WithError(err).Error("Failed to get destinations")
		c.JSON(http.StatusInternalServerError, utils.NewErrorResponse("Failed to get destinations"))
		return
	}

	c.JSON(http.StatusOK, utils.NewSuccessResponse(destinations, "Destinations retrieved successfully"))
}

// createDestination creates a new destination for the current user
func (s *Server) createDestination(c *gin.Context) {
	user, err := s.getCurrentUser(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, utils.NewErrorResponse("Unauthorized"))
		return
	}

	var req CreateDestinationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, utils.NewErrorResponse("Invalid request data"))
		return
	}

	// Sanitize input
	req.Name = s.validator.SanitizeInput(req.Name)
	req.Description = s.validator.SanitizeInput(req.Description)

	// Generate unique token
	tokenGenerator := utils.NewTokenGenerator()
	token := tokenGenerator.GenerateDestinationToken()

	// Create destination
	destination := &models.Destination{
		UserID:      user.ID,
		Name:        req.Name,
		Description: req.Description,
		Token:       token,
		IsActive:    true,
	}

	repo := db.NewRepository(s.db)
	if err := repo.CreateDestination(destination); err != nil {
		s.logger.WithError(err).Error("Failed to create destination")
		c.JSON(http.StatusInternalServerError, utils.NewErrorResponse("Failed to create destination"))
		return
	}

	// Load the created destination with relationships
	createdDestination, err := repo.GetDestinationByID(destination.ID)
	if err != nil {
		s.logger.WithError(err).Error("Failed to get created destination")
		c.JSON(http.StatusInternalServerError, utils.NewErrorResponse("Failed to retrieve created destination"))
		return
	}

	s.logger.WithFields(map[string]interface{}{
		"user_id":        user.ID,
		"destination_id": destination.ID,
		"name":           destination.Name,
	}).Info("Destination created")

	c.JSON(http.StatusCreated, utils.NewSuccessResponse(createdDestination, "Destination created successfully"))
}

// getDestination returns a specific destination by ID
func (s *Server) getDestination(c *gin.Context) {
	user, err := s.getCurrentUser(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, utils.NewErrorResponse("Unauthorized"))
		return
	}

	idParam := c.Param("id")
	id, err := strconv.ParseUint(idParam, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, utils.NewErrorResponse("Invalid destination ID"))
		return
	}

	repo := db.NewRepository(s.db)
	destination, err := repo.GetDestinationByID(uint(id))
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, utils.NewErrorResponse("Destination not found"))
			return
		}
		s.logger.WithError(err).Error("Failed to get destination")
		c.JSON(http.StatusInternalServerError, utils.NewErrorResponse("Failed to get destination"))
		return
	}

	// Check if destination belongs to current user
	if destination.UserID != user.ID {
		c.JSON(http.StatusForbidden, utils.NewErrorResponse("Access denied"))
		return
	}

	c.JSON(http.StatusOK, utils.NewSuccessResponse(destination, "Destination retrieved successfully"))
}

// updateDestination updates a destination
func (s *Server) updateDestination(c *gin.Context) {
	user, err := s.getCurrentUser(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, utils.NewErrorResponse("Unauthorized"))
		return
	}

	idParam := c.Param("id")
	id, err := strconv.ParseUint(idParam, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, utils.NewErrorResponse("Invalid destination ID"))
		return
	}

	var req UpdateDestinationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, utils.NewErrorResponse("Invalid request data"))
		return
	}

	repo := db.NewRepository(s.db)
	destination, err := repo.GetDestinationByID(uint(id))
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, utils.NewErrorResponse("Destination not found"))
			return
		}
		s.logger.WithError(err).Error("Failed to get destination")
		c.JSON(http.StatusInternalServerError, utils.NewErrorResponse("Failed to get destination"))
		return
	}

	// Check if destination belongs to current user
	if destination.UserID != user.ID {
		c.JSON(http.StatusForbidden, utils.NewErrorResponse("Access denied"))
		return
	}

	// Sanitize input
	req.Name = s.validator.SanitizeInput(req.Name)
	req.Description = s.validator.SanitizeInput(req.Description)

	// Update fields
	destination.Name = req.Name
	destination.Description = req.Description
	if req.IsActive != nil {
		destination.IsActive = *req.IsActive
	}

	if err := repo.UpdateDestination(destination); err != nil {
		s.logger.WithError(err).Error("Failed to update destination")
		c.JSON(http.StatusInternalServerError, utils.NewErrorResponse("Failed to update destination"))
		return
	}

	s.logger.WithFields(map[string]interface{}{
		"user_id":        user.ID,
		"destination_id": destination.ID,
		"name":           destination.Name,
		"is_active":      destination.IsActive,
	}).Info("Destination updated")

	c.JSON(http.StatusOK, utils.NewSuccessResponse(destination, "Destination updated successfully"))
}

// deleteDestination deletes a destination
func (s *Server) deleteDestination(c *gin.Context) {
	user, err := s.getCurrentUser(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, utils.NewErrorResponse("Unauthorized"))
		return
	}

	idParam := c.Param("id")
	id, err := strconv.ParseUint(idParam, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, utils.NewErrorResponse("Invalid destination ID"))
		return
	}

	repo := db.NewRepository(s.db)
	destination, err := repo.GetDestinationByID(uint(id))
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, utils.NewErrorResponse("Destination not found"))
			return
		}
		s.logger.WithError(err).Error("Failed to get destination")
		c.JSON(http.StatusInternalServerError, utils.NewErrorResponse("Failed to get destination"))
		return
	}

	// Check if destination belongs to current user
	if destination.UserID != user.ID {
		c.JSON(http.StatusForbidden, utils.NewErrorResponse("Access denied"))
		return
	}

	// Check if destination has any travelers (notifications)
	travelers, err := repo.GetTravelersByDestinationID(destination.ID, 1, 0)
	if err != nil {
		s.logger.WithError(err).Error("Failed to check for travelers")
		c.JSON(http.StatusInternalServerError, utils.NewErrorResponse("Failed to check destination usage"))
		return
	}

	if len(travelers) > 0 {
		c.JSON(http.StatusConflict, utils.NewErrorResponse("Cannot delete destination with existing notifications"))
		return
	}

	if err := repo.DeleteDestination(uint(id)); err != nil {
		s.logger.WithError(err).Error("Failed to delete destination")
		c.JSON(http.StatusInternalServerError, utils.NewErrorResponse("Failed to delete destination"))
		return
	}

	s.logger.WithFields(map[string]interface{}{
		"user_id":        user.ID,
		"destination_id": id,
		"name":           destination.Name,
	}).Info("Destination deleted")

	c.JSON(http.StatusOK, utils.NewSuccessResponse(nil, "Destination deleted successfully"))
}

// regenerateDestinationToken generates a new token for a destination
func (s *Server) regenerateDestinationToken(c *gin.Context) {
	user, err := s.getCurrentUser(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, utils.NewErrorResponse("Unauthorized"))
		return
	}

	idParam := c.Param("id")
	id, err := strconv.ParseUint(idParam, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, utils.NewErrorResponse("Invalid destination ID"))
		return
	}

	repo := db.NewRepository(s.db)
	destination, err := repo.GetDestinationByID(uint(id))
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, utils.NewErrorResponse("Destination not found"))
			return
		}
		s.logger.WithError(err).Error("Failed to get destination")
		c.JSON(http.StatusInternalServerError, utils.NewErrorResponse("Failed to get destination"))
		return
	}

	// Check if destination belongs to current user
	if destination.UserID != user.ID {
		c.JSON(http.StatusForbidden, utils.NewErrorResponse("Access denied"))
		return
	}

	// Generate new token
	tokenGenerator := utils.NewTokenGenerator()
	newToken := tokenGenerator.GenerateDestinationToken()

	// Update destination with new token
	destination.Token = newToken
	if err := repo.UpdateDestination(destination); err != nil {
		s.logger.WithError(err).Error("Failed to update destination token")
		c.JSON(http.StatusInternalServerError, utils.NewErrorResponse("Failed to regenerate token"))
		return
	}

	s.logger.WithFields(map[string]interface{}{
		"user_id":        user.ID,
		"destination_id": destination.ID,
		"name":           destination.Name,
	}).Info("Destination token regenerated")

	c.JSON(http.StatusOK, utils.NewSuccessResponse(map[string]interface{}{
		"destination": destination,
		"new_token":   newToken,
	}, "Token regenerated successfully"))
}
