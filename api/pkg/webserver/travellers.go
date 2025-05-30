package webserver

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/Warky-Devs/NotifyGate/api/pkg/db"
	"github.com/Warky-Devs/NotifyGate/api/pkg/models"
	"github.com/Warky-Devs/NotifyGate/api/pkg/utils"
)

// UpdateTravelerStatusRequest represents the request to update traveler status
type UpdateTravelerStatusRequest struct {
	Status string `json:"status" binding:"required"`
}

// ForwardTravelerRequest represents the request to forward a traveler
type ForwardTravelerRequest struct {
	DestinationID uint   `json:"destination_id" binding:"required"`
	Title         string `json:"title"`
	Body          string `json:"body"`
}

// TravelerListResponse represents the paginated response for travelers
type TravelerListResponse struct {
	Travelers  []models.Traveler `json:"travelers"`
	Pagination *utils.Pagination `json:"pagination"`
}

// getTravelers returns paginated travelers for the current user
func (s *Server) getTravelers(c *gin.Context) {
	user, err := s.getCurrentUser(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, utils.NewErrorResponse("Unauthorized"))
		return
	}

	// Parse query parameters
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))
	status := c.Query("status")
	destinationID := c.Query("destination_id")
	priority := c.Query("priority")

	repo := db.NewRepository(s.db)

	// Build query filters
	filters := map[string]interface{}{
		"user_id": user.ID,
	}

	if status != "" {
		// Validate status
		validStatuses := []string{"received", "read", "unread", "deleted", "forwarded"}
		statusValid := false
		for _, validStatus := range validStatuses {
			if status == validStatus {
				statusValid = true
				break
			}
		}
		if !statusValid {
			c.JSON(http.StatusBadRequest, utils.NewErrorResponse("Invalid status filter"))
			return
		}
		filters["status"] = status
	}

	if destinationID != "" {
		destID, err := strconv.ParseUint(destinationID, 10, 32)
		if err != nil {
			c.JSON(http.StatusBadRequest, utils.NewErrorResponse("Invalid destination ID"))
			return
		}
		filters["destination_id"] = destID
	}

	if priority != "" {
		validPriorities := []string{"low", "normal", "high", "critical"}
		priorityValid := false
		for _, validPriority := range validPriorities {
			if priority == validPriority {
				priorityValid = true
				break
			}
		}
		if !priorityValid {
			c.JSON(http.StatusBadRequest, utils.NewErrorResponse("Invalid priority filter"))
			return
		}
		filters["priority"] = priority
	}

	// Get total count
	totalCount, err := repo.GetTravelersCount(filters)
	if err != nil {
		s.logger.WithError(err).Error("Failed to get travelers count")
		c.JSON(http.StatusInternalServerError, utils.NewErrorResponse("Failed to get travelers"))
		return
	}

	// Create pagination
	pagination := utils.NewPagination(page, limit, totalCount)

	// Get travelers
	travelers, err := repo.GetTravelersWithFilters(filters, pagination.Limit, pagination.GetOffset())
	if err != nil {
		s.logger.WithError(err).Error("Failed to get travelers")
		c.JSON(http.StatusInternalServerError, utils.NewErrorResponse("Failed to get travelers"))
		return
	}

	response := TravelerListResponse{
		Travelers:  travelers,
		Pagination: pagination,
	}

	c.JSON(http.StatusOK, utils.NewPaginatedResponse(response.Travelers, pagination, "Travelers retrieved successfully"))
}

// getTraveler returns a specific traveler by ID
func (s *Server) getTraveler(c *gin.Context) {
	user, err := s.getCurrentUser(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, utils.NewErrorResponse("Unauthorized"))
		return
	}

	idParam := c.Param("id")
	id, err := strconv.ParseUint(idParam, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, utils.NewErrorResponse("Invalid traveler ID"))
		return
	}

	repo := db.NewRepository(s.db)
	traveler, err := repo.GetTravelerByID(uint(id))
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, utils.NewErrorResponse("Traveler not found"))
			return
		}
		s.logger.WithError(err).Error("Failed to get traveler")
		c.JSON(http.StatusInternalServerError, utils.NewErrorResponse("Failed to get traveler"))
		return
	}

	// Check if traveler belongs to current user
	if traveler.UserID != user.ID {
		c.JSON(http.StatusForbidden, utils.NewErrorResponse("Access denied"))
		return
	}

	c.JSON(http.StatusOK, utils.NewSuccessResponse(traveler, "Traveler retrieved successfully"))
}

// updateTravelerStatus updates the status of a traveler
func (s *Server) updateTravelerStatus(c *gin.Context) {
	user, err := s.getCurrentUser(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, utils.NewErrorResponse("Unauthorized"))
		return
	}

	idParam := c.Param("id")
	id, err := strconv.ParseUint(idParam, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, utils.NewErrorResponse("Invalid traveler ID"))
		return
	}

	var req UpdateTravelerStatusRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, utils.NewErrorResponse("Invalid request data"))
		return
	}

	// Validate status
	var status models.TravelerStatus
	switch strings.ToLower(req.Status) {
	case "read":
		status = models.StatusRead
	case "unread":
		status = models.StatusUnread
	case "deleted":
		status = models.StatusDeleted
	default:
		c.JSON(http.StatusBadRequest, utils.NewErrorResponse("Invalid status"))
		return
	}

	repo := db.NewRepository(s.db)
	traveler, err := repo.GetTravelerByID(uint(id))
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, utils.NewErrorResponse("Traveler not found"))
			return
		}
		s.logger.WithError(err).Error("Failed to get traveler")
		c.JSON(http.StatusInternalServerError, utils.NewErrorResponse("Failed to get traveler"))
		return
	}

	// Check if traveler belongs to current user
	if traveler.UserID != user.ID {
		c.JSON(http.StatusForbidden, utils.NewErrorResponse("Access denied"))
		return
	}

	// Update status
	if err := repo.UpdateTravelerStatus(uint(id), status); err != nil {
		s.logger.WithError(err).Error("Failed to update traveler status")
		c.JSON(http.StatusInternalServerError, utils.NewErrorResponse("Failed to update status"))
		return
	}

	s.logger.LogTraveler(uint(id), traveler.DestinationID, "status_updated", true, string(status))

	// Get updated traveler
	updatedTraveler, err := repo.GetTravelerByID(uint(id))
	if err != nil {
		s.logger.WithError(err).Error("Failed to get updated traveler")
		c.JSON(http.StatusInternalServerError, utils.NewErrorResponse("Failed to retrieve updated traveler"))
		return
	}

	c.JSON(http.StatusOK, utils.NewSuccessResponse(updatedTraveler, "Status updated successfully"))
}

// forwardTraveler forwards a traveler to another destination
func (s *Server) forwardTraveler(c *gin.Context) {
	user, err := s.getCurrentUser(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, utils.NewErrorResponse("Unauthorized"))
		return
	}

	idParam := c.Param("id")
	id, err := strconv.ParseUint(idParam, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, utils.NewErrorResponse("Invalid traveler ID"))
		return
	}

	var req ForwardTravelerRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, utils.NewErrorResponse("Invalid request data"))
		return
	}

	repo := db.NewRepository(s.db)

	// Get original traveler
	originalTraveler, err := repo.GetTravelerByID(uint(id))
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, utils.NewErrorResponse("Traveler not found"))
			return
		}
		s.logger.WithError(err).Error("Failed to get traveler")
		c.JSON(http.StatusInternalServerError, utils.NewErrorResponse("Failed to get traveler"))
		return
	}

	// Check if traveler belongs to current user
	if originalTraveler.UserID != user.ID {
		c.JSON(http.StatusForbidden, utils.NewErrorResponse("Access denied"))
		return
	}

	// Check if destination exists and belongs to user
	destination, err := repo.GetDestinationByID(req.DestinationID)
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
		c.JSON(http.StatusForbidden, utils.NewErrorResponse("Access denied to destination"))
		return
	}

	// Sanitize input
	title := req.Title
	body := req.Body
	if title == "" {
		title = "Forwarded: " + originalTraveler.Title
	}
	if body == "" {
		body = originalTraveler.Body
	}
	title = s.validator.SanitizeInput(title)
	body = s.validator.SanitizeInput(body)

	// Create forwarded traveler
	forwardedTraveler := &models.Traveler{
		UserID:        user.ID,
		DestinationID: req.DestinationID,
		Title:         title,
		Body:          body,
		ImageURL:      originalTraveler.ImageURL,
		Link:          originalTraveler.Link,
		Attachment:    originalTraveler.Attachment,
		Priority:      originalTraveler.Priority,
		Status:        models.StatusReceived,
		SourceIP:      c.ClientIP(),
		UserAgent:     "NotifyGate-Forward",
		RawPayload:    originalTraveler.RawPayload,
	}

	if err := repo.CreateTraveler(forwardedTraveler); err != nil {
		s.logger.WithError(err).Error("Failed to create forwarded traveler")
		c.JSON(http.StatusInternalServerError, utils.NewErrorResponse("Failed to forward traveler"))
		return
	}

	// Update original traveler status to forwarded
	if err := repo.UpdateTravelerStatus(uint(id), models.StatusForwarded); err != nil {
		s.logger.WithError(err).Error("Failed to update original traveler status")
		// Don't fail the request, just log the error
	}

	// Queue forwarded traveler for delivery
	go s.queueTravelerForDelivery(forwardedTraveler)

	s.logger.LogTraveler(uint(id), originalTraveler.DestinationID, "forwarded", true, "")
	s.logger.LogTraveler(forwardedTraveler.ID, req.DestinationID, "received_via_forward", true, "")

	c.JSON(http.StatusCreated, utils.NewSuccessResponse(forwardedTraveler, "Traveler forwarded successfully"))
}

// deleteTraveler deletes a traveler
func (s *Server) deleteTraveler(c *gin.Context) {
	user, err := s.getCurrentUser(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, utils.NewErrorResponse("Unauthorized"))
		return
	}

	idParam := c.Param("id")
	id, err := strconv.ParseUint(idParam, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, utils.NewErrorResponse("Invalid traveler ID"))
		return
	}

	repo := db.NewRepository(s.db)
	traveler, err := repo.GetTravelerByID(uint(id))
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, utils.NewErrorResponse("Traveler not found"))
			return
		}
		s.logger.WithError(err).Error("Failed to get traveler")
		c.JSON(http.StatusInternalServerError, utils.NewErrorResponse("Failed to get traveler"))
		return
	}

	// Check if traveler belongs to current user
	if traveler.UserID != user.ID {
		c.JSON(http.StatusForbidden, utils.NewErrorResponse("Access denied"))
		return
	}

	if err := repo.DeleteTraveler(uint(id)); err != nil {
		s.logger.WithError(err).Error("Failed to delete traveler")
		c.JSON(http.StatusInternalServerError, utils.NewErrorResponse("Failed to delete traveler"))
		return
	}

	s.logger.LogTraveler(uint(id), traveler.DestinationID, "deleted", true, "")

	c.JSON(http.StatusOK, utils.NewSuccessResponse(nil, "Traveler deleted successfully"))
}
