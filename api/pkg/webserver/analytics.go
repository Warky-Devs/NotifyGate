package webserver

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/Warky-Devs/NotifyGate/api/pkg/db"
	"github.com/Warky-Devs/NotifyGate/api/pkg/models"
	"github.com/Warky-Devs/NotifyGate/api/pkg/utils"
)

// DashboardStats represents dashboard statistics
type DashboardStats struct {
	TotalDestinations   int                    `json:"total_destinations"`
	TotalTravelers      int                    `json:"total_travelers"`
	TravelersToday      int                    `json:"travelers_today"`
	TravelersThisWeek   int                    `json:"travelers_this_week"`
	TravelersThisMonth  int                    `json:"travelers_this_month"`
	UnreadTravelers     int                    `json:"unread_travelers"`
	ActiveEndpoints     int                    `json:"active_endpoints"`
	RecentTravelers     []models.Traveler      `json:"recent_travelers"`
	TravelersByStatus   map[string]int         `json:"travelers_by_status"`
	TravelersByPriority map[string]int         `json:"travelers_by_priority"`
	TravelersOverTime   []db.TimeSeriesData    `json:"travelers_over_time"`
	EndpointUsage       []db.EndpointUsageData `json:"endpoint_usage"`
}

// TravelerStats represents detailed traveler statistics
type TravelerStats struct {
	TotalCount          int                       `json:"total_count"`
	StatusBreakdown     map[string]int            `json:"status_breakdown"`
	PriorityBreakdown   map[string]int            `json:"priority_breakdown"`
	TravelersOverTime   []db.TimeSeriesData       `json:"travelers_over_time"`
	DestinationStats    []db.DestinationStatsData `json:"destination_stats"`
	AverageResponseTime float64                   `json:"average_response_time_minutes"`
	DeliverySuccessRate float64                   `json:"delivery_success_rate"`
}

// EndpointStats represents endpoint statistics
type EndpointStats struct {
	TotalEndpoints    int                    `json:"total_endpoints"`
	EnabledEndpoints  int                    `json:"enabled_endpoints"`
	EndpointBreakdown []db.EndpointStatsData `json:"endpoint_breakdown"`
	DeliveryStats     []db.DeliveryStatsData `json:"delivery_stats"`
	ErrorRates        []db.ErrorRateData     `json:"error_rates"`
}

// getDashboardStats returns overview statistics for the dashboard
func (s *Server) getDashboardStats(c *gin.Context) {
	user, err := s.getCurrentUser(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, utils.NewErrorResponse("Unauthorized"))
		return
	}

	repo := db.NewRepository(s.db)

	// Get basic counts
	destinations, err := repo.GetDestinationsByUserID(user.ID)
	if err != nil {
		s.logger.WithError(err).Error("Failed to get destinations for stats")
		c.JSON(http.StatusInternalServerError, utils.NewErrorResponse("Failed to get dashboard stats"))
		return
	}

	totalTravelers, err := repo.GetTravelersCount(map[string]interface{}{"user_id": user.ID})
	if err != nil {
		s.logger.WithError(err).Error("Failed to get total travelers count")
		c.JSON(http.StatusInternalServerError, utils.NewErrorResponse("Failed to get dashboard stats"))
		return
	}

	// Get time-based counts
	now := time.Now()
	today := now.Format("2006-01-02")
	weekStart := now.AddDate(0, 0, -7).Format("2006-01-02")
	monthStart := now.AddDate(0, -1, 0).Format("2006-01-02")

	travelersToday, _ := repo.GetTravelersCountByDateRange(user.ID, today, today)
	travelersThisWeek, _ := repo.GetTravelersCountByDateRange(user.ID, weekStart, today)
	travelersThisMonth, _ := repo.GetTravelersCountByDateRange(user.ID, monthStart, today)

	// Get unread count
	unreadCount, _ := repo.GetTravelersCount(map[string]interface{}{
		"user_id": user.ID,
		"status":  models.StatusUnread,
	})

	// Get active endpoints count
	userEndpointSettings, _ := repo.GetUserEndpointSettings(user.ID)
	activeEndpoints := 0
	for _, setting := range userEndpointSettings {
		if setting.IsEnabled {
			activeEndpoints++
		}
	}

	// Get recent travelers
	recentTravelers, _ := repo.GetTravelersWithFilters(
		map[string]interface{}{"user_id": user.ID},
		5, 0,
	)

	// Get status breakdown
	statusBreakdown, _ := repo.GetTravelersStatusBreakdown(user.ID)

	// Get priority breakdown
	priorityBreakdown, _ := repo.GetTravelersPriorityBreakdown(user.ID)

	// Get travelers over time (last 30 days)
	travelersOverTime, _ := repo.GetTravelersOverTime(user.ID, 30)

	// Get endpoint usage
	endpointUsage, _ := repo.GetEndpointUsage(user.ID)

	stats := DashboardStats{
		TotalDestinations:   len(destinations),
		TotalTravelers:      totalTravelers,
		TravelersToday:      travelersToday,
		TravelersThisWeek:   travelersThisWeek,
		TravelersThisMonth:  travelersThisMonth,
		UnreadTravelers:     unreadCount,
		ActiveEndpoints:     activeEndpoints,
		RecentTravelers:     recentTravelers,
		TravelersByStatus:   statusBreakdown,
		TravelersByPriority: priorityBreakdown,
		TravelersOverTime:   travelersOverTime,
		EndpointUsage:       endpointUsage,
	}

	c.JSON(http.StatusOK, utils.NewSuccessResponse(stats, "Dashboard stats retrieved successfully"))
}

// getTravelerStats returns detailed traveler statistics
func (s *Server) getTravelerStats(c *gin.Context) {
	user, err := s.getCurrentUser(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, utils.NewErrorResponse("Unauthorized"))
		return
	}

	repo := db.NewRepository(s.db)

	// Get total count
	totalCount, err := repo.GetTravelersCount(map[string]interface{}{"user_id": user.ID})
	if err != nil {
		s.logger.WithError(err).Error("Failed to get travelers count")
		c.JSON(http.StatusInternalServerError, utils.NewErrorResponse("Failed to get traveler stats"))
		return
	}

	// Get status breakdown
	statusBreakdown, _ := repo.GetTravelersStatusBreakdown(user.ID)

	// Get priority breakdown
	priorityBreakdown, _ := repo.GetTravelersPriorityBreakdown(user.ID)

	// Get travelers over time (last 90 days)
	travelersOverTime, _ := repo.GetTravelersOverTime(user.ID, 90)

	// Get destination stats
	destinationStats, _ := repo.GetDestinationStats(user.ID)

	// Get average response time (time from received to read)
	avgResponseTime, _ := repo.GetAverageResponseTime(user.ID)

	// Get delivery success rate
	deliverySuccessRate, _ := repo.GetDeliverySuccessRate(user.ID)

	stats := TravelerStats{
		TotalCount:          totalCount,
		StatusBreakdown:     statusBreakdown,
		PriorityBreakdown:   priorityBreakdown,
		TravelersOverTime:   travelersOverTime,
		DestinationStats:    destinationStats,
		AverageResponseTime: avgResponseTime,
		DeliverySuccessRate: deliverySuccessRate,
	}

	c.JSON(http.StatusOK, utils.NewSuccessResponse(stats, "Traveler stats retrieved successfully"))
}

// getEndpointStats returns endpoint statistics
func (s *Server) getEndpointStats(c *gin.Context) {
	user, err := s.getCurrentUser(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, utils.NewErrorResponse("Unauthorized"))
		return
	}

	repo := db.NewRepository(s.db)

	// Get all endpoints
	allEndpoints, err := repo.GetEndpoints()
	if err != nil {
		s.logger.WithError(err).Error("Failed to get endpoints")
		c.JSON(http.StatusInternalServerError, utils.NewErrorResponse("Failed to get endpoint stats"))
		return
	}

	// Get user's endpoint settings
	userSettings, _ := repo.GetUserEndpointSettings(user.ID)
	enabledCount := 0
	for _, setting := range userSettings {
		if setting.IsEnabled {
			enabledCount++
		}
	}

	// Get endpoint breakdown
	endpointBreakdown, _ := repo.GetEndpointBreakdown(user.ID)

	// Get delivery stats
	deliveryStats, _ := repo.GetDeliveryStats(user.ID)

	// Get error rates over time
	errorRates, _ := repo.GetErrorRates(user.ID, 30)

	stats := EndpointStats{
		TotalEndpoints:    len(allEndpoints),
		EnabledEndpoints:  enabledCount,
		EndpointBreakdown: endpointBreakdown,
		DeliveryStats:     deliveryStats,
		ErrorRates:        errorRates,
	}

	c.JSON(http.StatusOK, utils.NewSuccessResponse(stats, "Endpoint stats retrieved successfully"))
}
