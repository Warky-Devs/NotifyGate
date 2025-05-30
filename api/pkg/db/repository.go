package db

import (
	"time"

	"github.com/Warky-Devs/NotifyGate/api/pkg/models"
	"gorm.io/gorm"
)

type TimeSeriesData struct {
	Date  string `json:"date"`
	Count int    `json:"count"`
}

type DeliveryStatsData struct {
	EndpointName string  `json:"endpoint_name"`
	TotalSent    int     `json:"total_sent"`
	Successful   int     `json:"successful"`
	Failed       int     `json:"failed"`
	SuccessRate  float64 `json:"success_rate"`
	AvgRetries   float64 `json:"avg_retries"`
}

type ErrorRateData struct {
	EndpointName string  `json:"endpoint_name"`
	Date         string  `json:"date"`
	ErrorRate    float64 `json:"error_rate"`
	ErrorCount   int     `json:"error_count"`
	TotalCount   int     `json:"total_count"`
}

type EndpointUsageData struct {
	EndpointName string `json:"endpoint_name"`
	Count        int    `json:"count"`
	Enabled      bool   `json:"enabled"`
}

type DestinationStatsData struct {
	DestinationID   uint   `json:"destination_id"`
	DestinationName string `json:"destination_name"`
	Count           int    `json:"count"`
	LastReceived    string `json:"last_received"`
}

type EndpointStatsData struct {
	EndpointID    uint    `json:"endpoint_id"`
	EndpointName  string  `json:"endpoint_name"`
	DisplayName   string  `json:"display_name"`
	UserCount     int     `json:"user_count"`
	DeliveryCount int     `json:"delivery_count"`
	SuccessRate   float64 `json:"success_rate"`
}

// Repository provides database operations for specific models
type Repository struct {
	db *DB
}

// NewRepository creates a new repository instance
func NewRepository(db *DB) *Repository {
	return &Repository{db: db}
}

func (r *Repository) DB() *DB {
	return r.db
}

// User repository methods
func (r *Repository) CreateUser(user *models.User) error {
	return r.db.Create(user).Error
}

func (r *Repository) GetUserByID(id uint) (*models.User, error) {
	var user models.User
	err := r.db.Preload("Destinations").Preload("UserEndpointSettings").First(&user, id).Error
	return &user, err
}

func (r *Repository) GetUserByOAuth(provider, oauthID string) (*models.User, error) {
	var user models.User
	err := r.db.Where("oauth_provider = ? AND oauth_id = ?", provider, oauthID).First(&user).Error
	return &user, err
}

func (r *Repository) GetUserByEmail(email string) (*models.User, error) {
	var user models.User
	err := r.db.Where("email = ?", email).First(&user).Error
	return &user, err
}

func (r *Repository) UpdateUser(user *models.User) error {
	return r.db.Save(user).Error
}

func (r *Repository) DeleteUser(id uint) error {
	return r.db.Delete(&models.User{}, id).Error
}

// Destination repository methods
func (r *Repository) CreateDestination(destination *models.Destination) error {
	return r.db.Create(destination).Error
}

func (r *Repository) GetDestinationsByUserID(userID uint) ([]models.Destination, error) {
	var destinations []models.Destination
	err := r.db.Where("user_id = ?", userID).Find(&destinations).Error
	return destinations, err
}

func (r *Repository) GetDestinationByToken(token string) (*models.Destination, error) {
	var destination models.Destination
	err := r.db.Where("token = ? AND is_active = ?", token, true).First(&destination).Error
	return &destination, err
}

func (r *Repository) UpdateDestination(destination *models.Destination) error {
	return r.db.Save(destination).Error
}

func (r *Repository) DeleteDestination(id uint) error {
	return r.db.Delete(&models.Destination{}, id).Error
}

// Traveler repository methods
func (r *Repository) CreateTraveler(traveler *models.Traveler) error {
	return r.db.Create(traveler).Error
}

func (r *Repository) GetTravelersByUserID(userID uint, limit, offset int) ([]models.Traveler, error) {
	var travelers []models.Traveler
	err := r.db.Where("user_id = ?", userID).
		Preload("Destination").
		Order("created_at DESC").
		Limit(limit).
		Offset(offset).
		Find(&travelers).Error
	return travelers, err
}

func (r *Repository) GetTravelersByDestinationID(destinationID uint, limit, offset int) ([]models.Traveler, error) {
	var travelers []models.Traveler
	err := r.db.Where("destination_id = ?", destinationID).
		Order("created_at DESC").
		Limit(limit).
		Offset(offset).
		Find(&travelers).Error
	return travelers, err
}

func (r *Repository) UpdateTravelerStatus(id uint, status models.TravelerStatus) error {
	now := time.Now()
	updates := map[string]interface{}{
		"status": status,
	}

	switch status {
	case models.StatusRead:
		updates["read_at"] = &now
	case models.StatusForwarded:
		updates["forwarded_at"] = &now
	}

	return r.db.Model(&models.Traveler{}).Where("id = ?", id).Updates(updates).Error
}

func (r *Repository) DeleteTraveler(id uint) error {
	return r.db.Delete(&models.Traveler{}, id).Error
}

// Endpoint repository methods
func (r *Repository) GetEndpoints() ([]models.Endpoint, error) {
	var endpoints []models.Endpoint
	err := r.db.Where("is_active = ?", true).Find(&endpoints).Error
	return endpoints, err
}

func (r *Repository) GetEndpointByName(name string) (*models.Endpoint, error) {
	var endpoint models.Endpoint
	err := r.db.Where("name = ?", name).First(&endpoint).Error
	return &endpoint, err
}

// UserEndpointSetting repository methods
func (r *Repository) GetUserEndpointSettings(userID uint) ([]models.UserEndpointSetting, error) {
	var settings []models.UserEndpointSetting
	err := r.db.Where("user_id = ?", userID).Preload("Endpoint").Find(&settings).Error
	return settings, err
}

func (r *Repository) GetUserEndpointSetting(userID, endpointID uint) (*models.UserEndpointSetting, error) {
	var setting models.UserEndpointSetting
	err := r.db.Where("user_id = ? AND endpoint_id = ?", userID, endpointID).First(&setting).Error
	return &setting, err
}

func (r *Repository) CreateOrUpdateUserEndpointSetting(setting *models.UserEndpointSetting) error {
	var existing models.UserEndpointSetting
	result := r.db.Where("user_id = ? AND endpoint_id = ?", setting.UserID, setting.EndpointID).First(&existing)

	if result.Error == gorm.ErrRecordNotFound {
		return r.db.Create(setting).Error
	}

	setting.ID = existing.ID
	return r.db.Save(setting).Error
}

// Queue repository methods
func (r *Repository) CreateTravelerQueue(queue *models.TravelerQueue) error {
	return r.db.Create(queue).Error
}

func (r *Repository) GetPendingQueueItems(limit int) ([]models.TravelerQueue, error) {
	var items []models.TravelerQueue
	err := r.db.Where("status = ? AND scheduled_for <= ?", models.QueueStatusPending, time.Now()).
		Preload("Traveler").
		Preload("Endpoint").
		Limit(limit).
		Find(&items).Error
	return items, err
}

func (r *Repository) UpdateQueueItemStatus(id uint, status models.QueueStatus) error {
	updates := map[string]interface{}{
		"status": status,
	}

	if status == models.QueueStatusSent || status == models.QueueStatusFailed {
		updates["processed_at"] = time.Now()
	}

	return r.db.Model(&models.TravelerQueue{}).Where("id = ?", id).Updates(updates).Error
}

// Additional helper function to get delivery preferences
func (repo *Repository) GetDeliveryPreferences(userID uint) ([]models.DeliveryPreference, error) {
	var preferences []models.DeliveryPreference
	err := repo.db.Where("user_id = ? AND is_enabled = ?", userID, true).
		Preload("Endpoint").
		Find(&preferences).Error
	return preferences, err
}

func (repo *Repository) GetAllDeliveryPreferences(userID uint) ([]models.DeliveryPreference, error) {
	var preferences []models.DeliveryPreference
	err := repo.db.Where("user_id = ?", userID).
		Preload("Endpoint").
		Preload("Destination").
		Find(&preferences).Error
	return preferences, err
}

func (repo *Repository) GetDestinationDeliveryPreferences(userID, destinationID uint) ([]models.DeliveryPreference, error) {
	var preferences []models.DeliveryPreference
	err := repo.db.Where("user_id = ? AND destination_id = ?", userID, destinationID).
		Preload("Endpoint").
		Preload("Destination").
		Find(&preferences).Error
	return preferences, err
}

func (repo *Repository) CreateOrUpdateDeliveryPreference(preference *models.DeliveryPreference) error {
	var existing models.DeliveryPreference

	query := repo.db.Where("user_id = ? AND endpoint_id = ?", preference.UserID, preference.EndpointID)
	if preference.DestinationID != nil {
		query = query.Where("destination_id = ?", *preference.DestinationID)
	} else {
		query = query.Where("destination_id IS NULL")
	}

	result := query.First(&existing)

	if result.Error == gorm.ErrRecordNotFound {
		return repo.db.Create(preference).Error
	}

	preference.ID = existing.ID
	return repo.db.Save(preference).Error
}

// Additional repository methods needed
func (repo *Repository) GetTravelerByID(id uint) (*models.Traveler, error) {
	var traveler models.Traveler
	err := repo.db.Preload("Destination").Preload("User").First(&traveler, id).Error
	return &traveler, err
}

func (repo *Repository) GetTravelersCount(filters map[string]interface{}) (int, error) {
	var count int64
	query := repo.db.Model(&models.Traveler{})

	for key, value := range filters {
		query = query.Where(key+" = ?", value)
	}

	err := query.Count(&count).Error
	return int(count), err
}

func (repo *Repository) GetTravelersWithFilters(filters map[string]interface{}, limit, offset int) ([]models.Traveler, error) {
	var travelers []models.Traveler
	query := repo.db.Preload("Destination").Preload("User")

	for key, value := range filters {
		query = query.Where(key+" = ?", value)
	}

	err := query.Order("created_at DESC").
		Limit(limit).
		Offset(offset).
		Find(&travelers).Error

	return travelers, err
}

func (repo *Repository) GetEndpointByID(id uint) (*models.Endpoint, error) {
	var endpoint models.Endpoint
	err := repo.db.First(&endpoint, id).Error
	return &endpoint, err
}
func (repo *Repository) GetDestinationByID(id uint) (*models.Destination, error) {
	var destination models.Destination
	err := repo.db.Preload("User").First(&destination, id).Error
	return &destination, err
}

func (repo *Repository) GetTravelersCountByDateRange(userID uint, startDate, endDate string) (int, error) {
	var count int64
	err := repo.db.Model(&models.Traveler{}).
		Where("user_id = ? AND DATE(created_at) BETWEEN ? AND ?", userID, startDate, endDate).
		Count(&count).Error
	return int(count), err
}

func (repo *Repository) GetTravelersStatusBreakdown(userID uint) (map[string]int, error) {
	type StatusCount struct {
		Status string
		Count  int
	}

	var results []StatusCount
	err := repo.db.Model(&models.Traveler{}).
		Select("status, COUNT(*) as count").
		Where("user_id = ?", userID).
		Group("status").
		Scan(&results).Error

	breakdown := make(map[string]int)
	for _, result := range results {
		breakdown[result.Status] = result.Count
	}

	return breakdown, err
}

func (repo *Repository) GetTravelersPriorityBreakdown(userID uint) (map[string]int, error) {
	type PriorityCount struct {
		Priority string
		Count    int
	}

	var results []PriorityCount
	err := repo.db.Model(&models.Traveler{}).
		Select("priority, COUNT(*) as count").
		Where("user_id = ?", userID).
		Group("priority").
		Scan(&results).Error

	breakdown := make(map[string]int)
	for _, result := range results {
		breakdown[result.Priority] = result.Count
	}

	return breakdown, err
}

func (repo *Repository) GetTravelersOverTime(userID uint, days int) ([]TimeSeriesData, error) {
	type DateCount struct {
		Date  string
		Count int
	}

	var results []DateCount
	err := repo.db.Model(&models.Traveler{}).
		Select("DATE(created_at) as date, COUNT(*) as count").
		Where("user_id = ? AND created_at >= ?", userID, time.Now().AddDate(0, 0, -days)).
		Group("DATE(created_at)").
		Order("date").
		Scan(&results).Error

	var timeSeries []TimeSeriesData
	for _, result := range results {
		timeSeries = append(timeSeries, TimeSeriesData{
			Date:  result.Date,
			Count: result.Count,
		})
	}

	return timeSeries, err
}

func (repo *Repository) GetEndpointUsage(userID uint) ([]EndpointUsageData, error) {
	type EndpointCount struct {
		EndpointName string
		Count        int
		Enabled      bool
	}

	var results []EndpointCount
	err := repo.db.Table("user_endpoint_settings").
		Select("endpoints.name as endpoint_name, COUNT(traveler_queues.id) as count, user_endpoint_settings.is_enabled as enabled").
		Joins("JOIN endpoints ON user_endpoint_settings.endpoint_id = endpoints.id").
		Joins("LEFT JOIN traveler_queues ON user_endpoint_settings.endpoint_id = traveler_queues.endpoint_id").
		Where("user_endpoint_settings.user_id = ?", userID).
		Group("endpoints.name, user_endpoint_settings.is_enabled").
		Scan(&results).Error

	var usage []EndpointUsageData
	for _, result := range results {
		usage = append(usage, EndpointUsageData{
			EndpointName: result.EndpointName,
			Count:        result.Count,
			Enabled:      result.Enabled,
		})
	}

	return usage, err
}

func (repo *Repository) GetDestinationStats(userID uint) ([]DestinationStatsData, error) {
	type DestinationCount struct {
		DestinationID   uint
		DestinationName string
		Count           int
		LastReceived    *time.Time
	}

	var results []DestinationCount
	err := repo.db.Table("destinations").
		Select("destinations.id as destination_id, destinations.name as destination_name, COUNT(travelers.id) as count, MAX(travelers.created_at) as last_received").
		Joins("LEFT JOIN travelers ON destinations.id = travelers.destination_id").
		Where("destinations.user_id = ?", userID).
		Group("destinations.id, destinations.name").
		Scan(&results).Error

	var stats []DestinationStatsData
	for _, result := range results {
		lastReceived := ""
		if result.LastReceived != nil {
			lastReceived = result.LastReceived.Format(time.RFC3339)
		}

		stats = append(stats, DestinationStatsData{
			DestinationID:   result.DestinationID,
			DestinationName: result.DestinationName,
			Count:           result.Count,
			LastReceived:    lastReceived,
		})
	}

	return stats, err
}

func (repo *Repository) GetAverageResponseTime(userID uint) (float64, error) {
	type AvgTime struct {
		AvgMinutes float64
	}

	var result AvgTime
	err := repo.db.Model(&models.Traveler{}).
		Select("AVG(EXTRACT(EPOCH FROM (read_at - created_at))/60) as avg_minutes").
		Where("user_id = ? AND read_at IS NOT NULL", userID).
		Scan(&result).Error

	return result.AvgMinutes, err
}

func (repo *Repository) GetDeliverySuccessRate(userID uint) (float64, error) {
	type SuccessRate struct {
		SuccessRate float64
	}

	var result SuccessRate
	err := repo.db.Table("traveler_queues").
		Select("(COUNT(CASE WHEN status = 'sent' THEN 1 END) * 100.0 / COUNT(*)) as success_rate").
		Joins("JOIN travelers ON traveler_queues.traveler_id = travelers.id").
		Where("travelers.user_id = ?", userID).
		Scan(&result).Error

	return result.SuccessRate, err
}

func (repo *Repository) GetEndpointBreakdown(userID uint) ([]EndpointStatsData, error) {
	type EndpointBreakdown struct {
		EndpointID    uint
		EndpointName  string
		DisplayName   string
		UserCount     int
		DeliveryCount int
		SuccessCount  int
	}

	var results []EndpointBreakdown
	err := repo.db.Table("endpoints").
		Select(`
			endpoints.id as endpoint_id,
			endpoints.name as endpoint_name,
			endpoints.display_name as display_name,
			COUNT(DISTINCT user_endpoint_settings.user_id) as user_count,
			COUNT(traveler_queues.id) as delivery_count,
			COUNT(CASE WHEN traveler_queues.status = 'sent' THEN 1 END) as success_count
		`).
		Joins("LEFT JOIN user_endpoint_settings ON endpoints.id = user_endpoint_settings.endpoint_id").
		Joins("LEFT JOIN traveler_queues ON endpoints.id = traveler_queues.endpoint_id").
		Joins("LEFT JOIN travelers ON traveler_queues.traveler_id = travelers.id").
		Where("travelers.user_id = ? OR travelers.user_id IS NULL", userID).
		Group("endpoints.id, endpoints.name, endpoints.display_name").
		Scan(&results).Error

	var stats []EndpointStatsData
	for _, result := range results {
		successRate := float64(0)
		if result.DeliveryCount > 0 {
			successRate = (float64(result.SuccessCount) / float64(result.DeliveryCount)) * 100
		}

		stats = append(stats, EndpointStatsData{
			EndpointID:    result.EndpointID,
			EndpointName:  result.EndpointName,
			DisplayName:   result.DisplayName,
			UserCount:     result.UserCount,
			DeliveryCount: result.DeliveryCount,
			SuccessRate:   successRate,
		})
	}

	return stats, err
}

func (repo *Repository) GetDeliveryStats(userID uint) ([]DeliveryStatsData, error) {
	type DeliveryBreakdown struct {
		EndpointName string
		TotalSent    int
		Successful   int
		Failed       int
		TotalRetries int
	}

	var results []DeliveryBreakdown
	err := repo.db.Table("endpoints").
		Select(`
			endpoints.name as endpoint_name,
			COUNT(traveler_queues.id) as total_sent,
			COUNT(CASE WHEN traveler_queues.status = 'sent' THEN 1 END) as successful,
			COUNT(CASE WHEN traveler_queues.status = 'failed' THEN 1 END) as failed,
			COALESCE(SUM(traveler_queues.attempts), 0) as total_retries
		`).
		Joins("JOIN traveler_queues ON endpoints.id = traveler_queues.endpoint_id").
		Joins("JOIN travelers ON traveler_queues.traveler_id = travelers.id").
		Where("travelers.user_id = ?", userID).
		Group("endpoints.name").
		Scan(&results).Error

	var stats []DeliveryStatsData
	for _, result := range results {
		successRate := float64(0)
		if result.TotalSent > 0 {
			successRate = (float64(result.Successful) / float64(result.TotalSent)) * 100
		}

		avgRetries := float64(0)
		if result.TotalSent > 0 {
			avgRetries = float64(result.TotalRetries) / float64(result.TotalSent)
		}

		stats = append(stats, DeliveryStatsData{
			EndpointName: result.EndpointName,
			TotalSent:    result.TotalSent,
			Successful:   result.Successful,
			Failed:       result.Failed,
			SuccessRate:  successRate,
			AvgRetries:   avgRetries,
		})
	}

	return stats, err
}

func (repo *Repository) GetErrorRates(userID uint, days int) ([]ErrorRateData, error) {
	type ErrorRateBreakdown struct {
		EndpointName string
		Date         string
		ErrorCount   int
		TotalCount   int
	}

	var results []ErrorRateBreakdown
	err := repo.db.Table("endpoints").
		Select(`
			endpoints.name as endpoint_name,
			DATE(traveler_queues.created_at) as date,
			COUNT(CASE WHEN traveler_queues.status = 'failed' THEN 1 END) as error_count,
			COUNT(traveler_queues.id) as total_count
		`).
		Joins("JOIN traveler_queues ON endpoints.id = traveler_queues.endpoint_id").
		Joins("JOIN travelers ON traveler_queues.traveler_id = travelers.id").
		Where("travelers.user_id = ? AND traveler_queues.created_at >= ?", userID, time.Now().AddDate(0, 0, -days)).
		Group("endpoints.name, DATE(traveler_queues.created_at)").
		Order("date").
		Scan(&results).Error

	var errorRates []ErrorRateData
	for _, result := range results {
		errorRate := float64(0)
		if result.TotalCount > 0 {
			errorRate = (float64(result.ErrorCount) / float64(result.TotalCount)) * 100
		}

		errorRates = append(errorRates, ErrorRateData{
			EndpointName: result.EndpointName,
			Date:         result.Date,
			ErrorRate:    errorRate,
			ErrorCount:   result.ErrorCount,
			TotalCount:   result.TotalCount,
		})
	}

	return errorRates, err
}

func (repo *Repository) UpdateUserEndpointSetting(setting *models.UserEndpointSetting) error {
	return repo.db.Save(setting).Error
}

func (repo *Repository) UpdateTraveler(traveler *models.Traveler) error {
	return repo.db.Save(traveler).Error
}
