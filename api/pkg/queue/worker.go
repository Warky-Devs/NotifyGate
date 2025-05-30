package queue

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/Warky-Devs/NotifyGate/api/pkg/config"
	"github.com/Warky-Devs/NotifyGate/api/pkg/db"
	"github.com/Warky-Devs/NotifyGate/api/pkg/log"
	"github.com/Warky-Devs/NotifyGate/api/pkg/models"
	"github.com/Warky-Devs/NotifyGate/api/pkg/providers"
	"github.com/Warky-Devs/NotifyGate/api/pkg/utils"
)

// Worker represents a queue worker
type Worker struct {
	id       int
	config   *config.Config
	db       *db.DB
	logger   *log.Logger
	provider providers.ProviderManager
	stopCh   chan struct{}
	wg       *sync.WaitGroup
}

// Manager manages multiple workers
type Manager struct {
	config    *config.Config
	db        *db.DB
	logger    *log.Logger
	providers providers.ProviderManager
	workers   []*Worker
	stopCh    chan struct{}
	wg        sync.WaitGroup
}

// NewManager creates a new queue manager
func NewManager(cfg *config.Config, database *db.DB, logger *log.Logger) (*Manager, error) {
	// Initialize provider manager
	providerManager, err := providers.NewProviderManager(cfg, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create provider manager: %w", err)
	}

	return &Manager{
		config:    cfg,
		db:        database,
		logger:    logger,
		providers: providerManager,
		stopCh:    make(chan struct{}),
	}, nil
}

// Start starts the queue manager and workers
func (m *Manager) Start(ctx context.Context) error {
	workerCount := m.config.Queue.WorkerCount
	if workerCount <= 0 {
		workerCount = 5
	}

	m.logger.WithField("worker_count", workerCount).Info("Starting queue workers")

	// Start workers
	for i := 0; i < workerCount; i++ {
		worker := &Worker{
			id:       i + 1,
			config:   m.config,
			db:       m.db,
			logger:   m.logger,
			provider: m.providers,
			stopCh:   make(chan struct{}),
			wg:       &m.wg,
		}

		m.workers = append(m.workers, worker)
		m.wg.Add(1)
		go worker.start(ctx)
	}

	// Start cleanup goroutine
	m.wg.Add(1)
	go m.cleanupWorker(ctx)

	m.logger.Info("Queue manager started successfully")
	return nil
}

// Stop stops the queue manager and all workers
func (m *Manager) Stop() {
	m.logger.Info("Stopping queue manager...")

	// Signal all workers to stop
	close(m.stopCh)
	for _, worker := range m.workers {
		close(worker.stopCh)
	}

	// Wait for all workers to finish
	m.wg.Wait()

	m.logger.Info("Queue manager stopped")
}

// start starts a single worker
func (w *Worker) start(ctx context.Context) {
	defer w.wg.Done()

	w.logger.WithField("worker_id", w.id).Info("Worker started")

	ticker := time.NewTicker(5 * time.Second) // Process every 5 seconds
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			w.logger.WithField("worker_id", w.id).Info("Worker stopped by context")
			return
		case <-w.stopCh:
			w.logger.WithField("worker_id", w.id).Info("Worker stopped")
			return
		case <-ticker.C:
			w.processQueue()
		}
	}
}

// processQueue processes pending queue items
func (w *Worker) processQueue() {
	repo := db.NewRepository(w.db)

	// Get pending queue items
	queueItems, err := repo.GetPendingQueueItems(10) // Process up to 10 items
	if err != nil {
		w.logger.WithError(err).Error("Failed to get pending queue items")
		return
	}

	if len(queueItems) == 0 {
		return
	}

	w.logger.WithFields(map[string]interface{}{
		"worker_id": w.id,
		"count":     len(queueItems),
	}).Debug("Processing queue items")

	for _, item := range queueItems {
		w.processQueueItem(&item)
	}
}

// processQueueItem processes a single queue item
func (w *Worker) processQueueItem(item *models.TravelerQueue) {
	repo := db.NewRepository(w.db)

	// Update status to processing
	if err := repo.UpdateQueueItemStatus(item.ID, models.QueueStatusProcessing); err != nil {
		w.logger.WithError(err).Error("Failed to update queue item status to processing")
		return
	}

	// Get traveler details
	traveler, err := repo.GetTravelerByID(item.TravelerID)
	if err != nil {
		w.logger.WithError(err).Error("Failed to get traveler for queue item")
		w.failQueueItem(repo, item, "Failed to get traveler")
		return
	}

	// Get endpoint details
	endpoint, err := repo.GetEndpointByID(item.EndpointID)
	if err != nil {
		w.logger.WithError(err).Error("Failed to get endpoint for queue item")
		w.failQueueItem(repo, item, "Failed to get endpoint")
		return
	}

	// Get user endpoint settings
	userSetting, err := repo.GetUserEndpointSetting(traveler.UserID, item.EndpointID)
	if err != nil {
		w.logger.WithError(err).Error("Failed to get user endpoint setting")
		w.failQueueItem(repo, item, "Failed to get user settings")
		return
	}

	if !userSetting.IsEnabled {
		w.logger.WithField("endpoint", endpoint.Name).Warn("Endpoint is disabled for user")
		w.failQueueItem(repo, item, "Endpoint is disabled")
		return
	}

	// Check rate limiting
	if w.isRateLimited(userSetting) {
		w.logger.WithField("endpoint", endpoint.Name).Debug("Rate limited, rescheduling")
		w.rescheduleQueueItem(repo, item, time.Minute)
		return
	}

	// Decrypt credentials
	credentials, err := w.decryptCredentials(userSetting.EncryptedCredentials)
	if err != nil {
		w.logger.WithError(err).Error("Failed to decrypt credentials")
		w.failQueueItem(repo, item, "Failed to decrypt credentials")
		return
	}

	// Send notification
	success, errorMsg := w.sendNotification(endpoint, userSetting, credentials, traveler)

	// Update rate limiting timestamp
	now := time.Now()
	userSetting.LastSentAt = &now
	repo.UpdateUserEndpointSetting(userSetting)

	if success {
		// Mark as sent
		repo.UpdateQueueItemStatus(item.ID, models.QueueStatusSent)

		// Update traveler delivered timestamp
		traveler.DeliveredAt = &now
		repo.UpdateTraveler(traveler)

		w.logger.LogQueue(item.ID, item.TravelerID, endpoint.Name, "sent", true, item.Attempts+1, "")
		w.logger.LogTraveler(item.TravelerID, traveler.DestinationID, "delivered", true, endpoint.Name)
	} else {
		// Handle failure
		w.handleFailure(repo, item, errorMsg)
	}
}

// sendNotification sends a notification using the appropriate provider
func (w *Worker) sendNotification(endpoint *models.Endpoint, setting *models.UserEndpointSetting, credentials map[string]interface{}, traveler *models.Traveler) (bool, string) {
	// Get provider for endpoint
	provider := w.provider.GetProvider(endpoint.Name)
	if provider == nil {
		return false, fmt.Sprintf("Provider not found for endpoint: %s", endpoint.Name)
	}

	// Prepare notification data
	notification := &providers.NotificationData{
		Title:      traveler.Title,
		Body:       traveler.Body,
		ImageURL:   traveler.ImageURL,
		Link:       traveler.Link,
		Attachment: traveler.Attachment,
		Priority:   string(traveler.Priority),
		Metadata:   traveler.RawPayload,
	}

	// Send notification
	return provider.Send(notification, credentials, setting.Settings)
}

// isRateLimited checks if the endpoint is rate limited
func (w *Worker) isRateLimited(setting *models.UserEndpointSetting) bool {
	if setting.LastSentAt == nil {
		return false
	}

	// Calculate time since last send
	timeSinceLastSend := time.Since(*setting.LastSentAt)

	// Calculate minimum interval (60 seconds / rate per minute)
	minInterval := time.Duration(60/setting.RateLimitPerMinute) * time.Second

	return timeSinceLastSend < minInterval
}

// decryptCredentials decrypts user credentials
func (w *Worker) decryptCredentials(encryptedCredentials []byte) (map[string]interface{}, error) {
	if len(encryptedCredentials) == 0 {
		return make(map[string]interface{}), nil
	}

	encryption, err := utils.NewEncryption(w.config.Security.EncryptionKey)
	if err != nil {
		return nil, err
	}

	decryptedData, err := encryption.Decrypt(string(encryptedCredentials))
	if err != nil {
		return nil, err
	}

	var credentials map[string]interface{}
	if err := json.Unmarshal([]byte(decryptedData), &credentials); err != nil {
		return nil, err
	}

	return credentials, nil
}

// handleFailure handles failed queue items
func (w *Worker) handleFailure(repo *db.Repository, item *models.TravelerQueue, errorMsg string) {
	item.Attempts++
	item.LastError = errorMsg
	item.ErrorCount++

	if item.Attempts >= item.MaxAttempts {
		// Max attempts reached, mark as failed
		repo.UpdateQueueItemStatus(item.ID, models.QueueStatusFailed)
		w.logger.LogQueue(item.ID, item.TravelerID, "", "failed_max_attempts", false, item.Attempts, "")
	} else {
		// Schedule retry with exponential backoff
		backoffSeconds := w.calculateBackoff(item.Attempts)
		nextRetry := time.Now().Add(time.Duration(backoffSeconds) * time.Second)

		item.NextRetryAt = &nextRetry
		item.Status = models.QueueStatusPending

		repo.DB().Save(item)

		w.logger.LogQueue(item.ID, item.TravelerID, "", "retry_scheduled", false, item.Attempts, nextRetry.Format(time.RFC3339))
	}
}

// failQueueItem marks a queue item as failed
func (w *Worker) failQueueItem(repo *db.Repository, item *models.TravelerQueue, errorMsg string) {
	item.LastError = errorMsg
	item.ErrorCount++
	repo.UpdateQueueItemStatus(item.ID, models.QueueStatusFailed)
	w.logger.LogQueue(item.ID, item.TravelerID, "", "failed", false, item.Attempts, "")
}

// rescheduleQueueItem reschedules a queue item
func (w *Worker) rescheduleQueueItem(repo *db.Repository, item *models.TravelerQueue, delay time.Duration) {
	nextScheduled := time.Now().Add(delay)
	item.ScheduledFor = nextScheduled
	item.Status = models.QueueStatusPending
	repo.DB().Save(item)
}

// calculateBackoff calculates exponential backoff delay
func (w *Worker) calculateBackoff(attempts int) int {
	minBackoff := w.config.Queue.RetryBackoffMin
	maxBackoff := w.config.Queue.RetryBackoffMax

	// Exponential backoff: min * 2^(attempts-1)
	backoff := minBackoff * (1 << uint(attempts-1))

	if backoff > maxBackoff {
		backoff = maxBackoff
	}

	return backoff
}

// cleanupWorker performs periodic cleanup tasks
func (m *Manager) cleanupWorker(ctx context.Context) {
	defer m.wg.Done()

	ticker := time.NewTicker(1 * time.Hour) // Cleanup every hour
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-m.stopCh:
			return
		case <-ticker.C:
			m.performCleanup()
		}
	}
}

// performCleanup performs database cleanup tasks
func (m *Manager) performCleanup() {
	m.logger.Debug("Performing queue cleanup")

	repo := db.NewRepository(m.db)

	// Clean up old completed queue items (older than 7 days)
	cutoffDate := time.Now().AddDate(0, 0, -7)

	result := repo.DB().Where("status IN ? AND updated_at < ?",
		[]models.QueueStatus{models.QueueStatusSent, models.QueueStatusFailed},
		cutoffDate).
		Delete(&models.TravelerQueue{})

	if result.Error == nil && result.RowsAffected > 0 {
		m.logger.WithField("cleaned_items", result.RowsAffected).Info("Cleaned up old queue items")
	}

	// Reset stuck processing items (older than 1 hour)
	stuckCutoff := time.Now().Add(-1 * time.Hour)
	result = repo.DB().Model(&models.TravelerQueue{}).
		Where("status = ? AND updated_at < ?", models.QueueStatusProcessing, stuckCutoff).
		Updates(map[string]interface{}{
			"status":        models.QueueStatusPending,
			"scheduled_for": time.Now(),
		})

	if result.Error == nil && result.RowsAffected > 0 {
		m.logger.WithField("reset_items", result.RowsAffected).Warn("Reset stuck processing items")
	}
}
