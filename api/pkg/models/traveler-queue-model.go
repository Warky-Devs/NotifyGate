package models

import (
	"time"

	"gorm.io/gorm"
)

// QueueStatus enum
type QueueStatus string

const (
	QueueStatusPending    QueueStatus = "pending"
	QueueStatusProcessing QueueStatus = "processing"
	QueueStatusSent       QueueStatus = "sent"
	QueueStatusFailed     QueueStatus = "failed"
	QueueStatusCancelled  QueueStatus = "cancelled"
)

// TravelerQueue handles delayed and scheduled travelers
type TravelerQueue struct {
	ID        uint           `gorm:"primaryKey" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"deleted_at,omitempty"`

	TravelerID uint     `gorm:"not null;index" json:"traveler_id"`
	Traveler   Traveler `gorm:"foreignKey:TravelerID" json:"traveler,omitempty"`
	EndpointID uint     `gorm:"not null;index" json:"endpoint_id"`
	Endpoint   Endpoint `gorm:"foreignKey:EndpointID" json:"endpoint,omitempty"`

	// Queue metadata
	Status       QueueStatus `gorm:"default:'pending';index" json:"status"`
	ScheduledFor time.Time   `gorm:"index" json:"scheduled_for"`
	ProcessedAt  *time.Time  `json:"processed_at,omitempty"`

	// Retry logic
	Attempts    int        `gorm:"default:0" json:"attempts"`
	MaxAttempts int        `gorm:"default:3" json:"max_attempts"`
	NextRetryAt *time.Time `gorm:"index" json:"next_retry_at,omitempty"`

	// Error tracking
	LastError  string `json:"last_error,omitempty"`
	ErrorCount int    `gorm:"default:0" json:"error_count"`
}
