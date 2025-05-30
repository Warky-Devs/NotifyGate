package models

import (
	"time"

	"gorm.io/gorm"
)

// TravelerStatus enum
type TravelerStatus string

const (
	StatusReceived  TravelerStatus = "received"
	StatusRead      TravelerStatus = "read"
	StatusUnread    TravelerStatus = "unread"
	StatusDeleted   TravelerStatus = "deleted"
	StatusForwarded TravelerStatus = "forwarded"
)

// Priority enum
type Priority string

const (
	PriorityLow      Priority = "low"
	PriorityNormal   Priority = "normal"
	PriorityHigh     Priority = "high"
	PriorityCritical Priority = "critical"
)

// Traveler represents an incoming notification message
type Traveler struct {
	ID        uint           `gorm:"primaryKey" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"deleted_at,omitempty"`

	UserID        uint        `gorm:"not null;index" json:"user_id"`
	User          User        `gorm:"foreignKey:UserID" json:"user,omitempty"`
	DestinationID uint        `gorm:"not null;index" json:"destination_id"`
	Destination   Destination `gorm:"foreignKey:DestinationID" json:"destination,omitempty"`

	// Traveler content
	Title      string   `gorm:"not null" json:"title"`
	Body       string   `gorm:"type:text" json:"body"`
	ImageURL   string   `json:"image_url,omitempty"`
	Link       string   `json:"link,omitempty"`
	Attachment string   `json:"attachment,omitempty"`
	Priority   Priority `gorm:"default:'normal'" json:"priority"`

	// Status and metadata
	Status      TravelerStatus `gorm:"default:'received';index" json:"status"`
	SourceIP    string         `json:"source_ip,omitempty"`
	UserAgent   string         `json:"user_agent,omitempty"`
	RawPayload  JSON           `gorm:"type:json" json:"raw_payload,omitempty"`
	DeliveredAt *time.Time     `json:"delivered_at,omitempty"`
	ReadAt      *time.Time     `json:"read_at,omitempty"`
	ForwardedAt *time.Time     `json:"forwarded_at,omitempty"`

	// Relationships
	QueueItems []TravelerQueue `gorm:"foreignKey:TravelerID" json:"queue_items,omitempty"`
}
