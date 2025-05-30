package models

import (
	"time"

	"gorm.io/gorm"
)

// DeliveryPreference stores user preferences for traveler delivery
type DeliveryPreference struct {
	ID        uint           `gorm:"primaryKey" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"deleted_at,omitempty"`

	UserID        uint        `gorm:"not null;index" json:"user_id"`
	User          User        `gorm:"foreignKey:UserID" json:"user,omitempty"`
	DestinationID *uint       `gorm:"index" json:"destination_id,omitempty"` // Optional: destination-specific preferences
	Destination   Destination `gorm:"foreignKey:DestinationID" json:"destination,omitempty"`

	// Endpoint preferences
	EndpointID uint     `gorm:"not null;index" json:"endpoint_id"`
	Endpoint   Endpoint `gorm:"foreignKey:EndpointID" json:"endpoint,omitempty"`

	// Delivery settings
	IsEnabled   bool     `gorm:"default:true" json:"is_enabled"`
	MinPriority Priority `gorm:"default:'low'" json:"min_priority"`

	// Time window (24-hour format: "09:00-17:30")
	TimeWindow string `gorm:"default:'00:00-23:59'" json:"time_window"`

	// Days of week (JSON array: ["monday", "tuesday", ...])
	DaysOfWeek JSON `gorm:"type:json;default:'[\"monday\",\"tuesday\",\"wednesday\",\"thursday\",\"friday\",\"saturday\",\"sunday\"]'" json:"days_of_week"`

	// Digest settings
	EnableDigest   bool `gorm:"default:false" json:"enable_digest"`
	DigestInterval int  `gorm:"default:60" json:"digest_interval"` // minutes

	// Unique constraint per user/destination/endpoint
	_ struct{} `gorm:"uniqueIndex:idx_user_destination_endpoint,unique"`
}
