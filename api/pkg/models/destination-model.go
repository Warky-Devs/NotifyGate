package models

import (
	"time"

	"gorm.io/gorm"
)

// Destination represents a notification destination with unique token
type Destination struct {
	ID        uint           `gorm:"primaryKey" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"deleted_at,omitempty"`

	UserID uint `gorm:"not null;index" json:"user_id"`
	User   User `gorm:"foreignKey:UserID" json:"user,omitempty"`

	Name        string `gorm:"not null" json:"name"`
	Description string `json:"description,omitempty"`
	Token       string `gorm:"uniqueIndex;not null" json:"token"`
	IsActive    bool   `gorm:"default:true" json:"is_active"`

	// Relationships
	Travelers           []Traveler           `gorm:"foreignKey:DestinationID" json:"travelers,omitempty"`
	DeliveryPreferences []DeliveryPreference `gorm:"foreignKey:DestinationID" json:"delivery_preferences,omitempty"`
}
