package models

import (
	"time"

	"gorm.io/gorm"
)

// User represents a registered user with OAuth2 authentication
type User struct {
	ID        uint           `gorm:"primaryKey" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"deleted_at,omitempty"`

	// OAuth2 fields
	OAuthProvider string `gorm:"not null;index" json:"oauth_provider"` // google, github
	OAuthID       string `gorm:"not null;index" json:"oauth_id"`
	Email         string `gorm:"uniqueIndex;not null" json:"email"`
	Name          string `gorm:"not null" json:"name"`
	AvatarURL     string `json:"avatar_url,omitempty"`

	// User preferences
	Timezone          string `gorm:"default:'UTC'" json:"timezone"`
	DefaultTimeWindow string `gorm:"default:'00:00-23:59'" json:"default_time_window"`

	// Relationships
	Destinations         []Destination         `gorm:"foreignKey:UserID" json:"destinations,omitempty"`
	UserEndpointSettings []UserEndpointSetting `gorm:"foreignKey:UserID" json:"endpoint_settings,omitempty"`
	DeliveryPreferences  []DeliveryPreference  `gorm:"foreignKey:UserID" json:"delivery_preferences,omitempty"`
	Travelers            []Traveler            `gorm:"foreignKey:UserID" json:"travelers,omitempty"`
}
