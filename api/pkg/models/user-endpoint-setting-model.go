package models

import (
	"time"

	"gorm.io/gorm"
)

// UserEndpointSetting stores user-specific endpoint configurations
type UserEndpointSetting struct {
	ID        uint           `gorm:"primaryKey" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"deleted_at,omitempty"`

	UserID     uint     `gorm:"not null;index" json:"user_id"`
	User       User     `gorm:"foreignKey:UserID" json:"user,omitempty"`
	EndpointID uint     `gorm:"not null;index" json:"endpoint_id"`
	Endpoint   Endpoint `gorm:"foreignKey:EndpointID" json:"endpoint,omitempty"`

	IsEnabled bool `gorm:"default:false" json:"is_enabled"`

	// Encrypted credentials and settings
	EncryptedCredentials []byte `json:"-"` // Encrypted JSON
	CredentialsHash      string `json:"-"` // For validation

	// Public settings (non-sensitive)
	Settings JSON `gorm:"type:json" json:"settings,omitempty"`

	// Rate limiting
	RateLimitPerMinute int        `gorm:"default:10" json:"rate_limit_per_minute"`
	LastSentAt         *time.Time `json:"last_sent_at,omitempty"`

	// Unique constraint
	_ struct{} `gorm:"uniqueIndex:idx_user_endpoint,unique"`
}
