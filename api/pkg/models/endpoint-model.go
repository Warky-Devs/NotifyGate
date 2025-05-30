package models

import (
	"time"

	"gorm.io/gorm"
)

// Endpoint represents available notification endpoints
type Endpoint struct {
	ID        uint           `gorm:"primaryKey" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"deleted_at,omitempty"`

	Name        string `gorm:"uniqueIndex;not null" json:"name"` // discord, slack, telegram, etc.
	DisplayName string `gorm:"not null" json:"display_name"`     // Discord, Slack, Telegram, etc.
	Description string `json:"description,omitempty"`
	IconURL     string `json:"icon_url,omitempty"`
	IsActive    bool   `gorm:"default:true" json:"is_active"`

	// Configuration schema (JSON defining required fields)
	ConfigSchema JSON `gorm:"type:json" json:"config_schema"`

	// Relationships
	UserEndpointSettings []UserEndpointSetting `gorm:"foreignKey:EndpointID" json:"user_settings,omitempty"`
}
