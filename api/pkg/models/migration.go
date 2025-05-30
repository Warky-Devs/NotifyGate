package models

import (
	"gorm.io/gorm"
)

// Database migration function
func AutoMigrate(db *gorm.DB) error {
	return db.AutoMigrate(
		&User{},
		&Destination{},
		&Traveler{},
		&Endpoint{},
		&UserEndpointSetting{},
		&DeliveryPreference{},
		&TravelerQueue{},
	)
}

func CreateIndexes(db *gorm.DB) error {
	// Composite indexes for common queries
	if err := db.Exec("CREATE INDEX IF NOT EXISTS idx_travelers_user_destination_status ON travelers(user_id, destination_id, status)").Error; err != nil {
		return err
	}

	if err := db.Exec("CREATE INDEX IF NOT EXISTS idx_travelers_created_at_desc ON travelers(created_at DESC)").Error; err != nil {
		return err
	}

	if err := db.Exec("CREATE INDEX IF NOT EXISTS idx_queue_status_scheduled ON traveler_queues(status, scheduled_for)").Error; err != nil {
		return err
	}

	return nil
}
