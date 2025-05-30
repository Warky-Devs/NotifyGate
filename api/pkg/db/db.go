package db

import (
	"context"
	"fmt"
	"time"

	"github.com/Warky-Devs/NotifyGate/api/pkg/config"
	"github.com/Warky-Devs/NotifyGate/api/pkg/models"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// DB wraps the gorm.DB instance with additional functionality
type DB struct {
	*gorm.DB
	config *config.DatabaseConfig
}

// New creates a new database connection
func New(cfg *config.DatabaseConfig) (*DB, error) {
	var dialector gorm.Dialector

	switch cfg.Driver {
	case "postgres":
		dialector = postgres.Open(cfg.GetDSN())
	case "sqlite":
		dialector = sqlite.Open(cfg.GetDSN())
	default:
		return nil, fmt.Errorf("unsupported database driver: %s", cfg.Driver)
	}

	// Configure GORM
	gormConfig := &gorm.Config{
		Logger: logger.Default.LogMode(logger.Info),
		NowFunc: func() time.Time {
			return time.Now().UTC()
		},
	}

	// Open database connection
	db, err := gorm.Open(dialector, gormConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// Get underlying sql.DB for connection pooling
	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("failed to get underlying sql.DB: %w", err)
	}

	// Configure connection pool
	sqlDB.SetMaxOpenConns(cfg.MaxOpenConns)
	sqlDB.SetMaxIdleConns(cfg.MaxIdleConns)
	sqlDB.SetConnMaxLifetime(time.Duration(cfg.ConnMaxLifetime) * time.Second)

	// Test the connection
	if err := sqlDB.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return &DB{
		DB:     db,
		config: cfg,
	}, nil
}

// Migrate runs database migrations
func (db *DB) Migrate() error {
	if err := models.AutoMigrate(db.DB); err != nil {
		return fmt.Errorf("failed to migrate database: %w", err)
	}

	if err := models.CreateIndexes(db.DB); err != nil {
		return fmt.Errorf("failed to create indexes: %w", err)
	}

	return nil
}

// SeedInitialData seeds the database with initial data
func (db *DB) SeedInitialData() error {
	// Seed initial endpoints
	endpoints := []models.Endpoint{
		{
			Name:        "discord",
			DisplayName: "Discord",
			Description: "Send notifications to Discord channels via webhooks",
			IconURL:     "https://assets-global.website-files.com/6257adef93867e50d84d30e2/636e0a6a49cf127bf92de1e2_icon_clyde_blurple_RGB.png",
			IsActive:    true,
			ConfigSchema: models.JSON{
				"webhook_url": map[string]interface{}{
					"type":        "string",
					"required":    true,
					"description": "Discord webhook URL",
					"pattern":     "^https://discord(app)?\\.com/api/webhooks/",
				},
			},
		},
		{
			Name:        "slack",
			DisplayName: "Slack",
			Description: "Send notifications to Slack channels",
			IconURL:     "https://a.slack-edge.com/80588/marketing/img/icons/icon_slack_hash_colored.png",
			IsActive:    true,
			ConfigSchema: models.JSON{
				"webhook_url": map[string]interface{}{
					"type":        "string",
					"required":    true,
					"description": "Slack webhook URL",
					"pattern":     "^https://hooks\\.slack\\.com/",
				},
			},
		},
		{
			Name:        "telegram",
			DisplayName: "Telegram",
			Description: "Send notifications via Telegram bot",
			IconURL:     "https://telegram.org/img/t_logo.png",
			IsActive:    true,
			ConfigSchema: models.JSON{
				"bot_token": map[string]interface{}{
					"type":        "string",
					"required":    true,
					"description": "Telegram bot token",
					"sensitive":   true,
				},
				"chat_id": map[string]interface{}{
					"type":        "string",
					"required":    true,
					"description": "Telegram chat ID",
				},
			},
		},
		{
			Name:        "email",
			DisplayName: "Email",
			Description: "Send notifications via email",
			IconURL:     "https://cdn-icons-png.flaticon.com/512/732/732200.png",
			IsActive:    true,
			ConfigSchema: models.JSON{
				"smtp_host": map[string]interface{}{
					"type":        "string",
					"required":    true,
					"description": "SMTP server host",
				},
				"smtp_port": map[string]interface{}{
					"type":        "integer",
					"required":    true,
					"description": "SMTP server port",
					"default":     587,
				},
				"username": map[string]interface{}{
					"type":        "string",
					"required":    true,
					"description": "SMTP username",
					"sensitive":   true,
				},
				"password": map[string]interface{}{
					"type":        "string",
					"required":    true,
					"description": "SMTP password",
					"sensitive":   true,
				},
				"from_email": map[string]interface{}{
					"type":        "string",
					"required":    true,
					"description": "From email address",
				},
				"to_email": map[string]interface{}{
					"type":        "string",
					"required":    true,
					"description": "To email address",
				},
			},
		},
		{
			Name:        "webhook",
			DisplayName: "Generic Webhook",
			Description: "Send notifications to any HTTP endpoint",
			IconURL:     "https://cdn-icons-png.flaticon.com/512/2164/2164832.png",
			IsActive:    true,
			ConfigSchema: models.JSON{
				"url": map[string]interface{}{
					"type":        "string",
					"required":    true,
					"description": "Webhook URL",
					"pattern":     "^https?://",
				},
				"method": map[string]interface{}{
					"type":        "string",
					"required":    false,
					"description": "HTTP method",
					"default":     "POST",
					"enum":        []string{"POST", "PUT", "PATCH"},
				},
				"headers": map[string]interface{}{
					"type":        "object",
					"required":    false,
					"description": "Custom headers",
				},
			},
		},
	}

	for _, endpoint := range endpoints {
		var existing models.Endpoint
		result := db.Where("name = ?", endpoint.Name).First(&existing)
		if result.Error == gorm.ErrRecordNotFound {
			if err := db.Create(&endpoint).Error; err != nil {
				return fmt.Errorf("failed to seed endpoint %s: %w", endpoint.Name, err)
			}
		}
	}

	return nil
}

// Close closes the database connection
func (db *DB) Close() error {
	sqlDB, err := db.DB.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}

// HealthCheck performs a health check on the database
func (db *DB) HealthCheck() error {
	sqlDB, err := db.DB.DB()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	return sqlDB.PingContext(ctx)
}

// Transaction executes a function within a database transaction
func (db *DB) Transaction(fn func(*gorm.DB) error) error {
	return db.DB.Transaction(fn)
}
