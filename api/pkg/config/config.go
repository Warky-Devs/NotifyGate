package config

import (
	"fmt"

	"os"
	"strconv"
	"strings"

	"github.com/joho/godotenv"
)

// Load loads configuration from environment variables with fallback to defaults
func Load() (*Config, error) {
	err := godotenv.Load()
	if err != nil {
		fmt.Printf("Warning: Error loading .env file: %v", err)
		fmt.Println("Continuing with environment variables...")
	}

	config := &Config{
		Server: ServerConfig{
			Host:         getEnv("SERVER_HOST", "localhost"),
			Port:         getEnvInt("SERVER_PORT", 8080),
			ReadTimeout:  getEnvInt("SERVER_READ_TIMEOUT", 30),
			WriteTimeout: getEnvInt("SERVER_WRITE_TIMEOUT", 30),
			IdleTimeout:  getEnvInt("SERVER_IDLE_TIMEOUT", 120),
			GracefulStop: getEnvInt("SERVER_GRACEFUL_STOP", 30),
		},
		Database: DatabaseConfig{
			Driver:          getEnv("DB_DRIVER", "sqlite"),
			Host:            getEnv("DB_HOST", "localhost"),
			Port:            getEnvInt("DB_PORT", 5432),
			Database:        getEnv("DB_NAME", "notifygate.db"),
			Username:        getEnv("DB_USERNAME", ""),
			Password:        getEnv("DB_PASSWORD", ""),
			SSLMode:         getEnv("DB_SSL_MODE", "disable"),
			MaxOpenConns:    getEnvInt("DB_MAX_OPEN_CONNS", 25),
			MaxIdleConns:    getEnvInt("DB_MAX_IDLE_CONNS", 5),
			ConnMaxLifetime: getEnvInt("DB_CONN_MAX_LIFETIME", 300),
		},
		OAuth: OAuth2Config{
			Google: GoogleOAuthConfig{
				ClientID:     getEnv("GOOGLE_CLIENT_ID", ""),
				ClientSecret: getEnv("GOOGLE_CLIENT_SECRET", ""),
				RedirectURL:  getEnv("GOOGLE_REDIRECT_URL", ""),
				Scopes:       getEnvSlice("GOOGLE_SCOPES", []string{"email", "profile"}),
			},
			GitHub: GitHubOAuthConfig{
				ClientID:     getEnv("GITHUB_CLIENT_ID", ""),
				ClientSecret: getEnv("GITHUB_CLIENT_SECRET", ""),
				RedirectURL:  getEnv("GITHUB_REDIRECT_URL", ""),
				Scopes:       getEnvSlice("GITHUB_SCOPES", []string{"user:email"}),
			},
		},
		Security: SecurityConfig{
			JWTSecret:           getEnv("JWT_SECRET", ""),
			JWTExpirationHours:  getEnvInt("JWT_EXPIRATION_HOURS", 24),
			EncryptionKey:       getEnv("ENCRYPTION_KEY", ""),
			SessionCookieName:   getEnv("SESSION_COOKIE_NAME", "notifygate_session"),
			SessionCookieSecure: getEnvBool("SESSION_COOKIE_SECURE", true),
			CSRFProtection:      getEnvBool("CSRF_PROTECTION", true),
			RateLimitEnabled:    getEnvBool("RATE_LIMIT_ENABLED", true),
			RateLimitPerMinute:  getEnvInt("RATE_LIMIT_PER_MINUTE", 60),
			RateLimitBurstSize:  getEnvInt("RATE_LIMIT_BURST_SIZE", 10),
		},
		Logging: LoggingConfig{
			Level:      getEnv("LOG_LEVEL", "info"),
			Format:     getEnv("LOG_FORMAT", "json"),
			Output:     getEnv("LOG_OUTPUT", "stdout"),
			FilePath:   getEnv("LOG_FILE_PATH", "logs/notifygate.log"),
			MaxSize:    getEnvInt("LOG_MAX_SIZE", 100),
			MaxBackups: getEnvInt("LOG_MAX_BACKUPS", 3),
			MaxAge:     getEnvInt("LOG_MAX_AGE", 28),
			Compress:   getEnvBool("LOG_COMPRESS", true),
		},
		Queue: QueueConfig{
			Driver:          getEnv("QUEUE_DRIVER", "memory"),
			RedisURL:        getEnv("REDIS_URL", ""),
			WorkerCount:     getEnvInt("QUEUE_WORKER_COUNT", 5),
			RetryAttempts:   getEnvInt("QUEUE_RETRY_ATTEMPTS", 3),
			RetryBackoffMin: getEnvInt("QUEUE_RETRY_BACKOFF_MIN", 1),
			RetryBackoffMax: getEnvInt("QUEUE_RETRY_BACKOFF_MAX", 300),
		},
	}

	// Validate required fields
	if err := validateConfig(config); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	return config, nil
}

// validateConfig validates required configuration fields
func validateConfig(config *Config) error {
	if config.Security.JWTSecret == "" {
		return fmt.Errorf("JWT_SECRET is required")
	}

	if config.Security.EncryptionKey == "" {
		return fmt.Errorf("ENCRYPTION_KEY is required")
	}

	if len(config.Security.EncryptionKey) != 32 {
		return fmt.Errorf("ENCRYPTION_KEY must be exactly 32 bytes for AES-256: Given Length: %v", len(config.Security.EncryptionKey))
	}

	// Validate OAuth2 configuration (at least one provider must be configured)
	if config.OAuth.Google.ClientID == "" && config.OAuth.GitHub.ClientID == "" {
		return fmt.Errorf("at least one OAuth2 provider must be configured")
	}

	return nil
}

// GetDSN returns the database connection string
func (c *DatabaseConfig) GetDSN() string {
	switch c.Driver {
	case "postgres":
		return fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
			c.Host, c.Port, c.Username, c.Password, c.Database, c.SSLMode)
	case "sqlite":
		return c.Database
	default:
		return ""
	}
}

// GetServerAddr returns the server address string
func (c *ServerConfig) GetServerAddr() string {
	return fmt.Sprintf("%s:%d", c.Host, c.Port)
}

// Helper functions for environment variable parsing
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if parsed, err := strconv.Atoi(value); err == nil {
			return parsed
		}
	}
	return defaultValue
}

func getEnvBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if parsed, err := strconv.ParseBool(value); err == nil {
			return parsed
		}
	}
	return defaultValue
}

func getEnvSlice(key string, defaultValue []string) []string {
	if value := os.Getenv(key); value != "" {
		return strings.Split(value, ",")
	}
	return defaultValue
}
