package config

type Config struct {
	// Server settings
	Server ServerConfig `json:"server"`

	// Database settings
	Database DatabaseConfig `json:"database"`

	// OAuth2 settings
	OAuth OAuth2Config `json:"oauth"`

	// Security settings
	Security SecurityConfig `json:"security"`

	// Logging settings
	Logging LoggingConfig `json:"logging"`

	// Queue settings
	Queue QueueConfig `json:"queue"`
}

type ServerConfig struct {
	Host         string `json:"host" default:"localhost"`
	Port         int    `json:"port" default:"8080"`
	ReadTimeout  int    `json:"read_timeout" default:"30"`  // seconds
	WriteTimeout int    `json:"write_timeout" default:"30"` // seconds
	IdleTimeout  int    `json:"idle_timeout" default:"120"` // seconds
	GracefulStop int    `json:"graceful_stop" default:"30"` // seconds
}

type DatabaseConfig struct {
	Driver   string `json:"driver" default:"sqlite"` // sqlite, postgres
	Host     string `json:"host" default:"localhost"`
	Port     int    `json:"port" default:"5432"`
	Database string `json:"database" default:"notifygate.db"`
	Username string `json:"username"`
	Password string `json:"password"`
	SSLMode  string `json:"ssl_mode" default:"disable"`

	// Connection pool settings
	MaxOpenConns    int `json:"max_open_conns" default:"25"`
	MaxIdleConns    int `json:"max_idle_conns" default:"5"`
	ConnMaxLifetime int `json:"conn_max_lifetime" default:"300"` // seconds
}

type OAuth2Config struct {
	Google GoogleOAuthConfig `json:"google"`
	GitHub GitHubOAuthConfig `json:"github"`
}

type GoogleOAuthConfig struct {
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	RedirectURL  string   `json:"redirect_url"`
	Scopes       []string `json:"scopes" default:"[\"email\",\"profile\"]"`
}

type GitHubOAuthConfig struct {
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	RedirectURL  string   `json:"redirect_url"`
	Scopes       []string `json:"scopes" default:"[\"user:email\"]"`
}

type SecurityConfig struct {
	JWTSecret           string `json:"jwt_secret"`
	JWTExpirationHours  int    `json:"jwt_expiration_hours" default:"24"`
	EncryptionKey       string `json:"encryption_key"` // 32 bytes for AES-256
	SessionCookieName   string `json:"session_cookie_name" default:"notifygate_session"`
	SessionCookieSecure bool   `json:"session_cookie_secure" default:"true"`
	CSRFProtection      bool   `json:"csrf_protection" default:"true"`

	// Rate limiting
	RateLimitEnabled   bool `json:"rate_limit_enabled" default:"true"`
	RateLimitPerMinute int  `json:"rate_limit_per_minute" default:"60"`
	RateLimitBurstSize int  `json:"rate_limit_burst_size" default:"10"`
}

type LoggingConfig struct {
	Level      string `json:"level" default:"info"`    // debug, info, warn, error
	Format     string `json:"format" default:"json"`   // json, text
	Output     string `json:"output" default:"stdout"` // stdout, file
	FilePath   string `json:"file_path" default:"logs/notifygate.log"`
	MaxSize    int    `json:"max_size" default:"100"` // MB
	MaxBackups int    `json:"max_backups" default:"3"`
	MaxAge     int    `json:"max_age" default:"28"` // days
	Compress   bool   `json:"compress" default:"true"`
}

type QueueConfig struct {
	Driver          string `json:"driver" default:"memory"` // memory, redis
	RedisURL        string `json:"redis_url"`
	WorkerCount     int    `json:"worker_count" default:"5"`
	RetryAttempts   int    `json:"retry_attempts" default:"3"`
	RetryBackoffMin int    `json:"retry_backoff_min" default:"1"`   // seconds
	RetryBackoffMax int    `json:"retry_backoff_max" default:"300"` // seconds
}
