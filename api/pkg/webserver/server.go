package webserver

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"

	"github.com/Warky-Devs/NotifyGate/api/pkg/config"
	"github.com/Warky-Devs/NotifyGate/api/pkg/db"
	"github.com/Warky-Devs/NotifyGate/api/pkg/log"
	"github.com/Warky-Devs/NotifyGate/api/pkg/models"
	"github.com/Warky-Devs/NotifyGate/api/pkg/utils"
)

// Server represents the HTTP server
type Server struct {
	config     *config.Config
	db         *db.DB
	logger     *log.Logger
	router     *gin.Engine
	httpServer *http.Server
	jwtManager *utils.JWTManager
	encryption *utils.Encryption
	validator  *utils.Validator
	timeUtils  *utils.TimeUtils
}

// New creates a new HTTP server instance
func New(cfg *config.Config, database *db.DB, logger *log.Logger) (*Server, error) {
	// Initialize utilities
	jwtManager := utils.NewJWTManager(cfg.Security.JWTSecret, cfg.Security.JWTExpirationHours)
	encryption, err := utils.NewEncryption(cfg.Security.EncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize encryption: %w", err)
	}
	validator := utils.NewValidator()
	timeUtils := utils.NewTimeUtils()

	// Set Gin mode
	if cfg.Logging.Level == "debug" {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}

	// Create router
	router := gin.New()

	// Create server
	server := &Server{
		config:     cfg,
		db:         database,
		logger:     logger,
		router:     router,
		jwtManager: jwtManager,
		encryption: encryption,
		validator:  validator,
		timeUtils:  timeUtils,
	}

	// Setup middleware
	server.setupMiddleware()

	// Setup routes
	server.setupRoutes()

	// Create HTTP server
	server.httpServer = &http.Server{
		Addr:         cfg.Server.GetServerAddr(),
		Handler:      router,
		ReadTimeout:  time.Duration(cfg.Server.ReadTimeout) * time.Second,
		WriteTimeout: time.Duration(cfg.Server.WriteTimeout) * time.Second,
		IdleTimeout:  time.Duration(cfg.Server.IdleTimeout) * time.Second,
	}

	return server, nil
}

// setupMiddleware configures middleware
func (s *Server) setupMiddleware() {
	// Recovery middleware
	s.router.Use(gin.CustomRecovery(func(c *gin.Context, recovered interface{}) {
		s.logger.WithField("panic", recovered).Error("Panic recovered")
		c.JSON(http.StatusInternalServerError, utils.NewErrorResponse("Internal server error"))
		c.Abort()
	}))

	// Logging middleware
	s.router.Use(s.loggingMiddleware())

	// CORS middleware
	s.router.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://localhost:3000", "http://localhost:5173"}, // Add your frontend URLs
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization", "X-Requested-With"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	// Session middleware
	store := cookie.NewStore([]byte(s.config.Security.JWTSecret))
	store.Options(sessions.Options{
		MaxAge:   86400 * 7, // 7 days
		HttpOnly: true,
		Secure:   s.config.Security.SessionCookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
	s.router.Use(sessions.Sessions(s.config.Security.SessionCookieName, store))

	// Rate limiting middleware
	if s.config.Security.RateLimitEnabled {
		s.router.Use(s.rateLimitMiddleware())
	}

	// Security headers middleware
	s.router.Use(s.securityHeadersMiddleware())
}

// loggingMiddleware logs HTTP requests
func (s *Server) loggingMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		raw := c.Request.URL.RawQuery

		// Process request
		c.Next()

		// Calculate latency
		latency := time.Since(start)

		// Get client IP
		clientIP := c.ClientIP()

		// Log request
		s.logger.LogRequest(
			c.Request.Method,
			path,
			c.Request.UserAgent(),
			clientIP,
			c.Writer.Status(),
			latency.Milliseconds(),
		)

		// Log slow requests
		if latency > 1*time.Second {
			s.logger.LogPerformance("http_request", latency.Milliseconds(), map[string]interface{}{
				"method": c.Request.Method,
				"path":   path,
				"query":  raw,
				"status": c.Writer.Status(),
			})
		}
	}
}

// rateLimitMiddleware implements rate limiting
func (s *Server) rateLimitMiddleware() gin.HandlerFunc {
	// Create a rate limiter
	limiter := rate.NewLimiter(
		rate.Limit(s.config.Security.RateLimitPerMinute)/60, // per second
		s.config.Security.RateLimitBurstSize,
	)

	return func(c *gin.Context) {
		if !limiter.Allow() {
			s.logger.LogSecurity("rate_limit_exceeded", 0, c.ClientIP(), map[string]interface{}{
				"path":   c.Request.URL.Path,
				"method": c.Request.Method,
			})
			c.JSON(http.StatusTooManyRequests, utils.NewErrorResponse("Rate limit exceeded"))
			c.Abort()
			return
		}
		c.Next()
	}
}

// securityHeadersMiddleware adds security headers
func (s *Server) securityHeadersMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-XSS-Protection", "1; mode=block")
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		c.Header("Content-Security-Policy", "default-src 'self'")
		c.Next()
	}
}

// authMiddleware validates JWT tokens
func (s *Server) authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get token from Authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, utils.NewErrorResponse("Authorization header required"))
			c.Abort()
			return
		}

		// Extract token from "Bearer <token>" format
		tokenString := ""
		if len(authHeader) > 7 && authHeader[:7] == "Bearer " {
			tokenString = authHeader[7:]
		} else {
			c.JSON(http.StatusUnauthorized, utils.NewErrorResponse("Invalid authorization header format"))
			c.Abort()
			return
		}

		// Validate token
		claims, err := s.jwtManager.ValidateToken(tokenString)
		if err != nil {
			s.logger.LogSecurity("invalid_token", 0, c.ClientIP(), map[string]interface{}{
				"error": err.Error(),
			})
			c.JSON(http.StatusUnauthorized, utils.NewErrorResponse("Invalid token"))
			c.Abort()
			return
		}

		// Get user from database
		repo := db.NewRepository(s.db)
		user, err := repo.GetUserByID(claims.UserID)
		if err != nil {
			s.logger.LogSecurity("user_not_found", claims.UserID, c.ClientIP(), map[string]interface{}{
				"error": err.Error(),
			})
			c.JSON(http.StatusUnauthorized, utils.NewErrorResponse("User not found"))
			c.Abort()
			return
		}

		// Set user in context
		c.Set("user", user)
		c.Set("user_id", user.ID)
		c.Next()
	}
}

// getCurrentUser gets the current user from context
func (s *Server) getCurrentUser(c *gin.Context) (*models.User, error) {
	user, exists := c.Get("user")
	if !exists {
		return nil, fmt.Errorf("user not found in context")
	}

	userModel, ok := user.(*models.User)
	if !ok {
		return nil, fmt.Errorf("invalid user type in context")
	}

	return userModel, nil
}

// Start starts the HTTP server
func (s *Server) Start() error {
	s.logger.Info(fmt.Sprintf("Starting server on %s", s.config.Server.GetServerAddr()))

	if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("failed to start server: %w", err)
	}

	return nil
}

// Stop gracefully stops the HTTP server
func (s *Server) Stop(ctx context.Context) error {
	s.logger.Info("Stopping server...")

	if err := s.httpServer.Shutdown(ctx); err != nil {
		return fmt.Errorf("failed to stop server: %w", err)
	}

	s.logger.Info("Server stopped")
	return nil
}

// Health check endpoint
func (s *Server) healthCheck(c *gin.Context) {
	// Check database connection
	if err := s.db.HealthCheck(); err != nil {
		c.JSON(http.StatusServiceUnavailable, utils.NewErrorResponse("Database unavailable"))
		return
	}

	c.JSON(http.StatusOK, utils.NewSuccessResponse(map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().UTC(),
		"version":   "1.0.0",
	}, "Service is healthy"))
}
