package webserver

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// setupRoutes configures all API routes
func (s *Server) setupRoutes() {
	// Health check endpoint (no auth required)
	s.router.GET("/health", s.healthCheck)

	// API v1 routes
	v1 := s.router.Group("/api/v1")
	{
		// Public routes (no authentication required)
		public := v1.Group("")
		{
			// OAuth2 authentication routes
			auth := public.Group("/auth")
			{
				auth.GET("/login/:provider", s.handleOAuthLogin)
				auth.GET("/callback/:provider", s.handleOAuthCallback)
				auth.POST("/logout", s.handleLogout)
			}

			// Webhook routes (token-based authentication)
			webhook := public.Group("/webhook")
			{
				webhook.POST("/:token", s.handleWebhookPost)
				webhook.GET("/:token", s.handleWebhookGet)
			}
		}

		// Protected routes (JWT authentication required)
		protected := v1.Group("")
		protected.Use(s.authMiddleware())
		{
			// User management
			user := protected.Group("/user")
			{
				//user.GET("", s.getUser)
				user.PUT("", s.updateUser)
				user.DELETE("", s.deleteUser)
			}

			// Destination management
			destinations := protected.Group("/destinations")
			{
				destinations.GET("", s.getDestinations)
				destinations.POST("", s.createDestination)
				destinations.GET("/:id", s.getDestination)
				destinations.PUT("/:id", s.updateDestination)
				destinations.DELETE("/:id", s.deleteDestination)
				destinations.POST("/:id/regenerate-token", s.regenerateDestinationToken)
			}

			// Traveler (notification) management
			travelers := protected.Group("/travelers")
			{
				travelers.GET("", s.getTravelers)
				travelers.GET("/:id", s.getTraveler)
				travelers.PUT("/:id/status", s.updateTravelerStatus)
				travelers.POST("/:id/forward", s.forwardTraveler)
				travelers.DELETE("/:id", s.deleteTraveler)
			}

			// Endpoint management
			endpoints := protected.Group("/endpoints")
			{
				endpoints.GET("", s.getEndpoints)
				endpoints.GET("/:name", s.getEndpoint)
			}

			// User endpoint settings
			settings := protected.Group("/settings")
			{
				settings.GET("/endpoints", s.getUserEndpointSettings)
				settings.PUT("/endpoints/:endpoint_id", s.updateUserEndpointSetting)
				settings.POST("/endpoints/:endpoint_id/test", s.testEndpoint)
			}

			// Delivery preferences
			preferences := protected.Group("/preferences")
			{
				preferences.GET("", s.getDeliveryPreferences)
				preferences.PUT("", s.updateDeliveryPreferences)
				preferences.GET("/destinations/:destination_id", s.getDestinationPreferences)
				preferences.PUT("/destinations/:destination_id", s.updateDestinationPreferences)
			}

			// Analytics and statistics
			analytics := protected.Group("/analytics")
			{
				analytics.GET("/dashboard", s.getDashboardStats)
				analytics.GET("/travelers/stats", s.getTravelerStats)
				analytics.GET("/endpoints/stats", s.getEndpointStats)
			}
		}
	}

	// Serve static files for frontend (if needed)
	s.router.Static("/static", "./web/static")

	// Catch-all route for SPA frontend
	s.router.NoRoute(func(c *gin.Context) {
		// For API routes, return 404
		if gin.Mode() == gin.ReleaseMode && len(c.Request.URL.Path) > 3 && c.Request.URL.Path[:4] == "/api" {
			c.JSON(http.StatusNotFound, gin.H{"error": "Route not found"})
			return
		}

		// For other routes, serve the frontend app
		//c.File("./web/dist/index.html")
		c.JSON(http.StatusNotFound, gin.H{"error": "Route not found"})
	})
}
