package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Warky-Devs/NotifyGate/api/pkg/config"
	"github.com/Warky-Devs/NotifyGate/api/pkg/db"
	"github.com/Warky-Devs/NotifyGate/api/pkg/log"
	"github.com/Warky-Devs/NotifyGate/api/pkg/queue"
	"github.com/Warky-Devs/NotifyGate/api/pkg/webserver"
)

func main() {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		fmt.Printf("Failed to load configuration: %v\n", err)
		os.Exit(1)
	}

	// Initialize logger
	if err := log.Init(&cfg.Logging); err != nil {
		fmt.Printf("Failed to initialize logger: %v\n", err)
		os.Exit(1)
	}
	logger := log.GetLogger()

	logger.Info("Starting NotifyGate API Server")
	logger.WithField("version", "1.0.0").Info("Server initialization")

	// Initialize database
	logger.Info("Connecting to database...")
	database, err := db.New(&cfg.Database)
	if err != nil {
		logger.WithError(err).Fatal("Failed to connect to database")
	}
	defer func() {
		if err := database.Close(); err != nil {
			logger.WithError(err).Error("Failed to close database connection")
		}
	}()

	// Run database migrations
	logger.Info("Running database migrations...")
	if err := database.Migrate(); err != nil {
		logger.WithError(err).Fatal("Failed to run database migrations")
	}

	// Seed initial data
	logger.Info("Seeding initial data...")
	if err := database.SeedInitialData(); err != nil {
		logger.WithError(err).Fatal("Failed to seed initial data")
	}

	// Initialize queue manager
	logger.Info("Initializing queue manager...")
	queueManager, err := queue.NewManager(cfg, database, logger)
	if err != nil {
		logger.WithError(err).Fatal("Failed to initialize queue manager")
	}

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start queue manager
	logger.Info("Starting queue manager...")
	if err := queueManager.Start(ctx); err != nil {
		logger.WithError(err).Fatal("Failed to start queue manager")
	}

	// Initialize web server
	logger.Info("Initializing web server...")
	server, err := webserver.New(cfg, database, logger)
	if err != nil {
		logger.WithError(err).Fatal("Failed to initialize web server")
	}

	// Start server in a goroutine
	go func() {
		if err := server.Start(); err != nil {
			logger.WithError(err).Fatal("Failed to start server")
		}
	}()

	logger.WithField("address", cfg.Server.GetServerAddr()).Info("Server started successfully")

	// Wait for interrupt signal to gracefully shutdown the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("Shutting down server...")

	// Cancel context to stop queue manager
	cancel()

	// Create a context with timeout for graceful shutdown
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(),
		time.Duration(cfg.Server.GracefulStop)*time.Second)
	defer shutdownCancel()

	// Gracefully stop the web server
	if err := server.Stop(shutdownCtx); err != nil {
		logger.WithError(err).Error("Server forced to shutdown")
	} else {
		logger.Info("Web server exited gracefully")
	}

	// Stop queue manager
	queueManager.Stop()

	logger.Info("Application exited gracefully")
}
