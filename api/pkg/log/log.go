package log

import (
	"io"
	"os"
	"path/filepath"

	"github.com/Warky-Devs/NotifyGate/api/pkg/config"
	"github.com/sirupsen/logrus"
	"gopkg.in/natefinch/lumberjack.v2"
)

// Logger wraps logrus.Logger with additional functionality
type Logger struct {
	*logrus.Logger
	config *config.LoggingConfig
}

// Fields represents a map of fields for structured logging
type Fields map[string]interface{}

// New creates a new logger instance
func New(cfg *config.LoggingConfig) (*Logger, error) {
	logger := logrus.New()

	// Set log level
	level, err := logrus.ParseLevel(cfg.Level)
	if err != nil {
		return nil, err
	}
	logger.SetLevel(level)

	// Set format
	switch cfg.Format {
	case "json":
		logger.SetFormatter(&logrus.JSONFormatter{
			TimestampFormat: "2006-01-02T15:04:05.000Z",
		})
	case "text":
		logger.SetFormatter(&logrus.TextFormatter{
			FullTimestamp:   true,
			TimestampFormat: "2006-01-02 15:04:05",
		})
	default:
		logger.SetFormatter(&logrus.JSONFormatter{
			TimestampFormat: "2006-01-02T15:04:05.000Z",
		})
	}

	// Set output
	var output io.Writer
	switch cfg.Output {
	case "file":
		// Ensure log directory exists
		if err := os.MkdirAll(filepath.Dir(cfg.FilePath), 0755); err != nil {
			return nil, err
		}

		output = &lumberjack.Logger{
			Filename:   cfg.FilePath,
			MaxSize:    cfg.MaxSize,
			MaxBackups: cfg.MaxBackups,
			MaxAge:     cfg.MaxAge,
			Compress:   cfg.Compress,
		}
	case "stdout":
		output = os.Stdout
	default:
		output = os.Stdout
	}

	logger.SetOutput(output)

	return &Logger{
		Logger: logger,
		config: cfg,
	}, nil
}

// WithFields adds fields to log entry
func (l *Logger) WithFields(fields Fields) *logrus.Entry {
	return l.Logger.WithFields(logrus.Fields(fields))
}

// WithField adds a single field to log entry
func (l *Logger) WithField(key string, value interface{}) *logrus.Entry {
	return l.Logger.WithField(key, value)
}

// WithError adds an error field to log entry
func (l *Logger) WithError(err error) *logrus.Entry {
	return l.Logger.WithError(err)
}

// Request logging helpers
func (l *Logger) LogRequest(method, path, userAgent, clientIP string, statusCode int, duration int64) {
	l.WithFields(Fields{
		"method":      method,
		"path":        path,
		"user_agent":  userAgent,
		"client_ip":   clientIP,
		"status_code": statusCode,
		"duration_ms": duration,
		"type":        "request",
	}).Info("HTTP request")
}

func (l *Logger) LogAuth(userID uint, email, provider, action string, success bool) {
	entry := l.WithFields(Fields{
		"user_id":  userID,
		"email":    email,
		"provider": provider,
		"action":   action,
		"success":  success,
		"type":     "auth",
	})

	if success {
		entry.Info("Authentication event")
	} else {
		entry.Warn("Authentication failed")
	}
}

func (l *Logger) LogTraveler(travelerID uint, destinationID uint, action string, success bool, endpoint string) {
	entry := l.WithFields(Fields{
		"traveler_id":    travelerID,
		"destination_id": destinationID,
		"action":         action,
		"success":        success,
		"endpoint":       endpoint,
		"type":           "traveler",
	})

	if success {
		entry.Info("Traveler event")
	} else {
		entry.Error("Traveler event failed")
	}
}

func (l *Logger) LogEndpoint(endpointName string, userID uint, action string, success bool, error string) {
	entry := l.WithFields(Fields{
		"endpoint": endpointName,
		"user_id":  userID,
		"action":   action,
		"success":  success,
		"type":     "endpoint",
	})

	if error != "" {
		entry = entry.WithField("error", error)
	}

	if success {
		entry.Info("Endpoint event")
	} else {
		entry.Error("Endpoint event failed")
	}
}

func (l *Logger) LogSecurity(event string, userID uint, ip string, details map[string]interface{}) {
	fields := Fields{
		"event":   event,
		"user_id": userID,
		"ip":      ip,
		"type":    "security",
	}

	for k, v := range details {
		fields[k] = v
	}

	l.WithFields(fields).Warn("Security event")
}

func (l *Logger) LogSystem(component string, action string, success bool, details map[string]interface{}) {
	fields := Fields{
		"component": component,
		"action":    action,
		"success":   success,
		"type":      "system",
	}

	for k, v := range details {
		fields[k] = v
	}

	entry := l.WithFields(fields)
	if success {
		entry.Info("System event")
	} else {
		entry.Error("System event failed")
	}
}

// Performance logging
func (l *Logger) LogPerformance(operation string, duration int64, details map[string]interface{}) {
	fields := Fields{
		"operation":   operation,
		"duration_ms": duration,
		"type":        "performance",
	}

	for k, v := range details {
		fields[k] = v
	}

	entry := l.WithFields(fields)

	// Log different levels based on duration
	switch {
	case duration > 5000: // > 5 seconds
		entry.Error("Slow operation detected")
	case duration > 1000: // > 1 second
		entry.Warn("Operation took longer than expected")
	default:
		entry.Debug("Operation completed")
	}
}

// Database logging
func (l *Logger) LogDatabase(operation string, table string, duration int64, rowsAffected int64) {
	l.WithFields(Fields{
		"operation":     operation,
		"table":         table,
		"duration_ms":   duration,
		"rows_affected": rowsAffected,
		"type":          "database",
	}).Debug("Database operation")
}

// Queue logging
func (l *Logger) LogQueue(queueID uint, travelerID uint, endpointName string, action string, success bool, attempts int, nextRetry string) {
	entry := l.WithFields(Fields{
		"queue_id":    queueID,
		"traveler_id": travelerID,
		"endpoint":    endpointName,
		"action":      action,
		"success":     success,
		"attempts":    attempts,
		"next_retry":  nextRetry,
		"type":        "queue",
	})

	if success {
		entry.Info("Queue event")
	} else {
		entry.Error("Queue event failed")
	}
}

// Webhook logging
func (l *Logger) LogWebhook(token string, sourceIP string, userAgent string, success bool, error string, payload interface{}) {
	entry := l.WithFields(Fields{
		"token":      token,
		"source_ip":  sourceIP,
		"user_agent": userAgent,
		"success":    success,
		"type":       "webhook",
	})

	if error != "" {
		entry = entry.WithField("error", error)
	}

	if payload != nil {
		entry = entry.WithField("payload_size", len(payload.(string)))
	}

	if success {
		entry.Info("Webhook received")
	} else {
		entry.Error("Webhook processing failed")
	}
}

// Global logger instance
var defaultLogger *Logger

// Init initializes the default logger
func Init(cfg *config.LoggingConfig) error {
	logger, err := New(cfg)
	if err != nil {
		return err
	}
	defaultLogger = logger
	return nil
}

// GetLogger returns the default logger instance
func GetLogger() *Logger {
	return defaultLogger
}

// Convenience functions for global logger
func Debug(args ...interface{}) {
	if defaultLogger != nil {
		defaultLogger.Debug(args...)
	}
}

func Info(args ...interface{}) {
	if defaultLogger != nil {
		defaultLogger.Info(args...)
	}
}

func Warn(args ...interface{}) {
	if defaultLogger != nil {
		defaultLogger.Warn(args...)
	}
}

func Error(args ...interface{}) {
	if defaultLogger != nil {
		defaultLogger.Error(args...)
	}
}

func Fatal(args ...interface{}) {
	if defaultLogger != nil {
		defaultLogger.Fatal(args...)
	}
}

func WithFields(fields Fields) *logrus.Entry {
	if defaultLogger != nil {
		return defaultLogger.WithFields(fields)
	}
	return logrus.NewEntry(logrus.StandardLogger())
}

func WithError(err error) *logrus.Entry {
	if defaultLogger != nil {
		return defaultLogger.WithError(err)
	}
	return logrus.NewEntry(logrus.StandardLogger())
}
