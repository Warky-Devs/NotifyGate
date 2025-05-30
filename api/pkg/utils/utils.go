package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// TokenGenerator generates secure tokens for destinations
type TokenGenerator struct{}

// NewTokenGenerator creates a new token generator
func NewTokenGenerator() *TokenGenerator {
	return &TokenGenerator{}
}

// GenerateDestinationToken generates a unique token for a destination
func (tg *TokenGenerator) GenerateDestinationToken() string {
	// Generate UUID v4 and remove hyphens for cleaner URLs
	return strings.ReplaceAll(uuid.New().String(), "-", "")
}

// GenerateSecureToken generates a cryptographically secure random token
func (tg *TokenGenerator) GenerateSecureToken(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// Encryption provides AES-256 encryption/decryption
type Encryption struct {
	key []byte
}

// NewEncryption creates a new encryption instance
func NewEncryption(key string) (*Encryption, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("encryption key must be exactly 32 bytes")
	}
	return &Encryption{key: []byte(key)}, nil
}

// Encrypt encrypts plaintext using AES-256-GCM
func (e *Encryption) Encrypt(plaintext string) (string, error) {
	block, err := aes.NewCipher(e.key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts ciphertext using AES-256-GCM
func (e *Encryption) Decrypt(ciphertext string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(e.key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext_bytes := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext_bytes, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// Hash generates SHA-256 hash
func (e *Encryption) Hash(input string) string {
	hash := sha256.Sum256([]byte(input))
	return hex.EncodeToString(hash[:])
}

// JWTManager handles JWT token operations
type JWTManager struct {
	secret     []byte
	expiration time.Duration
}

// NewJWTManager creates a new JWT manager
func NewJWTManager(secret string, expirationHours int) *JWTManager {
	return &JWTManager{
		secret:     []byte(secret),
		expiration: time.Duration(expirationHours) * time.Hour,
	}
}

// UserClaims represents JWT claims for users
type UserClaims struct {
	UserID uint   `json:"user_id"`
	Email  string `json:"email"`
	Name   string `json:"name"`
	jwt.RegisteredClaims
}

// GenerateToken generates a JWT token for a user
func (jm *JWTManager) GenerateToken(userID uint, email, name string) (string, error) {
	claims := UserClaims{
		UserID: userID,
		Email:  email,
		Name:   name,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(jm.expiration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "notifygate",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jm.secret)
}

// ValidateToken validates and parses a JWT token
func (jm *JWTManager) ValidateToken(tokenString string) (*UserClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &UserClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return jm.secret, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*UserClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token")
}

// Validator provides input validation functions
type Validator struct{}

// NewValidator creates a new validator
func NewValidator() *Validator {
	return &Validator{}
}

// ValidateEmail validates email format
func (v *Validator) ValidateEmail(email string) bool {
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	return emailRegex.MatchString(email)
}

// ValidateURL validates URL format
func (v *Validator) ValidateURL(url string) bool {
	urlRegex := regexp.MustCompile(`^https?://[^\s/$.?#].[^\s]*$`)
	return urlRegex.MatchString(url)
}

// ValidateTimeWindow validates time window format (HH:MM-HH:MM)
func (v *Validator) ValidateTimeWindow(timeWindow string) bool {
	timeWindowRegex := regexp.MustCompile(`^([01]?[0-9]|2[0-3]):[0-5][0-9]-([01]?[0-9]|2[0-3]):[0-5][0-9]$`)
	return timeWindowRegex.MatchString(timeWindow)
}

// ValidateToken validates destination token format
func (v *Validator) ValidateToken(token string) bool {
	// UUID without hyphens (32 hex characters)
	tokenRegex := regexp.MustCompile(`^[a-f0-9]{32}$`)
	return tokenRegex.MatchString(token)
}

// SanitizeInput sanitizes user input
func (v *Validator) SanitizeInput(input string) string {
	// Remove null bytes and control characters
	input = strings.ReplaceAll(input, "\x00", "")
	input = regexp.MustCompile(`[\x00-\x1f\x7f-\x9f]`).ReplaceAllString(input, "")

	// Trim whitespace
	return strings.TrimSpace(input)
}

// TimeUtils provides time-related utility functions
type TimeUtils struct{}

// NewTimeUtils creates a new time utils instance
func NewTimeUtils() *TimeUtils {
	return &TimeUtils{}
}

// IsWithinTimeWindow checks if current time is within the specified window
func (tu *TimeUtils) IsWithinTimeWindow(timeWindow string, timezone string) (bool, error) {
	if timeWindow == "" || timeWindow == "00:00-23:59" {
		return true, nil // Always allow if no restriction
	}

	// Parse timezone
	loc, err := time.LoadLocation(timezone)
	if err != nil {
		loc = time.UTC
	}

	now := time.Now().In(loc)

	// Parse time window
	parts := strings.Split(timeWindow, "-")
	if len(parts) != 2 {
		return false, fmt.Errorf("invalid time window format")
	}

	startTime, err := time.Parse("15:04", parts[0])
	if err != nil {
		return false, fmt.Errorf("invalid start time: %w", err)
	}

	endTime, err := time.Parse("15:04", parts[1])
	if err != nil {
		return false, fmt.Errorf("invalid end time: %w", err)
	}

	// Create today's start and end times
	startToday := time.Date(now.Year(), now.Month(), now.Day(),
		startTime.Hour(), startTime.Minute(), 0, 0, loc)
	endToday := time.Date(now.Year(), now.Month(), now.Day(),
		endTime.Hour(), endTime.Minute(), 59, 999999999, loc)

	// Handle overnight windows (e.g., 22:00-06:00)
	if endToday.Before(startToday) {
		endToday = endToday.AddDate(0, 0, 1)
		return now.After(startToday) || now.Before(endToday), nil
	}

	return now.After(startToday) && now.Before(endToday), nil
}

// IsWithinDaysOfWeek checks if current day is in the allowed days
func (tu *TimeUtils) IsWithinDaysOfWeek(daysOfWeek []string, timezone string) bool {
	if len(daysOfWeek) == 0 || len(daysOfWeek) == 7 {
		return true // Allow all days if not specified or all days selected
	}

	// Parse timezone
	loc, err := time.LoadLocation(timezone)
	if err != nil {
		loc = time.UTC
	}

	now := time.Now().In(loc)
	currentDay := strings.ToLower(now.Weekday().String())

	for _, day := range daysOfWeek {
		if strings.ToLower(day) == currentDay {
			return true
		}
	}

	return false
}

// CalculateNextAllowedTime calculates the next time a notification can be sent
func (tu *TimeUtils) CalculateNextAllowedTime(timeWindow string, daysOfWeek []string, timezone string) time.Time {
	loc, err := time.LoadLocation(timezone)
	if err != nil {
		loc = time.UTC
	}

	now := time.Now().In(loc)

	// If no restrictions, return now
	if (timeWindow == "" || timeWindow == "00:00-23:59") && len(daysOfWeek) == 7 {
		return now
	}

	// Start checking from tomorrow if current time is not allowed
	checkTime := now
	if !tu.IsWithinDaysOfWeek(daysOfWeek, timezone) {
		checkTime = checkTime.AddDate(0, 0, 1)
	}

	// Check up to 7 days in the future
	for i := 0; i < 7; i++ {
		if tu.IsWithinDaysOfWeek(daysOfWeek, timezone) {
			// Parse time window start
			if timeWindow != "" && timeWindow != "00:00-23:59" {
				parts := strings.Split(timeWindow, "-")
				if len(parts) == 2 {
					startTime, err := time.Parse("15:04", parts[0])
					if err == nil {
						nextTime := time.Date(checkTime.Year(), checkTime.Month(), checkTime.Day(),
							startTime.Hour(), startTime.Minute(), 0, 0, loc)

						if nextTime.After(now) {
							return nextTime
						}
					}
				}
			}

			// If we're already in the right day and time window, return now
			if i == 0 {
				return now
			}
		}

		checkTime = checkTime.AddDate(0, 0, 1)
	}

	// Fallback: return 24 hours from now
	return now.Add(24 * time.Hour)
}

// FormatDuration formats duration in human-readable format
func (tu *TimeUtils) FormatDuration(duration time.Duration) string {
	if duration < time.Minute {
		return fmt.Sprintf("%.0fs", duration.Seconds())
	} else if duration < time.Hour {
		return fmt.Sprintf("%.1fm", duration.Minutes())
	} else if duration < 24*time.Hour {
		return fmt.Sprintf("%.1fh", duration.Hours())
	} else {
		return fmt.Sprintf("%.1fd", duration.Hours()/24)
	}
}

// Pagination helps with paginating results
type Pagination struct {
	Page       int `json:"page"`
	Limit      int `json:"limit"`
	TotalCount int `json:"total_count"`
	TotalPages int `json:"total_pages"`
}

// NewPagination creates a new pagination instance
func NewPagination(page, limit, totalCount int) *Pagination {
	if page < 1 {
		page = 1
	}
	if limit < 1 {
		limit = 10
	}
	if limit > 100 {
		limit = 100
	}

	totalPages := (totalCount + limit - 1) / limit
	if totalPages < 1 {
		totalPages = 1
	}

	return &Pagination{
		Page:       page,
		Limit:      limit,
		TotalCount: totalCount,
		TotalPages: totalPages,
	}
}

// GetOffset returns the offset for database queries
func (p *Pagination) GetOffset() int {
	return (p.Page - 1) * p.Limit
}

// HasNextPage returns true if there's a next page
func (p *Pagination) HasNextPage() bool {
	return p.Page < p.TotalPages
}

// HasPrevPage returns true if there's a previous page
func (p *Pagination) HasPrevPage() bool {
	return p.Page > 1
}

// Response helpers
type APIResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
	Meta    interface{} `json:"meta,omitempty"`
}

// NewSuccessResponse creates a success API response
func NewSuccessResponse(data interface{}, message string) *APIResponse {
	return &APIResponse{
		Success: true,
		Message: message,
		Data:    data,
	}
}

// NewErrorResponse creates an error API response
func NewErrorResponse(error string) *APIResponse {
	return &APIResponse{
		Success: false,
		Error:   error,
	}
}

// NewPaginatedResponse creates a paginated API response
func NewPaginatedResponse(data interface{}, pagination *Pagination, message string) *APIResponse {
	return &APIResponse{
		Success: true,
		Message: message,
		Data:    data,
		Meta:    pagination,
	}
}
