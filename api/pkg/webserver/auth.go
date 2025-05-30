package webserver

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"

	"github.com/Warky-Devs/NotifyGate/api/pkg/db"
	"github.com/Warky-Devs/NotifyGate/api/pkg/models"
	"github.com/Warky-Devs/NotifyGate/api/pkg/utils"
)

// OAuth2Provider represents an OAuth2 provider configuration
type OAuth2Provider struct {
	AuthURL      string
	TokenURL     string
	UserInfoURL  string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
}

// GoogleUserInfo represents Google user information
type GoogleUserInfo struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
	VerifiedEmail bool   `json:"verified_email"`
}

// GitHubUserInfo represents GitHub user information
type GitHubUserInfo struct {
	ID        int    `json:"id"`
	Login     string `json:"login"`
	Name      string `json:"name"`
	Email     string `json:"email"`
	AvatarURL string `json:"avatar_url"`
}

// GitHubEmail represents GitHub email information
type GitHubEmail struct {
	Email    string `json:"email"`
	Primary  bool   `json:"primary"`
	Verified bool   `json:"verified"`
}

// getOAuth2Provider returns the OAuth2 configuration for a provider
func (s *Server) getOAuth2Provider(provider string) (*OAuth2Provider, error) {
	switch provider {
	case "google":
		return &OAuth2Provider{
			AuthURL:      "https://accounts.google.com/o/oauth2/auth",
			TokenURL:     "https://oauth2.googleapis.com/token",
			UserInfoURL:  "https://www.googleapis.com/oauth2/v2/userinfo",
			ClientID:     s.config.OAuth.Google.ClientID,
			ClientSecret: s.config.OAuth.Google.ClientSecret,
			RedirectURL:  s.config.OAuth.Google.RedirectURL,
			Scopes:       s.config.OAuth.Google.Scopes,
		}, nil
	case "github":
		return &OAuth2Provider{
			AuthURL:      "https://github.com/login/oauth/authorize",
			TokenURL:     "https://github.com/login/oauth/access_token",
			UserInfoURL:  "https://api.github.com/user",
			ClientID:     s.config.OAuth.GitHub.ClientID,
			ClientSecret: s.config.OAuth.GitHub.ClientSecret,
			RedirectURL:  s.config.OAuth.GitHub.RedirectURL,
			Scopes:       s.config.OAuth.GitHub.Scopes,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported OAuth2 provider: %s", provider)
	}
}

// handleOAuthLogin initiates OAuth2 login flow
func (s *Server) handleOAuthLogin(c *gin.Context) {
	provider := c.Param("provider")

	oauthProvider, err := s.getOAuth2Provider(provider)
	if err != nil {
		s.logger.WithError(err).Error("Invalid OAuth2 provider")
		c.JSON(http.StatusBadRequest, utils.NewErrorResponse("Invalid OAuth2 provider"))
		return
	}

	// Generate state parameter for CSRF protection
	state, err := utils.NewTokenGenerator().GenerateSecureToken(16)
	if err != nil {
		s.logger.WithError(err).Error("Failed to generate OAuth2 state")
		c.JSON(http.StatusInternalServerError, utils.NewErrorResponse("Internal server error"))
		return
	}

	// Store state in session
	session := sessions.Default(c)
	session.Set("oauth_state", state)
	session.Set("oauth_provider", provider)
	if err := session.Save(); err != nil {
		s.logger.WithError(err).Error("Failed to save OAuth2 state to session")
		c.JSON(http.StatusInternalServerError, utils.NewErrorResponse("Internal server error"))
		return
	}

	// Build authorization URL
	authURL := fmt.Sprintf("%s?client_id=%s&redirect_uri=%s&scope=%s&response_type=code&state=%s",
		oauthProvider.AuthURL,
		url.QueryEscape(oauthProvider.ClientID),
		url.QueryEscape(oauthProvider.RedirectURL),
		url.QueryEscape(strings.Join(oauthProvider.Scopes, " ")),
		url.QueryEscape(state),
	)

	s.logger.LogAuth(0, "", provider, "login_initiated", true)
	c.Redirect(http.StatusTemporaryRedirect, authURL)
}

// handleOAuthCallback handles OAuth2 callback
func (s *Server) handleOAuthCallback(c *gin.Context) {
	provider := c.Param("provider")
	code := c.Query("code")
	state := c.Query("state")
	errorParam := c.Query("error")

	// Check for OAuth2 error
	if errorParam != "" {
		s.logger.LogAuth(0, "", provider, "callback_error", false)
		c.JSON(http.StatusBadRequest, utils.NewErrorResponse(fmt.Sprintf("OAuth2 error: %s", errorParam)))
		return
	}

	// Validate state parameter
	session := sessions.Default(c)
	sessionState := session.Get("oauth_state")
	sessionProvider := session.Get("oauth_provider")

	if sessionState == nil || sessionProvider == nil {
		s.logger.LogSecurity("oauth_invalid_session", 0, c.ClientIP(), map[string]interface{}{
			"provider": provider,
		})
		c.JSON(http.StatusBadRequest, utils.NewErrorResponse("Invalid session"))
		return
	}

	if sessionState.(string) != state || sessionProvider.(string) != provider {
		s.logger.LogSecurity("oauth_state_mismatch", 0, c.ClientIP(), map[string]interface{}{
			"provider":       provider,
			"expected_state": sessionState,
			"received_state": state,
		})
		c.JSON(http.StatusBadRequest, utils.NewErrorResponse("Invalid state parameter"))
		return
	}

	// Clear session state
	session.Delete("oauth_state")
	session.Delete("oauth_provider")
	session.Save()

	// Get OAuth2 provider configuration
	oauthProvider, err := s.getOAuth2Provider(provider)
	if err != nil {
		s.logger.WithError(err).Error("Invalid OAuth2 provider in callback")
		c.JSON(http.StatusBadRequest, utils.NewErrorResponse("Invalid OAuth2 provider"))
		return
	}

	// Exchange code for access token
	accessToken, err := s.exchangeCodeForToken(oauthProvider, code)
	if err != nil {
		s.logger.WithError(err).Error("Failed to exchange code for token")
		c.JSON(http.StatusInternalServerError, utils.NewErrorResponse("Failed to authenticate"))
		return
	}

	// Get user information
	userInfo, err := s.getUserInfo(provider, oauthProvider, accessToken)
	if err != nil {
		s.logger.WithError(err).Error("Failed to get user info")
		c.JSON(http.StatusInternalServerError, utils.NewErrorResponse("Failed to get user information"))
		return
	}

	// Create or update user
	user, err := s.createOrUpdateUser(provider, userInfo)
	if err != nil {
		s.logger.WithError(err).Error("Failed to create or update user")
		c.JSON(http.StatusInternalServerError, utils.NewErrorResponse("Failed to create user"))
		return
	}

	// Generate JWT token
	token, err := s.jwtManager.GenerateToken(user.ID, user.Email, user.Name)
	if err != nil {
		s.logger.WithError(err).Error("Failed to generate JWT token")
		c.JSON(http.StatusInternalServerError, utils.NewErrorResponse("Failed to generate token"))
		return
	}

	s.logger.LogAuth(user.ID, user.Email, provider, "login_success", true)

	// Return success response with token
	c.JSON(http.StatusOK, utils.NewSuccessResponse(map[string]interface{}{
		"token": token,
		"user":  user,
	}, "Login successful"))
}

// exchangeCodeForToken exchanges authorization code for access token
func (s *Server) exchangeCodeForToken(provider *OAuth2Provider, code string) (string, error) {
	data := url.Values{}
	data.Set("client_id", provider.ClientID)
	data.Set("client_secret", provider.ClientSecret)
	data.Set("code", code)
	data.Set("grant_type", "authorization_code")
	data.Set("redirect_uri", provider.RedirectURL)

	req, err := http.NewRequest("POST", provider.TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token exchange failed with status: %d", resp.StatusCode)
	}

	var tokenResponse map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		return "", err
	}

	accessToken, ok := tokenResponse["access_token"].(string)
	if !ok {
		return "", fmt.Errorf("access token not found in response")
	}

	return accessToken, nil
}

// getUserInfo gets user information from OAuth2 provider
func (s *Server) getUserInfo(provider string, oauthProvider *OAuth2Provider, accessToken string) (map[string]interface{}, error) {
	req, err := http.NewRequest("GET", oauthProvider.UserInfoURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("user info request failed with status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var userInfo map[string]interface{}
	if err := json.Unmarshal(body, &userInfo); err != nil {
		return nil, err
	}

	// For GitHub, we need to get the primary email separately if not present
	if provider == "github" {
		if email, exists := userInfo["email"]; email == nil || !exists {
			email, err := s.getGitHubUserEmail(accessToken)
			if err != nil {
				return nil, err
			}
			userInfo["email"] = email
		}
	}

	return userInfo, nil
}

// getGitHubUserEmail gets the primary email for GitHub user
func (s *Server) getGitHubUserEmail(accessToken string) (string, error) {
	req, err := http.NewRequest("GET", "https://api.github.com/user/emails", nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("email request failed with status: %d", resp.StatusCode)
	}

	var emails []GitHubEmail
	if err := json.NewDecoder(resp.Body).Decode(&emails); err != nil {
		return "", err
	}

	// Find primary email
	for _, email := range emails {
		if email.Primary && email.Verified {
			return email.Email, nil
		}
	}

	// Fallback to first verified email
	for _, email := range emails {
		if email.Verified {
			return email.Email, nil
		}
	}

	return "", fmt.Errorf("no verified email found")
}

// createOrUpdateUser creates a new user or updates existing user
func (s *Server) createOrUpdateUser(provider string, userInfo map[string]interface{}) (*models.User, error) {
	repo := db.NewRepository(s.db)

	// Extract user information based on provider
	var oauthID, email, name, avatarURL string

	switch provider {
	case "google":
		oauthID = fmt.Sprintf("%.0f", userInfo["id"].(float64))
		email = userInfo["email"].(string)
		name = userInfo["name"].(string)
		if pic, exists := userInfo["picture"]; exists && pic != nil {
			avatarURL = pic.(string)
		}
	case "github":
		oauthID = fmt.Sprintf("%.0f", userInfo["id"].(float64))
		email = userInfo["email"].(string)
		if nameVal, exists := userInfo["name"]; exists && nameVal != nil {
			name = nameVal.(string)
		} else {
			name = userInfo["login"].(string)
		}
		if avatar, exists := userInfo["avatar_url"]; exists && avatar != nil {
			avatarURL = avatar.(string)
		}
	default:
		return nil, fmt.Errorf("unsupported provider: %s", provider)
	}

	// Validate email
	if !s.validator.ValidateEmail(email) {
		return nil, fmt.Errorf("invalid email address: %s", email)
	}

	// Try to find existing user by OAuth ID
	existingUser, err := repo.GetUserByOAuth(provider, oauthID)
	if err == nil {
		// Update existing user
		existingUser.Email = email
		existingUser.Name = name
		existingUser.AvatarURL = avatarURL

		if err := repo.UpdateUser(existingUser); err != nil {
			return nil, err
		}

		return existingUser, nil
	}

	// Try to find existing user by email (for account linking)
	existingUser, err = repo.GetUserByEmail(email)
	if err == nil {
		// Link OAuth account to existing email
		existingUser.OAuthProvider = provider
		existingUser.OAuthID = oauthID
		existingUser.Name = name
		existingUser.AvatarURL = avatarURL

		if err := repo.UpdateUser(existingUser); err != nil {
			return nil, err
		}

		return existingUser, nil
	}

	// Create new user
	newUser := &models.User{
		OAuthProvider:     provider,
		OAuthID:           oauthID,
		Email:             email,
		Name:              name,
		AvatarURL:         avatarURL,
		Timezone:          "UTC",
		DefaultTimeWindow: "00:00-23:59",
	}

	if err := repo.CreateUser(newUser); err != nil {
		return nil, err
	}

	return newUser, nil
}

// handleLogout handles user logout
func (s *Server) handleLogout(c *gin.Context) {
	// Clear session
	session := sessions.Default(c)
	session.Clear()
	session.Save()

	// If user is authenticated, log the logout
	if user, err := s.getCurrentUser(c); err == nil {
		s.logger.LogAuth(user.ID, user.Email, "", "logout", true)
	}

	c.JSON(http.StatusOK, utils.NewSuccessResponse(nil, "Logged out successfully"))
}
