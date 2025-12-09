package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
	"gorm.io/gorm"
)

// Auth handles authentication logic and stores a reference to the database.
type Auth struct {
	Database *Database // Database connection used for user/session management

	StateEncryptionKey [32]byte // Key used to encrypt OAuth state parameter
}

// NewAuth creates a new Auth instance with the provided database connection.
func NewAuth(db *Database) *Auth {
	return &Auth{
		Database: db,

		// Derive encryption key from OAuth secret
		StateEncryptionKey: sha256.Sum256([]byte(config.OAuthSecret)),
	}
}

// Register sets up the authentication routes on the provided router.
func (a *Auth) Register(router gin.IRouter) {
	authGroup := router.Group("/auth")

	authGroup.GET("/login", a.login)
	authGroup.GET("/callback", a.callback)
}

// CheckUserToken verifies the user's OAuth token and updates it if necessary.
// Returns two errors: the first for token validity, the second for database errors.
func (a *Auth) CheckUserToken(user *User, c *gin.Context) (error, error) {
	conf := config.OAuthConfig(c)
	token := user.OAuthToken()

	// Check token for validity and request a new token from the OAuth provider is access token is expired
	source := conf.TokenSource(context.Background(), token)
	tok, err := source.Token()
	if err != nil {
		return err, nil
	}

	// If the access token has changed, update the user record in the database
	if tok.AccessToken != token.AccessToken {
		user.SetOAuthToken(tok)
		if err := a.Database.Db.Save(user).Error; err != nil {
			return nil, err
		}
		slog.Debug("Updated user token in database")
	}

	return nil, nil
}

// CheckAuth is a middleware that checks if the user is authenticated.
// If not, it redirects to the login page.
func (a *Auth) CheckAuth(c *gin.Context) {
	sessionKey, err := c.Cookie("session_key")
	if err != nil {
		// No session cookie -> redirect to login
		c.Redirect(http.StatusTemporaryRedirect, "/auth/login")
		c.Abort()
		return
	}

	user, err := a.Database.GetUserBySessionId(sessionKey)
	if err != nil {
		// Session not found -> redirect to login
		c.Redirect(http.StatusTemporaryRedirect, "/auth/login")
		c.Abort()
		return
	}

	// Check if token is still valid
	err, err2 := a.CheckUserToken(user, c)
	if err != nil {
		// Session invalid -> redirect to login
		c.Redirect(http.StatusTemporaryRedirect, "/auth/login")
		c.Abort()
		return
	}
	// err2 indicates a database error which should not be shown to the user
	if err2 != nil {
		slog.Error("failed to update access token in database", "error", err2, "user", user.Name)
		c.Status(http.StatusInternalServerError)
		c.Abort()
		return
	}

	// Session found -> set user in context for downstream handlers
	c.Set("user", user)
}

// login initiates the OAuth login process by redirecting to the provider's login page.
func (a *Auth) login(c *gin.Context) {
	// generate random state parameter
	stateBytes, err := generateRandom()
	if err != nil {
		slog.Error("failed to generate random state", "error", err)
		c.Status(http.StatusInternalServerError)
		return
	}

	// store encrypted state in cookie
	encryptedStateBytes, err := encrypt(stateBytes, a.StateEncryptionKey[:])
	if err != nil {
		slog.Error("failed to encrypt state", "error", err)
		c.Status(http.StatusInternalServerError)
		return
	}
	c.SetCookie("oauth_state", hex.EncodeToString(encryptedStateBytes), 300, "/", "", false, true)

	// Redirect user to OAuth provider's login page
	conf := config.OAuthConfig(c)
	c.Redirect(http.StatusTemporaryRedirect, conf.AuthCodeURL(hex.EncodeToString(stateBytes), oauth2.AccessTypeOffline))
}

// callback handles the OAuth provider's callback and creates the user session.
func (a *Auth) callback(c *gin.Context) {
	state, ok := c.GetQuery("state")
	if !ok {
		c.String(http.StatusBadRequest, "Missing OAuth state in callback")
		return
	}

	// retrieve and decrypt state from cookie
	encryptedStateHex, err := c.Cookie("oauth_state")
	if err != nil {
		c.String(http.StatusBadRequest, "Missing OAuth state cookie in callback")
		return
	}
	encryptedStateBytes, err := hex.DecodeString(encryptedStateHex)
	if err != nil {
		slog.Error("failed to decode encrypted state", "error", err)
		c.String(http.StatusBadRequest, "Invalid OAuth state cookie in callback")
		return
	}
	decryptedStateBytes, err := decrypt(encryptedStateBytes, a.StateEncryptionKey[:])
	if err != nil {
		slog.Error("failed to decrypt state", "error", err)
		c.String(http.StatusBadRequest, "Invalid OAuth state cookie in callback")
		return
	}

	// compare state parameters
	if state != hex.EncodeToString(decryptedStateBytes) {
		c.String(http.StatusBadRequest, "Invalid OAuth state in callback")
		return
	}

	// get code from query
	code, ok := c.GetQuery("code")
	if !ok {
		c.String(http.StatusBadRequest, "Missing OAuth code in callback")
		return
	}

	conf := config.OAuthConfig(c)
	// Exchange the code for a token
	tok, err := conf.Exchange(c, code)
	if err != nil {
		slog.Error("token exchange failed", "error", err)
		return
	}

	// Parse the JWT token to extract user information
	token, err := jwt.Parse(tok.AccessToken, func(token *jwt.Token) (interface{}, error) {
		return []byte(conf.ClientSecret), nil
	})
	if err != nil {
		slog.Error("failed to parse JWT token", "error", err)
		return
	}

	// Try to get the user from the database, create if not found
	username, ok := token.Claims.(jwt.MapClaims)[config.OAuthUsernameClaim].(string)
	if !ok {
		slog.Error("failed to extract username from token")
		return
	}

	user, err := a.Database.GetUser(username)
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		slog.Error("failed to query database", "error", err)
		c.Status(http.StatusInternalServerError)
		return
	}

	// create new user if not exist
	if user.Name == "" {
		user, err = a.Database.CreateUser(username)
		if err != nil {
			slog.Error("failed to create user", "error", err)
			c.Status(http.StatusInternalServerError)
			return
		}
	}

	// Generate a new session ID for the user
	sessionID, err := generateSessionID()
	if err != nil {
		slog.Error("failed to generate session id", "error", err)
		c.Status(http.StatusInternalServerError)
		return
	}

	user.SessionId = sessionID
	user.SetOAuthToken(tok)
	if err := a.Database.Db.Save(user).Error; err != nil {
		slog.Error("failed to update user in database", "error", err)
		c.Status(http.StatusInternalServerError)
		return
	}

	// Set session cookie and redirect to home
	c.SetCookie("session_key", sessionID, 60*60*24, "/", "", false, true)
	c.Redirect(http.StatusTemporaryRedirect, "/")
}
