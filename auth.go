package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
	"gorm.io/gorm"
)

// Auth handles authentication logic and stores a reference to the database.
type Auth struct {
	Database *Database // Database connection used for user/session management
}

// Register sets up the authentication routes on the provided router.
func (a *Auth) Register(router gin.IRouter) {
	authGroup := router.Group("/auth")

	authGroup.GET("/login", func(c *gin.Context) {
		// Redirect user to OAuth provider's login page
		conf := config.OAuthConfig(c)
		c.Redirect(http.StatusTemporaryRedirect, conf.AuthCodeURL("state", oauth2.AccessTypeOffline))
	})
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
		log.Print("Updated user token in database")
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
		log.Print(err2)
		c.Status(http.StatusInternalServerError)
		c.Abort()
		return
	}

	// Session found -> set user in context for downstream handlers
	c.Set("user", user)
}

// callback handles the OAuth provider's callback and creates the user session.
func (a *Auth) callback(c *gin.Context) {
	code, ok := c.GetQuery("code")
	if !ok {
		c.Status(http.StatusBadRequest)
		return
	}

	conf := config.OAuthConfig(c)
	// Exchange the code for a token
	tok, err := conf.Exchange(c, code)
	if err != nil {
		log.Print(err)
		return
	}

	// Parse the JWT token to extract user information
	token, err := jwt.Parse(tok.AccessToken, func(token *jwt.Token) (interface{}, error) {
		return []byte(conf.ClientSecret), nil
	})
	if err != nil {
		log.Print(err)
		return
	}

	// Try to get the user from the database, create if not found
	user, err := a.Database.GetUser(token.Claims.(jwt.MapClaims)["name"].(string))
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			user, err = a.Database.CreateUser(token.Claims.(jwt.MapClaims)["name"].(string))
			if err != nil {
				log.Print(err)
				c.Status(http.StatusInternalServerError)
				return
			}
		} else {
			log.Print(err)
			c.Status(http.StatusInternalServerError)
			return
		}
	}

	// Generate a new session ID for the user
	sessionID, err := generateSessionID()
	if err != nil {
		log.Print(err)
		c.Status(http.StatusInternalServerError)
		return
	}

	user.SessionId = sessionID
	user.SetOAuthToken(tok)
	if err := a.Database.Db.Save(user).Error; err != nil {
		log.Print(err)
		c.Status(http.StatusInternalServerError)
		return
	}

	// Set session cookie and redirect to home
	c.SetCookie("session_key", sessionID, 60*60*24, "/", "", false, true)
	c.Redirect(http.StatusTemporaryRedirect, "/")
}

// generateSessionID generates a random session ID of 128 characters (64 bytes).
func generateSessionID() (string, error) {
	bytes := make([]byte, 64)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}
