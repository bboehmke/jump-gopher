package main

import (
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

type Auth struct {
	Database *Database
}

func (a *Auth) Register(router gin.IRouter) {
	authGroup := router.Group("/auth")

	authGroup.GET("/login", func(c *gin.Context) {
		conf := config.OAuthConfig(c)
		c.Redirect(http.StatusTemporaryRedirect, conf.AuthCodeURL("state", oauth2.AccessTypeOffline))
	})
	authGroup.GET("/callback", a.callback)
	authGroup.GET("/test", a.CheckAuth, a.test)
}

func (a *Auth) test(c *gin.Context) {
	conf := config.OAuthConfig(c)

	user := c.MustGet("user").(*User) // ensure user is set
	token := user.OAuthToken()

	source := conf.TokenSource(c, token)
	tok, err := source.Token()
	if err != nil {
		log.Print(err)
		c.Status(http.StatusInternalServerError)
		return
	}

	if tok.AccessToken != token.AccessToken {
		user.SetOAuthToken(tok)
		if err := a.Database.Db.Save(user).Error; err != nil {
			log.Print(err)
			c.Status(http.StatusInternalServerError)
			return
		}
		log.Print("Updated user token in database")
	}
	c.String(http.StatusOK, "OK")
}

func (a *Auth) CheckAuth(c *gin.Context) {
	sessionKey, err := c.Cookie("session_key")
	if err != nil {
		// no session cookie -> redirect to login
		c.Redirect(http.StatusTemporaryRedirect, "/auth/login")
		c.Abort()
		return
	}

	user, err := a.Database.GetUserBySessionId(sessionKey)
	if err != nil {
		// session not found -> redirect to login
		c.Redirect(http.StatusTemporaryRedirect, "/auth/login")
		c.Abort()
		return
	}

	// session found -> set user in context
	c.Set("user", user)
}

func (a *Auth) callback(c *gin.Context) {
	code, ok := c.GetQuery("code")
	if !ok {
		c.Status(http.StatusBadRequest)
		return
	}

	conf := config.OAuthConfig(c)
	tok, err := conf.Exchange(c, code)
	if err != nil {
		log.Print(err)
		return
	}

	token, err := jwt.Parse(tok.AccessToken, func(token *jwt.Token) (interface{}, error) {
		return []byte(conf.ClientSecret), nil
	})
	if err != nil {
		log.Print(err)
		return
	}
	_ = token

	/*source := conf.TokenSource(context.Background(), tok)
	tok, err = source.Token()
	if err != nil {
		log.Print(err)
		c.Status(http.StatusInternalServerError)
		return
	}*/
	/*client := conf.Client(c, tok)
	_ = client*/

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
