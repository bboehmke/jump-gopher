package main

import (
	"embed"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	gossh "golang.org/x/crypto/ssh"
)

//go:embed templates
var templates embed.FS

type Web struct {
	database    *Database
	auth        *Auth
	permissions *Permissions

	router *gin.Engine
}

func NewWeb(database *Database, auth *Auth, permissions *Permissions) (*Web, error) {
	web := &Web{
		database:    database,
		auth:        auth,
		permissions: permissions,

		router: gin.New(),
	}

	tpl, err := template.ParseFS(templates, "templates/*")
	if err != nil {
		return nil, fmt.Errorf("error parsing templates: %w", err)
	}

	web.router.Use(gin.Logger(), gin.Recovery())
	web.router.SetHTMLTemplate(tpl)

	auth.Register(web.router)

	web.router.GET("/", auth.CheckAuth, web.handleIndex)
	web.router.POST("/", auth.CheckAuth, web.handleIndex)

	if strings.ToLower(config.WebEnableProxy) == "true" {
		web.router.GET("/proxy", web.handleProxy)
	}
	return web, nil
}

func (w *Web) Run() {
	server := http.Server{
		Addr:    ":" + config.WebPort,
		Handler: w.router,
	}
	err := server.ListenAndServe()
	if err != nil {
		log.Fatal(err)
	}
}

func (w *Web) handleIndex(c *gin.Context) {
	user := c.MustGet("user").(*User)

	postError := w.handleIndexPost(c, user)

	keys, err := w.database.GetPublicKeysOfUser(user)
	if err != nil {
		c.String(http.StatusInternalServerError, "Database error")
		return
	}
	c.HTML(http.StatusOK, "index.html", gin.H{
		"user_name":   c.MustGet("user").(*User).Name,
		"keys":        keys,
		"permissions": w.permissions.GetUserPermissions(user.Name),
		"error":       postError,
	})
}

func (w *Web) handleIndexPost(c *gin.Context, user *User) error {
	if c.Request.Method != http.MethodPost {
		return nil
	}

	action := c.PostForm("action")
	if action == "add" {
		name := c.PostForm("name")
		publicKey := c.PostForm("public_key")

		if publicKey == "" {
			return errors.New("public Key is required")
		}

		key, comment, _, _, err := gossh.ParseAuthorizedKey([]byte(publicKey))
		if err != nil {
			return fmt.Errorf("invalid public key: %w", err)
		}
		if name == "" {
			name = comment
		}

		err = w.database.AddPublicKeyToUser(user, name, string(gossh.MarshalAuthorizedKey(key)))
		if err != nil {
			log.Printf("Failed to add public key: %v", err)
			return errors.New("failed to add public key")
		}
		return nil

	} else if action == "delete" {
		id := c.PostForm("id")
		if id == "" {
			return errors.New("id is required")
		}
		err := w.database.Db.Delete(&UserPublicKeys{}, "id = ? AND user_id = ?", id, user.ID).Error
		if err != nil {
			log.Printf("Failed to delete public key: %v", err)
			return errors.New("failed to delete public key")
		}
		return nil

	} else {
		return fmt.Errorf("invalid action: %s", action)
	}
}
