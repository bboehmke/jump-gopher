package main

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/bboehmke/jump-gopher/lib"
	"github.com/coder/websocket"
	"github.com/gin-gonic/gin"
	gossh "golang.org/x/crypto/ssh"
)

//go:embed templates
var templates embed.FS

// Web provides the HTTP web interface for login and key management.
type Web struct {
	database    *Database
	auth        *Auth
	permissions *Permissions

	router *gin.Engine
}

// NewWeb creates and configures a new Web instance, setting up routes and templates.
func NewWeb(database *Database, auth *Auth, permissions *Permissions) (*Web, error) {
	// disable debug mode if not enabled
	if config.WebDebug != "true" {
		gin.SetMode(gin.ReleaseMode)
	}

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

// Run starts the HTTP server for the web interface.
func (w *Web) Run() {
	server := http.Server{
		Addr:    ":" + config.WebPort,
		Handler: w.router,
	}
	err := server.ListenAndServe()
	if err != nil {
		slog.Error("failed to start web server", "error", err)
		os.Exit(10)
	}
}

// handleIndex renders the index page, showing user info, keys, and permissions.
func (w *Web) handleIndex(c *gin.Context) {
	user := c.MustGet("user").(*User)

	// Handle POST actions (add/delete keys)
	postError := w.handleIndexPost(c, user)

	// Fetch user's public keys from the database
	keys, err := w.database.GetPublicKeysOfUser(user)
	if err != nil {
		c.String(http.StatusInternalServerError, "Database error")
		return
	}

	host := strings.Split(c.Request.Host, ":")[0]
	c.HTML(http.StatusOK, "index.html", gin.H{
		"user_name":   c.MustGet("user").(*User).Name,
		"keys":        keys,
		"permissions": w.permissions.GetUserPermissions(user.Name),
		"error":       postError,
		"host":        host,
		"port":        config.SshPort,
	})
}

// handleIndexPost processes form submissions for adding or deleting public keys.
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

		// Parse and validate the SSH public key
		key, comment, _, _, err := gossh.ParseAuthorizedKey([]byte(publicKey))
		if err != nil {
			return fmt.Errorf("invalid public key: %w", err)
		}
		if name == "" {
			name = comment
		}

		// Add the public key to the user in the database
		err = w.database.AddPublicKeyToUser(user, name, string(gossh.MarshalAuthorizedKey(key)))
		if err != nil {
			slog.Error("failed to add public key", "user", user.Name, "error", err)
			return errors.New("failed to add public key")
		}
		return nil

	} else if action == "delete" {
		id := c.PostForm("id")
		if id == "" {
			return errors.New("id is required")
		}
		// Delete the public key from the database
		err := w.database.Db.Delete(&UserPublicKeys{}, "id = ? AND user_id = ?", id, user.ID).Error
		if err != nil {
			slog.Error("failed to delete public key", "user", user.Name, "error", err)
			return errors.New("failed to delete public key")
		}
		return nil

	} else {
		return fmt.Errorf("invalid action: %s", action)
	}
}

// handleProxy upgrades the HTTP connection to a websocket and proxies data between
// the websocket and a local SSH server socket.
func (w *Web) handleProxy(c *gin.Context) {
	ws, err := websocket.Accept(c.Writer, c.Request, nil)
	if err != nil {
		slog.Error("failed to accept websocket connection", "error", err)
		return
	}
	defer ws.CloseNow()

	// Connect directly to own SSH server
	sshSocket, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", config.SshPort), time.Second*5)
	if err != nil {
		slog.Error("failed to connect to ssh server", "error", err)
		return
	}
	defer sshSocket.Close()

	ctx, cancel := context.WithCancel(c)
	defer cancel()

	// websocket -> server
	go func() {
		err := lib.WsReader(ctx, ws, sshSocket)
		if err != nil {
			slog.Error("failed to read from websocket", "error", err)
		}
		cancel()
	}()

	// server -> websocket
	err = lib.WsWriter(ctx, ws, sshSocket)
	if err != nil {
		slog.Error("failed to write to websocket", "error", err)
	}
}
