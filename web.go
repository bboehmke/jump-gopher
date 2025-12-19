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
	"github.com/prometheus/client_golang/prometheus/promhttp"
	gossh "golang.org/x/crypto/ssh"
)

//go:embed templates
var templates embed.FS

// Web provides the HTTP web interface for login and key management.
type Web struct {
	database    *Database
	auth        *Auth
	permissions *Permissions

	tpl *template.Template
	mux *http.ServeMux
}

// NewWeb creates and configures a new Web instance, setting up routes and templates.
func NewWeb(database *Database, auth *Auth, permissions *Permissions) (*Web, error) {
	web := &Web{
		database:    database,
		auth:        auth,
		permissions: permissions,

		mux: http.NewServeMux(),
	}

	var err error
	web.tpl, err = template.ParseFS(templates, "templates/*")
	if err != nil {
		return nil, fmt.Errorf("error parsing templates: %w", err)
	}

	web.mux.HandleFunc("/{$}", web.handleIndex)
	web.mux.HandleFunc("/auth/login", auth.login)
	web.mux.HandleFunc("/auth/callback", auth.callback)

	if strings.ToLower(config.WebEnableProxy) == "true" {
		web.mux.HandleFunc("/proxy", web.handleProxy)
	}

	web.mux.Handle("/metrics", promhttp.Handler())
	return web, nil
}

// Run starts the HTTP server for the web interface.
func (w *Web) Run() {
	server := http.Server{
		Addr:              ":" + config.WebPort,
		Handler:           httpRecovery(httpLogger(w.mux)),
		ReadHeaderTimeout: time.Second * 5,
	}

	err := server.ListenAndServe()
	if err != nil {
		slog.Error("failed to start web server", "error", err)
		os.Exit(10)
	}
}

// handleIndex renders the index page, showing user info, keys, and permissions.
func (w *Web) handleIndex(writer http.ResponseWriter, request *http.Request) {
	// Check user authentication
	user := w.auth.CheckAuth(writer, request)
	if user == nil {
		// User not authenticated, CheckAuth already handled the response
		return
	}

	// Handle POST actions (add/delete keys)
	postError := w.handleIndexPost(request, user)

	// Fetch user's public keys from the database
	keys, err := w.database.GetPublicKeysOfUser(user)
	if err != nil {
		slog.Error("failed to fetch public keys", "user", user.Name, "error", err)
		writer.WriteHeader(http.StatusInternalServerError)
		_, _ = writer.Write([]byte("Database error"))
		return
	}

	// render the index template
	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	writer.WriteHeader(http.StatusOK)
	host := strings.Split(request.Host, ":")[0]
	err = w.tpl.ExecuteTemplate(writer, "index.html", map[string]interface{}{
		"user_name":   user.Name,
		"keys":        keys,
		"permissions": w.permissions.GetUserPermissions(user.Name),
		"error":       postError,
		"host":        host,
		"port":        config.SshPort,
	})
	if err != nil {
		slog.Error("failed to render template", "error", err)
	}
}

// handleIndexPost processes form submissions for adding or deleting public keys.
func (w *Web) handleIndexPost(request *http.Request, user *User) error {
	if request.Method != http.MethodPost {
		return nil
	}

	err := request.ParseForm()
	if err != nil {
		return fmt.Errorf("failed to parse form: %w", err)
	}

	action := request.PostForm.Get("action")
	if action == "add" {
		name := request.PostForm.Get("name")
		publicKey := request.PostForm.Get("public_key")

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
		id := request.PostForm.Get("id")
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

	}
	return fmt.Errorf("invalid action: %s", action)
}

// handleProxy upgrades the HTTP connection to a websocket and proxies data between
// the websocket and a local SSH server socket.
func (w *Web) handleProxy(writer http.ResponseWriter, request *http.Request) {
	ws, err := websocket.Accept(writer, request, nil)
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

	ctx, cancel := context.WithCancel(request.Context())
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

// writeString is a helper function to write a string response with a given status code.
func writeString(writer http.ResponseWriter, status int, body string) {
	writer.WriteHeader(status)
	_, _ = writer.Write([]byte(body))
}

// httpLogger is a middleware that logs HTTP requests with method, path, client IP, and duration.
func httpLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		start := time.Now()
		next.ServeHTTP(writer, request)
		duration := time.Since(start)

		clientIp := request.Header.Get("X-Forwarded-For")
		if clientIp == "" {
			clientIp, _, _ = net.SplitHostPort(strings.TrimSpace(request.RemoteAddr))
		}

		slog.Info("http",
			"method", request.Method,
			"path", request.URL.Path,
			"client_ip", clientIp,
			"duration", duration.String(),
		)
	})
}

// httpRecovery is a middleware that recovers from panics in HTTP handlers and returns a 500 error.
func httpRecovery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				slog.Error("panic recovered in http handler", "error", err)
				writeString(writer, http.StatusInternalServerError, "Internal Server Error (Panic)")
			}
		}()
		next.ServeHTTP(writer, request)
	})
}
