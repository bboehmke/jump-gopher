package main

import (
	"fmt"
	"log/slog"
	"text/template"
	"time"

	"github.com/gliderlabs/ssh"
	gossh "golang.org/x/crypto/ssh"
)

// SSHServer provides the SSH proxy server, handling authentication and permissions.
type SSHServer struct {
	database    *Database
	auth        *Auth
	permissions *Permissions

	server *ssh.Server

	tpl *template.Template
}

// NewSSHServer creates and configures a new SSHServer instance.
func NewSSHServer(database *Database, auth *Auth, permissions *Permissions) (*SSHServer, error) {
	sshServer := SSHServer{
		database:    database,
		auth:        auth,
		permissions: permissions,
	}

	var err error
	sshServer.tpl, err = template.ParseFS(templates, "templates/*")
	if err != nil {
		return nil, fmt.Errorf("error parsing templates: %w", err)
	}

	signers, err := loadHostKeys()
	if err != nil {
		return nil, fmt.Errorf("error loading host keys: %w", err)
	}

	sshServer.server = &ssh.Server{
		Version:          "JumpGopher SSH Proxy 0.0",
		Addr:             ":" + config.SshPort,
		Handler:          sshServer.sessionHandler,
		PublicKeyHandler: sshServer.publicKeyHandler,
		HostSigners:      signers,
		ChannelHandlers: map[string]ssh.ChannelHandler{
			"direct-tcpip": sshServer.directTCPIPHandler,
			"session":      ssh.DefaultSessionHandler,
		},
	}

	return &sshServer, nil
}

// Run starts the SSH server and listens for incoming connections.
func (s *SSHServer) Run() error {
	return s.server.ListenAndServe()
}

// publicKeyHandler checks if the provided public key is valid for the given user.
func (s *SSHServer) publicKeyHandler(ctx ssh.Context, key ssh.PublicKey) bool {
	ok, err := s.database.CheckPublicKeyForUserName(ctx.User(), string(gossh.MarshalAuthorizedKey(key)))
	if err != nil {
		slog.Error("failed to check public key", "user", ctx.User(), "error", err)
	}

	// track active connections
	if ok {
		mActiveConnections.WithLabelValues(ctx.User()).Inc()
		go func() {
			<-ctx.Done()
			mActiveConnections.WithLabelValues(ctx.User()).Dec()
		}()
	}
	return ok
}

// sessionHandler handles an SSH session, displaying account status and permissions.
func (s *SSHServer) sessionHandler(ses ssh.Session) {
	user, err := s.database.GetUser(ses.User())
	var accountStatus string
	var accountValid bool
	if err != nil {
		slog.Error("failed to get user from database", "user", ses.User(), "error", err)
		accountStatus = "invalid - no access"
	} else {
		// Check OAuth token validity
		err, err2 := s.auth.CheckUserToken(user, nil)
		if err != nil {
			// invalid token
			accountStatus = fmt.Sprintf("invalid - no access (%s)", err.Error())
		} else if err2 != nil {
			slog.Error("failed to update access token in database", "error", err2, "user", ses.User())
			accountStatus = "Database error"
		} else {
			// token valid - show expiry date
			accountStatus = fmt.Sprintf("valid - expires at %s", user.Expiry.Format(time.RFC3339))
			accountValid = true
		}
	}

	permissions := s.permissions.GetUserPermissions(ses.User())

	// Render SSH session message using template
	err = s.tpl.ExecuteTemplate(ses, "ssh.txt", map[string]any{
		"user_name":      ses.User(),
		"account_status": accountStatus,
		"account_valid":  accountValid,
		"permissions":    permissions,
	})
	if err != nil {
		slog.Error("error executing ssh.txt template", "error", err)
	}
}
