package main

import (
	"fmt"
	"log"
	"net"
	"text/template"

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

	forwardHandler := &ssh.ForwardedTCPHandler{}

	sshServer.server = &ssh.Server{
		Version:          "JumpGopher SSH Proxy 0.0",
		Addr:             ":" + config.SshPort,
		Handler:          sshServer.sessionHandler,
		PublicKeyHandler: sshServer.publicKeyHandler,
		HostSigners:      signers,
		RequestHandlers: map[string]ssh.RequestHandler{
			"tcpip-forward":        forwardHandler.HandleSSHRequest,
			"cancel-tcpip-forward": forwardHandler.HandleSSHRequest,
		},
		ChannelHandlers: map[string]ssh.ChannelHandler{
			"direct-tcpip": ssh.DirectTCPIPHandler,
			"session":      ssh.DefaultSessionHandler,
		},
		LocalPortForwardingCallback:   sshServer.checkDestination,
		ReversePortForwardingCallback: sshServer.checkDestination,
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
		log.Printf("Error checking public key for user %s: %v", ctx.User(), err)
	}
	return ok
}

// sessionHandler handles an SSH session, displaying account status and permissions.
func (s *SSHServer) sessionHandler(ses ssh.Session) {
	user, err := s.database.GetUser(ses.User())
	var accountStatus string
	if err != nil {
		log.Printf("Error fetching user %s from database: %v", ses.User(), err)
		accountStatus = "invalid - no access"
	} else {
		// Check OAuth token validity
		err, err2 := s.auth.CheckUserToken(user, nil)
		accountStatus = "valid"
		if err != nil {
			// invalid token
			accountStatus = "invalid - no access"
		}
		if err2 != nil {
			log.Printf("Database error while checking OAuth token for user %s: %v", ses.User(), err2)
			accountStatus = "Database error"
		}
	}

	permissions := s.permissions.GetUserPermissions(ses.User())

	// Render SSH session message using template
	err = s.tpl.ExecuteTemplate(ses, "ssh.txt", map[string]any{
		"user_name":      ses.User(),
		"account_status": accountStatus,
		"permissions":    permissions,
	})
	if err != nil {
		log.Printf("Error executing ssh.txt template: %v", err)
	}
}

// checkDestination validates if the user is allowed to forward to the given destination.
func (s *SSHServer) checkDestination(ctx ssh.Context, destHost string, destPort uint32) bool {
	user, err := s.database.GetUser(ctx.User())
	if err != nil {
		log.Printf("Error fetching user %s from database: %v", ctx.User(), err)
		return false
	}
	// Check OAuth token validity
	err, err2 := s.auth.CheckUserToken(user, nil)
	if err != nil {
		// token invalid
		return false
	}
	if err2 != nil {
		log.Printf("Database error while checking OAuth token for user %s: %v", ctx.User(), err2)
		return false
	}

	// Resolve destination host to IP addresses
	ips, err := net.LookupIP(destHost)
	if err != nil || len(ips) == 0 {
		log.Printf("Error looking up IP for host %s: %v", destHost, err)
		return false
	}

	// Check permissions for each resolved IP
	for _, ip := range ips {
		if !s.permissions.CheckPermission(ctx.User(), ip.String()) {
			log.Print("Permission denied for user ", ctx.User(), " to access ", ip.String())
			return false
		}
	}
	return true
}
