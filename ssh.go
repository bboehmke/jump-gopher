package main

import (
	"fmt"
	"log"
	"net"
	"text/template"

	"github.com/gliderlabs/ssh"
	gossh "golang.org/x/crypto/ssh"
)

type SSHServer struct {
	database    *Database
	auth        *Auth
	permissions *Permissions

	server *ssh.Server

	tpl *template.Template
}

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

func (s *SSHServer) Run() error {
	return s.server.ListenAndServe()
}

func (s *SSHServer) publicKeyHandler(ctx ssh.Context, key ssh.PublicKey) bool {
	ok, err := s.database.CheckPublicKeyForUserName(ctx.User(), string(gossh.MarshalAuthorizedKey(key)))
	if err != nil {
		log.Printf("Error checking public key for user %s: %v", ctx.User(), err)
	}
	return ok
}

func (s *SSHServer) sessionHandler(ses ssh.Session) {
	user, err := s.database.GetUser(ses.User())
	var accountStatus string
	if err != nil {
		log.Printf("Error fetching user %s from database: %v", ses.User(), err)
		accountStatus = "invalid - no access"
	} else {
		err, err2 := s.auth.CheckUserToken(user, nil)
		accountStatus = "valid"
		if err != nil {
			log.Printf("Error checking OAuth token for user %s: %v", ses.User(), err)
			accountStatus = "invalid - no access"
		}
		if err2 != nil {
			log.Printf("Database error while checking OAuth token for user %s: %v", ses.User(), err2)
			accountStatus = "Database error"
		}
	}

	permissions := s.permissions.GetUserPermissions(ses.User())

	err = s.tpl.ExecuteTemplate(ses, "ssh.txt", map[string]any{
		"user_name":      ses.User(),
		"account_status": accountStatus,
		"permissions":    permissions,
	})
	if err != nil {
		log.Printf("Error executing ssh.txt template: %v", err)
	}
}

func (s *SSHServer) checkDestination(ctx ssh.Context, destHost string, destPort uint32) bool {
	user, err := s.database.GetUser(ctx.User())
	if err != nil {
		log.Printf("Error fetching user %s from database: %v", ctx.User(), err)
		return false
	}
	err, err2 := s.auth.CheckUserToken(user, nil)
	if err != nil {
		log.Printf("Error checking OAuth token for user %s: %v", ctx.User(), err)
		return false
	}
	if err2 != nil {
		log.Printf("Database error while checking OAuth token for user %s: %v", ctx.User(), err2)
		return false
	}

	ips, err := net.LookupIP(destHost)
	if err != nil || len(ips) == 0 {
		log.Printf("Error looking up IP for host %s: %v", destHost, err)
		return false
	}

	for _, ip := range ips {
		if !s.permissions.CheckPermission(ctx.User(), ip.String()) {
			log.Print("Permission denied for user ", ctx.User(), " to access ", ip.String())
			return false
		}
	}
	return true
}
