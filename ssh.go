package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"os"

	"github.com/gliderlabs/ssh"
	gossh "golang.org/x/crypto/ssh"
)

type SSHServer struct {
	database    *Database
	auth        *Auth
	permissions *Permissions

	server *ssh.Server
}

func NewSSHServer(database *Database, auth *Auth, permissions *Permissions) (*SSHServer, error) {
	sshServer := SSHServer{
		database:    database,
		auth:        auth,
		permissions: permissions,
	}

	keyName := "ssh_host_rsa_key"
	var hostKey *rsa.PrivateKey
	if _, err := os.Stat(keyName); err != nil {
		hostKey, err = rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			return nil, fmt.Errorf("error generating RSA key: %w", err)
		}

		// Get ASN.1 DER format
		privDER := x509.MarshalPKCS1PrivateKey(hostKey)

		// pem.Block
		privBlock := pem.Block{
			Type:    "RSA PRIVATE KEY",
			Headers: nil,
			Bytes:   privDER,
		}

		file, err := os.Create(keyName)
		if err != nil {
			return nil, fmt.Errorf("error creating RSA key file: %w", err)
		}

		err = pem.Encode(file, &privBlock)
		file.Close()
		if err != nil {
			return nil, fmt.Errorf("error encoding RSA key: %w", err)
		}
	} else {
		bytes, err := os.ReadFile(keyName)
		if err != nil {
			return nil, fmt.Errorf("error reading RSA key file: %w", err)
		}
		block, _ := pem.Decode(bytes)
		hostKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("error parsing RSA key: %w", err)
		}
	}

	signer, err := gossh.NewSignerFromKey(hostKey)
	if err != nil {
		return nil, fmt.Errorf("error creating SSH signer: %w", err)
	}

	forwardHandler := &ssh.ForwardedTCPHandler{}

	sshServer.server = &ssh.Server{
		Addr:             ":" + config.SshPort,
		Handler:          sshServer.sessionHandler,
		PublicKeyHandler: sshServer.publicKeyHandler,
		HostSigners: []ssh.Signer{
			signer,
		},
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
	authorizedKey := gossh.MarshalAuthorizedKey(ses.PublicKey())
	io.WriteString(ses, fmt.Sprintf("Hello %s your public key is\n", ses.User()))
	ses.Write(authorizedKey)
}

func (s *SSHServer) checkDestination(ctx ssh.Context, destHost string, destPort uint32) bool {
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
