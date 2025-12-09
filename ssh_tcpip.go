package main

import (
	"io"
	"log/slog"
	"net"
	"strconv"

	"github.com/gliderlabs/ssh"
	gossh "golang.org/x/crypto/ssh"
)

// based on tcpip.go of github.com/gliderlabs/ssh
//  > add metric collection
//  > improved error messages

// direct-tcpip data struct as specified in RFC4254, Section 7.2
type localForwardChannelData struct {
	DestAddr string
	DestPort uint32

	OriginAddr string
	OriginPort uint32
}

// directTCPIPHandler handles direct-tcpip channels
func (s *SSHServer) directTCPIPHandler(_ *ssh.Server, conn *gossh.ServerConn, newChan gossh.NewChannel, ctx ssh.Context) {
	d := localForwardChannelData{}
	if err := gossh.Unmarshal(newChan.ExtraData(), &d); err != nil {
		_ = newChan.Reject(gossh.ConnectionFailed, "error parsing forward data: "+err.Error())
		return
	}

	// get user from database and check for validity
	user, err := s.database.GetUser(ctx.User())
	if err != nil {
		slog.Error("failed to get user from database", "user", ctx.User(), "error", err)
		_ = newChan.Reject(gossh.ConnectionFailed, "failed to get user from database")
		return
	}
	if user.ID == 0 {
		_ = newChan.Reject(gossh.Prohibited, "unknown user")
		return
	}

	// Check OAuth token validity
	err, err2 := s.auth.CheckUserToken(user, nil)
	if err != nil {
		_ = newChan.Reject(gossh.Prohibited, "invalid/expired auth token > login on web interface")
		return
	}
	if err2 != nil {
		slog.Error("failed to update access token in database", "error", err2, "user", ctx.User())
		_ = newChan.Reject(gossh.ConnectionFailed, "failed to update access token")
		return
	}

	// Resolve destination host to IP addresses
	ips, err := net.LookupIP(d.DestAddr)
	if err != nil || len(ips) == 0 {
		slog.Error("failed to resolve destination host", "host", d.DestAddr, "error", err)
		_ = newChan.Reject(gossh.ConnectionFailed, "failed to resolve destination host "+d.DestAddr)
		return
	}

	// Check permissions for each resolved IP
	for _, ip := range ips {
		if !s.permissions.CheckPermission(ctx.User(), ip.String()) {
			slog.Warn("permission denied for user", "user", ctx.User(), "ip", ip.String())
			_ = newChan.Reject(gossh.Prohibited, "permission denied for "+ip.String())
			return
		}
	}

	dest := net.JoinHostPort(d.DestAddr, strconv.FormatInt(int64(d.DestPort), 10))

	var dialer net.Dialer
	dconn, err := dialer.DialContext(ctx, "tcp", dest)
	if err != nil {
		_ = newChan.Reject(gossh.ConnectionFailed, err.Error())
		return
	}

	ch, reqs, err := newChan.Accept()
	if err != nil {
		_ = dconn.Close()
		return
	}
	go gossh.DiscardRequests(reqs)

	go func() {
		defer ch.Close()
		defer dconn.Close()

		_, _ = io.Copy(ch, handleMetric(dconn, mDataReceived, conn.User()))
	}()
	go func() {
		defer ch.Close()
		defer dconn.Close()

		_, _ = io.Copy(dconn, handleMetric(ch, mDataSend, conn.User()))
	}()
}
