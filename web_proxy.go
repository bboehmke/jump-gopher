package main

import (
	"context"
	"log"
	"net"
	"time"

	"github.com/bboehmke/jump-gopher/lib"
	"github.com/coder/websocket"
	"github.com/gin-gonic/gin"
)

func (w *Web) handleProxy(c *gin.Context) {
	ws, err := websocket.Accept(c.Writer, c.Request, nil)
	if err != nil {
		log.Println(err)
		return
	}
	defer ws.CloseNow()

	sshSocket, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", config.SshPort), time.Second*5)
	if err != nil {
		log.Println(err)
		return
	}
	defer sshSocket.Close()

	ctx, cancel := context.WithCancel(c)
	defer cancel()

	// websocket -> server
	go func() {
		err := lib.WsReader(ctx, ws, sshSocket)
		if err != nil {
			log.Printf("Websocket reader error: %v", err)
		}
		cancel()
	}()

	// server -> websocket
	err = lib.WsWriter(ctx, ws, sshSocket)
	if err != nil {
		log.Printf("Websocket writer error: %v", err)
	}
}
