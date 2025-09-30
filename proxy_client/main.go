package main

import (
	"context"
	"crypto/tls"
	"flag"
	"log"
	"net/http"
	"os"

	"github.com/bboehmke/jump-gopher/lib"
	"github.com/coder/websocket"
)

var ignoreCert = flag.Bool("ignore_certificates", false, "Skip certificate validation")

func main() {
	flag.Parse()

	if flag.NArg() != 1 {
		log.Fatalf("Exactly one argument required, the URL to connect to.")
	}
	url := flag.Arg(0)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wsOpts websocket.DialOptions
	if *ignoreCert {
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		wsOpts.HTTPClient = &http.Client{Transport: tr}
	}

	ws, _, err := websocket.Dial(ctx, url, &wsOpts)
	if err != nil {
		panic(err)
	}
	defer ws.CloseNow()

	// websocket -> stdout
	go func() {
		err := lib.WsReader(ctx, ws, os.Stdout)
		if err != nil {
			log.Printf("Websocket reader error: %v", err)
		}
		cancel()
	}()

	// stdin -> websocket
	err = lib.WsWriter(ctx, ws, os.Stdin)
	if err != nil {
		log.Printf("Websocket writer error: %v", err)
	}
}
