package lib

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"

	"github.com/coder/websocket"
)

func WsReader(ctx context.Context, ws *websocket.Conn, writer io.Writer) error {
	for {
		msgType, reader, err := ws.Reader(ctx)
		if errors.Is(err, context.Canceled) || errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("failed to get websocket reader: %w", err)
		}
		if msgType != websocket.MessageBinary {
			log.Printf("Ignoring non-binary websocket message of type %d", msgType)
			continue
		}
		if _, err := io.Copy(writer, reader); err != nil {
			return fmt.Errorf("failed to copy from websocket: %w", err)
		}
	}
}

func WsWriter(ctx context.Context, ws *websocket.Conn, reader io.Reader) error {
	for {
		if ctx.Err() != nil {
			return nil
		}

		buffer := make([]byte, 32*1024)
		n, err := reader.Read(buffer)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("failed to read reader: %w", err)
		}
		buffer = buffer[:n]

		err = ws.Write(ctx, websocket.MessageBinary, buffer)
		if err != nil {
			return fmt.Errorf("failed to write to websocket: %w", err)

		}
	}
}
