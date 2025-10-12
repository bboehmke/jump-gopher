package main

import (
	"log/slog"
	"os"
)

func main() {
	initConfig()

	if *checkConfig {
		slog.Info("Check permissions config")
	} else {
		slog.Info("Starting jump-gopher server")
	}

	permissions, err := NewPermissions()
	if err != nil {
		slog.Error("Failed to load permissions", "error", err)
		os.Exit(1)
	}

	if *checkConfig {
		os.Exit(0)
	}

	database, err := NewDatabase()
	if err != nil {
		slog.Error("Failed to connect to database", "error", err)
		os.Exit(2)
	}

	auth := &Auth{Database: database}

	web, err := NewWeb(database, auth, permissions)
	if err != nil {
		slog.Error("Failed to initialize web", "error", err)
		os.Exit(3)
	}
	go web.Run()

	sshServer, err := NewSSHServer(database, auth, permissions)
	if err != nil {
		slog.Error("Failed to initialize ssh server", "error", err)
		os.Exit(4)
	}
	err = sshServer.Run()
	if err != nil {
		slog.Error("Failed to start ssh server", "error", err)
		os.Exit(5)
	}
}
