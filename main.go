package main

import (
	"log"
)

func main() {
	permissions, err := NewPermissions()
	if err != nil {
		log.Fatal(err)
	}

	database, err := NewDatabase()
	if err != nil {
		log.Fatal(err)
	}

	auth := &Auth{Database: database}

	web, err := NewWeb(database, auth, permissions)
	if err != nil {
		log.Fatal(err)
	}
	go web.Run()

	sshServer, err := NewSSHServer(database, auth, permissions)
	if err != nil {
		log.Fatal(err)
	}
	err = sshServer.Run()
	if err != nil {
		log.Fatal(err)
	}
}
