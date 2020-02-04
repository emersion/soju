package main

import (
	"log"
	"net"

	"git.sr.ht/~emersion/jounce"
)

func main() {
	addr := ":6667"

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("failed to start listener: %v", err)
	}

	log.Printf("Server listening on %v", addr)
	log.Fatal(jounce.Serve(ln))
}
