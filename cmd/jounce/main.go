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

	srv := jounce.NewServer()
	// TODO: load from config/DB
	srv.Hostname = "localhost"
	srv.Upstreams = []jounce.Upstream{{
		Addr:     "chat.freenode.net:6697",
		Nick:     "jounce",
		Username: "jounce",
		Realname: "jounce",
		Channels: []string{"#jounce"},
	}}

	log.Printf("Server listening on %v", addr)
	go srv.Run()
	log.Fatal(srv.Serve(ln))
}
