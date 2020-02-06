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

	// TODO: load from config/DB
	s := jounce.Server{
		Hostname: "localhost",
		Logger:   log.New(log.Writer(), "", log.LstdFlags),
		Upstreams: []jounce.Upstream{{
			Addr:     "chat.freenode.net:6697",
			Nick:     "jounce",
			Username: "jounce",
			Realname: "jounce",
		}},
	}

	log.Printf("Server listening on %v", addr)
	go s.Run()
	log.Fatal(s.Serve(ln))
}
