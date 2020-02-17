package main

import (
	"flag"
	"log"
	"net"

	"git.sr.ht/~emersion/jounce"
)

func main() {
	var addr, hostname string
	flag.StringVar(&addr, "addr", ":6667", "listening address")
	flag.StringVar(&hostname, "hostname", "localhost", "server hostname")
	flag.Parse()

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("failed to start listener: %v", err)
	}

	srv := jounce.NewServer()
	// TODO: load from config/DB
	srv.Hostname = hostname
	srv.Upstreams = []jounce.Upstream{{
		Addr:     "chat.freenode.net:6697",
		Nick:     "jounce",
		Username: "jounce",
		Realname: "jounce",
		Channels: []string{"#jounce"},
	}}

	log.Printf("server listening on %v", addr)
	go srv.Run()
	log.Fatal(srv.Serve(ln))
}
