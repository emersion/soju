package jounce

import (
	"fmt"
	"log"
	"net"

	"gopkg.in/irc.v3"
)

func handleConn(conn net.Conn) error {
	defer conn.Close()

	ircConn := irc.NewConn(conn)
	for {
		msg, err := ircConn.ReadMessage()
		if err != nil {
			return err
		}

		log.Println(msg)
	}
}

func Serve(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return fmt.Errorf("failed to accept connection: %v", err)
		}

		go func() {
			if err := handleConn(conn); err != nil {
				log.Printf("error handling connection: %v", err)
			}
		}()
	}
}
