// Package main is a minimal WebSocket echo verification client used by the
// Phase 7c deployment verification (g): connects to the gateway's WSS
// listener, sends one text frame and expects the echo back.
package main

import (
	"crypto/tls"
	"fmt"
	"os"
	"time"

	"github.com/gorilla/websocket"
)

func main() {
	url := os.Args[1]
	msg := os.Args[2]

	dialer := websocket.Dialer{
		TLSClientConfig:  &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // local Vault PKI CA
		HandshakeTimeout: 10 * time.Second,
	}

	conn, _, err := dialer.Dial(url, nil)
	if err != nil {
		fmt.Println("DIAL_ERROR:", err)
		os.Exit(1)
	}
	defer func() { _ = conn.Close() }()

	if err := conn.WriteMessage(websocket.TextMessage, []byte(msg)); err != nil {
		fmt.Println("WRITE_ERROR:", err)
		os.Exit(1)
	}

	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	_, reply, err := conn.ReadMessage()
	if err != nil {
		fmt.Println("READ_ERROR:", err)
		os.Exit(1)
	}
	fmt.Printf("WS_ECHO_REPLY: %s\n", string(reply))
}
