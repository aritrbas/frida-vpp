// echo_server.go — Simple TCP echo server for testing Frida VCL interception
//
// Build: go build -o echo_server echo_server.go
//
// Run (without Frida — verifies basic functionality):
//   ./echo_server
//
// Run (with Frida + VCL interception):
//   VCL_CONFIG=/tmp/server-share/vcl.conf frida ./echo_server -l interceptor_fixed.js
//
// The server listens on 0.0.0.0:9876 and echoes back anything it receives.
// It logs each syscall-level operation so you can verify Frida intercepts them.

package main

import (
	"fmt"
	"io"
	"net"
	"os"
)

func main() {
	addr := "0.0.0.0:9876"
	if len(os.Args) > 1 {
		addr = os.Args[1]
	}

	fmt.Println("[server] Starting echo server on", addr)

	// This triggers: syscall.socket, syscall.setsockopt, syscall.bind, syscall.Listen, syscall.getsockname
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[server] Listen error: %v\n", err)
		os.Exit(1)
	}
	defer ln.Close()

	fmt.Println("[server] Listening. Waiting for connections...")

	for {
		// This triggers: syscall.accept4
		conn, err := ln.Accept()
		if err != nil {
			fmt.Fprintf(os.Stderr, "[server] Accept error: %v\n", err)
			continue
		}

		fmt.Println("[server] Accepted connection from", conn.RemoteAddr())

		// Handle each connection in a goroutine
		go handleConn(conn)
	}
}

func handleConn(conn net.Conn) {
	defer conn.Close()

	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			if err != io.EOF {
				fmt.Fprintf(os.Stderr, "[server] Read error: %v\n", err)
			}
			fmt.Println("[server] Connection closed from", conn.RemoteAddr())
			return
		}

		fmt.Printf("[server] Received %d bytes from %s: %s\n", n, conn.RemoteAddr(), string(buf[:n]))

		// Echo back
		_, err = conn.Write(buf[:n])
		if err != nil {
			fmt.Fprintf(os.Stderr, "[server] Write error: %v\n", err)
			return
		}
	}
}
