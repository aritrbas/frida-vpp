// echo_client.go — Simple TCP echo client for testing Frida VCL interception
//
// Build: go build -o echo_client echo_client.go
//
// Run (without Frida — verifies basic functionality):
//   ./echo_client
//   ./echo_client localhost:9876
//
// Run (with Frida + VCL interception):
//   VCL_CONFIG=/tmp/client-share/vcl.conf frida ./echo_client -l interceptor_fixed_client.js
//
// The client connects to the echo server, sends messages, and prints responses.
// It triggers: syscall.socket, syscall.connect, syscall.getsockopt

package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
)

func main() {
	addr := "127.0.0.1:9876"
	if len(os.Args) > 1 {
		addr = os.Args[1]
	}

	fmt.Println("[client] Connecting to", addr)

	// This triggers: syscall.socket, syscall.connect, syscall.getsockopt
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[client] Dial error: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	fmt.Println("[client] Connected. Type messages (Ctrl+D to quit):")

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		msg := scanner.Text()
		if strings.TrimSpace(msg) == "" {
			continue
		}

		// Send message
		_, err := conn.Write([]byte(msg + "\n"))
		if err != nil {
			fmt.Fprintf(os.Stderr, "[client] Write error: %v\n", err)
			return
		}

		// Read echo response
		buf := make([]byte, 4096)
		n, err := conn.Read(buf)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[client] Read error: %v\n", err)
			return
		}

		fmt.Printf("[client] Echo: %s", string(buf[:n]))
	}

	fmt.Println("[client] Done.")
}
