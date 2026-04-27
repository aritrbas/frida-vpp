// echo_client.go — Simple TCP echo client for testing Frida VCL interception
//
// Build: go build -o echo_client echo_client.go
//
// Run (without Frida — verifies basic functionality):
//   ./echo_client
//   ./echo_client localhost:9876
//
// Run (with Frida + VCL interception):
//   VCL_CONFIG=/tmp/client-share/vcl.conf frida -f ./echo_client -l ../interceptor.js
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

	// If a second argument is given, use it as a one-shot message instead of stdin.
	// This avoids Frida REPL stealing stdin when run as:
	//   frida -f ./echo_client -l script.js -- 127.0.0.1:9876 "hello vcl"
	var oneShot string
	if len(os.Args) > 2 {
		oneShot = os.Args[2]
	}

	fmt.Println("[client] Connecting to", addr)

	// This triggers: syscall.socket, syscall.connect, syscall.getsockopt
	// Use "tcp4" to force IPv4 — matches server's tcp4 listener.
	conn, err := net.Dial("tcp4", addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[client] Dial error: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	fmt.Println("[client] Connected.")

	sendRecv := func(msg string) bool {
		_, err := conn.Write([]byte(msg + "\n"))
		if err != nil {
			fmt.Fprintf(os.Stderr, "[client] Write error: %v\n", err)
			return false
		}
		buf := make([]byte, 4096)
		n, err := conn.Read(buf)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[client] Read error: %v\n", err)
			return false
		}
		fmt.Printf("[client] Echo: %s", string(buf[:n]))
		return true
	}

	if oneShot != "" {
		sendRecv(oneShot)
	} else {
		fmt.Println("[client] Type messages (Ctrl+D to quit):")
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			msg := scanner.Text()
			if strings.TrimSpace(msg) == "" {
				continue
			}
			if !sendRecv(msg) {
				break
			}
		}
	}

	fmt.Println("[client] Done.")
}
