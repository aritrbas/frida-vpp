// http_client.go — Raw TCP HTTP client for testing Frida VCL interception
//
// Uses raw TCP (not net/http) for explicit control over syscall flow.
// Sends a GET request, reads the response, and validates it.
//
// Build: go build -o http_client http_client.go
//
// Run (without Frida):
//   ./http_client
//   ./http_client 127.0.0.1:8080 /health
//
// Run (with Frida + VCL interception):
//   VCL_CONFIG=/tmp/vcl.conf frida -f ./http_client -l ../interceptor.js -- 127.0.0.1:8080 /
//
// Exit codes:
//   0 = success (got HTTP 200 OK)
//   1 = failure (connection error, bad response, etc.)

package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"time"
)

func main() {
	addr := "127.0.0.1:8080"
	path := "/"

	if len(os.Args) > 1 {
		addr = os.Args[1]
	}
	if len(os.Args) > 2 {
		path = os.Args[2]
	}

	log.Printf("[http_client] PID: %d", os.Getpid())
	log.Printf("[http_client] GET http://%s%s", addr, path)

	// Use "tcp4" to force IPv4 — matches server
	conn, err := net.DialTimeout("tcp4", addr, 5*time.Second)
	if err != nil {
		log.Fatalf("[http_client] Connect error: %v", err)
	}
	defer conn.Close()

	log.Printf("[http_client] Connected to %s", conn.RemoteAddr().String())

	// Send HTTP request
	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, addr)
	_, err = conn.Write([]byte(req))
	if err != nil {
		log.Fatalf("[http_client] Write error: %v", err)
	}

	// Read full response
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	var resp []byte
	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			resp = append(resp, buf[:n]...)
		}
		if err != nil {
			if err != io.EOF {
				log.Printf("[http_client] Read error: %v", err)
			}
			break
		}
	}

	if len(resp) == 0 {
		fmt.Println("FAIL: empty response")
		os.Exit(1)
	}

	respStr := string(resp)
	fmt.Println(respStr)

	// Validate response
	if strings.HasPrefix(respStr, "HTTP/1.1 200 OK") {
		fmt.Println("PASS: got HTTP 200 OK")
	} else {
		fmt.Println("FAIL: unexpected response status")
		os.Exit(1)
	}
}
