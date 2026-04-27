// http_server.go — Raw TCP HTTP server for testing Frida VCL interception
//
// Uses raw TCP (not net/http) for explicit control over syscall flow.
// Supports concurrent connections via goroutines — frida-vpp's per-function
// hook strategy is goroutine-safe (Frida's this._ is per-invocation).
//
// Build: go build -o http_server http_server.go
//
// Run (without Frida — verifies basic functionality):
//   ./http_server
//   ./http_server 8080
//
// Run (with Frida + VCL interception):
//   VCL_CONFIG=/tmp/vcl.conf frida -f ./http_server -l ../interceptor.js -- 8080
//
// Test with curl:
//   curl http://127.0.0.1:8080/
//   curl http://127.0.0.1:8080/health
//
// Or use the companion http_client.go.

package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

var requestCount int64

func main() {
	port := "8080"
	if len(os.Args) > 1 {
		port = os.Args[1]
	}

	addr := "0.0.0.0:" + port

	log.Printf("[http_server] Starting on %s (PID: %d)", addr, os.Getpid())

	// Use "tcp4" to force IPv4 — avoids dual-stack issues with VPP
	ln, err := net.Listen("tcp4", addr)
	if err != nil {
		log.Fatalf("[http_server] Listen error: %v", err)
	}
	defer ln.Close()

	log.Printf("[http_server] Listening on %s", ln.Addr().String())

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("[http_server] Accept error: %v", err)
			continue
		}

		// Handle each connection concurrently — goroutine-safe with frida-vpp
		go handleHTTP(conn)
	}
}

func handleHTTP(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	remote := conn.RemoteAddr().String()

	// Read request (up to 8KB header)
	buf := make([]byte, 8192)
	n, err := conn.Read(buf)
	if err != nil {
		if err != io.EOF {
			log.Printf("[http_server] Read error from %s: %v", remote, err)
		}
		return
	}

	req := string(buf[:n])
	lines := strings.SplitN(req, "\r\n", 2)
	if len(lines) == 0 {
		return
	}

	// Parse request line: "GET /path HTTP/1.1"
	parts := strings.Fields(lines[0])
	method := "?"
	path := "/"
	if len(parts) >= 2 {
		method = parts[0]
		path = parts[1]
	}

	count := atomic.AddInt64(&requestCount, 1)
	log.Printf("[http_server] [%d] %s %s from %s", count, method, path, remote)

	// Route by path
	var statusCode int
	var body string

	switch path {
	case "/health":
		statusCode = 200
		body = `{"status":"ok"}` + "\n"
		sendResponse(conn, statusCode, "application/json", body)
	default:
		statusCode = 200
		body = fmt.Sprintf(`<!DOCTYPE html>
<html>
<head><title>Go HTTP Server with VPP</title></head>
<body>
    <h1>Hello from Go + VPP!</h1>
    <p>Request #%d</p>
    <p>Method: %s</p>
    <p>Path: %s</p>
    <p>Client: %s</p>
    <p>Time: %s</p>
    <hr>
    <p><i>Served via Frida VCL interceptor (goroutine-safe)</i></p>
</body>
</html>
`, count, method, path, remote, time.Now().Format(time.RFC3339))
		sendResponse(conn, statusCode, "text/html; charset=utf-8", body)
	}
}

func sendResponse(conn net.Conn, statusCode int, contentType, body string) {
	statusText := "OK"
	if statusCode == 404 {
		statusText = "Not Found"
	}

	resp := fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Type: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		statusCode, statusText, contentType, len(body), body)

	_, err := conn.Write([]byte(resp))
	if err != nil {
		log.Printf("[http_server] Write error: %v", err)
	}
}
