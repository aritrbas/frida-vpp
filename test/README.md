# Testing the Frida VCL Interceptor

This directory contains sample Go programs to test the Frida-based VCL interception.
All test binaries are designed to work with the unified `interceptor.js` script.

## Test Programs

| Program | Type | Description |
|---------|------|-------------|
| `echo_server.go` | TCP echo | Listens on `0.0.0.0:9876`, echoes back any data received |
| `echo_client.go` | TCP echo | Connects, sends message, prints echo response |
| `http_server.go` | Raw TCP HTTP | Listens on `0.0.0.0:8080`, serves HTML and JSON endpoints |
| `http_client.go` | Raw TCP HTTP | Sends GET request, validates HTTP 200 OK response |

All programs use `"tcp4"` (IPv4) to avoid dual-stack issues with VPP.
HTTP programs use raw TCP (not `net/http`) for explicit control over the syscall flow.

## Prerequisites

- Linux x86_64 with VPP built from source at `/home/aritrbas/vpp`
- Frida installed: `pip3 install frida frida-tools`
- Go compiler: `apt install golang-go`

The VCL library lives in the VPP build tree — **not** `/usr/lib`:
```
/home/aritrbas/vpp/build-root/install-vpp_debug-native/vpp/lib/x86_64-linux-gnu/libvcl_ldpreload.so
```

You **must** set `LD_LIBRARY_PATH` to that directory before running frida so that
`libvcl_ldpreload.so`'s own dependencies (`libvppcom.so.26.06` etc.) are found:
```bash
export VPP_LIB=/home/aritrbas/vpp/build-root/install-vpp_debug-native/vpp/lib/x86_64-linux-gnu
export LD_LIBRARY_PATH=$VPP_LIB
```

## Step 1: Build the Test Binaries

```bash
cd test/

# Build all test binaries (with symbols — do NOT strip)
go build -o echo_server echo_server.go
go build -o echo_client echo_client.go
go build -o http_server http_server.go
go build -o http_client http_client.go
```

**Important:** Do NOT use `-ldflags="-s -w"` — Frida needs the Go symbols.

## Step 2: Verify Without Frida (Baseline Test)

### Echo (TCP):

In terminal 1:
```bash
./echo_server
# Output: [server] Starting echo server on 0.0.0.0:9876
# Output: [server] Listening. Waiting for connections...
```

In terminal 2:
```bash
./echo_client
# Output: [client] Connecting to 127.0.0.1:9876
# Output: [client] Connected. Type messages (Ctrl+D to quit):
# Type: hello
# Output: [client] Echo: hello
```

### HTTP:

In terminal 1:
```bash
./http_server
# Output: [http_server] Starting on 0.0.0.0:8080
# Output: [http_server] Listening on 0.0.0.0:8080
```

In terminal 2:
```bash
./http_client
# Output: HTTP/1.1 200 OK ...
# Output: PASS: got HTTP 200 OK

./http_client 127.0.0.1:8080 /health
# Output: {"status":"ok"}
# Output: PASS: got HTTP 200 OK
```

## Step 3: Test with Frida (Without VCL — Passthrough Mode)

This step verifies that the Frida hooks are detected correctly before adding VCL.

From the repo root:
```bash
export VPP_LIB=/home/aritrbas/vpp/build-root/install-vpp_debug-native/vpp/lib/x86_64-linux-gnu
export LD_LIBRARY_PATH=$VPP_LIB

# interceptor.js auto-detects the Go binary — no moduleName editing needed
frida -f ./test/echo_server -l interceptor.js
```

You should see:
```
[+] Auto-detected Go binary: echo_server
[+] Found syscall.socket at 0x...
[+] Found syscall.bind at 0x...
...
[*] VCL_CONFIG not set — passthrough mode (hooks log but syscalls go to kernel).
```

## Step 4: Test with VPP/VCL

Ensure VPP is running with session support and VCL config is available.

### Create VCL config (only needed once):
```bash
mkdir -p /tmp/server-share /tmp/client-share
printf 'vcl {\n  rx-fifo-size 4000000\n  tx-fifo-size 4000000\n  app-scope-local\n  app-scope-global\n  use-mq-eventfd\n  app-socket-api /run/vpp/app_ns_sockets/default\n}\n' \
  > /tmp/server-share/vcl.conf
cp /tmp/server-share/vcl.conf /tmp/client-share/vcl.conf
```

### Echo (TCP) Test:
```bash
# Terminal 1 — server
VCL_CONFIG=/tmp/server-share/vcl.conf frida -f ./test/echo_server -l interceptor.js

# Terminal 2 — client (one-shot mode)
VCL_CONFIG=/tmp/client-share/vcl.conf \
  frida -f ./test/echo_client -l interceptor.js \
  -- 127.0.0.1:9876 "hello vcl"
# Expected: [client] Echo: hello vcl
```

### HTTP Test:
```bash
# Terminal 1 — server
VCL_CONFIG=/tmp/server-share/vcl.conf frida -f ./test/http_server -l interceptor.js -- 8080

# Terminal 2 — client
VCL_CONFIG=/tmp/client-share/vcl.conf \
  frida -f ./test/http_client -l interceptor.js \
  -- 127.0.0.1:8080 /
# Expected: PASS: got HTTP 200 OK

# Health endpoint
VCL_CONFIG=/tmp/client-share/vcl.conf \
  frida -f ./test/http_client -l interceptor.js \
  -- 127.0.0.1:8080 /health
# Expected: {"status":"ok"} + PASS
```

### In Docker (HST framework):
```bash
# Copy files to container
docker cp echo_server <container_id>:/usr/bin/echo_server
docker cp interceptor.js <container_id>:/usr/bin/interceptor.js

# In server container
docker exec -it <server_container> bash
VCL_CONFIG=/tmp/server-share/vcl.conf frida -f /usr/bin/echo_server -l /usr/bin/interceptor.js

# In client container
docker exec -it <client_container> bash
VCL_CONFIG=/tmp/client-share/vcl.conf \
  frida -f /usr/bin/echo_client -l /usr/bin/interceptor.js \
  -- 127.0.0.1:9876 "hello vcl"
```

### Automated Test Runner:
```bash
cd test/
./run_tests.sh          # run all tests (echo + HTTP)
./run_tests.sh echo     # echo test only
./run_tests.sh http     # HTTP test only
./run_tests.sh setup    # create VCL configs only
```

The test runner handles VCL config creation, server startup, client execution, and result validation automatically.

## What to Look For

### Success indicators:
- `[+] Auto-detected Go binary: ...` — interceptor.js found the Go module
- `[+] socket ok: ret=N` — VCL returned a valid session handle
- `[+] bind ok: ret=0`
- `[+] listen ok: ret=0`
- `[+] accept4 ok: ret=N` — Accepted a VCL session
- `[>] connect: POLLOUT → session READY` — Connect completed via epoll MQ pump
- `[client] Echo: hello vcl` — Full E2E echo working
- `PASS: got HTTP 200 OK` — HTTP test passed
- `[client] Done.` — Client exited cleanly

### Failure indicators:
- `[!] socket failed: ret=-1, errno=N` — Check VCL_CONFIG and VPP status
- `connect failed! no route` — IPv4/IPv6 mismatch; use `"tcp4"` in Go binaries
- `fatal error: runtime: split stack overflow` — Stack issue, ensure Go binary is not stripped
- No hook output at all — Ensure Go binary was built with symbols
- Infinite `getsockopt(SO_ERROR)` spam — EINPROGRESS passed to Go runtime; this is handled by interceptor.js

## Troubleshooting

### Enabling verbose logging

`interceptor.js` has configurable log levels. Edit the `LOG_LEVEL` variable:

| Level | Output |
|-------|--------|
| `0` | Errors only |
| `1` | Lifecycle events (symbols found, hooks installed) |
| `2` | All syscall invocations with arguments and results (default) |

### Checking VCL status
```bash
# Verify VPP is running
vppctl show version

# Verify VCL config
cat $VCL_CONFIG
```

### Common issues

| Problem | Cause | Fix |
|---------|-------|-----|
| Hooks don't fire | Stripped binary | Rebuild without `-ldflags="-s -w"` |
| `symbol not found` | Stripped binary | Same as above |
| VCL errors | VPP not running / bad config | Check `VCL_CONFIG`, restart VPP |
| `accept4` hangs forever | No client connecting | Connect a client |
| Crash in LDP function | Bad pointer argument | Check register values in logs |
| `connect failed! no route` | IPv4/IPv6 mismatch | Use `"tcp4"` in Go `net.Listen`/`net.Dial` |
| write ENOTCONN forever | VCL MQ not processed | Ensure hooks use `ldp.epoll_wait()` pattern |

## Architecture of the Fix

```
Go code: net.Listen("tcp4", ":9876")
  └→ syscall.socket(AF_INET, SOCK_STREAM, 0)
       │
       ├─ [BEFORE] Go ABI: rax=2, rbx=1, rcx=0
       │
       ├─ Frida onEnter: save rax→_domain, rbx→_type, rcx→_protocol
       │
       ├─ Trampoline: `ret` (immediate return, no-op)
       │
       ├─ Frida onLeave:
       │    ├─ Call ldp.socket(_domain, _type, _protocol) → fd=32 (VCL fake fd)
       │    ├─ retval.replace(32)       → rax = 32
       │    ├─ context.rbx = ptr(0)     → rbx = 0  (no second return value)
       │    └─ context.rcx = ptr(0)     → rcx = 0  (no error)
       │
       └─ [AFTER] Go ABI: rax=32, rbx=0, rcx=0  ← Go sees success!
```

See [docs/interceptor_architecture.md](../docs/interceptor_architecture.md) for the full technical design.
