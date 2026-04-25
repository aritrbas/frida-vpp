# Testing the Frida VCL Interceptor

This directory contains sample Go programs to test the Frida-based VCL interception.
See `docs/abi_analysis.md` for the technical background on why this is needed.

## Prerequisites

- Linux x86_64 with VPP installed
- `libvcl_ldpreload.so` at `/usr/lib/libvcl_ldpreload.so`
- Frida installed: `pip3 install frida frida-tools`
- Go compiler: `apt install golang-go`

## Step 1: Build the Test Binaries

```bash
cd test/

# Build server (with symbols — do NOT strip)
go build -o echo_server echo_server.go

# Build client
go build -o echo_client echo_client.go
```

**Important:** Do NOT use `-ldflags="-s -w"` — Frida needs the Go symbols.

## Step 2: Verify Without Frida (Baseline Test)

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

## Step 3: Test with Frida (Without VCL — Verify Hooks Fire)

This step verifies that the Frida hooks are installed correctly before adding VCL to the mix.

In terminal 1 (run from the repo root):
```bash
frida ./test/echo_server -l interceptor_server.js --no-pause
```

You should see:
```
[+] Found syscall.socket at 0x...
[+] Found syscall.setsockopt at 0x...
[+] Found syscall.bind at 0x...
[+] Found syscall.Listen at 0x...
[+] Found syscall.getsockname at 0x...
[+] Found syscall.accept4 at 0x...
[+] Loaded /usr/lib/libvcl_ldpreload.so
[+] Hooked syscall.socket
[+] Hooked syscall.setsockopt
[+] Hooked syscall.bind
[+] Hooked syscall.Listen
[+] Hooked syscall.getsockname
[+] Hooked syscall.accept4
[+] All hooks installed. Go syscalls will be redirected to VCL.
[>] socket(2, 524289, 0)
[+] socket succeeded: ret=...
[>] setsockopt(...)
...
```

## Step 4: Test with VPP/VCL

Ensure VPP is running and VCL config is available.

### Server:
```bash
VCL_CONFIG=/tmp/server-share/vcl.conf frida /path/to/echo_server -l interceptor_server.js --no-pause
```

### Client:
```bash
VCL_CONFIG=/tmp/client-share/vcl.conf frida /path/to/echo_client -l interceptor_client.js --no-pause
```

### In Docker (HST framework):
```bash
# Copy files to container
docker cp echo_server <container_id>:/usr/bin/echo_server
docker cp echo_client <container_id>:/usr/bin/echo_client
docker cp interceptor_server.js <container_id>:/usr/bin/interceptor_server.js
docker cp interceptor_client.js <container_id>:/usr/bin/interceptor_client.js

# In server container
docker exec -it <server_container> bash
VCL_CONFIG=/tmp/server-share/vcl.conf frida /usr/bin/echo_server -l /usr/bin/interceptor_server.js --no-pause

# In client container
docker exec -it <client_container> bash
VCL_CONFIG=/tmp/client-share/vcl.conf frida /usr/bin/echo_client -l /usr/bin/interceptor_client.js --no-pause
```

## What to Look For

### Success indicators:
- `[+] socket succeeded: ret=N` — VCL returned a valid session handle
- `[+] bind succeeded: ret=0`
- `[+] listen succeeded: ret=0`
- `[+] accept4 succeeded: ret=N` — Accepted a VCL session
- Server echoes data back to client

### Failure indicators:
- `[!] socket failed: ret=-1, errno=N` — Check VCL_CONFIG and VPP status
- `fatal error: runtime: split stack overflow` — Stack issue, ensure Go binary is not stripped
- No hook output at all — Binary name mismatch (check `moduleName` in the script)
- Hooks fire but wrong arguments — ABI mapping issue (check register values in logs)

## Troubleshooting

### Enabling verbose logging

Add register dumps to the script by modifying `onEnter`:
```js
onEnter: function(args) {
    console.log('Registers:', JSON.stringify(this.context, null, 2));
    // ... existing code ...
}
```

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
| Hooks don't fire | Wrong `moduleName` | Set to basename of binary |
| `symbol not found` | Stripped binary | Rebuild without `-ldflags="-s -w"` |
| VCL errors | VPP not running / bad config | Check `VCL_CONFIG`, restart VPP |
| `accept4` hangs forever | No client connecting | Connect a client |
| Crash in LDP function | Bad pointer argument | Check `rdi`/`rbx` pointer validity |

## Architecture of the Fix

```
Go code: net.Listen("tcp", ":9876")
  └→ syscall.socket(AF_INET, SOCK_STREAM, 0)
       │
       ├─ [BEFORE] Go ABI: rax=2, rbx=1, rcx=0
       │
       ├─ Frida onEnter: save rax→_domain, rbx→_type, rcx→_protocol
       │
       ├─ Trampoline: `ret` (immediate return, no-op)
       │
       ├─ Frida onLeave:
       │    ├─ Call ldp.socket(_domain, _type, _protocol) → fd=3
       │    ├─ retval.replace(3)        → rax = 3
       │    ├─ context.rbx = ptr(0)     → rbx = 0  (no second return value)
       │    └─ context.rcx = ptr(0)     → rcx = 0  (no error)
       │
       └─ [AFTER] Go ABI: rax=3, rbx=0, rcx=0  ← Go sees success!
```
