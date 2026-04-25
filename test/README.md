# Testing the Frida VCL Interceptor

This directory contains sample Go programs to test the Frida-based VCL interception.
See `docs/abi_analysis.md` for the technical background on why this is needed.

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
export VPP_LIB=/home/aritrbas/vpp/build-root/install-vpp_debug-native/vpp/lib/x86_64-linux-gnu
export LD_LIBRARY_PATH=$VPP_LIB
frida ./test/echo_server -l interceptor_server.js
```

You should see:
```
[+] Found syscall.socket at 0x...
[+] Found syscall.setsockopt at 0x...
[+] Found syscall.bind at 0x...
[+] Found syscall.Listen at 0x...
[+] Found syscall.getsockname at 0x...
[+] Found syscall.accept4 at 0x...
[+] Loaded /home/aritrbas/vpp/build-root/install-vpp_debug-native/vpp/lib/x86_64-linux-gnu/libvcl_ldpreload.so
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
export VPP_LIB=/home/aritrbas/vpp/build-root/install-vpp_debug-native/vpp/lib/x86_64-linux-gnu
export LD_LIBRARY_PATH=$VPP_LIB
VCL_CONFIG=/tmp/server-share/vcl.conf frida ./test/echo_server -l interceptor_server.js
```

### Client:
```bash
export VPP_LIB=/home/aritrbas/vpp/build-root/install-vpp_debug-native/vpp/lib/x86_64-linux-gnu
export LD_LIBRARY_PATH=$VPP_LIB
# Use -f (spawn mode) and pass address + message as arguments to avoid Frida REPL stealing stdin
VCL_CONFIG=/tmp/client-share/vcl.conf \
  frida -f ./test/echo_client -l interceptor_client.js \
  -- 127.0.0.1:9876 "hello vcl"
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
VCL_CONFIG=/tmp/server-share/vcl.conf frida /usr/bin/echo_server -l /usr/bin/interceptor_server.js

# In client container
docker exec -it <client_container> bash
VCL_CONFIG=/tmp/client-share/vcl.conf frida /usr/bin/echo_client -l /usr/bin/interceptor_client.js
```

## What to Look For

### Success indicators:
- `[+] socket succeeded: ret=N` — VCL returned a valid session handle
- `[+] bind succeeded: ret=0`
- `[+] listen succeeded: ret=0`
- `[+] accept4 succeeded: ret=N` — Accepted a VCL session
- `[dbg] POLLOUT fired — session READY` — Connect completed via epoll MQ pump
- `[client] Echo: hello vcl` — Full E2E echo working
- `[client] Done.` — Client exited cleanly
- Server echoes data back to client

### Failure indicators:
- `[!] socket failed: ret=-1, errno=N` — Check VCL_CONFIG and VPP status
- `connect failed! no route` — IPv4/IPv6 mismatch; use `"tcp4"` in Go binaries
- `fatal error: runtime: split stack overflow` — Stack issue, ensure Go binary is not stripped
- No hook output at all — Binary name mismatch (check `moduleName` in the script)
- Hooks fire but wrong arguments — ABI mapping issue (check register values in logs)
- Infinite `getsockopt(SO_ERROR)` spam — EINPROGRESS passed to Go runtime; fix: use epoll_wait in hook

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
| `connect failed! no route` | IPv4/IPv6 mismatch | Use `"tcp4"` in Go `net.Listen`/`net.Dial` |
| write ENOTCONN forever | VCL MQ not processed | Ensure hooks use `ldp.epoll_wait()` pattern |
| getsockopt SO_ERROR spam | EINPROGRESS passed to Go | Don't pass EINPROGRESS to Go; use epoll_wait in connect hook |

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
