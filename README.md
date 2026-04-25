# frida-vpp — Frida-Based VCL Interception for Go Binaries

## Problem

[VPP](https://fd.io/)'s VCL (VPP Communications Library) provides a user-space networking stack via `libvcl_ldpreload.so`, which intercepts POSIX socket calls through `LD_PRELOAD`. This works transparently for **C programs** because they call socket functions through libc's PLT/GOT.

**Go programs bypass libc entirely.** The Go runtime issues syscalls directly via the `SYSCALL` instruction (`runtime/internal/syscall.Syscall6`), so `LD_PRELOAD` has nothing to intercept. Additionally, Go uses its own register-based calling convention (Go ABI) that differs from the System V AMD64 ABI used by C libraries:

| Arg | Go ABI Register | System V Register |
|-----|----------------|-------------------|
| 1st | `rax` | `rdi` |
| 2nd | `rbx` | `rsi` |
| 3rd | `rcx` | `rdx` |
| Return | `rax, rbx, rcx` | `rax, rdx` |

This project uses [Frida](https://frida.re/) to dynamically intercept Go's socket-layer syscalls at runtime and redirect them to VCL, bridging the ABI gap.

**Status:** Full end-to-end echo test (client→server→client) working over VPP VCL.

## Repository Structure

```
frida-vpp/
├── interceptor_server.js          # Working Frida script for Go server binaries
├── interceptor_client.js          # Working Frida script for Go client binaries
├── docs/
│   ├── session2_debugging_report.md  # Sessions 2 & 3: all fixes, flowcharts, root cause analysis
│   ├── failed_attempt_analysis.md    # All experimental attempts and why they failed
│   └── abi_analysis.md               # Go ABI vs System V ABI + VCL MQ pump architecture
├── test/
│   ├── echo_server.go             # Sample TCP echo server for testing
│   ├── echo_client.go             # Sample TCP echo client for testing
│   └── README.md                  # Build, run, and test instructions
└── experiments/                   # All previous experimental attempts (for reference)
    ├── interceptor2.js            # Attempt: Hook libc symbols (fails — Go bypasses libc)
    ├── interceptor3.js            # Attempt: Direct replace Go symbols with LDP (fails — ABI mismatch)
    ├── interceptor4.js            # Attempt: Hook RawSyscall6 (fails — wrong register indexing)
    ├── interceptor5.js            # Attempt: prepRegs shim v1 (fails — copy-paste bug, no return cleanup)
    ├── interceptor_full_attempt.js    # Most complete attempt (fails — no rbx/rcx cleanup)
    ├── interceptor_syscall_level.js   # Syscall/RawSyscall6 level hooks (fails — no redirect)
    ├── interceptor_server_v1.js       # Server with global flag dispatch (fails — thread-unsafe)
    ├── interceptor_client_v1.js       # Client with global flag dispatch (fails — thread-unsafe)
    ├── prepRegs.asm               # NASM ABI shim (3-arg register shuffle)
    ├── prepRegs2.asm              # NASM ABI shim (multiple named variants)
    ├── prepRegs.s                 # Go plan9 assembly approach (can't inject via Frida)
    ├── wrapper.asm                # Various assembly wrapper experiments
    └── wrapper.go                 # Go CGo wrapper experiment
```

## How It Works

The interceptors (`interceptor_server.js`, `interceptor_client.js`) use this approach:

1. **Find Go symbols** — `Process.getModuleByName(name).enumerateSymbols()` locates `syscall.socket`, `syscall.bind`, `syscall.read`, `syscall.write`, `syscall.Close`, etc. in the Go binary.
2. **Replace with `ret` trampoline** — `Interceptor.replace()` swaps each Go function with a dynamically-allocated single-instruction `ret` (no-op).
3. **Read Go ABI registers in `onEnter`** — Before the trampoline runs, save arguments from Go ABI positions (`rax`, `rbx`, `rcx`, `rdi`, `rsi`).
4. **Call VCL in `onLeave`** — After the trampoline returns, call the corresponding LDP function with the saved arguments.
5. **Set Go return convention** — Set `rax=result`, `rbx=0`, `rcx=0` (success) or `rax=-1`, `rbx=err.itab`, `rcx=err.data` (error) using `go:itab.syscall.Errno,error` for arbitrary errno values.
6. **Conditional VCL loading** — If `VCL_CONFIG` is not set, the script runs in passthrough mode: hooks fire and log calls, but syscalls go to the kernel normally.

```
Go: syscall.socket(domain=2, type=1, proto=0)
  │ rax=2, rbx=1, rcx=0
  ├─ onEnter: save _domain=rax, _type=rbx, _protocol=rcx
  ├─ trampoline: ret (no-op)
  ├─ onLeave: ret = ldp.socket(2, 1, 0) → fd=32 (VCL fake fd = vlsh+32)
  │           rax=32, rbx=0, rcx=0
  └─ Go sees: fd=32, errno=0 ✓

Go: syscall.read(fd=32, buf, len)
  │ rax=32, rbx=buf_ptr, rcx=len
  ├─ onEnter: save _fd=32, _buf=buf_ptr, _len=len
  ├─ trampoline: ret (no-op)
  ├─ onLeave: ret = ldp.read(32, buf, len)  ← LDP routes fd≥32 to VCL
  │           if EAGAIN on VCL fd → ldp.epoll_wait(EPOLLIN, 5s)
  │           (epoll_wait processes VCL message queue, then retry)
  └─ Go sees: n bytes read ✓
```

### Why `read`/`write`/`close` must be hooked

LDP assigns fake fd numbers to VCL sessions (`fd = vlsh + 32`). These do not exist as kernel file descriptors. If Go calls the kernel's `read(fd=32, ...)` directly, the kernel returns `EBADF`. Hooking `syscall.read`, `syscall.write`, and `syscall.Close` ensures all I/O goes through LDP, which internally routes based on the fd value:
- `fd ≥ 32` → VCL session path
- `fd < 32` → real kernel fd path (libc passthrough)

## Quick Start

```bash
# Build test binaries (on Linux x86_64 with Go installed)
cd test/
go build -o echo_server echo_server.go
go build -o echo_client echo_client.go
cd ..

# Set LD_LIBRARY_PATH so VCL's own dependencies are found
export VPP_LIB=/home/aritrbas/vpp/build-root/install-vpp_debug-native/vpp/lib/x86_64-linux-gnu
export LD_LIBRARY_PATH=$VPP_LIB

# Step 3: Test without VCL — verify hooks fire (no VCL_CONFIG set)
frida ./test/echo_server -l interceptor_server.js
# Expected: "[*] VCL_CONFIG not set — passthrough mode"
# Then connect a client and see hooks log socket/bind/listen/accept4 calls.

# Step 4: Test with VPP/VCL (VPP must be running first)
# Create vcl.conf files (only needed once):
mkdir -p /tmp/server-share /tmp/client-share
printf 'vcl {\n  rx-fifo-size 4000000\n  tx-fifo-size 4000000\n  app-scope-local\n  app-scope-global\n  use-mq-eventfd\n  app-socket-api /run/vpp/app_ns_sockets/default\n}\n' \
  > /tmp/server-share/vcl.conf
cp /tmp/server-share/vcl.conf /tmp/client-share/vcl.conf

# Terminal 1 — server
VCL_CONFIG=/tmp/server-share/vcl.conf frida ./test/echo_server -l interceptor_server.js

# Terminal 2 — client (one-shot mode avoids Frida REPL stealing stdin)
VCL_CONFIG=/tmp/client-share/vcl.conf \
  frida -f ./test/echo_client -l interceptor_client.js \
  -- 127.0.0.1:9876 "hello vcl"
# Expected output: [client] Echo: hello vcl
```

See [test/README.md](test/README.md) for detailed instructions including Docker/HST setup.

## Key Bugs Fixed

All previous attempts failed due to three fundamental issues, plus additional bugs discovered during sessions 2 and 3. See [docs/session2_debugging_report.md](docs/session2_debugging_report.md) for the full analysis.

### Original Design Bugs (Session 1)

| Bug | Root Cause | Fix |
|-----|-----------|-----|
| Go return values corrupted | Only `rax` was set; `rbx`/`rcx` left as garbage from C call | Always set `rbx`/`rcx` using `go:itab.syscall.Errno,error` + heap-allocated errno slots |
| Thread-unsafe dispatch | Global flag to identify which syscall is active | Per-invocation state via `this._xxx` in Frida's `onEnter` |
| No assembly shim needed | prepRegs.asm + two-step replace+attach was fragile | Single `ret` trampoline + JS-side register read/write |

### Session 2 Bugs Fixed

| Bug | Symptom | Root Cause | Fix |
|-----|---------|-----------|-----|
| accept4 EBADF | "bad file descriptor" from Go's net.Accept | LDP fake fds (≥32) — kernel doesn't know about them; Go tried epoll on fake fd | Make accept4 blocking (spin-wait EAGAIN) to prevent Go's epoll path |
| read/write EBADF on connected sessions | Connection data transfer silently fails | Same fake fd issue — kernel read/write return EBADF for VCL fds | Hook `syscall.read`, `syscall.write`, `syscall.Close` to route through LDP |
| MPTCP duplicate listeners | EADDRINUSE on listen() | Go 1.21+ creates proto=262 (IPPROTO_MPTCP) socket in addition to TCP | Reject proto=262 with EPROTONOSUPPORT; Go falls back to TCP |
| IPv6 dual-stack EADDRINUSE | listen() fails | Go binds `[::]:port` → VPP creates both IPv4 and IPv6 listeners | Set `IPV6_V6ONLY=1` before calling `ldp.listen()` |
| connect stuck in SO_ERROR loop | Client hangs forever | `VPPCOM_ATTR_GET_ERROR` is a VPP stub returning 0 always | Use `ldp.epoll_wait(EPOLLOUT)` to wait for session READY |
| connect using ldp.poll blocks JS thread | Frida JS thread frozen indefinitely | `ldp.poll()` is a blocking call; blocks Frida's entire JS event loop | Use `ldp.epoll_wait()` instead (bounded timeout, processes MQ) |
| findLdpSym returns null | No LDP functions found | After `Module.load()`, Frida registers versioned soname `libvcl_ldpreload.so.26.06` | Search all modules for 'ldpreload' substring |
| goErrFromErrno nil pointer panic | Go crashes in error.Error() | `syscall.Errno` has pointer receivers — data word must be `*Errno`, not inline `Errno` | Allocate 8-byte slot per errno value; use slot address as data pointer |

### Session 3 Bugs Fixed

| Bug | Symptom | Root Cause | Fix |
|-----|---------|-----------|-----|
| VCL MQ starvation | write returns ENOTCONN, read returns EAGAIN forever | `vppcom_session_write/read` don't process VCL message queue; SESSION_CONNECTED event stuck unread | Use `ldp.epoll_wait()` as MQ pump (routes through `vppcom_epoll_wait` which drains MQ) |
| IPv4/IPv6 mismatch | "connect failed! no route" from VPP | Go's `net.Listen("tcp")` creates AF_INET6 socket; VPP can't match IPv4 connect to IPv6 listener | Use `"tcp4"` in both Go binaries to force AF_INET |
| Go runtime poller bypass | EINPROGRESS passthrough causes getsockopt spam loop | Go's runtime poller uses raw syscalls (not libc) → can't register VCL fake fds with kernel epoll | Handle all async connect in Frida hooks via `ldp.epoll_wait(EPOLLOUT)` |

### Frida 17 API Compatibility Fixes

| Broken API (Frida ≤16) | Replacement (Frida 17) |
|------------------------|------------------------|
| `Module.enumerateSymbols(name, {onMatch, onComplete})` | `Process.getModuleByName(name).enumerateSymbols()` (returns array) |
| `Process.enumerateModules({onMatch, onComplete})` | `Process.enumerateModules()` (returns array) |
| `Module.findExportByName(modName, sym)` static form | `findExport()` helper using `Process.findModuleByName(mod).findExportByName(sym)` |
| `Process.getEnvironmentVariable(name)` | `getenv()` via `NativeFunction` calling libc's `getenv` |
| `--no-pause` CLI flag | Removed in Frida 17 (auto-resume is now the default) |
| `Module.findExportByName(null, sym)` at spawn time | Must specify module name explicitly (e.g., `'libc.so.6'`) |

## Requirements

- Linux x86_64
- VPP built from source (e.g., at `/home/aritrbas/vpp`); `libvcl_ldpreload.so` in the build tree
- `LD_LIBRARY_PATH` pointing at VPP's lib directory (see Quick Start above)
- Frida 17+ (`pip3 install frida frida-tools`)
- Go binary built **without stripping** (no `-ldflags="-s -w"`) — Frida needs symbols
